use clap::Parser;
use dpdk::{Environment, MempoolConfig, Packet, Port, PortConfig};
use etherip::config::{Config, Tunnel, build_tunnels, split_args};
use etherip::etherip::{
    add_vlan_tag, decapsulate_packet, encapsulate_packet, strip_vlan_tag, tunnel_for_lan_frame,
    tunnel_index_for_wan, vlan_id,
};
use etherip::mac_table::MacTable;
use etherip::ndp::{icmpv6_packet_too_big, ndp_advertisement};
use etherip::reassembly::Reassembly;
use std::{
    env, io,
    net::Ipv6Addr,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU32, Ordering},
    },
    time::{Duration, Instant},
};
use tracing::{debug, error};

fn main() -> io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args: Vec<_> = env::args().collect();
    let (eal_args, app_args) = split_args(&args);
    let config = Config::parse_from(app_args);
    let tunnels = Arc::new(build_tunnels(&config)?);
    let workers = config.workers;

    let (dpdk, _) = Environment::init_with_config(
        &eal_args,
        MempoolConfig {
            socket_id: config
                .socket_id
                .map(i32::try_from)
                .transpose()
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "socket ID exceeds i32")
                })?,
            ..MempoolConfig::default()
        },
    )?;
    let port_config = PortConfig {
        rx_queue: config.rx_queue,
        tx_queue: config.tx_queue,
        rx_queues: if workers > 1 {
            workers
        } else {
            config.rx_queue.saturating_add(1)
        },
        tx_queues: if workers > 1 {
            workers
        } else {
            config.tx_queue.saturating_add(1)
        },
        rx_descriptors: config.rx_descriptors,
        tx_descriptors: config.tx_descriptors,
        socket_id: config.socket_id,
        promiscuous: true,
        rss: workers > 1,
    };
    let dpdk = Arc::new(dpdk);
    let lan = Arc::new(dpdk.open_with_config(config.lan, port_config)?);
    let wan = Arc::new(dpdk.open_with_config(config.wan, port_config)?);
    let wan_mac = wan.mac()?;

    let mac_tables = Arc::new(
        (0..tunnels.len())
            .map(|_| RwLock::new(MacTable::default()))
            .collect::<Vec<_>>(),
    );
    let reassembly = Arc::new(Mutex::new(Reassembly::default()));
    let path_mtu = Arc::new(
        tunnels
            .iter()
            .map(|tunnel| AtomicU32::new(tunnel.mtu as u32))
            .collect::<Vec<_>>(),
    );
    let frag_id = Arc::new(AtomicU32::new(0));

    if workers == 1 {
        let worker = Worker {
            lan: Arc::clone(&lan),
            wan: Arc::clone(&wan),
            dpdk: Arc::clone(&dpdk),
            tunnels: Arc::clone(&tunnels),
            mac_tables,
            reassembly,
            path_mtu,
            frag_id,
            rx_queue: config.rx_queue,
            tx_queue: config.tx_queue,
            wan_mac,
            local_ipv6: config.local_ipv6,
            burst_size: config.burst_size,
        };
        let code = worker.run();
        return if code == 0 {
            Ok(())
        } else {
            Err(io::Error::other("forwarding worker failed"))
        };
    }

    if dpdk::lcore_count() as usize <= workers as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "--workers {workers} requires {} lcores in the EAL -l mask, but only {} are configured",
                workers + 1,
                dpdk::lcore_count()
            ),
        ));
    }
    let mut lcore = dpdk::next_lcore(None);
    let mut launched = Vec::with_capacity(usize::from(workers));
    for worker_id in 0..workers {
        let Some(lcore_id) = lcore else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not enough worker lcores in the EAL -l mask",
            ));
        };
        let worker = Worker {
            lan: Arc::clone(&lan),
            wan: Arc::clone(&wan),
            dpdk: Arc::clone(&dpdk),
            tunnels: Arc::clone(&tunnels),
            mac_tables: Arc::clone(&mac_tables),
            reassembly: Arc::clone(&reassembly),
            path_mtu: Arc::clone(&path_mtu),
            frag_id: Arc::clone(&frag_id),
            rx_queue: worker_id,
            tx_queue: worker_id,
            wan_mac,
            local_ipv6: config.local_ipv6,
            burst_size: config.burst_size,
        };
        dpdk::launch_on_lcore(lcore_id, move || worker.run())?;
        launched.push(lcore_id);
        lcore = dpdk::next_lcore(Some(lcore_id));
    }
    for lcore in launched {
        dpdk::wait_on_lcore(lcore)?;
    }
    Ok(())
}

struct Worker {
    lan: Arc<Port>,
    wan: Arc<Port>,
    dpdk: Arc<Environment>,
    tunnels: Arc<Vec<Tunnel>>,
    mac_tables: Arc<Vec<RwLock<MacTable>>>,
    reassembly: Arc<Mutex<Reassembly>>,
    path_mtu: Arc<Vec<AtomicU32>>,
    frag_id: Arc<AtomicU32>,
    rx_queue: u16,
    tx_queue: u16,
    wan_mac: [u8; 6],
    local_ipv6: Ipv6Addr,
    burst_size: u16,
}

impl Worker {
    fn run(mut self) -> i32 {
        match self.forward() {
            Ok(()) => 0,
            Err(error) => {
                error!(?error, "worker stopped");
                -1
            }
        }
    }

    fn forward(&mut self) -> io::Result<()> {
        let capacity = usize::from(self.burst_size);
        let mut lan_received = Vec::with_capacity(capacity);
        let mut wan_received = Vec::with_capacity(capacity);
        let mut tunnel_packets = Vec::with_capacity(capacity);
        let mut lan_packets = Vec::with_capacity(capacity);
        let mut next_expiry = Instant::now() + Duration::from_secs(5);

        loop {
            self.lan
                .receive_burst_into(self.rx_queue, &mut lan_received, self.burst_size)?;
            for mut packet in lan_received.drain(..) {
                let Some(data) = packet.data() else {
                    debug!("dropping multi-segment LAN packet");
                    continue;
                };
                let Some(index) = tunnel_for_lan_frame(data, &self.tunnels) else {
                    match vlan_id(data) {
                        Some(vlan) => {
                            debug!(
                                frame_length = data.len(),
                                vlan, "dropping LAN frame for unknown VLAN"
                            )
                        }
                        None => debug!(frame_length = data.len(), "dropping untagged LAN frame"),
                    }
                    continue;
                };
                if self.mac_tables[index].read().unwrap().contains_source(data) {
                    debug!(
                        frame_length = data.len(),
                        tunnel = index,
                        "dropping LAN frame reflected from the remote"
                    );
                    continue;
                }
                if self.tunnels[index].vlan.is_some() {
                    strip_vlan_tag(&mut packet)?;
                }
                let mtu = self.path_mtu[index].load(Ordering::Relaxed) as usize;
                encapsulate_packet(
                    packet,
                    &self.dpdk,
                    &self.tunnels[index],
                    mtu,
                    self.wan_mac,
                    &self.frag_id,
                    &mut tunnel_packets,
                )?;
            }
            transmit(&self.wan, self.tx_queue, &mut tunnel_packets)?;

            self.wan
                .receive_burst_into(self.rx_queue, &mut wan_received, self.burst_size)?;
            for packet in wan_received.drain(..) {
                let Some(data) = packet.data() else {
                    continue;
                };
                let Some(index) = tunnel_index_for_wan(data, &self.tunnels) else {
                    if let Some(reply) = ndp_advertisement(data, self.local_ipv6, self.wan_mac) {
                        tunnel_packets.push(self.dpdk.packet(&reply)?);
                        continue;
                    }
                    if let Some((mtu, remote)) = icmpv6_packet_too_big(data, self.local_ipv6) {
                        if let Some(index) = self
                            .tunnels
                            .iter()
                            .position(|tunnel| tunnel.remote_ipv6 == remote)
                        {
                            let old = self.path_mtu[index].load(Ordering::Relaxed);
                            let new = mtu.max(1280).min(old);
                            if new != old {
                                self.path_mtu[index].store(new, Ordering::Relaxed);
                                debug!(
                                    ?remote,
                                    mtu = new,
                                    "updated path MTU from ICMPv6 Packet Too Big"
                                );
                            }
                        }
                        continue;
                    }
                    let source = data
                        .get(22..38)
                        .and_then(|bytes| <[u8; 16]>::try_from(bytes).ok())
                        .map(Ipv6Addr::from);
                    let destination = data
                        .get(38..54)
                        .and_then(|bytes| <[u8; 16]>::try_from(bytes).ok())
                        .map(Ipv6Addr::from);
                    debug!(
                        frame_length = data.len(),
                        ?source,
                        ?destination,
                        next_header = data.get(20).copied(),
                        "dropping WAN packet from an unknown tunnel"
                    );
                    continue;
                };
                let mut reassembly = self.reassembly.lock().unwrap();
                if let Some(mut packet) =
                    decapsulate_packet(packet, &self.dpdk, &self.tunnels[index], &mut reassembly)?
                {
                    drop(reassembly);
                    if let Some(frame) = packet.data() {
                        self.mac_tables[index].write().unwrap().learn_source(frame);
                    }
                    if let Some(vlan) = self.tunnels[index].vlan {
                        add_vlan_tag(&mut packet, vlan)?;
                    }
                    lan_packets.push(packet);
                }
            }
            transmit(&self.wan, self.tx_queue, &mut tunnel_packets)?;
            transmit(&self.lan, self.tx_queue, &mut lan_packets)?;

            if Instant::now() >= next_expiry {
                for table in self.mac_tables.iter() {
                    table.write().unwrap().expire();
                }
                self.reassembly.lock().unwrap().expire();
                next_expiry = Instant::now() + Duration::from_secs(5);
            }
        }
    }
}

fn transmit(port: &Port, queue: u16, packets: &mut Vec<Packet>) -> io::Result<()> {
    let sent = port.send_burst(queue, packets)?;
    packets.drain(..sent);
    Ok(())
}
