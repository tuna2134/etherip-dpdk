use clap::Parser;
use dpdk::{Environment, MempoolConfig, Packet, Port, PortConfig};
use etherip::config::{Config, build_tunnels, split_args};
use etherip::etherip::{
    add_vlan_tag, decapsulate_packet, encapsulate_packet, strip_vlan_tag, tunnel_for_lan_frame,
    tunnel_index_for_wan, vlan_id,
};
use etherip::mac_table::MacTable;
use etherip::ndp::ndp_advertisement;
use etherip::reassembly::Reassembly;
use std::{env, io, net::Ipv6Addr};
use tracing::debug;

fn main() -> io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args: Vec<_> = env::args().collect();
    let (eal_args, app_args) = split_args(&args);
    let config = Config::parse_from(app_args);
    let tunnels = build_tunnels(&config)?;
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
        rx_descriptors: config.rx_descriptors,
        tx_descriptors: config.tx_descriptors,
        socket_id: config.socket_id,
        ..PortConfig::default()
    };
    let lan = dpdk.open_with_config(config.lan, port_config)?;
    let wan = dpdk.open_with_config(config.wan, port_config)?;
    let wan_mac = wan.mac()?;
    let mut tables: Vec<MacTable> = (0..tunnels.len()).map(|_| MacTable::default()).collect();
    let mut reassembly = Reassembly::default();
    let mut identification = 0u32;
    let capacity = usize::from(config.burst_size);
    let mut lan_received = Vec::with_capacity(capacity);
    let mut wan_received = Vec::with_capacity(capacity);
    let mut tunnel_packets = Vec::with_capacity(capacity);
    let mut lan_packets = Vec::with_capacity(capacity);

    loop {
        lan.receive_burst_into(&mut lan_received, config.burst_size)?;
        for mut packet in lan_received.drain(..) {
            let Some(data) = packet.data() else {
                debug!("dropping multi-segment LAN packet");
                continue;
            };
            let Some(index) = tunnel_for_lan_frame(data, &tunnels) else {
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
            if tables[index].contains_source(data) {
                debug!(
                    frame_length = data.len(),
                    tunnel = index,
                    "dropping LAN frame reflected from the remote"
                );
                continue;
            }
            if tunnels[index].vlan.is_some() {
                strip_vlan_tag(&mut packet)?;
            }
            encapsulate_packet(
                packet,
                &dpdk,
                &tunnels[index],
                wan_mac,
                &mut identification,
                &mut tunnel_packets,
            )?;
        }
        transmit(&wan, &mut tunnel_packets)?;

        wan.receive_burst_into(&mut wan_received, config.burst_size)?;
        for packet in wan_received.drain(..) {
            let Some(data) = packet.data() else {
                continue;
            };
            let Some(index) = tunnel_index_for_wan(data, &tunnels) else {
                if let Some(reply) = ndp_advertisement(data, config.local_ipv6, wan_mac) {
                    tunnel_packets.push(dpdk.packet(&reply)?);
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
            if let Some(mut packet) =
                decapsulate_packet(packet, &dpdk, &tunnels[index], &mut reassembly)?
            {
                if let Some(frame) = packet.data() {
                    tables[index].learn_source(frame);
                }
                if let Some(vlan) = tunnels[index].vlan {
                    add_vlan_tag(&mut packet, vlan)?;
                }
                lan_packets.push(packet);
            }
        }
        transmit(&wan, &mut tunnel_packets)?;
        transmit(&lan, &mut lan_packets)?;
        reassembly.expire();
        for table in &mut tables {
            table.expire();
        }
    }
}

fn transmit(port: &Port, packets: &mut Vec<Packet>) -> io::Result<()> {
    let sent = port.send_burst(packets)?;
    packets.drain(..sent);
    Ok(())
}
