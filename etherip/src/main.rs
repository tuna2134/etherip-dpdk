use clap::Parser;
use dpdk::{Environment, MempoolConfig, Packet, Port, PortConfig};
use std::{
    collections::HashMap,
    env, io,
    net::Ipv6Addr,
    time::{Duration, Instant},
};

const ETHER_TYPE_IPV6: u16 = 0x86dd;
const NEXT_ETHERIP: u8 = 97;
const NEXT_FRAGMENT: u8 = 44;
const ETHERIP_HEADER: [u8; 2] = [0x30, 0];
const MAX_PACKET: usize = 65_535;
const MAC_AGE: Duration = Duration::from_secs(300);

#[derive(Parser)]
#[command(
    version,
    about = "Bridge Ethernet frames through an RFC 3378 EtherIP/IPv6 tunnel",
    after_help = "DPDK EAL options go before `--`, for example:\n  etherip -l 0 -- --lan-port 0 --wan-port 1 --local-ipv6 2001:db8::1 --remote-ipv6 2001:db8::2 --next-hop-mac 02:00:00:00:00:02"
)]
struct Config {
    /// DPDK port connected to the bridged LAN.
    #[arg(long = "lan-port")]
    lan: u16,

    /// DPDK port carrying the outer IPv6 packets.
    #[arg(long = "wan-port")]
    wan: u16,

    /// Local address used by the outer IPv6 header.
    #[arg(long)]
    local_ipv6: Ipv6Addr,

    /// Remote EtherIP endpoint's IPv6 address.
    #[arg(long)]
    remote_ipv6: Ipv6Addr,

    /// Ethernet next-hop for the remote IPv6 endpoint.
    #[arg(long, value_parser = parse_mac)]
    next_hop_mac: [u8; 6],

    /// Outer IPv6 MTU. Larger EtherIP payloads use IPv6 fragments.
    #[arg(long, default_value_t = 1500, value_parser = parse_mtu)]
    mtu: usize,

    /// RX queue used on both ports.
    #[arg(long, default_value_t = 0)]
    rx_queue: u16,

    /// TX queue used on both ports.
    #[arg(long, default_value_t = 0)]
    tx_queue: u16,

    /// RX descriptors allocated per port.
    #[arg(long, default_value_t = 1024, value_parser = parse_nonzero_u16)]
    rx_descriptors: u16,

    /// TX descriptors allocated per port.
    #[arg(long, default_value_t = 1024, value_parser = parse_nonzero_u16)]
    tx_descriptors: u16,

    /// NUMA socket for the mempool and queues; DPDK chooses it when omitted.
    #[arg(long)]
    socket_id: Option<u32>,

    /// Number of packets requested from each RX burst (multiple of 8).
    #[arg(long, default_value_t = 32, value_parser = parse_burst_size)]
    burst_size: u16,
}

fn main() -> io::Result<()> {
    let args: Vec<_> = env::args().collect();
    let (eal_args, app_args) = split_args(&args);
    let config = Config::parse_from(app_args);
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
    let mut reassembly = Reassembly::default();
    let mut remote_macs = MacTable::default();
    let mut identification = 0u32;
    let capacity = usize::from(config.burst_size);
    let mut lan_received = Vec::with_capacity(capacity);
    let mut wan_received = Vec::with_capacity(capacity);
    let mut tunnel_packets = Vec::with_capacity(capacity);
    let mut lan_packets = Vec::with_capacity(capacity);

    loop {
        tunnel_packets.clear();
        lan.receive_burst_into(&mut lan_received, config.burst_size)?;
        for packet in lan_received.drain(..) {
            let tunnel = packet
                .data()
                .is_some_and(|frame| !remote_macs.contains_source(frame));
            if tunnel {
                tunnel_packets.extend(encapsulate_packet(
                    packet,
                    &dpdk,
                    &config,
                    wan_mac,
                    &mut identification,
                )?);
            }
        }
        transmit(&wan, &mut tunnel_packets)?;

        lan_packets.clear();
        wan.receive_burst_into(&mut wan_received, config.burst_size)?;
        for packet in wan_received.drain(..) {
            if let Some(packet) = decapsulate_packet(packet, &dpdk, &config, &mut reassembly)? {
                if let Some(frame) = packet.data() {
                    remote_macs.learn_source(frame);
                }
                lan_packets.push(packet);
            }
        }
        transmit(&lan, &mut lan_packets)?;
        reassembly.expire();
        remote_macs.expire();
    }
}

fn transmit(port: &Port, packets: &mut Vec<Packet>) -> io::Result<()> {
    let sent = port.send_burst(packets)?;
    packets.drain(..sent);
    Ok(())
}

fn split_args(args: &[String]) -> (Vec<String>, Vec<String>) {
    let Some(separator) = args.iter().position(|arg| arg == "--") else {
        return (vec![args[0].clone()], args.to_vec());
    };
    let mut app = Vec::with_capacity(args.len() - separator);
    app.push(args[0].clone());
    app.extend_from_slice(&args[separator + 1..]);
    (args[..separator].to_vec(), app)
}

fn parse_mac(value: &str) -> Result<[u8; 6], String> {
    let bytes: Vec<_> = value
        .split(':')
        .map(|part| u8::from_str_radix(part, 16))
        .collect::<Result<_, _>>()
        .map_err(|_| "invalid next-hop MAC")?;
    bytes
        .try_into()
        .map_err(|_| "next-hop MAC must contain six octets".into())
}

fn parse_mtu(value: &str) -> Result<usize, String> {
    let mtu = value.parse().map_err(|_| "MTU must be an integer")?;
    (70..=65_575)
        .contains(&mtu)
        .then_some(mtu)
        .ok_or_else(|| "MTU must be between 70 and 65575".into())
}

fn parse_nonzero_u16(value: &str) -> Result<u16, String> {
    let value = value.parse().map_err(|_| "value must be an integer")?;
    (value != 0)
        .then_some(value)
        .ok_or_else(|| "value must be greater than zero".into())
}

fn parse_burst_size(value: &str) -> Result<u16, String> {
    let value = parse_nonzero_u16(value)?;
    value
        .is_multiple_of(8)
        .then_some(value)
        .ok_or_else(|| "burst size must be a multiple of 8".into())
}

fn encapsulate_packet(
    mut packet: Packet,
    dpdk: &Environment,
    config: &Config,
    source_mac: [u8; 6],
    id: &mut u32,
) -> io::Result<Vec<Packet>> {
    let frame_length = packet
        .data()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "multi-segment LAN packet"))?
        .len();
    if 40 + ETHERIP_HEADER.len() + frame_length <= config.mtu {
        let header = packet.prepend(56)?;
        write_outer_header(header, config, source_mac, NEXT_ETHERIP, frame_length + 2);
        header[54..56].copy_from_slice(&ETHERIP_HEADER);
        return Ok(vec![packet]);
    }
    let frame = packet.data().expect("packet was checked as contiguous");
    fragment_packets(frame, config, source_mac, id)?
        .into_iter()
        .map(|bytes| dpdk.packet(&bytes))
        .collect()
}

fn fragment_packets(
    frame: &[u8],
    config: &Config,
    source_mac: [u8; 6],
    id: &mut u32,
) -> io::Result<Vec<Vec<u8>>> {
    let mut payload = Vec::with_capacity(frame.len() + 2);
    payload.extend_from_slice(&ETHERIP_HEADER);
    payload.extend_from_slice(frame);
    if payload.len() > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "EtherIP payload exceeds the IPv6 payload limit",
        ));
    }
    let chunk = ((config
        .mtu
        .checked_sub(40 + 8)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "MTU too small"))?)
        / 8)
        * 8;
    if chunk == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "EtherIP frame cannot be fragmented for this MTU",
        ));
    }
    *id = id.wrapping_add(1);
    Ok(payload
        .chunks(chunk)
        .enumerate()
        .map(|(index, part)| {
            let more = index * chunk + part.len() < payload.len();
            let offset_flags = (((index * chunk) / 8) as u16) << 3 | u16::from(more);
            let mut fragment = Vec::with_capacity(8 + part.len());
            fragment.push(NEXT_ETHERIP);
            fragment.push(0);
            fragment.extend_from_slice(&offset_flags.to_be_bytes());
            fragment.extend_from_slice(&id.to_be_bytes());
            fragment.extend_from_slice(part);
            ipv6_packet(config, source_mac, NEXT_FRAGMENT, &fragment)
        })
        .collect())
}

fn ipv6_packet(config: &Config, source_mac: [u8; 6], next: u8, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(54 + payload.len());
    packet.resize(54, 0);
    write_outer_header(&mut packet, config, source_mac, next, payload.len());
    packet.extend_from_slice(payload);
    packet
}

fn write_outer_header(
    header: &mut [u8],
    config: &Config,
    source_mac: [u8; 6],
    next: u8,
    payload_length: usize,
) {
    header[0..6].copy_from_slice(&config.next_hop_mac);
    header[6..12].copy_from_slice(&source_mac);
    header[12..14].copy_from_slice(&ETHER_TYPE_IPV6.to_be_bytes());
    header[14..18].copy_from_slice(&[0x60, 0, 0, 0]);
    header[18..20].copy_from_slice(&(payload_length as u16).to_be_bytes());
    header[20] = next;
    header[21] = 64;
    header[22..38].copy_from_slice(&config.local_ipv6.octets());
    header[38..54].copy_from_slice(&config.remote_ipv6.octets());
}

fn decapsulate_packet(
    mut packet: Packet,
    dpdk: &Environment,
    config: &Config,
    reassembly: &mut Reassembly,
) -> io::Result<Option<Packet>> {
    let Some(data) = packet.data() else {
        return Ok(None);
    };
    if !valid_outer_packet(data, config) {
        return Ok(None);
    }
    let payload_length = u16::from_be_bytes([data[18], data[19]]) as usize;
    let payload = &data[54..54 + payload_length];
    match data[20] {
        NEXT_ETHERIP if etherip_payload(payload).is_some() => {
            packet.adjust(56)?;
            Ok(Some(packet))
        }
        NEXT_FRAGMENT if payload.len() >= 8 && payload[0] == NEXT_ETHERIP && payload[1] == 0 => {
            let field = u16::from_be_bytes([payload[2], payload[3]]);
            if field & 6 != 0 {
                return Ok(None);
            }
            let key = (
                data[22..38].try_into().unwrap(),
                data[38..54].try_into().unwrap(),
                u32::from_be_bytes(payload[4..8].try_into().unwrap()),
            );
            let Some(etherip) = reassembly.insert(
                key,
                (field as usize >> 3) * 8,
                field & 1 != 0,
                &payload[8..],
            ) else {
                return Ok(None);
            };
            let Some(frame) = etherip_payload(&etherip) else {
                return Ok(None);
            };
            Ok(Some(dpdk.packet(frame)?))
        }
        _ => Ok(None),
    }
}

fn etherip_payload(payload: &[u8]) -> Option<&[u8]> {
    payload.strip_prefix(&ETHERIP_HEADER)
}

fn valid_outer_packet(packet: &[u8], config: &Config) -> bool {
    if packet.len() < 54
        || u16::from_be_bytes([packet[12], packet[13]]) != ETHER_TYPE_IPV6
        || packet[14] >> 4 != 6
    {
        return false;
    }
    let payload_length = u16::from_be_bytes([packet[18], packet[19]]) as usize;
    packet.len() >= 54 + payload_length
        && packet[22..38] == config.remote_ipv6.octets()
        && packet[38..54] == config.local_ipv6.octets()
}

type FragmentKey = ([u8; 16], [u8; 16], u32);

struct MacTable {
    remote: HashMap<[u8; 6], Instant>,
    next_expiry: Instant,
}

impl Default for MacTable {
    fn default() -> Self {
        Self {
            remote: HashMap::new(),
            next_expiry: Instant::now() + MAC_AGE,
        }
    }
}

impl MacTable {
    fn learn_source(&mut self, frame: &[u8]) {
        if let Some(source) = source_mac(frame)
            && source[0] & 1 == 0
        {
            self.remote.insert(source, Instant::now());
        }
    }

    fn contains_source(&self, frame: &[u8]) -> bool {
        source_mac(frame).is_some_and(|source| {
            self.remote
                .get(&source)
                .is_some_and(|seen| seen.elapsed() < MAC_AGE)
        })
    }

    fn expire(&mut self) {
        if Instant::now() >= self.next_expiry {
            self.remote.retain(|_, seen| seen.elapsed() < MAC_AGE);
            self.next_expiry = Instant::now() + MAC_AGE;
        }
    }
}

fn source_mac(frame: &[u8]) -> Option<[u8; 6]> {
    frame.get(6..12)?.try_into().ok()
}

#[derive(Default)]
struct Reassembly {
    packets: HashMap<FragmentKey, Partial>,
}
struct Partial {
    updated: Instant,
    total: Option<usize>,
    fragments: Vec<(usize, Vec<u8>)>,
}

impl Reassembly {
    fn insert(
        &mut self,
        key: FragmentKey,
        offset: usize,
        more: bool,
        data: &[u8],
    ) -> Option<Vec<u8>> {
        if (more && !data.len().is_multiple_of(8)) || offset.checked_add(data.len())? > MAX_PACKET {
            self.packets.remove(&key);
            return None;
        }
        // ponytail: fixed limits prevent fragment-memory exhaustion; make configurable if real traffic hits them.
        if self.packets.len() >= 1024 && !self.packets.contains_key(&key) {
            return None;
        }
        let partial = self.packets.entry(key).or_insert_with(|| Partial {
            updated: Instant::now(),
            total: None,
            fragments: Vec::new(),
        });
        if partial.fragments.len() >= 128 {
            self.packets.remove(&key);
            return None;
        }
        let end = offset + data.len();
        if partial
            .fragments
            .iter()
            .any(|(start, bytes)| offset < start + bytes.len() && *start < end)
        {
            self.packets.remove(&key);
            return None;
        }
        partial.updated = Instant::now();
        if !more {
            partial.total = Some(end);
        }
        partial.fragments.push((offset, data.to_vec()));
        partial.fragments.sort_unstable_by_key(|part| part.0);
        let total = partial.total?;
        if partial
            .fragments
            .iter()
            .scan(0, |next, (offset, bytes)| {
                let contiguous = *offset == *next;
                *next += bytes.len();
                Some(contiguous)
            })
            .all(|v| v)
            && partial
                .fragments
                .iter()
                .map(|(_, bytes)| bytes.len())
                .sum::<usize>()
                == total
        {
            let mut result = Vec::with_capacity(total);
            for (_, bytes) in &partial.fragments {
                result.extend_from_slice(bytes);
            }
            self.packets.remove(&key);
            return Some(result);
        }
        None
    }

    fn expire(&mut self) {
        self.packets
            .retain(|_, packet| packet.updated.elapsed() < Duration::from_secs(60));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragmented_round_trip() {
        let config = Config {
            lan: 0,
            wan: 1,
            local_ipv6: Ipv6Addr::from([1; 16]),
            remote_ipv6: Ipv6Addr::from([2; 16]),
            next_hop_mac: [3; 6],
            mtu: 1280,
            rx_queue: 0,
            tx_queue: 0,
            rx_descriptors: 1024,
            tx_descriptors: 1024,
            socket_id: None,
            burst_size: 32,
        };
        let frame = vec![0xa5; 2000];
        let packets = fragment_packets(&frame, &config, [4; 6], &mut 0).unwrap();
        let reverse = Config {
            local_ipv6: config.remote_ipv6,
            remote_ipv6: config.local_ipv6,
            ..config
        };
        let mut reassembly = Reassembly::default();
        let mut result = None;
        for packet in packets.into_iter().rev() {
            assert!(valid_outer_packet(&packet, &reverse));
            let payload = &packet[54..];
            let field = u16::from_be_bytes([payload[2], payload[3]]);
            let key = (
                packet[22..38].try_into().unwrap(),
                packet[38..54].try_into().unwrap(),
                u32::from_be_bytes(payload[4..8].try_into().unwrap()),
            );
            result = reassembly
                .insert(
                    key,
                    (field as usize >> 3) * 8,
                    field & 1 != 0,
                    &payload[8..],
                )
                .or(result);
        }
        assert_eq!(etherip_payload(&result.unwrap()).unwrap(), frame);
    }

    #[test]
    fn rejects_bad_etherip_header() {
        let config = Config {
            lan: 0,
            wan: 1,
            local_ipv6: Ipv6Addr::from([1; 16]),
            remote_ipv6: Ipv6Addr::from([2; 16]),
            next_hop_mac: [3; 6],
            mtu: 1500,
            rx_queue: 0,
            tx_queue: 0,
            rx_descriptors: 1024,
            tx_descriptors: 1024,
            socket_id: None,
            burst_size: 32,
        };
        let mut packet = ipv6_packet(&config, [4; 6], NEXT_ETHERIP, &[0x31, 0, 1]);
        let reverse = Config {
            local_ipv6: config.remote_ipv6,
            remote_ipv6: config.local_ipv6,
            ..config
        };
        assert!(valid_outer_packet(&packet, &reverse));
        assert!(etherip_payload(&packet[54..]).is_none());
        packet[54] = 0x30;
        assert_eq!(etherip_payload(&packet[54..]), Some([1].as_slice()));
    }

    #[test]
    fn suppresses_a_frame_returning_from_the_remote_lan() {
        let mut table = MacTable::default();
        let mut frame = [0u8; 14];
        frame[6..12].copy_from_slice(&[2, 3, 4, 5, 6, 7]);
        assert!(!table.contains_source(&frame));
        table.learn_source(&frame);
        assert!(table.contains_source(&frame));
    }

    #[test]
    fn parses_cli_after_eal_separator() {
        let args = [
            "etherip",
            "-l",
            "0",
            "--",
            "--lan-port",
            "0",
            "--wan-port",
            "1",
            "--local-ipv6",
            "2001:db8::1",
            "--remote-ipv6",
            "2001:db8::2",
            "--next-hop-mac",
            "02:00:00:00:00:02",
        ]
        .map(str::to_owned);
        let (eal, app) = split_args(&args);
        let config = Config::try_parse_from(app).unwrap();
        assert_eq!(eal, ["etherip", "-l", "0"]);
        assert_eq!(config.mtu, 1500);
        assert_eq!(config.next_hop_mac, [2, 0, 0, 0, 0, 2]);
    }
}
