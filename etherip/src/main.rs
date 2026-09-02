use clap::Parser;
use dpdk::{Environment, MempoolConfig, Packet, Port, PortConfig};
use std::{
    collections::HashMap,
    env, io,
    net::Ipv6Addr,
    time::{Duration, Instant},
};
use tracing::debug;

const ETHER_TYPE_IPV6: u16 = 0x86dd;
const ETHER_TYPE_VLAN: u16 = 0x8100;
const NEXT_ICMPV6: u8 = 58;
const NEXT_ETHERIP: u8 = 97;
const NEXT_FRAGMENT: u8 = 44;
const ETHERIP_HEADER: [u8; 2] = [0x30, 0];
const MAX_PACKET: usize = 65_535;
const MAC_AGE: Duration = Duration::from_secs(300);

/// One tunnel endpoint and the LAN-side VLAN that selects it.
///
/// `vlan: None` keeps the legacy single-tunnel mode, in which every LAN frame is
/// bridged as-is (VLAN tags pass through untouched).
#[derive(Clone, Copy, Debug)]
struct Tunnel {
    vlan: Option<u16>,
    local_ipv6: Ipv6Addr,
    remote_ipv6: Ipv6Addr,
    next_hop_mac: [u8; 6],
    mtu: usize,
}

/// Parsed value of one `--tunnel` argument before defaults are resolved.
#[derive(Clone, Copy, Debug)]
struct TunnelSpec {
    vlan: u16,
    remote_ipv6: Ipv6Addr,
    next_hop_mac: [u8; 6],
    mtu: Option<usize>,
}

#[derive(Parser)]
#[command(
    version,
    about = "Bridge Ethernet frames through an RFC 3378 EtherIP/IPv6 tunnel",
    after_help = "DPDK EAL options go before `--`, for example:\n  etherip -l 0 -- --lan-port 0 --wan-port 1 --local-ipv6 2001:db8::1 --remote-ipv6 2001:db8::2 --next-hop-mac 02:00:00:00:00:02\n  For multiple tunnels use --tunnel instead:\n  etherip -l 0 -- --lan-port 0 --wan-port 1 --local-ipv6 2001:db8::1 --tunnel 100,2001:db8::2,02:00:00:00:00:02 --tunnel 200,2001:db8::3,02:00:00:00:00:03"
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

    /// Remote EtherIP endpoint's IPv6 address for the single-tunnel mode.
    #[arg(long, conflicts_with = "tunnels")]
    remote_ipv6: Option<Ipv6Addr>,

    /// Ethernet next-hop for the remote IPv6 endpoint for the single-tunnel mode.
    #[arg(long, conflicts_with = "tunnels", value_parser = parse_mac)]
    next_hop_mac: Option<[u8; 6]>,

    /// Default outer IPv6 MTU; each --tunnel can override it.
    #[arg(long, default_value_t = 1500, value_parser = parse_mtu)]
    mtu: usize,

    /// Add an EtherIP tunnel as <VLAN>,<REMOTE_IPV6>,<NEXT_HOP_MAC>[,<MTU>].
    /// Repeatable. LAN frames tagged with the VLAN are bridged into the matching
    /// tunnel; the tag is stripped before encapsulation and re-added on receive.
    #[arg(long = "tunnel", value_parser = parse_tunnel)]
    tunnels: Vec<TunnelSpec>,

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
                continue;
            };
            let Some(index) = tunnel_for_lan_frame(data, &tunnels) else {
                continue;
            };
            if tables[index].contains_source(data) {
                continue;
            }
            if tunnels[index].vlan.is_some() {
                strip_vlan_tag(&mut packet)?;
            }
            tunnel_packets.extend(encapsulate_packet(
                packet,
                &dpdk,
                &tunnels[index],
                wan_mac,
                &mut identification,
            )?);
        }
        transmit(&wan, &mut tunnel_packets)?;

        wan.receive_burst_into(&mut wan_received, config.burst_size)?;
        for packet in wan_received.drain(..) {
            if let Some(reply) = packet
                .data()
                .and_then(|data| ndp_advertisement(data, &config, wan_mac))
            {
                tunnel_packets.push(dpdk.packet(&reply)?);
                continue;
            }
            let Some(data) = packet.data() else {
                continue;
            };
            let Some(index) = tunnel_index_for_wan(data, &tunnels) else {
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

fn build_tunnels(config: &Config) -> io::Result<Vec<Tunnel>> {
    if config.tunnels.is_empty() {
        let remote_ipv6 = config.remote_ipv6.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "--remote-ipv6 is required without --tunnel",
            )
        })?;
        let next_hop_mac = config.next_hop_mac.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "--next-hop-mac is required without --tunnel",
            )
        })?;
        return Ok(vec![Tunnel {
            vlan: None,
            local_ipv6: config.local_ipv6,
            remote_ipv6,
            next_hop_mac,
            mtu: config.mtu,
        }]);
    }
    let mut tunnels = Vec::with_capacity(config.tunnels.len());
    for spec in &config.tunnels {
        if tunnels
            .iter()
            .any(|tunnel: &Tunnel| tunnel.vlan == Some(spec.vlan))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("duplicate tunnel VLAN ID {}", spec.vlan),
            ));
        }
        tunnels.push(Tunnel {
            vlan: Some(spec.vlan),
            local_ipv6: config.local_ipv6,
            remote_ipv6: spec.remote_ipv6,
            next_hop_mac: spec.next_hop_mac,
            mtu: spec.mtu.unwrap_or(config.mtu),
        });
    }
    Ok(tunnels)
}

/// Selects the tunnel for a LAN-side frame. The legacy single tunnel accepts every
/// frame; with VLANs the frame must carry the matching 802.1Q tag.
fn tunnel_for_lan_frame(frame: &[u8], tunnels: &[Tunnel]) -> Option<usize> {
    if tunnels.len() == 1 && tunnels[0].vlan.is_none() {
        return Some(0);
    }
    let vlan = vlan_id(frame)?;
    tunnels.iter().position(|tunnel| tunnel.vlan == Some(vlan))
}

/// Selects the tunnel that an outer WAN packet belongs to by its source address.
fn tunnel_index_for_wan(packet: &[u8], tunnels: &[Tunnel]) -> Option<usize> {
    let source: [u8; 16] = packet.get(22..38)?.try_into().ok()?;
    tunnels
        .iter()
        .position(|tunnel| tunnel.remote_ipv6.octets() == source)
}

fn vlan_id(frame: &[u8]) -> Option<u16> {
    if frame.len() < 16 || u16::from_be_bytes([frame[12], frame[13]]) != ETHER_TYPE_VLAN {
        return None;
    }
    Some(u16::from_be_bytes([frame[14], frame[15]]) & 0x0fff)
}

/// Removes the 4-byte 802.1Q header so the tunnel carries an untagged frame.
fn strip_vlan_tag(packet: &mut Packet) -> io::Result<()> {
    let data = packet
        .data_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "multi-segment VLAN packet"))?;
    if data.len() < 16 || u16::from_be_bytes([data[12], data[13]]) != ETHER_TYPE_VLAN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "LAN frame has no VLAN tag",
        ));
    }
    data.copy_within(16.., 12);
    packet.trim_tail(4)
}

/// Prepends the configured 802.1Q header to a frame received from a tunnel.
fn add_vlan_tag(packet: &mut Packet, vlan: u16) -> io::Result<()> {
    let original = packet.len();
    packet.append(4)?;
    let data = packet
        .data_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "multi-segment tunnel frame"))?;
    data.copy_within(12..original, 16);
    data[12] = 0x81;
    data[13] = 0x00;
    data[14] = (vlan >> 8) as u8;
    data[15] = (vlan & 0xff) as u8;
    Ok(())
}

fn ndp_advertisement(packet: &[u8], config: &Config, local_mac: [u8; 6]) -> Option<Vec<u8>> {
    const ICMP_OFFSET: usize = 54;
    const NS_LENGTH: usize = 24;
    const NA_LENGTH: usize = 32;

    if packet.len() < ICMP_OFFSET + NS_LENGTH
        || u16::from_be_bytes(packet[12..14].try_into().ok()?) != ETHER_TYPE_IPV6
        || packet[14] >> 4 != 6
        || packet[20] != NEXT_ICMPV6
        || packet[21] != 255
    {
        return None;
    }
    let payload_length = u16::from_be_bytes(packet[18..20].try_into().ok()?) as usize;
    if payload_length < NS_LENGTH || packet.len() < ICMP_OFFSET + payload_length {
        return None;
    }
    let source_ip: [u8; 16] = packet[22..38].try_into().ok()?;
    let destination_ip: [u8; 16] = packet[38..54].try_into().ok()?;
    let target = config.local_ipv6.octets();
    let mut solicited_node = [0u8; 16];
    solicited_node[..13].copy_from_slice(&[0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff]);
    solicited_node[13..].copy_from_slice(&target[13..]);
    let icmp = &packet[ICMP_OFFSET..ICMP_OFFSET + payload_length];
    if (destination_ip != target && destination_ip != solicited_node)
        || icmp[0] != 135
        || icmp[1] != 0
        || icmp[8..24] != target
        || icmpv6_checksum(&source_ip, &destination_ip, icmp) != 0
    {
        return None;
    }

    let unspecified = source_ip == [0; 16];
    let destination_mac = if unspecified {
        [0x33, 0x33, 0, 0, 0, 1]
    } else {
        packet[6..12].try_into().ok()?
    };
    let reply_destination_ip = if unspecified {
        [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
    } else {
        source_ip
    };
    let mut reply = vec![0u8; ICMP_OFFSET + NA_LENGTH];
    reply[..6].copy_from_slice(&destination_mac);
    reply[6..12].copy_from_slice(&local_mac);
    reply[12..14].copy_from_slice(&ETHER_TYPE_IPV6.to_be_bytes());
    reply[14] = 0x60;
    reply[18..20].copy_from_slice(&(NA_LENGTH as u16).to_be_bytes());
    reply[20] = NEXT_ICMPV6;
    reply[21] = 255;
    reply[22..38].copy_from_slice(&target);
    reply[38..54].copy_from_slice(&reply_destination_ip);
    reply[54] = 136;
    reply[58] = if unspecified { 0x20 } else { 0x60 }; // Override, plus Solicited outside DAD.
    reply[62..78].copy_from_slice(&target);
    reply[78] = 2; // Target Link-Layer Address
    reply[79] = 1;
    reply[80..86].copy_from_slice(&local_mac);
    let checksum = icmpv6_checksum(&target, &reply_destination_ip, &reply[54..]);
    reply[56..58].copy_from_slice(&checksum.to_be_bytes());
    Some(reply)
}

fn icmpv6_checksum(source: &[u8; 16], destination: &[u8; 16], message: &[u8]) -> u16 {
    let mut sum = source
        .chunks_exact(2)
        .chain(destination.chunks_exact(2))
        .chain(message.chunks_exact(2))
        .map(|word| u16::from_be_bytes([word[0], word[1]]) as u32)
        .sum::<u32>();
    sum += message.len() as u32 + NEXT_ICMPV6 as u32;
    if let Some(&last) = message.chunks_exact(2).remainder().first() {
        sum += u32::from(last) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
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

fn parse_tunnel(value: &str) -> Result<TunnelSpec, String> {
    let parts: Vec<_> = value.split(',').collect();
    if !(3..=4).contains(&parts.len()) {
        return Err("--tunnel must be <VLAN>,<REMOTE_IPV6>,<NEXT_HOP_MAC>[,<MTU>]".into());
    }
    let vlan = parse_vlan(parts[0])?;
    let remote_ipv6 = parts[1]
        .parse()
        .map_err(|_| "invalid remote IPv6 address in --tunnel")?;
    let next_hop_mac = parse_mac(parts[2])?;
    let mtu = match parts.get(3) {
        Some(mtu) => Some(parse_mtu(mtu)?),
        None => None,
    };
    Ok(TunnelSpec {
        vlan,
        remote_ipv6,
        next_hop_mac,
        mtu,
    })
}

fn parse_vlan(value: &str) -> Result<u16, String> {
    let vlan = value.parse().map_err(|_| "VLAN ID must be an integer")?;
    (1..=4094)
        .contains(&vlan)
        .then_some(vlan)
        .ok_or_else(|| "VLAN ID must be between 1 and 4094".into())
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
    tunnel: &Tunnel,
    source_mac: [u8; 6],
    id: &mut u32,
) -> io::Result<Vec<Packet>> {
    let frame_length = packet
        .data()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "multi-segment LAN packet"))?
        .len();
    if 40 + ETHERIP_HEADER.len() + frame_length <= tunnel.mtu {
        let header = packet.prepend(56)?;
        write_outer_header(header, tunnel, source_mac, NEXT_ETHERIP, frame_length + 2);
        header[54..56].copy_from_slice(&ETHERIP_HEADER);
        debug!(frame_length, "sending EtherIP packet");
        return Ok(vec![packet]);
    }
    let frame = packet.data().expect("packet was checked as contiguous");
    let packets = fragment_packets(frame, tunnel, source_mac, id)?
        .into_iter()
        .map(|bytes| dpdk.packet(&bytes))
        .collect::<io::Result<Vec<_>>>()?;
    debug!(
        frame_length,
        fragments = packets.len(),
        "sending EtherIP packet"
    );
    Ok(packets)
}

fn fragment_packets(
    frame: &[u8],
    tunnel: &Tunnel,
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
    let chunk = ((tunnel
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
            ipv6_packet(tunnel, source_mac, NEXT_FRAGMENT, &fragment)
        })
        .collect())
}

fn ipv6_packet(tunnel: &Tunnel, source_mac: [u8; 6], next: u8, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(54 + payload.len());
    packet.resize(54, 0);
    write_outer_header(&mut packet, tunnel, source_mac, next, payload.len());
    packet.extend_from_slice(payload);
    packet
}

fn write_outer_header(
    header: &mut [u8],
    tunnel: &Tunnel,
    source_mac: [u8; 6],
    next: u8,
    payload_length: usize,
) {
    header[0..6].copy_from_slice(&tunnel.next_hop_mac);
    header[6..12].copy_from_slice(&source_mac);
    header[12..14].copy_from_slice(&ETHER_TYPE_IPV6.to_be_bytes());
    header[14..18].copy_from_slice(&[0x60, 0, 0, 0]);
    header[18..20].copy_from_slice(&(payload_length as u16).to_be_bytes());
    header[20] = next;
    header[21] = 64;
    header[22..38].copy_from_slice(&tunnel.local_ipv6.octets());
    header[38..54].copy_from_slice(&tunnel.remote_ipv6.octets());
}

fn decapsulate_packet(
    mut packet: Packet,
    dpdk: &Environment,
    tunnel: &Tunnel,
    reassembly: &mut Reassembly,
) -> io::Result<Option<Packet>> {
    let Some(data) = packet.data() else {
        return Ok(None);
    };
    if valid_outer_packet(data, tunnel).is_err() {
        return Ok(None);
    }
    let payload_length = u16::from_be_bytes([data[18], data[19]]) as usize;
    let payload = &data[54..54 + payload_length];
    match data[20] {
        NEXT_ETHERIP if etherip_payload(payload).is_some() => {
            packet.adjust(56)?;
            debug!(frame_length = payload_length - 2, "received EtherIP packet");
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
            debug!(frame_length = frame.len(), "received EtherIP packet");
            Ok(Some(dpdk.packet(frame)?))
        }
        NEXT_ETHERIP => Ok(None),
        _ => Ok(None),
    }
}

fn etherip_payload(payload: &[u8]) -> Option<&[u8]> {
    payload.strip_prefix(&ETHERIP_HEADER)
}

#[derive(Debug, PartialEq)]
enum OuterError {
    Short,
    EtherType,
    Version,
    Length,
    Protocol,
    Source,
    Destination,
}

fn valid_outer_packet(packet: &[u8], tunnel: &Tunnel) -> Result<(), OuterError> {
    if packet.len() < 54 {
        return Err(OuterError::Short);
    }
    if u16::from_be_bytes([packet[12], packet[13]]) != ETHER_TYPE_IPV6 {
        return Err(OuterError::EtherType);
    }
    if packet[14] >> 4 != 6 {
        return Err(OuterError::Version);
    }
    let payload_length = u16::from_be_bytes([packet[18], packet[19]]) as usize;
    if packet.len() < 54 + payload_length {
        return Err(OuterError::Length);
    }
    if packet[20] != NEXT_ETHERIP && packet[20] != NEXT_FRAGMENT {
        return Err(OuterError::Protocol);
    }
    if packet[22..38] != tunnel.remote_ipv6.octets() {
        return Err(OuterError::Source);
    }
    if packet[38..54] != tunnel.local_ipv6.octets() {
        return Err(OuterError::Destination);
    }
    Ok(())
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
        let end = partial
            .fragments
            .iter()
            .try_fold(0, |next, (offset, bytes)| {
                (*offset == next).then_some(next + bytes.len())
            });
        if let Some(total) = partial.total.filter(|&total| end == Some(total)) {
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

    fn config(mtu: usize) -> Config {
        Config {
            lan: 0,
            wan: 1,
            local_ipv6: Ipv6Addr::from([1; 16]),
            remote_ipv6: Some(Ipv6Addr::from([2; 16])),
            next_hop_mac: Some([3; 6]),
            tunnels: Vec::new(),
            mtu,
            rx_queue: 0,
            tx_queue: 0,
            rx_descriptors: 1024,
            tx_descriptors: 1024,
            socket_id: None,
            burst_size: 32,
        }
    }

    fn tunnel(config: &Config) -> Tunnel {
        build_tunnels(config).unwrap().pop().unwrap()
    }

    fn remote(byte: u8) -> Ipv6Addr {
        Ipv6Addr::from([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, byte])
    }

    fn vlan_frame(vlan: u16) -> [u8; 18] {
        let mut frame = [0u8; 18];
        frame[12] = 0x81;
        frame[13] = 0x00;
        frame[14] = (vlan >> 8) as u8;
        frame[15] = (vlan & 0xff) as u8;
        frame
    }

    fn two_tunnels(mtu: usize) -> Vec<Tunnel> {
        build_tunnels(&Config {
            tunnels: vec![
                TunnelSpec {
                    vlan: 100,
                    remote_ipv6: remote(2),
                    next_hop_mac: [3; 6],
                    mtu: None,
                },
                TunnelSpec {
                    vlan: 200,
                    remote_ipv6: remote(3),
                    next_hop_mac: [4; 6],
                    mtu: None,
                },
            ],
            ..config(mtu)
        })
        .unwrap()
    }

    #[test]
    fn fragmented_round_trip() {
        let config = config(1280);
        let t = tunnel(&config);
        let frame = vec![0xa5; 2000];
        let packets = fragment_packets(&frame, &t, [4; 6], &mut 0).unwrap();
        let reverse = tunnel(&Config {
            local_ipv6: config.remote_ipv6.unwrap(),
            remote_ipv6: Some(config.local_ipv6),
            ..config
        });
        let mut reassembly = Reassembly::default();
        let mut result = None;
        for packet in packets.into_iter().rev() {
            assert_eq!(valid_outer_packet(&packet, &reverse), Ok(()));
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
        let config = config(1500);
        let t = tunnel(&config);
        let mut packet = ipv6_packet(&t, [4; 6], NEXT_ETHERIP, &[0x31, 0, 1]);
        let reverse = tunnel(&Config {
            local_ipv6: config.remote_ipv6.unwrap(),
            remote_ipv6: Some(config.local_ipv6),
            ..config
        });
        assert_eq!(valid_outer_packet(&packet, &reverse), Ok(()));
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
    fn answers_neighbor_solicitation_for_local_wan_address() {
        let config = config(1500);
        let source_ip =
            Ipv6Addr::from([0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]).octets();
        let target = config.local_ipv6.octets();
        let source_mac = [2, 0, 0, 0, 0, 2];
        let local_mac = [2, 0, 0, 0, 0, 1];
        let destination_ip = [
            0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, target[13], target[14], target[15],
        ];
        let mut request = vec![0u8; 86];
        request[..6].copy_from_slice(&[0x33, 0x33, 0xff, target[13], target[14], target[15]]);
        request[6..12].copy_from_slice(&source_mac);
        request[12..14].copy_from_slice(&ETHER_TYPE_IPV6.to_be_bytes());
        request[14] = 0x60;
        request[18..20].copy_from_slice(&32u16.to_be_bytes());
        request[20] = NEXT_ICMPV6;
        request[21] = 255;
        request[22..38].copy_from_slice(&source_ip);
        request[38..54].copy_from_slice(&destination_ip);
        request[54] = 135;
        request[62..78].copy_from_slice(&target);
        request[78] = 1;
        request[79] = 1;
        request[80..86].copy_from_slice(&source_mac);
        let checksum = icmpv6_checksum(&source_ip, &destination_ip, &request[54..]);
        request[56..58].copy_from_slice(&checksum.to_be_bytes());

        let reply = ndp_advertisement(&request, &config, local_mac).unwrap();
        assert_eq!(&reply[..6], &source_mac);
        assert_eq!(&reply[6..12], &local_mac);
        assert_eq!(&reply[22..38], &target);
        assert_eq!(&reply[38..54], &source_ip);
        assert_eq!(reply[54], 136);
        assert_eq!(reply[58], 0x60);
        assert_eq!(icmpv6_checksum(&target, &source_ip, &reply[54..]), 0);
        assert_eq!(&reply[80..86], &local_mac);
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
        assert_eq!(config.next_hop_mac, Some([2, 0, 0, 0, 0, 2]));
        assert!(config.tunnels.is_empty());
        assert_eq!(tunnel(&config).vlan, None);
    }

    #[test]
    fn parses_multiple_tunnels_from_cli() {
        let args = [
            "etherip",
            "--lan-port",
            "0",
            "--wan-port",
            "1",
            "--local-ipv6",
            "2001:db8::1",
            "--tunnel",
            "100,2001:db8::2,02:00:00:00:00:02",
            "--tunnel",
            "200,2001:db8::3,02:00:00:00:00:03,9000",
        ]
        .map(str::to_owned);
        let config = Config::try_parse_from(args).unwrap();
        assert_eq!(config.remote_ipv6, None);
        assert_eq!(config.next_hop_mac, None);
        let tunnels = build_tunnels(&config).unwrap();
        assert_eq!(tunnels.len(), 2);
        assert_eq!(tunnels[0].vlan, Some(100));
        assert_eq!(tunnels[1].vlan, Some(200));
        assert_eq!(tunnels[1].mtu, 9000);
    }

    #[test]
    fn parses_expanded_ipv6_tunnel() {
        let spec =
            parse_tunnel("100,2001:0db8:0000:0000:0000:0000:0000:0002,02:00:00:00:00:02,9000")
                .unwrap();
        assert_eq!(spec.vlan, 100);
        assert_eq!(
            spec.remote_ipv6,
            Ipv6Addr::from([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2])
        );
        assert_eq!(spec.next_hop_mac, [2, 0, 0, 0, 0, 2]);
        assert_eq!(spec.mtu, Some(9000));
        assert!(parse_tunnel("100,2001:db8::2").is_err());
        assert!(parse_tunnel("100,2001:db8::2,02:00:00:00:00:02,1500,extra").is_err());
    }

    #[test]
    fn rejects_mixing_tunnel_and_legacy_options() {
        let args = [
            "etherip",
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
            "--tunnel",
            "100,2001:db8::2,02:00:00:00:00:02",
        ]
        .map(str::to_owned);
        assert!(Config::try_parse_from(args).is_err());
    }

    #[test]
    fn rejects_duplicate_tunnel_vlans() {
        let config = Config {
            tunnels: vec![
                parse_tunnel("100,2001:db8:1::2,02:00:00:00:00:02").unwrap(),
                parse_tunnel("100,2001:db8:1::3,02:00:00:00:00:03").unwrap(),
            ],
            ..config(1500)
        };
        assert!(build_tunnels(&config).is_err());
    }

    #[test]
    fn legacy_single_tunnel_accepts_any_frame() {
        let tunnels = build_tunnels(&config(1500)).unwrap();
        assert_eq!(tunnels[0].vlan, None);
        let untagged = [0u8; 14];
        let tagged = vlan_frame(100);
        assert_eq!(tunnel_for_lan_frame(&untagged, &tunnels), Some(0));
        assert_eq!(tunnel_for_lan_frame(&tagged, &tunnels), Some(0));
    }

    #[test]
    fn classifies_lan_frames_by_vlan() {
        let tunnels = two_tunnels(1500);
        assert_eq!(tunnel_for_lan_frame(&vlan_frame(100), &tunnels), Some(0));
        assert_eq!(tunnel_for_lan_frame(&vlan_frame(200), &tunnels), Some(1));
        assert_eq!(tunnel_for_lan_frame(&vlan_frame(300), &tunnels), None);
        assert_eq!(tunnel_for_lan_frame(&[0u8; 14], &tunnels), None);
        assert_eq!(
            tunnel_for_lan_frame(&vlan_frame(100), &tunnels[..1]),
            Some(0)
        );
    }

    #[test]
    fn selects_tunnel_by_wan_source() {
        let tunnels = two_tunnels(1500);
        let mut packet = [0u8; 54];
        packet[22..38].copy_from_slice(&remote(3).octets());
        assert_eq!(tunnel_index_for_wan(&packet, &tunnels), Some(1));
        packet[22..38].copy_from_slice(&remote(2).octets());
        assert_eq!(tunnel_index_for_wan(&packet, &tunnels), Some(0));
        packet[22..38].copy_from_slice(&remote(4).octets());
        assert_eq!(tunnel_index_for_wan(&packet, &tunnels), None);
    }
}
