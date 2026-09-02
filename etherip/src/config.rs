//! CLI parsing and resolved tunnel configuration.

use clap::Parser;
use std::{io, net::Ipv6Addr};

/// One tunnel endpoint and the LAN-side VLAN that selects it.
///
/// `vlan: None` keeps the legacy single-tunnel mode, in which every LAN frame is
/// bridged as-is (VLAN tags pass through untouched).
#[derive(Clone, Copy, Debug)]
pub struct Tunnel {
    pub vlan: Option<u16>,
    pub local_ipv6: Ipv6Addr,
    pub remote_ipv6: Ipv6Addr,
    pub next_hop_mac: [u8; 6],
    pub mtu: usize,
}

/// Parsed value of one `--tunnel` argument before defaults are resolved.
#[derive(Clone, Copy, Debug)]
pub struct TunnelSpec {
    pub vlan: u16,
    pub remote_ipv6: Ipv6Addr,
    pub next_hop_mac: [u8; 6],
    pub mtu: Option<usize>,
}

#[derive(Parser)]
#[command(
    version,
    about = "Bridge Ethernet frames through an RFC 3378 EtherIP/IPv6 tunnel",
    after_help = "DPDK EAL options go before `--`, for example:\n  etherip -l 0 -- --lan-port 0 --wan-port 1 --local-ipv6 2001:db8::1 --remote-ipv6 2001:db8::2 --next-hop-mac 02:00:00:00:00:02\n  For multiple tunnels use --tunnel instead:\n  etherip -l 0 -- --lan-port 0 --wan-port 1 --local-ipv6 2001:db8::1 --tunnel 100,2001:db8::2,02:00:00:00:00:02 --tunnel 200,2001:db8::3,02:00:00:00:00:03"
)]
pub struct Config {
    /// DPDK port connected to the bridged LAN.
    #[arg(long = "lan-port")]
    pub lan: u16,

    /// DPDK port carrying the outer IPv6 packets.
    #[arg(long = "wan-port")]
    pub wan: u16,

    /// Local address used by the outer IPv6 header.
    #[arg(long)]
    pub local_ipv6: Ipv6Addr,

    /// Remote EtherIP endpoint's IPv6 address for the single-tunnel mode.
    #[arg(long, conflicts_with = "tunnels")]
    pub remote_ipv6: Option<Ipv6Addr>,

    /// Ethernet next-hop for the remote IPv6 endpoint for the single-tunnel mode.
    #[arg(long, conflicts_with = "tunnels", value_parser = parse_mac)]
    pub next_hop_mac: Option<[u8; 6]>,

    /// Default outer IPv6 MTU; each --tunnel can override it.
    #[arg(long, default_value_t = 1500, value_parser = parse_mtu)]
    pub mtu: usize,

    /// Add an EtherIP tunnel as <VLAN>,<REMOTE_IPV6>,<NEXT_HOP_MAC>[,<MTU>].
    /// Repeatable. LAN frames tagged with the VLAN are bridged into the matching
    /// tunnel; the tag is stripped before encapsulation and re-added on receive.
    #[arg(long = "tunnel", value_parser = parse_tunnel)]
    pub tunnels: Vec<TunnelSpec>,

    /// RX queue used on both ports.
    #[arg(long, default_value_t = 0)]
    pub rx_queue: u16,

    /// TX queue used on both ports.
    #[arg(long, default_value_t = 0)]
    pub tx_queue: u16,

    /// RX descriptors allocated per port.
    #[arg(long, default_value_t = 1024, value_parser = parse_nonzero_u16)]
    pub rx_descriptors: u16,

    /// TX descriptors allocated per port.
    #[arg(long, default_value_t = 1024, value_parser = parse_nonzero_u16)]
    pub tx_descriptors: u16,

    /// NUMA socket for the mempool and queues; DPDK chooses it when omitted.
    #[arg(long)]
    pub socket_id: Option<u32>,

    /// Number of packets requested from each RX burst (multiple of 8).
    #[arg(long, default_value_t = 32, value_parser = parse_burst_size)]
    pub burst_size: u16,
}

/// Splits process arguments into DPDK EAL options and application options.
///
/// Without a `--` separator the whole vector is treated as application options.
pub fn split_args(args: &[String]) -> (Vec<String>, Vec<String>) {
    let Some(separator) = args.iter().position(|arg| arg == "--") else {
        return (vec![args[0].clone()], args.to_vec());
    };
    let mut app = Vec::with_capacity(args.len() - separator);
    app.push(args[0].clone());
    app.extend_from_slice(&args[separator + 1..]);
    (args[..separator].to_vec(), app)
}

/// Resolves the CLI tunnel definitions into the runtime [`Tunnel`] set.
///
/// The legacy single-tunnel mode uses `--remote-ipv6`/`--next-hop-mac` and keeps
/// `vlan: None`. With `--tunnel`, each entry must carry a unique VLAN ID.
pub fn build_tunnels(config: &Config) -> io::Result<Vec<Tunnel>> {
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

pub fn parse_tunnel(value: &str) -> Result<TunnelSpec, String> {
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
