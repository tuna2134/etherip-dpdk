use clap::Parser;
use etherip::config::{Config, Tunnel, TunnelSpec, build_tunnels, parse_tunnel, split_args};
use etherip::etherip::{
    etherip_payload, fragment_packets, ipv6_packet, tunnel_for_lan_frame, tunnel_index_for_wan,
    valid_outer_packet, vlan_id,
};
use etherip::mac_table::MacTable;
use etherip::ndp::{icmpv6_checksum, icmpv6_packet_too_big, ndp_advertisement};
use etherip::protocol::{ETHER_TYPE_IPV6, NEXT_ETHERIP, NEXT_ICMPV6};
use etherip::reassembly::Reassembly;
use std::net::Ipv6Addr;
use std::sync::atomic::AtomicU32;

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
        workers: 1,
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
    let id = AtomicU32::new(0);
    let packets = fragment_packets(&frame, &t, t.mtu, [4; 6], &id).unwrap();
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
    let source_ip = Ipv6Addr::from([0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]).octets();
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

    let reply = ndp_advertisement(&request, config.local_ipv6, local_mac).unwrap();
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
fn parses_packet_too_big_for_tunnel() {
    let config = config(1500);
    let local = config.local_ipv6;
    let remote = config.remote_ipv6.unwrap();
    let router: [u8; 16] = [4; 16];
    let mut packet = vec![0u8; 102];
    packet[12..14].copy_from_slice(&ETHER_TYPE_IPV6.to_be_bytes());
    packet[14] = 0x60;
    packet[18..20].copy_from_slice(&48u16.to_be_bytes());
    packet[20] = NEXT_ICMPV6;
    packet[21] = 64;
    packet[22..38].copy_from_slice(&router);
    packet[38..54].copy_from_slice(&local.octets());
    packet[54] = 2; // Packet Too Big
    packet[58..62].copy_from_slice(&1280u32.to_be_bytes());
    // The embedded offending packet is the one we sent: src = local, dst = remote.
    packet[62] = 0x60;
    packet[68] = NEXT_ETHERIP;
    packet[70..86].copy_from_slice(&local.octets());
    packet[86..102].copy_from_slice(&remote.octets());
    let checksum = icmpv6_checksum(&router, &local.octets(), &packet[54..]);
    packet[56..58].copy_from_slice(&checksum.to_be_bytes());

    let (mtu, destination) = icmpv6_packet_too_big(&packet, local).unwrap();
    assert_eq!(mtu, 1280);
    assert_eq!(destination, remote);
    assert!(icmpv6_packet_too_big(&packet, remote).is_none());
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
        parse_tunnel("100,2001:0db8:0000:0000:0000:0000:0000:0002,02:00:00:00:00:02,9000").unwrap();
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
fn classifies_qinq_by_outer_vlan() {
    let tunnels = two_tunnels(1500);
    // [dst][src][0x8100:outer=100][0x8100:inner=200][ethertype][payload]
    let mut frame = [0u8; 22];
    frame[12] = 0x81;
    frame[13] = 0x00;
    frame[14] = 0x00;
    frame[15] = 0x64; // outer VID 100
    frame[16] = 0x81;
    frame[17] = 0x00;
    frame[18] = 0x00;
    frame[19] = 0xc8; // inner VID 200
    assert_eq!(vlan_id(&frame), Some(100));
    assert_eq!(tunnel_for_lan_frame(&frame, &tunnels), Some(0));
    assert_eq!(vlan_id(&vlan_frame(200)), Some(200));
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
