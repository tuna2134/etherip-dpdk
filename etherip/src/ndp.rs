//! IPv6 Neighbor Discovery: replies to Neighbor Solicitations for the WAN address.

use crate::protocol::{ETHER_TYPE_IPV6, NEXT_ICMPV6};
use std::net::Ipv6Addr;

/// Builds a Neighbor Advertisement for a Neighbor Solicitation addressed to
/// `local_ipv6`, or `None` when the packet is unrelated or malformed.
pub fn ndp_advertisement(
    packet: &[u8],
    local_ipv6: Ipv6Addr,
    local_mac: [u8; 6],
) -> Option<Vec<u8>> {
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
    let target = local_ipv6.octets();
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

pub fn icmpv6_checksum(source: &[u8; 16], destination: &[u8; 16], message: &[u8]) -> u16 {
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
