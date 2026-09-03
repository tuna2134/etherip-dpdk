//! EtherIP/IPv6 encapsulation, decapsulation, fragmentation, and LAN VLAN handling.

use crate::{
    config::Tunnel,
    protocol::{ETHER_TYPE_IPV6, ETHER_TYPE_VLAN, ETHERIP_HEADER, NEXT_ETHERIP, NEXT_FRAGMENT},
    reassembly::Reassembly,
};
use dpdk::{Environment, Packet};
use std::{
    io,
    sync::atomic::{AtomicU32, Ordering},
};
use tracing::debug;

/// Selects the tunnel for a LAN-side frame. The legacy single tunnel accepts every
/// frame; with VLANs the frame must carry the matching 802.1Q tag.
pub fn tunnel_for_lan_frame(frame: &[u8], tunnels: &[Tunnel]) -> Option<usize> {
    if tunnels.len() == 1 && tunnels[0].vlan.is_none() {
        return Some(0);
    }
    let vlan = vlan_id(frame)?;
    tunnels.iter().position(|tunnel| tunnel.vlan == Some(vlan))
}

/// Selects the tunnel that an outer WAN packet belongs to by its source address.
pub fn tunnel_index_for_wan(packet: &[u8], tunnels: &[Tunnel]) -> Option<usize> {
    let source: [u8; 16] = packet.get(22..38)?.try_into().ok()?;
    tunnels
        .iter()
        .position(|tunnel| tunnel.remote_ipv6.octets() == source)
}

pub fn vlan_id(frame: &[u8]) -> Option<u16> {
    if frame.len() < 16 || u16::from_be_bytes([frame[12], frame[13]]) != ETHER_TYPE_VLAN {
        return None;
    }
    Some(u16::from_be_bytes([frame[14], frame[15]]) & 0x0fff)
}

/// Removes the 4-byte 802.1Q header so the tunnel carries an untagged frame.
pub fn strip_vlan_tag(packet: &mut Packet) -> io::Result<()> {
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
pub fn add_vlan_tag(packet: &mut Packet, vlan: u16) -> io::Result<()> {
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

/// Wraps a LAN frame as an EtherIP packet, prepending the outer header in place or
/// producing IPv6 fragments when the frame exceeds the current path MTU. Resulting
/// packets are appended to `out` to avoid per-packet allocations.
pub fn encapsulate_packet(
    mut packet: Packet,
    dpdk: &Environment,
    tunnel: &Tunnel,
    mtu: usize,
    source_mac: [u8; 6],
    id: &AtomicU32,
    out: &mut Vec<Packet>,
) -> io::Result<()> {
    let frame = packet
        .data()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "multi-segment LAN packet"))?;
    let frame_length = frame.len();
    if 40 + ETHERIP_HEADER.len() + frame_length <= mtu {
        let header = packet.prepend(56)?;
        write_outer_header(header, tunnel, source_mac, NEXT_ETHERIP, frame_length + 2);
        header[54..56].copy_from_slice(&ETHERIP_HEADER);
        debug!(frame_length, "sending EtherIP packet");
        out.push(packet);
        return Ok(());
    }
    let fragments = fragment_packets(frame, tunnel, mtu, source_mac, id)?;
    debug!(
        frame_length,
        fragments = fragments.len(),
        "sending fragmented EtherIP packet"
    );
    for bytes in fragments {
        out.push(dpdk.packet(&bytes)?);
    }
    Ok(())
}

pub fn fragment_packets(
    frame: &[u8],
    tunnel: &Tunnel,
    mtu: usize,
    source_mac: [u8; 6],
    id: &AtomicU32,
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
    let chunk = ((mtu
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
    let id = id.fetch_add(1, Ordering::Relaxed);
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

pub fn ipv6_packet(tunnel: &Tunnel, source_mac: [u8; 6], next: u8, payload: &[u8]) -> Vec<u8> {
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

/// Unwraps an outer IPv6 packet into the inner LAN frame, reassembling fragments as
/// needed. Returns `None` for unrelated or malformed packets.
pub fn decapsulate_packet(
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

pub fn etherip_payload(payload: &[u8]) -> Option<&[u8]> {
    payload.strip_prefix(&ETHERIP_HEADER)
}

#[derive(Debug, PartialEq)]
pub enum OuterError {
    Short,
    EtherType,
    Version,
    Length,
    Protocol,
    Source,
    Destination,
}

pub fn valid_outer_packet(packet: &[u8], tunnel: &Tunnel) -> Result<(), OuterError> {
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
