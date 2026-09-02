//! IPv6/EtherIP/Ethernet protocol constants shared across modules.

pub const ETHER_TYPE_IPV6: u16 = 0x86dd;
pub const ETHER_TYPE_VLAN: u16 = 0x8100;
pub const NEXT_ICMPV6: u8 = 58;
pub const NEXT_ETHERIP: u8 = 97;
pub const NEXT_FRAGMENT: u8 = 44;
pub const ETHERIP_HEADER: [u8; 2] = [0x30, 0];
