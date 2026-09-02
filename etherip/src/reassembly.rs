//! IPv6 fragment reassembly with bounded memory use.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

pub const MAX_PACKET: usize = 65_535;

pub type FragmentKey = ([u8; 16], [u8; 16], u32);

/// Reassembles out-of-order IPv6 fragments keyed by source, destination, and ID.
#[derive(Default)]
pub struct Reassembly {
    packets: HashMap<FragmentKey, Partial>,
}

struct Partial {
    updated: Instant,
    total: Option<usize>,
    fragments: Vec<(usize, Vec<u8>)>,
}

impl Reassembly {
    /// Returns the reassembled payload once every fragment has arrived, or `None`.
    pub fn insert(
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

    pub fn expire(&mut self) {
        self.packets
            .retain(|_, packet| packet.updated.elapsed() < Duration::from_secs(60));
    }
}
