//! Per-tunnel MAC learning that suppresses frames reflected back from the remote.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

const MAC_AGE: Duration = Duration::from_secs(300);

/// Remembers source MACs learned from the tunnel for a short window so the same
/// frame arriving from the LAN is not sent back into the tunnel.
pub struct MacTable {
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
    pub fn learn_source(&mut self, frame: &[u8]) {
        if let Some(source) = source_mac(frame)
            && source[0] & 1 == 0
        {
            self.remote.insert(source, Instant::now());
        }
    }

    pub fn contains_source(&self, frame: &[u8]) -> bool {
        source_mac(frame).is_some_and(|source| {
            self.remote
                .get(&source)
                .is_some_and(|seen| seen.elapsed() < MAC_AGE)
        })
    }

    pub fn expire(&mut self) {
        if Instant::now() >= self.next_expiry {
            self.remote.retain(|_, seen| seen.elapsed() < MAC_AGE);
            self.next_expiry = Instant::now() + MAC_AGE;
        }
    }
}

fn source_mac(frame: &[u8]) -> Option<[u8; 6]> {
    frame.get(6..12)?.try_into().ok()
}
