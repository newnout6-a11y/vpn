//! The network side of the automatic choice: which network the PC is on (a one-way tag the list
//! stores beside whitelist evidence) and what one network session has noted already.
use std::collections::HashSet;

use sha2::{Digest, Sha256};

use super::task::AutoPick;
use super::{Candidate, Network, PickHost};
use crate::adaptive::identity::{self, NetworkSnapshot};
use crate::coordinator::Coordinator;

/// What a server must carry while the network is in whitelist mode to count as passing it:
/// past the ~16 KB freeze band, so a handshake that then hangs proves nothing.
pub const WHITELIST_PROOF: u64 = 64 * 1024;

/// The one-way tag of the network the PC is on (`None`: no physical network up): 16 hex digits
/// of SHA-256 over the network identity. It tells «worked here» from «worked elsewhere» without
/// keeping an adapter, MAC address or gateway on disk.
pub async fn network_tag() -> Option<String> {
    identity::read().await.map(|snapshot| tag_of(&snapshot))
}

fn tag_of(snapshot: &NetworkSnapshot) -> String {
    let digest = Sha256::digest(format!("vpnte-whitelist-v1\n{}", snapshot.text()));
    digest[..8].iter().map(|b| format!("{b:02x}")).collect()
}

/// What the automatic choice noted on the current network.
#[derive(Debug, Default)]
pub(super) struct NetSession {
    /// Bumped by each network change: a tag read that a change overtook is not kept.
    epoch: u64,
    /// This network's tag once read (`Some(None)`: read, unknown).
    tag: Option<Option<String>>,
    /// Servers whose whitelist proof went to the list on this network (once each).
    noted: HashSet<String>,
}

impl<C: Coordinator, H: PickHost> AutoPick<C, H> {
    /// The memory says this network passes only whitelisted addresses.
    pub(super) fn in_whitelist(&self) -> bool {
        self.verdicts.as_ref().is_some_and(|v| v.whitelist())
    }

    /// What the network memory says now, for ranking `servers` (the tag is read only when one
    /// of them has evidence from a known network).
    pub(super) async fn network(&self, servers: &[Candidate]) -> Network {
        let Some(verdicts) = &self.verdicts else {
            return Network::default();
        };
        let (udp_blocked, whitelist) = (verdicts.udp_blocked(), verdicts.whitelist());
        let avoided = (servers.iter())
            .filter(|c| verdicts.avoided(&c.id))
            .map(|c| c.id.clone())
            .collect();
        let tagged = (servers.iter()).any(|c| c.whitelist.worked_on.iter().any(Option::is_some));
        let tag = if tagged { self.tag().await } else { None };
        Network {
            udp_blocked,
            whitelist,
            tag,
            avoided,
        }
    }

    /// This network's tag, read once per network session.
    pub(super) async fn tag(&self) -> Option<String> {
        let epoch = {
            let net = self.net.lock();
            if let Some(tag) = &net.tag {
                return tag.clone();
            }
            net.epoch
        };
        let tag = self.host.network().await;
        let mut net = self.net.lock();
        if net.epoch == epoch {
            net.tag = Some(tag.clone());
        }
        tag
    }

    /// `id` proved itself (a whole transfer, or [`WHITELIST_PROOF`] of the session's traffic):
    /// on a whitelist network the list keeps that, once per server and network session.
    pub(super) async fn proved(&self, id: &str) {
        if !self.in_whitelist() || !self.net.lock().noted.insert(id.to_owned()) {
            return;
        }
        let tag = self.tag().await;
        self.host.worked_under_whitelist(id, tag);
    }

    /// The network changed (or a change may have been missed): its tag and notes are gone.
    pub(super) fn forget_network(&self) {
        let mut net = self.net.lock();
        net.epoch += 1;
        net.tag = None;
        net.noted.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adaptive::identity::IdentityRow;

    /// p-net-aware: the tag is 16 hex digits, stable for one network, another for another.
    #[test]
    fn the_tag_is_one_way_and_stable() {
        let net = |gw: &str| {
            let row = IdentityRow {
                guid: "6f1d5a3e00004000800000000000c0de".into(),
                mac: "020000000001".into(),
                prefixes: vec!["192.168.43.0/24".into()],
                gateways: vec![format!("{gw}@0200000000fe")],
            };
            NetworkSnapshot::from_rows(vec![row]).unwrap()
        };
        let (a, b) = (tag_of(&net("192.168.43.1")), tag_of(&net("10.0.0.1")));
        assert_eq!(a, tag_of(&net("192.168.43.1")));
        assert_ne!(a, b);
        assert_eq!(a.len(), 16);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
