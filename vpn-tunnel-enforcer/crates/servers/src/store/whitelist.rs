//! Whitelist evidence of the rows: what the automatic choice learned (a server carried data while
//! the network was in whitelist mode) and the user's own mark.
use vpnte_base::AppResult;
use vpnte_base::types::UnixMs;

use super::{Servers, server_not_found};
use crate::model::{ArchiveReason, ProfileId, Whitelist};

impl Servers {
    /// Server `id` carried >= 64 KiB at its current endpoint while `network` (a one-way tag,
    /// `None`: unknown) was in whitelist mode. A row removed by the user or gone is skipped;
    /// returns whether it was stored.
    pub fn record_whitelist(
        &self,
        id: &ProfileId,
        network: Option<String>,
        at: UnixMs,
    ) -> AppResult<bool> {
        self.update(|doc| {
            let Some(row) = doc.row_mut(id) else {
                return Ok(false);
            };
            if row.archived_for(ArchiveReason::User) {
                return Ok(false);
            }
            let endpoint = row.endpoint();
            (row.whitelist.get_or_insert_with(Whitelist::default)).record(network, endpoint, at);
            Ok(true)
        })
    }

    /// The user's word: `true` marks the server «Работает в белых списках»; `false` takes the
    /// mark off together with the learned evidence (the badge goes; a new proof brings it back).
    pub fn set_whitelist_mark(&self, id: &ProfileId, on: bool) -> AppResult<()> {
        self.update(|doc| {
            let row = doc.row_mut(id).ok_or_else(server_not_found)?;
            row.whitelist = on.then(|| Whitelist {
                marked: true,
                ..row.whitelist.take().unwrap_or_default()
            });
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use vpnte_base::types::ClientDevice;

    use super::*;
    use crate::model::WHITELIST_NETWORKS_MAX;
    use crate::model::tests::{TempDir, UUID_A, UUID_B, vless};
    use crate::store::AddTarget;

    fn open_two() -> (TempDir, Servers, Vec<ProfileId>) {
        let dir = TempDir::new();
        let servers = Servers::open(&dir.0);
        let keys = AddTarget::Keys {
            group: None,
            device: ClientDevice::Pc,
        };
        let profiles = vec![
            vless("RU", "ru.example.com", 443, UUID_A),
            vless("NL", "nl.example.com", 443, UUID_B),
        ];
        let ids = servers.add(profiles, keys).unwrap().added;
        (dir, servers, ids)
    }

    /// p-net-aware: evidence is kept per network, newest first, at most four networks, survives a
    /// reopen; a user-removed row learns nothing.
    #[test]
    fn evidence_is_kept_per_network_and_persists() {
        let (dir, s, ids) = open_two();
        let tag = |n: usize| Some(format!("net-{n}"));
        assert!(s.record_whitelist(&ids[0], tag(1), 10).unwrap());
        assert!(s.record_whitelist(&ids[0], tag(2), 20).unwrap());
        assert!(s.record_whitelist(&ids[0], tag(1), 30).unwrap());
        let row = s.get(&ids[0]).unwrap();
        let worked: Vec<_> = row.worked_under_whitelist().map(|w| w.at).collect();
        assert_eq!(worked, [30, 20], "one entry per network, newest first");
        assert!(row.whitelist_ready());
        for n in 3..10 {
            s.record_whitelist(&ids[0], tag(n), 30 + n as i64).unwrap();
        }
        let row = s.get(&ids[0]).unwrap();
        assert_eq!(row.worked_under_whitelist().count(), WHITELIST_NETWORKS_MAX);
        assert!(!s.get(&ids[1]).unwrap().whitelist_ready());

        s.remove(&ids[1]).unwrap();
        assert!(!s.record_whitelist(&ids[1], tag(1), 40).unwrap());
        assert!(
            !s.record_whitelist(&ProfileId::from("gone"), tag(1), 40)
                .unwrap()
        );

        let again = Servers::open(&dir.0);
        assert_eq!(again.get(&ids[0]).unwrap().whitelist, row.whitelist);
    }

    /// p-net-aware: evidence of another endpoint proves nothing once the key moved.
    #[test]
    fn evidence_of_an_old_endpoint_is_void() {
        let (_dir, s, ids) = open_two();
        s.record_whitelist(&ids[0], None, 10).unwrap();
        let mut row = s.get(&ids[0]).unwrap();
        assert!(row.whitelist_ready());
        row.port = 8443;
        assert!(!row.whitelist_ready(), "the provider moved the key");
        assert_eq!(row.whitelist.as_ref().map(|w| w.worked.len()), Some(1));
    }

    /// p-net-aware: the user's mark comes and goes; taking it off also forgets what was learned.
    #[test]
    fn the_mark_is_the_users_word() {
        let (_dir, s, ids) = open_two();
        s.record_whitelist(&ids[0], None, 10).unwrap();
        s.set_whitelist_mark(&ids[0], true).unwrap();
        let w = s.get(&ids[0]).unwrap().whitelist.unwrap();
        assert!(w.marked);
        assert_eq!(w.worked.len(), 1, "marking keeps the evidence");
        s.set_whitelist_mark(&ids[0], false).unwrap();
        assert_eq!(s.get(&ids[0]).unwrap().whitelist, None);
        s.set_whitelist_mark(&ids[1], true).unwrap();
        assert!(s.get(&ids[1]).unwrap().whitelist_ready());
        let err = s.set_whitelist_mark(&ProfileId::from("gone"), true);
        assert!(err.is_err());
    }
}
