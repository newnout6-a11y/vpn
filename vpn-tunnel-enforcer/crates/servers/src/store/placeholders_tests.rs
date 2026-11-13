//! p-live-fix D6: placeholders an older build stored leave the list at open, and the servers their
//! answers pushed out come back.
use vpnte_base::types::ClientDevice;

use super::placeholders::retire;
use super::*;
use crate::model::tests::{TempDir, UUID_A, UUID_B, UUID_C, vless};
use crate::model::{ArchiveReason, Archived, GroupId, Origin, ServerGroup, ServerRow, ServersDoc};

const T1: UnixMs = 1_000_000;
const T2: UnixMs = T1 + 30 * 60 * 1000;

fn row(group: &GroupId, name: &str, host: &str, port: u16, uuid: &str, at: UnixMs) -> ServerRow {
    let profile = vless(name, host, port, uuid);
    ServerRow::new(&profile, group.clone(), Origin::Feed, ClientDevice::Pc, at).unwrap()
}

/// The owner's list after the bug: 2 servers archived by the second placeholder answer, one
/// missing since the first, the placeholder live and selected; a manual 127.0.0.1 key and an
/// older provider removal stay as they are.
fn owner_doc() -> (ServersDoc, GroupId) {
    let url = url::Url::parse("https://panel.example.com/sub/token").unwrap();
    let g = GroupId::from("sosa");
    let mut doc = ServersDoc::default();
    doc.groups.push(ServerGroup::subscription(
        g.clone(),
        &url,
        ClientDevice::Pc,
        1,
    ));
    let mut de = row(&g, "DE", "de.example.com", 443, UUID_A, 1);
    de.missing_since = Some(T1);
    de.archived = Some(Archived {
        at: T2,
        reason: ArchiveReason::Provider,
    });
    let mut nl = row(&g, "NL", "nl.example.com", 443, UUID_B, 1);
    nl.missing_since = Some(T1);
    let mut old = row(&g, "FR", "fr.example.com", 443, UUID_C, 1);
    old.archived = Some(Archived {
        at: T1 - 1,
        reason: ArchiveReason::Provider,
    });
    let stub = row(&g, "Приложение не поддерживается", "0.0.0.0", 1, UUID_A, T1);
    let mut local = row(&g, "Local", "127.0.0.1", 10808, UUID_B, 1);
    local.origin = Origin::Manual;
    doc.active_profile_id = Some(stub.id.clone());
    doc.profiles = vec![de, nl, old, stub, local];
    (doc, g)
}

#[test]
fn placeholders_leave_and_the_displaced_servers_return() {
    let (mut doc, _) = owner_doc();
    assert!(doc.profiles[3].is_placeholder());
    assert!(
        !doc.profiles[4].is_placeholder(),
        "the user's own key is no placeholder"
    );
    assert_eq!(retire(&mut doc, T2 + 5), 1);
    let [de, nl, old, stub, local] = doc.profiles.as_slice() else {
        panic!("rows")
    };
    assert_eq!((de.archived, de.missing_since), (None, None));
    assert_eq!(nl.missing_since, None);
    assert!(
        old.archived.is_some(),
        "a removal before the placeholders stays"
    );
    assert_eq!(
        stub.archived,
        Some(Archived {
            at: T2 + 5,
            reason: ArchiveReason::Provider
        })
    );
    assert_eq!((local.archived, local.origin), (None, Origin::Manual));
    // Nothing left to do the second time.
    assert_eq!(retire(&mut doc, T2 + 9), 0);
}

/// A stored placeholder is never the server a connection uses, nor selectable by anyone.
#[test]
fn a_placeholder_is_never_selected() {
    let dir = TempDir::new();
    let (doc, _) = owner_doc();
    let stub = doc.profiles[3].id.clone();
    let path = dir.0.join("profiles.json");
    let s = Servers::open(&dir.0);
    s.update(|current| {
        *current = doc;
        Ok(())
    })
    .unwrap();
    // Before the repair (an open does it): the selection falls back past the placeholder.
    let active = s.active().unwrap();
    assert_ne!(active.row.id, stub);
    assert!(active.fallback);
    for by in [SelectBy::User, SelectBy::Automation] {
        let err = s.select(&stub, by).unwrap_err();
        assert_eq!(err.user_msg().key, "servers.select.placeholder");
    }
    drop(s);
    assert!(path.exists());
    // The next open retires it and brings the servers back.
    let s = Servers::open(&dir.0);
    s.read(|doc| {
        let stub = doc.row(&stub).unwrap();
        assert!(stub.archived.is_some());
        assert_eq!(
            doc.profiles.iter().filter(|r| r.archived.is_none()).count(),
            3
        );
    });
}
