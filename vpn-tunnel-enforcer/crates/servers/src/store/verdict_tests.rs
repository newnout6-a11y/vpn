//! Tests of the classifier verdicts stored beside the health records (probe-discipline).
use serde_json::json;
use vpnte_base::types::ClientDevice;

use super::*;
use crate::model::tests::{TempDir, UUID_A, UUID_B, UUID_C, vless};
use crate::model::{ServerReaction, ServerVerdict};

fn open_three() -> (TempDir, Servers, Vec<ProfileId>) {
    let dir = TempDir::new();
    let servers = Servers::open(&dir.0);
    let keys = AddTarget::Keys {
        group: None,
        device: ClientDevice::Pc,
    };
    let profiles = vec![
        vless("DE", "de.example.com", 443, UUID_A),
        vless("NL", "nl.example.com", 443, UUID_B),
        vless("FR", "fr.example.com", 443, UUID_C),
    ];
    let ids = servers.add(profiles, keys).unwrap().added;
    (dir, servers, ids)
}

fn verdict(v: ServerVerdict, at: i64) -> VerdictRecord {
    VerdictRecord {
        verdict: v,
        reaction: ServerReaction::SwitchServer,
        at,
    }
}

fn update(s: &Servers, id: &ProfileId, record: VerdictRecord) -> VerdictUpdate {
    VerdictUpdate {
        id: id.clone(),
        identity: s.get(id).unwrap().identity().unwrap(),
        record,
    }
}

/// Verdicts land per row with the health guards: a re-keyed or user-removed row is skipped, an
/// older verdict never replaces a newer one, and they survive a reopen of the file.
#[test]
fn verdicts_land_with_the_row_guards_and_persist() {
    let (dir, s, ids) = open_three();
    let first = vec![
        update(&s, &ids[0], verdict(ServerVerdict::Frozen, 20)),
        update(&s, &ids[1], verdict(ServerVerdict::IpBanned, 20)),
        update(&s, &ids[2], verdict(ServerVerdict::Healthy, 20)),
    ];
    s.update(|doc| {
        doc.row_mut(&ids[1])
            .unwrap()
            .set_profile(&vless("NL", "nl2.example.com", 443, UUID_B))
    })
    .unwrap();
    s.remove(&ids[2]).unwrap();
    assert_eq!(s.record_verdicts(first).unwrap(), 1);
    let older = update(&s, &ids[0], verdict(ServerVerdict::Healthy, 10));
    assert_eq!(s.record_verdicts(vec![older]).unwrap(), 0);
    let stored = s.verdicts();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[&ids[0]].verdict, ServerVerdict::Frozen);
    drop(s);
    let reopened = Servers::open(&dir.0);
    assert_eq!(
        reopened.get(&ids[0]).unwrap().verdict,
        Some(verdict(ServerVerdict::Frozen, 20))
    );
    assert_eq!(reopened.get(&ids[1]).unwrap().verdict, None);
}

/// Old files have no `verdict`; a verdict or reaction name from a newer version reads as
/// `unknown` instead of failing the whole list; the wire names are kebab-case.
#[test]
fn verdict_records_read_old_and_newer_files() {
    let (_dir, s, ids) = open_three();
    let row = s.get(&ids[0]).unwrap();
    let mut value = serde_json::to_value(&row).unwrap();
    assert!(value.get("verdict").is_none(), "absent until judged");
    let back: ServerRow = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(back.verdict, None);
    value["verdict"] = json!({"verdict": "ip-banned", "reaction": "switch-server", "at": 5});
    let back: ServerRow = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(back.verdict, Some(verdict(ServerVerdict::IpBanned, 5)));
    value["verdict"] = json!({"verdict": "dns-poisoned", "reaction": "use-a-relay", "at": 6});
    let back: ServerRow = serde_json::from_value(value).unwrap();
    let record = back.verdict.unwrap();
    assert_eq!(
        (record.verdict, record.reaction),
        (ServerVerdict::Unknown, ServerReaction::Unknown)
    );
    let names = [
        (ServerVerdict::HandshakeFailed, "handshake-failed"),
        (ServerVerdict::UdpBlocked, "udp-blocked"),
        (ServerVerdict::NotVerified, "not-verified"),
    ];
    for (v, name) in names {
        assert_eq!(serde_json::to_value(v).unwrap(), json!(name));
    }
    let reaction = serde_json::to_value(ServerReaction::TryAnotherFingerprint).unwrap();
    assert_eq!(reaction, json!("try-another-fingerprint"));
}
