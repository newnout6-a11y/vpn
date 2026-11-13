//! Item 18: the row's TLS tricks choice — stored form, how it runs, the setter, and the
//! provider's value on new rows only (a refresh never touches a known row's choice).
use serde_json::json;
use vpnte_base::types::{ClientDevice, UnixMs};
use vpnte_core::secret::Secret;
use vpnte_profiles::model::{HelloSplit, Span, SubscriptionMeta, TlsTricks};
use vpnte_profiles::text::Controls;

use super::*;
use crate::model::tests::{TempDir, UUID_A, UUID_B, vless};
use crate::model::{GroupKind, ServerGroup};
use crate::refresh::reconcile;
use crate::store::{AddTarget, NewSubscription, Servers};

const NOW: UnixMs = 1_800_000_000_000;

fn provider_split() -> TlsTricks {
    TlsTricks::Hello(HelloSplit {
        len: Span::new(40, 60),
        interval_ms: Span::new(30, 50),
    })
}

/// A key whose link brings its own split and a pasted sing-box trick key.
fn provider_key() -> Profile {
    let link = format!(
        "vless://{UUID_A}@a.example:443?security=tls&sni=a.example&fragment=1,40-60,30-50#A"
    );
    let mut p = vpnte_profiles::uri::parse_uri(&link).expect("parses");
    p.singbox_extra
        .insert("tls.record_fragment".into(), json!(true));
    p
}

/// Old files load unchanged; the choice is stored compactly and read back.
#[test]
fn stored_form() {
    let row = ServerRow::new(
        &provider_key(),
        "g".into(),
        Origin::Feed,
        ClientDevice::Pc,
        NOW,
    )
    .expect("row");
    let mut stored = serde_json::to_value(&row).expect("serialises");
    assert!(stored.get("tlsTricks").is_none(), "{stored}");
    let old: ServerRow = serde_json::from_value(stored.clone()).expect("old file");
    assert_eq!(old.tls_tricks, None);
    stored["tlsTricks"] = json!("default");
    let back: ServerRow = serde_json::from_value(stored.clone()).expect("default");
    assert_eq!(back.tls_tricks, Some(RowTricks::Default));
    let set = ServerRow {
        tls_tricks: Some(RowTricks::Set(TlsTricks::STRONG)),
        ..old
    };
    let stored = serde_json::to_value(&set).expect("serialises");
    assert_eq!(
        stored["tlsTricks"],
        json!({ "set": { "mode": "both", "len": "100-200", "intervalMs": "10-20" } })
    );
    let back: ServerRow = serde_json::from_value(stored).expect("set");
    assert_eq!(back.tls_tricks, set.tls_tricks);
}

/// The run profile carries the user's choice over the key's own; `Default` drops the link's
/// value and the pasted keys alike, so the app default applies; export keeps the key as given.
#[test]
fn run_profile_applies_the_choice() {
    let mut row = ServerRow::new(
        &provider_key(),
        "g".into(),
        Origin::Feed,
        ClientDevice::Pc,
        NOW,
    )
    .expect("row");
    let own = row.run_profile().expect("run");
    assert_eq!(own.own_tls_tricks(), Some(provider_split()));
    row.tls_tricks = Some(RowTricks::Set(TlsTricks::Off));
    let off = row.run_profile().expect("run");
    assert_eq!(off.tls_tricks_for(true), TlsTricks::Off);
    row.tls_tricks = Some(RowTricks::Default);
    let default = row.run_profile().expect("run");
    assert_eq!(default.own_tls_tricks(), None);
    assert_eq!(default.tls_tricks_for(true), TlsTricks::STRONG);
    assert_eq!(default.tls_tricks_for(false), TlsTricks::Off);
    assert_eq!(row.profile().expect("given"), provider_key());
}

fn feed_group() -> ServerGroup {
    let mut group = ServerGroup::manual("feed".into(), 0);
    group.kind = GroupKind::Subscription {
        url: Secret::new("https://sub.example.com/feed"),
        device: ClientDevice::Pc,
    };
    group
}

/// A refresh keeps a known row's choice even when the key changes, and gives a new key the
/// provider's value that the group stores.
#[test]
fn refresh_keeps_the_choice_and_seeds_new_keys() {
    let mut group = feed_group();
    let old = vless("A", "a.example", 443, UUID_A);
    let mut row =
        ServerRow::new(&old, group.id.clone(), Origin::Feed, ClientDevice::Pc, NOW).expect("row");
    row.tls_tricks = Some(RowTricks::Set(TlsTricks::Record));
    let mut rows = vec![row];
    group.controls.tls_tricks = Some(TlsTricks::STRONG);
    let changed = vless("A", "a.example", 8443, UUID_A);
    let fresh = vec![changed, vless("B", "b.example", 443, UUID_B)];
    reconcile(&group, &mut rows, fresh, true, NOW).expect("reconcile");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].port, 8443);
    assert_eq!(rows[0].tls_tricks, Some(RowTricks::Set(TlsTricks::Record)));
    assert_eq!(rows[1].tls_tricks, Some(RowTricks::Set(TlsTricks::STRONG)));
}

fn subscription(controls: Controls) -> AddTarget {
    AddTarget::Subscription(Box::new(NewSubscription {
        url: url::Url::parse("https://sub.example.com/feed/token").expect("url"),
        device: ClientDevice::Pc,
        info: SubscriptionMeta::default(),
        partial: false,
        send_hwid: false,
        headers: None,
        controls,
        fallback: None,
        moved_at: None,
    }))
}

/// The first import puts the provider's tricks on its new rows (pasted keys get none); the
/// setter changes one row, persists it and refuses an unknown row.
#[test]
fn add_seeds_rows_and_the_setter_owns_them() {
    let dir = TempDir::new();
    let servers = Servers::open(&dir.0);
    let controls = Controls {
        tls_tricks: Some(TlsTricks::Off),
        ..Controls::default()
    };
    let added = servers
        .add(
            vec![vless("A", "a.example", 443, UUID_A)],
            subscription(controls),
        )
        .expect("added");
    let id = added.added[0].clone();
    let row = servers.get(&id).expect("row");
    assert_eq!(row.tls_tricks, Some(RowTricks::Set(TlsTricks::Off)));
    let pasted = AddTarget::Keys {
        group: None,
        device: ClientDevice::Pc,
    };
    let keys = servers
        .add(vec![vless("B", "b.example", 443, UUID_B)], pasted)
        .expect("added");
    assert_eq!(servers.get(&keys.added[0]).expect("row").tls_tricks, None);
    servers
        .set_tls_tricks(&id, Some(RowTricks::Default))
        .expect("set");
    let reopened = Servers::open(&dir.0);
    assert_eq!(
        reopened.get(&id).expect("row").tls_tricks,
        Some(RowTricks::Default)
    );
    let missing = servers.set_tls_tricks(&"nope".into(), None);
    assert!(missing.is_err());
}
