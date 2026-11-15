//! Tests of a subscription's request settings and the provider's hide-settings guard (ru-2026
//! items 1 and 22). Real DPAPI, temp dirs, fake URLs and keys.
use serde_json::json;
use vpnte_base::ErrorKind;
use vpnte_profiles::text::Controls;

use super::*;
use crate::legacy;
use crate::model::tests::{TempDir, UUID_A, UUID_B, vless};
use crate::model::{GroupId, ProfileId, ServerGroup};

const FEED: &str = "https://sub.example.com/feed/token";

fn open() -> (TempDir, Servers) {
    let dir = TempDir::new();
    let servers = Servers::open(&dir.0);
    (dir, servers)
}

fn subscription(url: &str, hide: Option<bool>, send_hwid: bool) -> AddTarget {
    AddTarget::Subscription(Box::new(NewSubscription {
        url: url::Url::parse(url).unwrap(),
        device: ClientDevice::Pc,
        info: SubscriptionMeta::default(),
        partial: false,
        send_hwid,
        headers: None,
        controls: Controls {
            hide_settings: hide,
            ..Controls::default()
        },
        fallback: None,
        moved_at: None,
    }))
}

fn key_of(err: AppError) -> (ErrorKind, String) {
    let key = err.user_msg().key.into_owned();
    (err.kind, key)
}

fn group(s: &Servers, id: &GroupId) -> ServerGroup {
    s.read(|d| d.group(id).cloned()).unwrap()
}

/// ru-2026 item 1 (verify note): new groups start without the HWID; a group stored before the
/// switch existed and every migrated Electron group keep sending it.
#[test]
fn hwid_defaults_for_new_stored_and_migrated_groups() {
    let (_dir, s) = open();
    let profiles = vec![vless("A", "a.example", 443, UUID_A)];
    let added = s.add(profiles, subscription(FEED, None, false)).unwrap();
    let new = group(&s, &added.group);
    assert!(!new.send_hwid);
    let mut stored = serde_json::to_value(&new).unwrap();
    assert_eq!(stored["sendHwid"], json!(false));
    stored.as_object_mut().unwrap().remove("sendHwid");
    let old: ServerGroup = serde_json::from_value(stored).unwrap();
    assert!(
        old.send_hwid,
        "a group stored without the field keeps sending"
    );
    let groups = json!({"groups": [{"id": "g1", "name": "Sub", "source": "subscription",
        "sourceUrl": FEED}]});
    let (doc, _) = legacy::from_legacy(None, Some(&groups), None, 1);
    assert!(doc.groups.iter().any(|g| g.url().is_some() && g.send_hwid));
}

#[test]
fn hwid_switch_and_headers_per_group() {
    let (dir, s) = open();
    let added = s
        .add(
            vec![vless("A", "a.example", 443, UUID_A)],
            subscription(FEED, None, false),
        )
        .unwrap();
    let id = added.group;
    s.set_group_send_hwid(&id, true).unwrap();
    assert!(group(&s, &id).send_hwid);
    let names = s
        .set_group_headers(
            &id,
            "X-Panel-Token: fake-secret-123\nUser-Agent: v2rayN/7.25",
        )
        .unwrap();
    assert_eq!(names, ["X-Panel-Token", "User-Agent"]);
    let view = s.view();
    let summary = view.groups.iter().find(|g| g.id == id).unwrap();
    assert_eq!(summary.header_names, names);
    assert!(summary.send_hwid);
    // Sealed like the URL: the value never reaches the file as plain text.
    let file = std::fs::read_to_string(dir.0.join("profiles.json")).unwrap();
    assert!(!file.contains("fake-secret-123") && !file.contains("feed/token"));
    let (kind, key) = key_of(s.set_group_headers(&id, "Host: evil.example").unwrap_err());
    assert_eq!(
        (kind, key.as_str()),
        (ErrorKind::Validation, "servers.headers.reserved")
    );
    assert!(
        group(&s, &id).headers.is_some(),
        "a refused edit changes nothing"
    );
    assert!(s.set_group_headers(&id, " \n ").unwrap().is_empty());
    assert!(group(&s, &id).headers.is_none());
    let target = AddTarget::Keys {
        group: None,
        device: ClientDevice::Pc,
    };
    let manual = s
        .add(vec![vless("B", "b.example", 443, UUID_B)], target)
        .unwrap();
    let (_, key) = key_of(s.set_group_send_hwid(&manual.group, true).unwrap_err());
    assert_eq!(key, "servers.group.manualNoRequest");
    let (_, key) = key_of(s.set_group_headers(&manual.group, "A: b").unwrap_err());
    assert_eq!(key, "servers.group.manualNoRequest");
}

/// ru-2026 item 22: a group with `hide-settings` refuses every key export of its servers; other
/// groups export as before.
#[test]
fn hidden_groups_refuse_key_exports() {
    let (_dir, s) = open();
    let hidden = s
        .add(
            vec![vless("A", "a.example", 443, UUID_A)],
            subscription(FEED, Some(true), false),
        )
        .unwrap();
    let open_feed = "https://other.example.com/feed/token";
    let shown = s
        .add(
            vec![vless("B", "b.example", 443, UUID_B)],
            subscription(open_feed, Some(false), false),
        )
        .unwrap();
    let (kind, key) = key_of(s.shareable_profile(&hidden.added[0]).unwrap_err());
    assert_eq!(
        (kind, key.as_str()),
        (ErrorKind::Validation, "servers.hidden.refused")
    );
    assert!(s.shareable_profile(&shown.added[0]).is_ok());
    let hidden_ids: Vec<ProfileId> = s.hidden_rows().into_iter().collect();
    assert_eq!(hidden_ids, hidden.added);
    assert!(group(&s, &hidden.group).hides_settings());
    assert!(!group(&s, &shown.group).hides_settings());

    // subs-a4 / subs-b9: deleting the group but keeping its servers keeps them hidden.
    s.delete_group(&hidden.group, false).unwrap();
    let kept = s.get(&hidden.added[0]).unwrap();
    assert!(kept.hidden && kept.group_id != hidden.group);
    let (_, key) = key_of(s.shareable_profile(&hidden.added[0]).unwrap_err());
    assert_eq!(key, "servers.hidden.refused");
    assert!(s.shareable_profile(&shown.added[0]).is_ok());
}
