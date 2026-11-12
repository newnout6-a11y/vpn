//! The import over synthetic old directories (storage §6.6, §7.3). Values are obvious fakes.
use std::io;
use std::path::PathBuf;

use serde_json::{Value, json};
use vpnte_automation::tweaks::{self, Target, Val, legacy::LegacySources};
use vpnte_base::Msg;

use super::ImportReport;
use super::run::{Host, MARKER, run};
use fixture::Fixture;

mod fixture;
mod live;

const UUID: &str = "11111111-2222-4333-8444-555555555555";
const PASS: &str = "FAKE-PASS-0001";
const TOKEN: &str = "FAKE-TOKEN-0002";

/// A host without the old Soft-mode leftovers.
fn host(elevated: bool) -> Host<'static> {
    Host {
        elevated,
        tweaks: None,
    }
}

fn keys(report: &ImportReport) -> Vec<&str> {
    report.notes.iter().map(|m| m.key.as_ref()).collect()
}

fn note<'a>(report: &'a ImportReport, key: &str) -> Option<&'a Msg> {
    report.notes.iter().find(|m| m.key == key)
}

fn rows(report: &ImportReport, file: &str) -> Option<usize> {
    report
        .imported
        .iter()
        .find(|(f, _)| f == file)
        .map(|(_, n)| *n)
}

fn outbound(host: &str) -> Value {
    json!({ "type": "vless", "tag": "proxy", "server": host, "server_port": 443, "uuid": UUID,
            "tls": { "enabled": true, "server_name": host } })
}

/// Settings, servers (key, link and group sealed), kill switch, language, theme, rules and a
/// leftover, as an encrypting old install wrote them.
fn encrypted_install(fx: &Fixture) {
    fx.local_state();
    fx.store(
        "settings",
        &json!({ "schemaVersion": 2, "extension": { "preserve": [1, 2] },
        "settings": { "routingMode": "soft", "firstRunComplete": true, "autoStart": true,
                      "firewallKillSwitch": true,
                      "proxyOverride": fx.seal(&format!("http://user:{PASS}@127.0.0.1:8080")),
                      "directVpnInput": fx.seal(""), "directVpnCachedProfiles": fx.seal("[]") } }),
    );
    let link = format!("vless://{UUID}@vpn.test:443?security=tls&sni=vpn.test#Fixture");
    fx.store(
        "server-picker",
        &json!({ "schemaVersion": 2, "activeProfileId": "p1",
        "profiles": [{ "id": "p1", "name": "Fixture", "protocol": "vless", "server": "vpn.test",
                       "port": 443, "outbound": fx.seal_json(&outbound("vpn.test")),
                       "sourceUri": fx.seal(&link) }] }),
    );
    let group = json!({ "id": "g1", "name": "Fixture", "source": "subscription",
                        "sourceUrl": format!("https://subscription.test/{TOKEN}"), "importedAt": 5 });
    fx.store(
        "server-groups",
        &json!({ "groups": [fx.seal_json(&group)] }),
    );
    fx.store("granular-kill-switch", &json!({ "killSwitchLevel": "standard",
        "killSwitchExceptions": [{ "id": "e1", "type": "ip", "value": "203.0.113.5", "label": "NAS" }] }));
    fx.store("i18n", &json!({ "locale": "en" }));
    fx.store(
        "themes",
        &json!({ "activeThemeId": "builtin-dark", "customThemes": [] }),
    );
    fx.store(
        "domain-routing",
        &json!({ "domainRules": [
        { "id": "r1", "pattern": "example.test", "action": "direct", "priority": 1 }] }),
    );
    fx.write_file("settings.json.bak-1700000000000", b"{\"settings\":{}}");
}

/// AT-00-006, AT-01-001 (storage §7.3): an encrypting install imports with its secrets opened and
/// sealed again for this account (no plaintext in the new files), the marker is written last,
/// the plaintext leftover is listed by name, and the old directory is byte-for-byte untouched.
#[test]
fn encrypted_install_imports_once_and_leaves_the_old_dir_alone() {
    let fx = Fixture::new("full");
    encrypted_install(&fx);
    let before = fx.old_files();

    let report = run(&fx.dirs(), &host(false)).expect("something imported");
    assert_eq!((report.locked, report.dropped), (0, 0), "{report:?}");
    assert_eq!(rows(&report, "settings.json"), Some(1));
    assert_eq!(rows(&report, "protection.json"), Some(1));
    assert_eq!(rows(&report, "profiles.json"), Some(1));
    assert_eq!(rows(&report, "rules.json"), Some(1));
    let leftovers = note(&report, "app.import.leftovers").expect("leftover listed");
    assert_eq!(leftovers.args[0].1, "settings.json.bak-1700000000000");
    assert_eq!(
        keys(&report),
        ["app.import.leftovers"],
        "Soft kept: no other note"
    );

    let settings = fx.doc("settings.json");
    assert_eq!(settings["routingMode"], "soft");
    assert_eq!(settings["locale"], "en");
    assert_eq!(settings["activeThemeId"], "builtin-dark");
    assert_eq!(settings["killSwitch"], "standard");
    assert_eq!(settings["autostart"], true);
    assert_eq!(settings["proxyOverride"]["host"], "127.0.0.1");
    assert!(
        settings["proxyOverride"]["credentials"]
            .as_str()
            .unwrap()
            .starts_with("dpapi:v1:")
    );
    let protection = fx.doc("protection.json");
    assert_eq!(protection["level"], "standard");
    let servers = fx.doc("profiles.json");
    assert_eq!(servers["activeProfileId"], "p1");
    let text = fx.new_text();
    for secret in [UUID, PASS, TOKEN, "vless://", "__vpnteSecretRef"] {
        assert!(!text.contains(secret), "{secret} written in plaintext");
    }
    let marker = fx.doc(MARKER);
    assert_eq!(
        (marker["source"].as_str(), marker["locked"].as_u64()),
        (Some("electron"), Some(0))
    );
    assert_eq!(fx.old_files(), before, "old directory changed");

    assert_eq!(run(&fx.dirs(), &host(false)), None, "one-shot");
    assert_eq!(fx.old_files(), before);
}

/// Storage §6.6: without the old key (no `Local State`) every encrypted value stays locked and is
/// counted; the rows that need one are not imported, the rest is, and the marker is written.
#[test]
fn without_the_old_key_secrets_stay_locked_and_are_counted() {
    let fx = Fixture::new("nokey");
    encrypted_install(&fx);
    std::fs::remove_file(fx.old.0.join("Local State")).unwrap();

    let report = run(&fx.dirs(), &host(false)).unwrap();
    // proxyOverride, directVpnInput, directVpnCachedProfiles, outbound, sourceUri, group.
    assert_eq!(report.locked, 6, "{report:?}");
    let locked = note(&report, "app.import.locked").expect("locked noted");
    assert_eq!(locked.args[0].1, "6");
    assert!(keys(&report).contains(&"core.settings.legacyProxyDropped"));
    assert_eq!(
        rows(&report, "profiles.json"),
        None,
        "nothing usable without the key"
    );
    assert_eq!(fx.doc("settings.json")["locale"], "en");
    assert!(
        fx.doc("settings.json")
            .get("proxyOverride")
            .is_none_or(Value::is_null)
    );
    assert_eq!(fx.doc(MARKER)["locked"], 6);
}

/// Nothing in the old directory (or no directory): a `none` marker, `None`; a marker that exists
/// ends the import before the old directory is looked at.
#[test]
fn nothing_to_import_and_done_earlier_return_none() {
    let fx = Fixture::new("none");
    assert_eq!(run(&fx.dirs(), &host(false)), None);
    assert_eq!(fx.doc(MARKER)["source"], "none");

    fx.store(
        "settings",
        &json!({ "settings": { "routingMode": "soft" } }),
    );
    assert_eq!(run(&fx.dirs(), &host(false)), None, "marker present");
    assert!(!fx.new.0.join("settings.json").exists());

    let gone = Fixture::new("gone");
    std::fs::remove_dir_all(&gone.old.0).unwrap();
    assert_eq!(run(&gone.dirs(), &host(false)), None);
    assert_eq!(gone.doc(MARKER)["source"], "none");
}

/// NOADMIN §0 / §2: unelevated, the old default Hard becomes Soft (said in a note), the strict
/// kill switch is kept with a note; an elevated process keeps Hard without notes.
#[test]
fn unelevated_import_uses_soft_and_keeps_strict() {
    for elevated in [false, true] {
        let fx = Fixture::new(&format!("admin-{elevated}"));
        fx.store(
            "settings",
            &json!({ "settings": { "routingMode": "hard" } }),
        );
        fx.store(
            "granular-kill-switch",
            &json!({ "killSwitchLevel": "strict" }),
        );
        let report = run(&fx.dirs(), &host(elevated)).unwrap();
        let settings = fx.doc("settings.json");
        assert_eq!(settings["killSwitch"], "strict");
        assert_eq!(fx.doc("protection.json")["level"], "strict");
        if elevated {
            assert_eq!(settings["routingMode"], "hard");
            assert!(report.notes.is_empty(), "{report:?}");
        } else {
            assert_eq!(settings["routingMode"], "soft");
            assert_eq!(
                keys(&report),
                ["app.import.softMode", "app.import.strictNeedsAdmin"]
            );
        }
    }
}

/// Rows the owning crates refuse are dropped and counted, with their warnings as notes.
#[test]
fn invalid_rows_are_dropped_and_counted() {
    let fx = Fixture::new("invalid");
    fx.store(
        "domain-routing",
        &json!({ "domainRules": [
        { "id": "r1", "pattern": "example.test", "action": "direct", "priority": 1 },
        { "id": "r2", "pattern": "", "action": "teleport", "priority": 2 }] }),
    );
    fx.store(
        "connection-history",
        &json!({ "connectionHistory": [{ "garbage": true }] }),
    );
    fx.store(
        "scheduler",
        &json!({ "schedules": [{ "name": "Broken", "mode": "warp" }] }),
    );
    fx.store("themes", &json!({ "customThemes": [{ "id": "t1" }] }));
    fx.store(
        "speed-test",
        &json!({ "history": [{ "profileName": "x" }] }),
    );

    let report = run(&fx.dirs(), &host(false)).unwrap();
    assert_eq!(report.dropped, 5, "{report:?}");
    for key in [
        "engine.routing.legacy.domainDropped",
        "tunnel.history.legacyDropped",
        "automation.scheduler.importSkipped",
    ] {
        assert!(keys(&report).contains(&key), "{key} missing: {report:?}");
    }
    assert_eq!(rows(&report, "rules.json"), Some(1));
    assert_eq!(rows(&report, "history/connections.json"), None);
    assert_eq!(
        rows(&report, "schedules.json"),
        None,
        "an empty document is not written"
    );
}

/// A file written by a newer version, or damaged, is noted and not imported; the old bytes
/// stay as they were and the import completes.
#[test]
fn newer_or_damaged_old_files_are_noted() {
    let fx = Fixture::new("newer");
    fx.store(
        "settings",
        &json!({ "schemaVersion": 3, "settings": { "routingMode": "soft" } }),
    );
    fx.write_file("server-picker.json", b"not json at all");
    let before = fx.old_files();
    let report = run(&fx.dirs(), &host(false)).unwrap();
    let file = |key: &str| note(&report, key).map(|m| m.args[0].1.clone());
    assert_eq!(
        file("app.import.fileNewer").as_deref(),
        Some("settings.json")
    );
    assert_eq!(
        file("app.import.fileInvalid").as_deref(),
        Some("server-picker.json")
    );
    assert!(!fx.new.0.join("settings.json").exists());
    assert_eq!(fx.doc(MARKER)["source"], "electron");
    assert_eq!(fx.old_files(), before);
}

/// Documents the new data dir already has are the user's: kept, never overwritten (a re-run
/// after a crash before the marker changes nothing either).
#[test]
fn existing_new_documents_are_kept() {
    let fx = Fixture::new("kept");
    encrypted_install(&fx);
    let mine = b"{\n  \"schemaVersion\": 1,\n  \"locale\": \"ru\"\n}\n";
    std::fs::write(fx.new.0.join("settings.json"), mine).unwrap();
    let report = run(&fx.dirs(), &host(false)).unwrap();
    assert_eq!(rows(&report, "settings.json"), None);
    assert_eq!(std::fs::read(fx.new.0.join("settings.json")).unwrap(), mine);
    assert_eq!(rows(&report, "profiles.json"), Some(1));

    std::fs::remove_file(fx.new.0.join(MARKER)).unwrap();
    let servers = std::fs::read(fx.new.0.join("profiles.json")).unwrap();
    let again = run(&fx.dirs(), &host(false)).unwrap();
    assert_eq!(rows(&again, "profiles.json"), None, "{again:?}");
    assert_eq!(
        std::fs::read(fx.new.0.join("profiles.json")).unwrap(),
        servers
    );
}

/// An old file another program holds open exclusively is retried: no marker, a note, and the
/// next start imports it.
#[test]
fn a_held_old_file_is_retried_at_the_next_start() {
    use std::os::windows::fs::OpenOptionsExt as _;
    let fx = Fixture::new("held");
    fx.store("i18n", &json!({ "locale": "en" }));
    let held = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(fx.old.0.join("i18n.json"))
        .unwrap();
    let report = run(&fx.dirs(), &host(false)).unwrap();
    let retry = note(&report, "app.import.retry").expect("retry noted");
    assert_eq!(retry.args[0].1, "i18n.json");
    assert!(!fx.new.0.join(MARKER).exists());
    drop(held);
    let report = run(&fx.dirs(), &host(false)).unwrap();
    assert_eq!(rows(&report, "settings.json"), Some(1));
    assert_eq!(fx.doc("settings.json")["locale"], "en");
    assert!(fx.new.0.join(MARKER).exists());
}

/// Storage §7.3 "legacy direct path", offline: an empty old list with a direct input that the
/// settings cache does not cover. Keys are added for `pc` with the old index clamped; a
/// subscription becomes an empty subscription group (URL sealed) that the first refresh fills.
#[test]
fn old_direct_input_is_imported_without_network() {
    let fx = Fixture::new("direct-keys");
    fx.local_state();
    let link = format!("vless://{UUID}@vpn.test:443?security=tls&sni=vpn.test#Direct");
    fx.store(
        "settings",
        &json!({ "settings": { "routingMode": "soft",
        "directVpnInput": fx.seal(&link), "directVpnSelectedIndex": 5 } }),
    );
    let report = run(&fx.dirs(), &host(false)).unwrap();
    assert_eq!(rows(&report, "profiles.json"), Some(1), "{report:?}");
    let doc = fx.doc("profiles.json");
    assert_eq!(doc["activeProfileId"], doc["profiles"][0]["id"]);
    assert!(!fx.new_text().contains(UUID));

    let fx = Fixture::new("direct-sub");
    fx.local_state();
    let url = format!("https://subscription.test/{TOKEN}");
    fx.store(
        "settings",
        &json!({ "settings": { "directVpnInput": fx.seal(&url) } }),
    );
    let report = run(&fx.dirs(), &host(false)).unwrap();
    assert!(keys(&report).contains(&"app.import.subscriptionPending"));
    assert_eq!(rows(&report, "profiles.json"), Some(0));
    let doc = fx.doc("profiles.json");
    assert_eq!(doc["groups"][0]["kind"], "subscription");
    assert!(!fx.new_text().contains(TOKEN));
}

/// Reads like `SoftSystem` but writes nothing: every variable holds an old-app proxy URL.
struct OldEnv;

impl tweaks::Backend for OldEnv {
    fn read(&self, _target: &Target) -> io::Result<Val> {
        Ok(Val::Sz("socks5h://127.0.0.1:10808".into()))
    }
    fn write(&self, _target: &Target, _value: &Val) -> io::Result<bool> {
        Err(io::Error::other("the import never writes the system"))
    }
    fn prune(&self, _target: &Target) -> io::Result<()> {
        Err(io::Error::other("the import never writes the system"))
    }
}

/// The old Soft mode's receipt becomes a journal record (rolled back later by the tunnel's
/// start-up recovery); it runs once and also when the old data dir is empty.
#[test]
fn old_soft_mode_leftovers_are_adopted_once() {
    let fx = Fixture::new("tweaks");
    let receipts = fx.old.0.join("receipts");
    std::fs::create_dir_all(&receipts).unwrap();
    std::fs::write(
        receipts.join("env-proxy-backup.json"),
        br#"{"httpProxy": null}"#,
    )
    .unwrap();
    let sources = LegacySources {
        receipts_dir: Some(receipts),
        gradle_props: None::<PathBuf>,
        studio_root: None,
    };
    let host = Host {
        elevated: false,
        tweaks: Some((&sources, &OldEnv)),
    };
    let report = run(&fx.dirs(), &host).expect("adoption reported");
    assert_eq!(report.imported, [("tweaks.json".to_owned(), 1)]);
    let journal = fx.doc("tweaks.json");
    assert_eq!(
        (
            journal["legacyImported"].as_bool(),
            journal["records"].as_array().map(Vec::len)
        ),
        (Some(true), Some(1))
    );
    assert_eq!(fx.doc(MARKER)["source"], "none");

    // A re-run without the import marker: the journal's own marker stops a second adoption.
    std::fs::remove_file(fx.new.0.join(MARKER)).unwrap();
    assert_eq!(run(&fx.dirs(), &host), None);
    assert_eq!(
        fx.doc("tweaks.json")["records"].as_array().map(Vec::len),
        Some(1)
    );
}

fn flat(prefix: &str, v: &Value, out: &mut std::collections::BTreeSet<String>) {
    match v {
        Value::Object(map) => {
            for (k, v) in map {
                let key = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                flat(&key, v, out);
            }
        }
        _ => {
            out.insert(prefix.to_owned());
        }
    }
}

/// The fragments are valid JSON with identical keys, and every `app.import.*` key the code uses
/// exists in both languages.
#[test]
fn locale_fragments_cover_the_code() {
    let mut sets = Vec::new();
    for text in [
        include_str!("../../../locales/app-import.ru.json"),
        include_str!("../../../locales/app-import.en.json"),
    ] {
        let json: Value = serde_json::from_str(text).unwrap();
        let mut keys = std::collections::BTreeSet::new();
        flat("", &json, &mut keys);
        sets.push(keys);
    }
    assert_eq!(sets[0], sets[1], "ru and en differ");
    let code = [
        include_str!("../run.rs"),
        include_str!("../steps.rs"),
        include_str!("../steps/servers.rs"),
    ]
    .concat();
    let used: std::collections::BTreeSet<String> = code
        .split("\"app.import.")
        .skip(1)
        .map(|rest| format!("app.import.{}", rest.split('"').next().unwrap()))
        .collect();
    assert!(!used.is_empty());
    assert_eq!(used, sets[0], "keys in the code vs the fragments");
}
