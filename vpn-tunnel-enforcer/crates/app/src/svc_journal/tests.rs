//! p-logs: the event journal (append, cap, rotation, redaction, clear, the history shown as
//! events), the notifier hook and the feeds. Temp folders only.
use std::time::Duration;

use vpnte_base::Msg;
use vpnte_base::types::{Level, Notice, Owner};
use vpnte_core::ops::Source;
use vpnte_tunnel::history::{Entry, NewEntry, Route, SessionMode};
use vpnte_tunnel::outcome::{OutcomeKind, SessionOutcome, verbatim};

use super::file::EventFile;
use super::*;
use crate::api_settings::test_support::{FakeTunnel, TempDir, backend};
use crate::svc_core::notify::NoticeCategory;

const T0: i64 = 1_800_000_000_000;

fn note(level: Level, key: &'static str) -> Notice {
    Notice::new(level, Msg::new(key))
}

fn titles(journal: &Journal) -> Vec<String> {
    journal
        .records()
        .iter()
        .map(|r| r.title.key.to_string())
        .collect()
}

fn entry(name: &str, start: i64, kind: OutcomeKind) -> NewEntry {
    NewEntry {
        correlation_id: None,
        source: Source::Ui,
        owner: Some(Owner::Manual),
        route: Route::Tun,
        started_at: start,
        ended_at: start + 60_000,
        duration_ms: 60_000,
        profile_name: name.into(),
        profile_id: "p1".into(),
        mode: SessionMode::Hard,
        bytes_down: 2048,
        bytes_up: 512,
        outcome: SessionOutcome::with_headline(kind, Default::default(), verbatim("Ended")),
    }
}

/// Appended events come back in order, numbered, and survive a reopen; the arguments are
/// redacted like the app log (secret names dropped, URIs and public addresses masked).
#[test]
fn appends_numbers_and_redacts() {
    let tmp = TempDir::new("journal-append");
    let journal = Journal::open(&tmp.0);
    let title = Msg::new("app.test.leak").arg("token", "abc123").arg(
        "server",
        "vless://11111111-2222-3333-4444-555555555555@203.0.113.7:443",
    );
    journal.append([NewRecord {
        at: T0,
        topic: Topic::Protection,
        tone: Tone::Warn,
        title,
        body: None,
        session: None,
    }]);
    journal
        .append([from_notice(&note(Level::Error, "app.test.failed"), None, T0 + 1).expect("kept")]);
    let records = journal.records();
    assert_eq!(records.iter().map(|r| r.seq).collect::<Vec<_>>(), [1, 2]);
    let args = &records[0].title.args;
    assert_eq!(args[0].1, vpnte_core::redact::REDACTED);
    assert!(!args[1].1.contains("11111111") && !args[1].1.contains("203.0.113.7"));
    let on_disk = std::fs::read_to_string(tmp.0.join(FILE)).expect("file");
    assert!(!on_disk.contains("abc123") && !on_disk.contains("11111111"));
    drop(journal);
    let again = Journal::open(&tmp.0);
    assert_eq!(again.records(), records);
    again.append([from_notice(&note(Level::Info, "app.test.x"), None, T0 + 2).expect("kept")]);
    assert_eq!(
        again.records()[2].seq,
        3,
        "numbering goes on after a reopen"
    );
}

/// Past the cap the current generation becomes the previous one; the one before is gone, from
/// the disk and from the page.
#[test]
fn rotates_at_the_cap() {
    let tmp = TempDir::new("journal-cap");
    let journal = Journal::open_capped(&tmp.0, 1000);
    for i in 0..40 {
        journal.append([
            from_notice(&note(Level::Info, "app.test.tick"), None, T0 + i).expect("kept"),
        ]);
    }
    let disk = EventFile::new(&tmp.0, 1000).read();
    assert_eq!(journal.records(), disk);
    assert!(
        disk.len() < 40,
        "older generations are gone: {}",
        disk.len()
    );
    assert_eq!(disk.last().map(|r| r.seq), Some(40));
    assert!(tmp.0.join(PREVIOUS).exists());
    let size = std::fs::metadata(tmp.0.join(FILE)).map_or(0, |m| m.len());
    assert!(size < 1000);
}

/// Clearing empties both generations and nothing else; a cleared journal is not seeded again.
#[test]
fn clears_only_the_events() {
    let tmp = TempDir::new("journal-clear");
    std::fs::write(tmp.0.join("other.json"), "{}").expect("other file");
    let journal = Journal::open_capped(&tmp.0, 300);
    for i in 0..5 {
        journal.append([
            from_notice(&note(Level::Info, "app.test.tick"), None, T0 + i).expect("kept"),
        ]);
    }
    journal.clear().expect("clear");
    assert!(journal.records().is_empty());
    assert!(!tmp.0.join(PREVIOUS).exists());
    assert_eq!(std::fs::read_to_string(tmp.0.join(FILE)).expect("file"), "");
    assert!(tmp.0.join("other.json").exists());
    drop(journal);
    let again = Journal::open(&tmp.0);
    again.seed(&[Entry::from_new(entry("NL", T0, OutcomeKind::UserStop)).expect("entry")]);
    assert!(
        again.records().is_empty(),
        "an existing journal is not seeded"
    );
}

/// After an upgrade the tab is not empty: a new journal starts with the stored sessions, a start
/// and an end each, in time order; only once.
#[test]
fn a_new_journal_starts_with_the_history() {
    let tmp = TempDir::new("journal-seed");
    let journal = Journal::open(&tmp.0);
    let entries = [
        Entry::from_new(entry("NL", T0, OutcomeKind::UserStop)).expect("entry"),
        Entry::from_new(entry("DE", T0 + 120_000, OutcomeKind::ServerDown)).expect("entry"),
    ];
    journal.seed(&entries);
    journal.seed(&entries);
    let records = journal.records();
    assert_eq!(
        titles(&journal),
        [
            "logs.events.sessionUp",
            "logs.events.sessionEnd",
            "logs.events.sessionUp",
            "logs.events.sessionEnd"
        ]
    );
    assert_eq!(records[1].tone, Tone::Info, "the user's own stop is plain");
    assert_eq!(
        records[3].tone,
        Tone::Error,
        "a server that went down is an error"
    );
    let facts = records[3].session.as_ref().expect("facts");
    assert_eq!(
        (facts.profile.as_str(), facts.duration_ms),
        ("DE", Some(60_000))
    );
    assert_eq!(facts.outcome, Some(OutcomeKind::ServerDown));
    assert_eq!(
        records[3].body.as_ref().map(|m| m.key.as_ref()),
        Some(vpnte_tunnel::outcome::VERBATIM)
    );
}

/// The hook sees every notice the app shows (also with Windows toasts off); the lifecycle's
/// plain connected / disconnected notices are left to the session lines.
#[test]
fn the_notifier_hook_writes_every_shown_notice() {
    let tmp = TempDir::new("journal-hook");
    let backend = backend(&tmp, FakeTunnel::new(false));
    let journal = attach(&backend);
    let n = &backend.notifier;
    n.notify(
        note(Level::Info, "tunnel.lifecycle.connected"),
        Some(NoticeCategory::VpnConnect),
    );
    n.notify(
        note(Level::Error, "tunnel.lifecycle.stopFailed"),
        Some(NoticeCategory::VpnDisconnect),
    );
    n.notify(
        note(Level::Warn, "probes.leak.webrtc"),
        Some(NoticeCategory::LeakDetected),
    );
    n.notify(note(Level::Success, "app.update.installed"), None);
    let records = journal.records();
    let got: Vec<(&str, Topic, Tone)> = records
        .iter()
        .map(|r| (r.title.key.as_ref(), r.topic, r.tone))
        .collect();
    assert_eq!(
        got,
        [
            (
                "tunnel.lifecycle.stopFailed",
                Topic::Connection,
                Tone::Error
            ),
            ("probes.leak.webrtc", Topic::Protection, Tone::Warn),
            ("app.update.installed", Topic::Update, Tone::Ok),
        ]
    );
}

#[test]
fn topics_follow_the_category_then_the_key() {
    use super::record::topic_of;
    assert_eq!(
        topic_of("x.y", Some(NoticeCategory::ScheduleTriggered)),
        Topic::Automation
    );
    assert_eq!(
        topic_of("automation.rotation.done", None),
        Topic::Automation
    );
    assert_eq!(topic_of("app.killSwitch.held", None), Topic::Protection);
    assert_eq!(topic_of("engine.xray.crashed", None), Topic::Connection);
    assert_eq!(topic_of("svc.update.ready", None), Topic::Update);
    assert_eq!(topic_of("app.import.done", None), Topic::Other);
}

async fn wait_for(what: &str, cond: impl Fn() -> bool) {
    for _ in 0..100 {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("timed out waiting for {what}");
}

/// Session starts (once, also for a session taken over), session ends from new history rows
/// and new runtime warnings reach the journal.
#[tokio::test]
async fn feeds_write_sessions_and_warnings() {
    use vpnte_base::types::AdaptiveMode;
    use vpnte_tunnel::lifecycle::SessionView;
    let tmp = TempDir::new("journal-feeds");
    let tunnel = FakeTunnel::new(false);
    let backend = backend(&tmp, tunnel.clone());
    let journal = Journal::open(&backend.dirs.root);
    spawn_feeds(journal.clone(), &backend);
    let view = SessionView {
        owner: Owner::Manual,
        profile_id: "p1".into(),
        profile_name: "NL".into(),
        mode: SessionMode::Soft,
        generation: Some(1),
        adaptive: AdaptiveMode::default(),
        started_at: T0,
        engine: None,
    };
    tunnel.session.send_replace(Some(view.clone()));
    wait_for("the start", || journal.records().len() == 1).await;
    tunnel.session.send_replace(None);
    tunnel.session.send_replace(Some(view));
    backend
        .history
        .add(entry("NL", T0, OutcomeKind::NetworkLost))
        .expect("row");
    wait_for("the end", || journal.records().len() == 2).await;
    tunnel
        .status
        .send_modify(|s| s.warning = Some(Msg::new("tunnel.runtime.restarting")));
    wait_for("the warning", || journal.records().len() == 3).await;
    assert_eq!(
        titles(&journal),
        [
            "logs.events.sessionUp",
            "logs.events.sessionEnd",
            "tunnel.runtime.restarting"
        ]
    );
    assert_eq!(journal.records()[1].tone, Tone::Warn);
    backend.shutdown.cancel();
}

/// The notes of this start's import of the old version's data become update events.
#[test]
fn import_notes_become_update_events() {
    let report = crate::import::ImportReport {
        imported: vec![("profiles.json".into(), 3)],
        locked: 0,
        dropped: 0,
        notes: vec![Msg::new("app.import.softMode")],
    };
    let events = import_events(&report, T0);
    assert_eq!(events.len(), 1);
    assert_eq!(
        (events[0].topic, events[0].tone),
        (Topic::Update, Tone::Info)
    );
    assert_eq!(events[0].title.key, "app.import.softMode");
}

/// p-tails-a: a document left read-only is one event, written by the start that first found it
/// (a warning, topic other); the next start with the same state adds nothing; `record` adds an
/// event to the journal the hook writes to.
#[test]
fn a_store_notice_is_recorded_once() {
    let tmp = TempDir::new("journal-store");
    let data = tmp.0.join("data");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::write(data.join("rules.json"), r#"{"schemaVersion":99}"#).unwrap();
    let count = |journal: &Journal| {
        let records = journal.records();
        let found: Vec<_> = records
            .iter()
            .filter(|r| r.title.key == "core.store.newerVersion")
            .map(|r| (r.topic, r.tone, r.title.args.clone()))
            .collect();
        for (topic, tone, args) in &found {
            assert_eq!((*topic, *tone), (Topic::Other, Tone::Warn));
            assert!(
                args.contains(&("file".into(), "rules.json".into())),
                "{args:?}"
            );
        }
        found.len()
    };
    {
        let backend = backend(&tmp, FakeTunnel::new(false));
        let journal = attach(&backend);
        assert_eq!(count(&journal), 1);
        record(
            &backend.dirs.root,
            Topic::Update,
            Tone::Ok,
            Msg::new("app.journal.update.downloaded").arg("what", "VPN Tunnel Enforcer 2.0.1"),
            None,
        );
        let last = journal.records().pop().unwrap();
        assert_eq!(last.title.key, "app.journal.update.downloaded");
    }
    // The marker as the previous start (another process) left it.
    let marker = data.join("rules.json.notice");
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&marker).unwrap()).unwrap();
    value["run"] = "1-1".into();
    std::fs::write(&marker, serde_json::to_vec(&value).unwrap()).unwrap();
    let backend = backend(&tmp, FakeTunnel::new(false));
    let journal = attach(&backend);
    assert_eq!(count(&journal), 1, "not again at the next start");
}

/// p-tails-a: the journal's own texts (update channel, kill switch) pair up in ru and en and
/// cover every key the producers write.
#[test]
fn journal_texts_pair_up() {
    fn keys(prefix: &str, value: &serde_json::Value, out: &mut Vec<String>) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, value) in map {
                    keys(&format!("{prefix}{key}."), value, out);
                }
            }
            _ => out.push(prefix.trim_end_matches('.').to_owned()),
        }
    }
    let flat = |text: &str| {
        let mut out = Vec::new();
        keys("", &serde_json::from_str(text).unwrap(), &mut out);
        out.sort();
        out
    };
    let ru = flat(include_str!("../../locales/p-tails-a.ru.json"));
    let en = flat(include_str!("../../locales/p-tails-a.en.json"));
    assert_eq!(ru, en);
    let used = [
        "offered",
        "downloaded",
        "started",
        "failed",
        "notFinished",
        "engine",
        "engineFailed",
        "service",
        "serviceBack",
    ]
    .map(|k| format!("app.journal.update.{k}"))
    .into_iter()
    .chain(
        [
            "off",
            "onDrop",
            "always",
            "exceptionAdded",
            "exceptionRemoved",
        ]
        .map(|k| format!("app.journal.killSwitch.{k}")),
    );
    for key in used {
        assert!(ru.contains(&key), "{key}");
    }
}

/// p-tails-a: the kill-switch level and its exceptions, changed in Settings, are protection
/// events in the journal the hook writes to; an exception's label is redacted like the app log.
#[test]
fn kill_switch_changes_are_protection_events() {
    let tmp = TempDir::new("journal-kill-switch");
    let journal = Journal::open(&tmp.0);
    for level in [
        KillSwitchLevel::Strict,
        KillSwitchLevel::Standard,
        KillSwitchLevel::Off,
    ] {
        kill_switch_level(&tmp.0, level);
    }
    let link = "vless://11111111-2222-3333-4444-555555555555@203.0.113.7:443";
    kill_switch_exception(&tmp.0, "Офис", true);
    kill_switch_exception(&tmp.0, link, false);
    let records = journal.records();
    let keys: Vec<&str> = records.iter().map(|r| &*r.title.key).collect();
    assert_eq!(
        keys,
        [
            "app.journal.killSwitch.always",
            "app.journal.killSwitch.onDrop",
            "app.journal.killSwitch.off",
            "app.journal.killSwitch.exceptionAdded",
            "app.journal.killSwitch.exceptionRemoved",
        ]
    );
    assert!(records.iter().all(|r| r.topic == Topic::Protection));
    assert_eq!(records[3].title.args[0].1, "Офис");
    assert!(!records[4].title.args[0].1.contains("11111111"));
}
