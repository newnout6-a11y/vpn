//! p-logs: the service log reaches only the user it concerns (temp folders, a scoped
//! dispatcher; never the real ProgramData folder).
use std::sync::Arc;

use parking_lot::Mutex;

use super::*;

const ALICE: &str = "S-1-5-21-1111111111-2222222222-3333333333-1001";
const BOB: &str = "S-1-5-21-1111111111-2222222222-3333333333-1002";

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("vpnte-svc-logs-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

/// Logs through the service layer with `owner` switching between lines.
fn write(dir: &Path, lines: &[(Owner, &str)]) {
    let file = RotatingFile::open(dir, STEM, MAX_BYTES, 0).expect("open");
    let current = Arc::new(Mutex::new(Owner::Service));
    let layer = ServiceLayer::new(file, {
        let current = current.clone();
        move || current.lock().clone()
    });
    let dispatch = tracing::Dispatch::new(tracing_subscriber::registry().with(layer));
    tracing::dispatcher::with_default(&dispatch, || {
        for (owner, msg) in lines {
            *current.lock() = owner.clone();
            tracing::info!(n = 1, "{msg}");
        }
    });
}

fn messages(log: &ServiceLogWire) -> Vec<String> {
    log.lines
        .iter()
        .map(|l| {
            let v: Value = serde_json::from_str(&l.text).expect("json");
            assert!(v.get("user").is_none(), "tag stripped: {}", l.text);
            v["msg"].as_str().unwrap_or_default().to_owned()
        })
        .collect()
}

/// p-logs: a user reads the service-wide lines and his own, never another user's or a busy one.
#[test]
fn a_user_reads_only_his_own_and_service_wide_lines() {
    let dir = temp("own");
    write(
        &dir,
        &[
            (Owner::Service, "service starting"),
            (Owner::User(ALICE.into()), "alice session started"),
            (Owner::User(BOB.into()), "bob session started"),
            (Owner::Busy, "logged under a lock"),
            (Owner::Service, "update checked"),
        ],
    );
    let alice = lines_for(&dir, ALICE).expect("read");
    assert_eq!(
        messages(&alice),
        [
            "service starting",
            "alice session started",
            "update checked"
        ]
    );
    let bob = lines_for(&dir, BOB).expect("read");
    assert_eq!(
        messages(&bob),
        ["service starting", "bob session started", "update checked"]
    );
    assert!(!alice.truncated);
    // Offsets are file offsets: Bob's own line sits after Alice's.
    assert!(bob.lines[1].offset > alice.lines[1].offset);
    let _ = std::fs::remove_dir_all(&dir);
}

/// p-logs: the tag survives the file's redaction, secrets in the message do not, and the plain
/// text of an older build (no attribution) is shown to nobody.
#[test]
fn tags_survive_redaction_and_old_text_is_hidden() {
    let dir = temp("redact");
    std::fs::write(
        dir.join("service.log"),
        "2026-11-12T08:00:00.000Z  INFO vpnte_service: client connected image=C:\\Users\\bob\n",
    )
    .expect("old line");
    write(
        &dir,
        &[(
            Owner::User(ALICE.into()),
            "server vless://11111111-2222-3333-4444-555555555555@example.com:443",
        )],
    );
    let alice = lines_for(&dir, ALICE).expect("read");
    let shown = messages(&alice);
    assert_eq!(shown.len(), 1, "{shown:?}");
    assert!(!shown[0].contains("11111111"), "{}", shown[0]);
    assert!(lines_for(&dir, BOB).expect("read").lines.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

/// p-logs: no log yet (fresh install, or before `init`) is an empty answer, not an error.
#[test]
fn a_missing_log_is_empty() {
    let dir = temp("missing");
    assert_eq!(
        lines_for(&dir, ALICE).expect("read"),
        ServiceLogWire::default()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// p-logs: a reply carries at most the last `REPLY_LINES` lines and says so.
#[test]
fn a_long_log_is_cut_to_the_reply_size() {
    let dir = temp("long");
    let many: Vec<(Owner, &str)> = (0..REPLY_LINES + 5)
        .map(|_| (Owner::Service, "tick"))
        .collect();
    write(&dir, &many);
    let log = lines_for(&dir, ALICE).expect("read");
    assert_eq!(log.lines.len(), REPLY_LINES);
    assert!(log.truncated);
    let _ = std::fs::remove_dir_all(&dir);
}

/// p-logs: the session's user wins over the controller (a kept session ended for another user
/// stays its owner's), the controller counts while no session was started, else the service.
#[test]
fn lines_belong_to_the_session_user_first() {
    assert_eq!(owner_of(Some(ALICE), Some(BOB)), Owner::User(ALICE.into()));
    assert_eq!(owner_of(None, Some(BOB)), Owner::User(BOB.into()));
    assert_eq!(owner_of(None, None), Owner::Service);
}
