//! Tests of the start-up pieces that run without a window or system changes: the single-instance
//! hand-off over throw-away names, the backend panic notice, the locale fragments.
use std::collections::BTreeSet;
use std::time::Instant;

use serde_json::Value;
use vpnte_winnet::single_instance::{Command, InstanceNames};

use super::*;

fn names() -> InstanceNames {
    let id = uuid::Uuid::new_v4().simple().to_string();
    InstanceNames {
        mutex: format!(r"Local\VPNTE-Test-{id}"),
        pipe: format!(r"\\.\pipe\VPNTE-Test-{id}"),
    }
}

fn args(list: &[&str]) -> Args {
    Args::parse(list.iter().map(|s| (*s).to_owned()))
}

/// The next command a later launch handed to the primary (polled, at most 5 s).
fn next_command(rx: &mut tokio::sync::mpsc::UnboundedReceiver<Command>) -> Option<Command> {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Ok(cmd) = rx.try_recv() {
            return Some(cmd);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    None
}

/// lifecycle-app §3.7: a second launch hands its command to the running instance and exits 0;
/// `--no-elevate` / `--elevated-relaunch` change nothing (NOADMIN §0).
#[test]
fn a_second_launch_hands_over_and_exits() {
    let names = names();
    let Instance::Primary(mut primary) = single_instance_with(&names, &args(&[])) else {
        panic!("the first launch is the primary");
    };
    assert!(primary.is_listening());
    let mut commands = primary.take_commands().expect("commands taken once");

    let second = single_instance_with(&names, &args(&["--no-elevate", "--elevated-relaunch"]));
    assert!(matches!(second, Instance::Exit(code) if code == ExitCode::SUCCESS));
    assert_eq!(next_command(&mut commands), Some(Command::Activate));

    let update = single_instance_with(&names, &args(&["--shutdown-for-update"]));
    assert!(matches!(update, Instance::Exit(code) if code == ExitCode::SUCCESS));
    assert_eq!(
        next_command(&mut commands),
        Some(Command::ShutdownForUpdate)
    );
}

/// Installer contract: `--shutdown-for-update` with no running instance starts nothing, exits 0
/// and leaves the instance lock free.
#[test]
fn shutdown_for_update_without_a_primary_starts_nothing() {
    let names = names();
    let first = single_instance_with(&names, &args(&["--shutdown-for-update"]));
    assert!(matches!(first, Instance::Exit(code) if code == ExitCode::SUCCESS));
    assert!(matches!(
        single_instance_with(&names, &args(&[])),
        Instance::Primary(_)
    ));
}

/// lifecycle-app A-01: a panic on a backend thread becomes one error notice; the UI thread's
/// panics are left to Dioxus.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_backend_panic_becomes_a_notice() {
    let dir = tempfile_dir("panic");
    let settings = Arc::new(Store::<Settings>::open(&dir));
    // List only: no real Windows toast from a test.
    settings
        .update(|s| s.desktop_notifications = false)
        .expect("settings writable");
    let notifier = Arc::new(Notifier::new(settings).expect("notifier"));
    let mut list = notifier.subscribe();
    let cancel = CancellationToken::new();
    tokio::spawn(report_backend_panics(notifier.clone(), cancel.clone()));

    install_panic_hook();
    let worker = std::thread::Builder::new()
        .name("backend-test".into())
        .spawn(|| panic!("test panic on a backend thread"))
        .expect("thread");
    assert!(worker.join().is_err());

    let notice = tokio::time::timeout(Duration::from_secs(5), list.recv())
        .await
        .expect("a notice within 5 s")
        .expect("list open");
    assert_eq!(notice.notice.title.key, "app.main.internalError");
    assert_eq!(notice.notice.level, Level::Error);
    assert_eq!(notice.category, Some(NoticeCategory::ConnectionError));
    cancel.cancel();
    let _ = std::fs::remove_dir_all(&dir);
}

fn tempfile_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "vpnte-app-main-{tag}-{}",
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

fn keys(value: &Value, prefix: &str, out: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                keys(child, &path, out);
            }
        }
        _ => {
            out.insert(prefix.to_owned());
        }
    }
}

fn fragment_keys(text: &str) -> BTreeSet<String> {
    let value: Value = serde_json::from_str(text).expect("valid JSON");
    let mut out = BTreeSet::new();
    keys(&value, "", &mut out);
    out
}

/// The `app-main` fragments are valid JSON with identical key sets, every `app.main.*` key the
/// code names exists, and the winnet text of the other-session box is registered.
#[test]
fn locale_fragments_match_the_code() {
    let ru = fragment_keys(include_str!("../../locales/app-main.ru.json"));
    let en = fragment_keys(include_str!("../../locales/app-main.en.json"));
    assert_eq!(ru, en);
    let code = [include_str!("mod.rs"), include_str!("../root/mod.rs")].concat();
    let used: BTreeSet<String> = code
        .split('"')
        .filter(|s| s.starts_with("app.main.") && !s.ends_with('.'))
        .map(str::to_owned)
        .collect();
    assert!(!used.is_empty());
    for key in &used {
        assert!(ru.contains(key), "missing in the fragments: {key}");
    }
    vpnte_ui::lang::init_locales(&crate::svc_core::locale_layers());
    for lang in [Lang::Ru, Lang::En] {
        for key in used
            .iter()
            .map(String::as_str)
            .chain(["winnet.singleInstance.otherSession"])
        {
            assert_ne!(Msg::new(key.to_owned()).render(lang), key, "{lang:?} {key}");
        }
    }
}
