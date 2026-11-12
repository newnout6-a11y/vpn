//! The exit-code table of the non-UI paths and the paths that must refuse before touching
//! anything (installer contract, `installer/PROGRESS.md`). No test here changes system state:
//! every command below stops at its argument checks.
use std::collections::BTreeSet;

use super::*;

fn parse(list: &[&str]) -> Args {
    Args::parse(list.iter().map(|s| (*s).to_owned()))
}

fn code(list: &[&str]) -> Option<u8> {
    command(&parse(list)).map(|end| end.code())
}

/// AT-11-002: 0 success, 1 failed / refused, 2 usage error.
#[test]
fn exit_code_table() {
    assert_eq!(End::Done(Vec::new()).code(), 0);
    assert_eq!(End::failed("x").code(), 1);
    assert_eq!(End::Usage("x".into()).code(), 2);
    assert_eq!(run(&parse(&["--version"])), Some(ExitCode::SUCCESS));
}

/// An unknown or malformed `--setup` is a usage error at once, never the UI.
#[test]
fn usage_errors_exit_2() {
    for list in [
        &["--setup", "nope"][..],
        &["--setup"],
        &["--setup", "await-shutdown", "--timeout", "0"],
        &[
            "--setup",
            "await-shutdown",
            "--timeout",
            "soon",
            "--install-dir",
            r"C:\x",
        ],
    ] {
        assert_eq!(code(list), Some(2), "{list:?}");
    }
}

/// Every command refuses without `--install-dir` (exit 1, one ASCII line), before any process,
/// file, registry or COM access.
#[test]
fn missing_install_dir_refuses_every_command() {
    let expected = [
        (
            "await-shutdown",
            "Installation path is missing; update refused.",
        ),
        (
            "uninstall",
            "Installation path is missing; nothing was removed.",
        ),
        (
            "stamp-shortcuts",
            "Installation path is missing; shortcuts not stamped.",
        ),
        (
            "launch-as-user",
            "Installation path is missing; not started.",
        ),
        (
            "register-links",
            "Installation path is missing; link schemes not registered.",
        ),
    ];
    for (name, line) in expected {
        let end = command(&parse(&["--setup", name, "--install-dir", " "]));
        assert_eq!(end, Some(End::failed(line)), "{name}");
        assert!(line.is_ascii());
    }
}

/// `launch-as-user` starts nothing when the installed client is not there.
#[test]
fn launch_as_user_needs_the_installed_client() {
    let dir = std::env::temp_dir().join(format!("vpnte-setup-test-{}", std::process::id()));
    let end = command(&parse(&[
        "--setup",
        "launch-as-user",
        "--install-dir",
        &dir.to_string_lossy(),
    ]));
    assert_eq!(
        end,
        Some(End::failed(
            "The installed client was not found; not started."
        ))
    );
}

/// Ordinary launches fall through to the UI.
#[test]
fn ui_launches_are_not_commands() {
    assert_eq!(code(&[]), None);
    assert_eq!(code(&["--autostart"]), None);
    assert_eq!(code(&["--shutdown-for-update"]), None);
    assert_eq!(code(&["--no-elevate", "--updated"]), None);
}

/// The installer decodes our output as ANSI: one printable ASCII line, whatever the input.
#[test]
fn output_is_one_ascii_line() {
    assert_eq!(ascii_line("ok: done"), "ok: done");
    assert_eq!(ascii_line("Ошибка\r\nx\t"), "????????x?");
}

/// Every output of this package is English ASCII for the installer: the fragments carry no keys.
#[test]
fn locale_fragments_are_empty_and_identical() {
    fn keys(text: &str) -> BTreeSet<String> {
        let value: serde_json::Value = serde_json::from_str(text).expect("valid JSON");
        let setup = &value["app"]["setup"];
        assert!(setup.is_object(), "top-level key app.setup");
        setup
            .as_object()
            .map(|o| o.keys().cloned().collect())
            .unwrap_or_default()
    }
    let ru = keys(include_str!("../../locales/app-setup.ru.json"));
    let en = keys(include_str!("../../locales/app-setup.en.json"));
    assert_eq!(ru, en);
    assert!(ru.is_empty());
}
