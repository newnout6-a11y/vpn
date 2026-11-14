//! Tests of the installer's WebView2 branch (`installer/webview2.nsh`). The shipped defines are checked against
//! Microsoft's documented keys and the pinned bootstrapper; the decisions themselves are compiled with the pinned
//! NSIS into a throw-away program and run against a throw-away HKCU key, with stand-ins for the bootstrapper.
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use windows_registry::CURRENT_USER;

use crate::manifest::Manifest;
use crate::tools;

const CLIENT: &str = r"Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}";

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

/// A repository text file with LF line ends: CI's Windows checkout turns them into CRLF
/// (core.autocrlf), and the checks below look for whole lines.
fn read(rel: &str) -> String {
    fs::read_to_string(root().join(rel))
        .unwrap()
        .replace("\r\n", "\n")
}

/// A path as NSIS reads it: backslashes only (makensis does not find `C:\dir/file`).
fn win(path: &Path) -> String {
    path.display().to_string().replace('/', r"\")
}

/// The lines of a script without their comments (no string in these files holds a `;`).
fn code(text: &str) -> Vec<&str> {
    text.lines()
        .map(|l| l.split(';').next().unwrap_or("").trim())
        .filter(|l| !l.is_empty())
        .collect()
}

/// The shipped branch: Microsoft's documented keys (64-bit Windows), the pinned bootstrapper with `/silent
/// /install` in this order, started with CreateProcess (never an elevation prompt) after the files are in place
/// and waited for only after the service step (lab live-9 L9-9: it runs beside the rest of setup); setup never
/// stops or shows a box here.
#[test]
fn shipped_branch_uses_the_documented_keys_and_the_pinned_bootstrapper() {
    let nsh = read("installer/webview2.nsh");
    let lines = code(&nsh);
    assert!(lines.contains(&"!define WV2_MACHINE_ROOT HKLM"));
    let machine = format!(r#"!define WV2_MACHINE_KEY "SOFTWARE\WOW6432Node\{CLIENT}""#);
    assert!(lines.contains(&machine.as_str()), "{machine}");
    let user = format!(r#"!define WV2_USER_KEY "Software\{CLIENT}""#);
    assert!(lines.contains(&user.as_str()), "{user}");
    let manifest = Manifest::load(&root()).unwrap();
    let pinned = manifest
        .download
        .iter()
        .find(|d| d.id == "webview2-bootstrapper")
        .unwrap()
        .install
        .as_str()
        .replace('/', r"\");
    let run = format!(r#"!define WV2_RUN '"$INSTDIR\{pinned}" /silent /install'"#);
    assert!(lines.contains(&run.as_str()), "{run}");
    assert!(lines.contains(&"StrCpy $R3 '${WV2_RUN}'"));
    assert!(
        lines
            .iter()
            .any(|l| l.contains("kernel32::CreateProcessW(p 0, t R3,"))
    );
    assert!(
        lines
            .iter()
            .any(|l| l.contains("kernel32::WaitForSingleObject(p $WebView2Process, i -1)"))
    );
    for banned in [
        "Abort",
        "Quit",
        "SetErrorLevel",
        "MessageBox",
        "ExecShell",
        "nsExec",
        "runas",
    ] {
        assert!(
            lines.iter().all(|l| !l.contains(banned)),
            "{banned} in webview2.nsh"
        );
    }
    let nsi = read("installer/vpnte.nsi");
    let at = |needle: &str| nsi.find(needle).unwrap_or_else(|| panic!("{needle}"));
    let files = at(r#"File /r "${STAGE}\resources\*""#);
    let (start, service) = (at("  Call StartWebView2\n"), at("  Call InstallService\n"));
    let wait = at("  Call EnsureWebView2\n");
    assert!(
        files < start,
        "the bootstrapper must be installed before it runs"
    );
    assert!(
        start < service && service < wait,
        "it runs beside the service step"
    );
    assert!(
        nsi.contains(r#"!define MUI_FINISHPAGE_TEXT "$(MUI_TEXT_FINISH_INFO_TEXT)$WebView2Note""#)
    );
    let lang = read("installer/lang.nsh");
    for key in ["WebView2Installing", "WebView2Later"] {
        for language in ["LANG_ENGLISH", "LANG_RUSSIAN"] {
            assert!(lang.contains(&format!("LangString {key} ${{{language}}} \"")));
        }
    }
}

/// A throw-away HKCU key, removed again even when an assertion fails.
struct ScratchKey(String);

impl Drop for ScratchKey {
    fn drop(&mut self) {
        let _ = CURRENT_USER.remove_tree(&self.0);
    }
}

/// One run of the branch: the registry state before, the stand-in "bootstrapper" command line, and the outcome
/// as `(version found, exit code, finish-page note shown)`; `beside`: the stand-in must still run when
/// `StartWebView2` returned (setup goes on meanwhile).
struct Case<'a> {
    machine: Option<&'a str>,
    user: Option<&'a str>,
    run: String,
    expect: (&'a str, &'a str, bool),
    beside: bool,
}

/// The branch's decisions, run for real with the pinned NSIS (fetched like `cargo xtask nsis`; skipped when it
/// cannot be had): runtime found under either key (nothing runs), `0.0.0.0` or empty = missing, a run that
/// registers the runtime, a failing run, a program that cannot be started, and an exit 0 without registration
/// (bounded wait, WebView2Feedback #1349). Missing afterwards = the finish-page note, never a stop.
#[test]
fn branch_decisions_run_against_a_scratch_key() {
    let root = root();
    let makensis = match tools::nsis(&root) {
        Ok(path) => path,
        Err(err) => {
            eprintln!("skipped: the pinned NSIS is not available ({err:#})");
            return;
        }
    };
    let key = ScratchKey(format!(
        r"Software\vpnte-xtask-test-wv2-{}",
        std::process::id()
    ));
    let k = &key.0;
    let reg = r#""$SYSDIR\reg.exe""#;
    let cases = [
        Case {
            machine: Some("120.0.2210.91"),
            user: None,
            run: format!(r#"{reg} add "HKCU\{k}\ran" /f"#),
            expect: ("120.0.2210.91", "", false),
            beside: false,
        },
        Case {
            machine: Some("0.0.0.0"),
            user: Some("121.0.1"),
            run: format!(r#"{reg} add "HKCU\{k}\ran" /f"#),
            expect: ("121.0.1", "", false),
            beside: false,
        },
        Case {
            machine: Some(""),
            user: None,
            run: format!(r#"{reg} add "HKCU\{k}\user" /v pv /d 1.2.3.4 /f"#),
            expect: ("1.2.3.4", "0", false),
            beside: false,
        },
        Case {
            machine: None,
            user: Some("0.0.0.0"),
            run: format!(r#"{reg} query "HKCU\{k}\absent""#),
            expect: ("", "1", true),
            beside: false,
        },
        Case {
            machine: None,
            user: None,
            run: r#""$TEMP\vpnte-no-such-bootstrapper.exe" /silent /install"#.to_owned(),
            expect: ("", "error", true),
            beside: false,
        },
        Case {
            machine: None,
            user: None,
            run: format!(r#"{reg} query "HKCU\{k}""#),
            expect: ("", "0", true),
            beside: false,
        },
        // Lab live-9 L9-9: a slow bootstrapper (2 s here) runs while setup goes on; the end waits for it.
        Case {
            machine: None,
            user: None,
            run: format!(
                r#""$SYSDIR\cmd.exe" /c ping -n 3 127.0.0.1 >nul & reg add HKCU\{k}\user /v pv /d 5.6.7.8 /f"#
            ),
            expect: ("5.6.7.8", "0", false),
            beside: true,
        },
    ];
    let scratch = root.join("target/xtask/test-scratch/nsis-webview2");
    let _ = fs::remove_dir_all(&scratch);
    fs::create_dir_all(&scratch).unwrap();
    for (i, case) in cases.iter().enumerate() {
        let _ = CURRENT_USER.remove_tree(k);
        let base = CURRENT_USER.create(k).unwrap();
        for (sub, value) in [("machine", case.machine), ("user", case.user)] {
            if let Some(value) = value {
                base.create(sub).unwrap().set_string("pv", value).unwrap();
            }
        }
        let (running, version, exit, note) = run_case(&makensis, &scratch, k, i, &case.run);
        let (want_version, want_exit, want_note) = case.expect;
        assert_eq!(
            (version.as_str(), exit.as_str(), note),
            (want_version, want_exit, want_note),
            "case {i}"
        );
        assert!(
            running || !case.beside,
            "case {i}: setup waited for the bootstrapper"
        );
        // Found runtime = the bootstrapper never ran.
        let ran = CURRENT_USER.open(format!(r"{k}\ran")).is_ok();
        assert!(
            !ran || !want_exit.is_empty(),
            "case {i}: ran although found"
        );
    }
    drop(key);
    fs::remove_dir_all(&scratch).unwrap();
}

/// Compiles the branch with the case's defines, runs it silently and returns its outcome.
fn run_case(
    makensis: &Path,
    scratch: &Path,
    key: &str,
    i: usize,
    run: &str,
) -> (bool, String, String, bool) {
    let exe = scratch.join(format!("wv2-case-{i}.exe"));
    let out = scratch.join(format!("wv2-case-{i}.txt"));
    let nsh = root().join("installer/webview2.nsh");
    let script = format!(
        "Unicode true\nRequestExecutionLevel user\nSilentInstall silent\nOutFile \"{exe}\"\n\
         !include LogicLib.nsh\n!define WV2_MACHINE_ROOT HKCU\n!define WV2_MACHINE_KEY \"{key}\\machine\"\n\
         !define WV2_USER_KEY \"{key}\\user\"\n!define WV2_RUN '{run}'\n!define WV2_SETTLE_SECONDS 2\n\
         !include \"{nsh}\"\nLangString WebView2Installing 1033 \"installing\"\n\
         LangString WebView2Later 1033 \"later\"\nFunction .onInit\n  SetRegView 64\nFunctionEnd\n\
         Section\n  Call StartWebView2\n  StrCpy $5 \"\"\n  ${{If}} $WebView2Process != \"\"\n\
         System::Call 'kernel32::WaitForSingleObject(p $WebView2Process, i 0) i .r5'\n  ${{EndIf}}\n\
         Call EnsureWebView2\n  FileOpen $0 \"{out}\" w\n  FileWrite $0 \"$5|$R0|$R1|$WebView2Note\"\n\
         FileClose $0\nSectionEnd\n",
        exe = win(&exe),
        nsh = win(&nsh),
        out = win(&out),
    );
    let script_path = scratch.join(format!("wv2-case-{i}.nsi"));
    fs::write(&script_path, script).unwrap();
    let compiled = Command::new(makensis)
        .args(["/V2", "/WX", "/INPUTCHARSET", "UTF8"])
        .arg(&script_path)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "case {i}: makensis failed:\n{}{}",
        String::from_utf8_lossy(&compiled.stdout),
        String::from_utf8_lossy(&compiled.stderr)
    );
    let mut child = Command::new(&exe).arg("/S").spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("case {i}: the branch did not finish within 60 s");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let text = fs::read_to_string(&out).unwrap();
    let mut parts = text.splitn(4, '|');
    // WAIT_TIMEOUT: the stand-in still ran when StartWebView2 returned.
    let running = parts.next() == Some("258");
    let version = parts.next().unwrap_or_default().to_owned();
    let exit = parts.next().unwrap_or_default().to_owned();
    let note = parts.next().unwrap_or_default();
    assert!(
        note.is_empty() || note == "\r\n\r\nlater",
        "case {i}: note {note:?}"
    );
    (running, version, exit, !note.is_empty())
}
