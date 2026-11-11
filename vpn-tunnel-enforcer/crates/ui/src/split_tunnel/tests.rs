//! Tests of the Apps page: the ported vectors of ui-pages §7.14 (search, display path, U-26),
//! icons, the rule keys, the demo's process-name rule, and VirtualDom runs over the demo.
use vpnte_base::i18n::Lang;

use super::demo::{DemoSplitTunnel, normalize_process};
use super::*;
use crate::schedule::tests::lookup;

fn app(name: &str, path: &str) -> SplitApp {
    SplitApp {
        id: name.into(),
        name: name.into(),
        path: path.into(),
        icon: None,
        rule: AppRule::None,
        kind: AppKind::App,
    }
}

/// ui-pages §7.14: «codex» finds the name match and the path match; «CS.EXE» only the first
/// (case-insensitive file name); the query is trimmed in Rust.
#[test]
fn search_vectors() {
    let apps = [
        app("Codex Switcher", r"C:\Apps\cs.exe"),
        app(
            "OpenAI CLI",
            r"C:\Users\u\AppData\Local\OpenAI\Codex\bin\codex.exe",
        ),
    ];
    let hits = |q: &str| -> Vec<&str> {
        apps.iter()
            .filter(|a| matches(a, q))
            .map(|a| a.name.as_str())
            .collect()
    };
    assert_eq!(hits("codex"), ["Codex Switcher", "OpenAI CLI"]);
    assert_eq!(hits("CS.EXE"), ["Codex Switcher"]);
    assert_eq!(hits("  codex "), ["Codex Switcher", "OpenAI CLI"]);
    assert_eq!(hits(""), ["Codex Switcher", "OpenAI CLI"]);
    assert!(hits("telegram").is_empty());
    assert!(matches(&app("Яндекс Музыка", r"C:\y.exe"), "ЯНДЕКС"));
}

/// ui-pages §7.14 / U-26: only U+FFFD segments get the display fallback; processes, clean and
/// CJK paths are shown verbatim.
#[test]
fn display_path_vectors() {
    let telegram = app(
        "Telegram",
        "C:\\Users\\x\\AppData\\Roaming\\\u{FFFD}\\Telegram.exe",
    );
    assert_eq!(
        display_path(&telegram),
        r"C:\Users\x\AppData\Roaming\Telegram\Telegram.exe"
    );
    let leaf = app("App", "C:\\T\\\u{FFFD}\u{FFFD}.exe");
    assert_eq!(display_path(&leaf), r"C:\T\App.exe");
    let no_ext = app("Tool", "C:\\T\\\u{FFFD}");
    assert_eq!(display_path(&no_ext), r"C:\T\Tool.exe");
    let nameless = app("", "C:\\T\\\u{FFFD}.exe");
    assert_eq!(display_path(&nameless), r"C:\T\app.exe");
    let kept = app("Music", "C:\\Музыка \u{FFFD}\\m.exe");
    assert_eq!(display_path(&kept), r"C:\Музыка\m.exe");
    let unc = app("Share", "\\\\srv\\\u{FFFD}\\s.exe");
    assert_eq!(display_path(&unc), r"\\srv\Share\s.exe");
    let process = SplitApp {
        kind: AppKind::Process,
        ..app("x", "\u{FFFD}.exe")
    };
    assert_eq!(display_path(&process), "\u{FFFD}.exe");
    let clean = app("Steam", r"C:\Program Files (x86)\Steam\steam.exe");
    assert_eq!(display_path(&clean), clean.path);
    let cjk = app("a", r"C:\用户\a.exe");
    assert_eq!(display_path(&cjk), r"C:\用户\a.exe");
    let hangul = app("b", r"C:\사용자\b.exe");
    assert_eq!(display_path(&hangul), r"C:\사용자\b.exe");
}

/// Icons: only plain base64 becomes a `data:` URL; otherwise the first letter.
#[test]
fn icons() {
    assert_eq!(
        icon_src("iVBORw0KGgo="),
        Some("data:image/png;base64,iVBORw0KGgo=".into())
    );
    assert_eq!(
        icon_src("data:image/png;base64,iVBO"),
        Some("data:image/png;base64,iVBO".into())
    );
    assert_eq!(icon_src("javascript:alert(1)"), None);
    assert_eq!(icon_src("\" onerror=\"x"), None);
    assert_eq!(icon_src(""), None);
    assert_eq!(initial("Google Chrome"), "G");
    assert_eq!(initial("яндекс"), "Я");
    assert_eq!(initial(" (x86) tool"), "X");
    assert_eq!(initial("--"), "?");
}

/// Every rule has a label and a hover text in both languages.
#[test]
fn rule_keys() {
    for rule in AppRule::ALL {
        for lang in [Lang::Ru, Lang::En] {
            assert!(lookup(lang, rule.label_key()).is_some(), "{rule:?}");
            assert!(lookup(lang, rule.title_key()).is_some(), "{rule:?}");
        }
    }
    assert_eq!(
        lookup(Lang::Ru, "splitTunneling.ruleDirectTitle").as_deref(),
        Some("Мимо VPN")
    );
}

/// The fake service applies the routing §2.3 name rule.
#[test]
fn demo_process_names() {
    assert_eq!(normalize_process("curl").as_deref(), Some("curl.exe"));
    assert_eq!(
        normalize_process(" \"C:\\Tools\\YT-DLP\" ").as_deref(),
        Some("yt-dlp.exe")
    );
    assert_eq!(
        normalize_process("C:/bin/Git.EXE").as_deref(),
        Some("git.exe")
    );
    assert_eq!(normalize_process("my tool"), None);
    assert_eq!(normalize_process("a|b"), None);
    assert_eq!(normalize_process("C:\\bin\\"), None);
    assert!(lookup(Lang::Ru, "splitTunneling.invalidProcess").is_some());
}

/// The demo publishes before an action returns, so the page never patches its list.
#[tokio::test]
async fn demo_publishes_before_returning() {
    let demo = DemoSplitTunnel::new("full").instant();
    let rx = demo.state();
    demo.set_rule("a7".into(), AppRule::Vpn)
        .await
        .expect("rule set");
    let rule = rx
        .borrow()
        .apps
        .ready()
        .and_then(|apps| apps.iter().find(|a| a.id == "a7").map(|a| a.rule));
    assert_eq!(rule, Some(AppRule::Vpn));
    let added = demo.add_process("CURL".into()).await.expect("process");
    assert_eq!(
        (added.path.as_str(), added.rule),
        ("curl.exe", AppRule::Direct)
    );
    let count =
        |rx: &tokio::sync::watch::Receiver<SplitSnapshot>| rx.borrow().apps.ready().map(Vec::len);
    assert_eq!(
        count(&rx),
        Some(11),
        "an existing process is flipped, not added"
    );
    assert_eq!(demo.refresh().await.expect("rescan"), 1);
    assert_eq!(demo.refresh().await.expect("rescan"), 0);
    assert!(demo.add_app().await.expect("pick").is_some());
    assert!(demo.add_app().await.expect("dismissed").is_none());
    demo.remove("a1".into()).await.expect("removed");
    assert_eq!(count(&rx), Some(12));
}
