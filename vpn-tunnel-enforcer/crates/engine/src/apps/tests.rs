use std::path::{Path, PathBuf};

use super::*;
use crate::test_support::TempDir;

/// Display-name vectors (splitTunneling.test.ts:77-111, splitTunnelDiscovery.test.ts:167-183).
#[test]
fn display_names() {
    let fffd = |n: usize| "\u{fffd}".repeat(n);
    assert_eq!(
        sanitize_name(
            &format!("Hiddify, {} 2.5.7+20507", fffd(5)),
            r"C:\Program Files\Hiddify\Hiddify.exe"
        ),
        "Hiddify 2.5.7+20507"
    );
    assert_eq!(
        sanitize_name(
            &format!("{} {}멋 5.108.3", fffd(6), fffd(2)),
            r"C:\Users\X\AppData\Local\Programs\YandexMusic\broken.exe"
        ),
        "YandexMusic"
    );
    assert_eq!(
        sanitize_name(
            &format!("WinRAR 7.01 (64-{}來{})", fffd(1), fffd(2)),
            r"C:\Program Files\WinRAR\Rar.exe"
        ),
        "WinRAR 7.01"
    );
    assert_eq!(fallback_name(r"C:\Program Files\WinRAR\Rar.exe"), "WinRAR");
    assert_eq!(fallback_name(r"C:\Program Files\7-Zip\7z.exe"), "7-Zip");
    assert_eq!(
        fallback_name(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
        "chrome"
    );
    assert!(!looks_corrupt("QQ 腾讯"));
    assert!(!looks_corrupt("카카오톡"));
    assert!(looks_corrupt("YandexMusic 䍩䃘蓤悜 5.108"));
    assert_eq!(sanitize_name("QQ 腾讯", r"C:\QQ\qq.exe"), "QQ 腾讯");
    assert_eq!(
        sanitize_name("  Visual Studio Code ( User )  ", r"C:\x\code.exe"),
        "Visual Studio Code (User)"
    );
    assert_eq!(sanitize_name("Tool , v2,", r"C:\x\tool.exe"), "Tool, v2");
    assert_eq!(sanitize_name("Tool, 2024", r"C:\x\tool.exe"), "Tool 2024");
    assert_eq!(sanitize_name("1.2.3", r"C:\Apps\Thing\thing.exe"), "Thing");
}

/// A fake executable at `rel` under `t`.
fn exe(t: &TempDir, rel: &str) -> PathBuf {
    let p = t.path().join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, b"MZ").unwrap();
    p
}

fn found(apps: &[InstalledApp], root: &Path) -> Vec<(String, String)> {
    apps.iter()
        .map(|a| {
            let rel = Path::new(a.path.as_str()).strip_prefix(root).unwrap();
            (a.name.clone(), rel.to_string_lossy().into_owned())
        })
        .collect()
}

/// splitTunnelDiscovery.test.ts:114-165 on a real temp tree: sibling products both found,
/// helpers skipped, the product word picks the launcher, generic folders do not name apps.
#[test]
fn programs_walk() {
    let t = TempDir::new("apps");
    exe(&t, r"Vendor\ProductA\producta.exe");
    exe(&t, r"Vendor\ProductB\productb.exe");
    exe(&t, r"Tool\unins000.exe");
    exe(&t, r"Tool\update.exe");
    exe(&t, r"Tool\tool.exe");
    exe(&t, r"OpenAI\Codex\bin\codex.exe");
    exe(&t, r"OpenAI\Codex\bin\codex-code-mode-host.exe");
    exe(&t, r"Helpers\uninstall.exe");
    exe(&t, r"Deep\a\b\c\deep.exe");
    let apps = scan_programs(t.path());
    assert_eq!(
        found(&apps, t.path()),
        vec![
            (
                "OpenAI Codex".to_owned(),
                r"OpenAI\Codex\bin\codex.exe".to_owned()
            ),
            ("Tool".to_owned(), r"Tool\tool.exe".to_owned()),
            (
                "Vendor ProductA".to_owned(),
                r"Vendor\ProductA\producta.exe".to_owned()
            ),
            (
                "Vendor ProductB".to_owned(),
                r"Vendor\ProductB\productb.exe".to_owned()
            ),
        ]
    );
}

/// `Codex\bin` as a directory link is followed (needs the symlink privilege or developer
/// mode; skipped quietly without it).
#[test]
fn programs_walk_follows_directory_links() {
    let t = TempDir::new("apps");
    let target = exe(&t, r"store\bin\codex.exe");
    std::fs::create_dir_all(t.path().join(r"root\Codex")).unwrap();
    let link = t.path().join(r"root\Codex\bin");
    if std::os::windows::fs::symlink_dir(target.parent().unwrap(), &link).is_err() {
        return;
    }
    let apps = scan_programs(&t.path().join("root"));
    assert_eq!(apps.len(), 1);
    assert!(apps[0].path.as_str().ends_with(r"Codex\bin\codex.exe"));
}

/// Uninstall entries: DisplayIcon first (unless a helper / not an exe / missing), else the
/// main exe of InstallLocation (B-ST-5); a comma inside the icon path survives.
#[test]
fn uninstall_entries() {
    let yes = |_: &Path| true;
    let no = |_: &Path| false;
    let none = |_: &Path| Vec::new();
    let tool_dir = |d: &Path| {
        vec![
            d.join("unins000.exe"),
            d.join("Tool.exe"),
            d.join("ToolHelper.exe"),
        ]
    };
    let app = uninstall_app(
        "Foo",
        None,
        Some(r#""C:\Apps\Foo, Inc\foo.exe",0"#),
        &yes,
        &none,
    )
    .unwrap();
    assert_eq!(app.path.as_str(), r"C:\Apps\Foo, Inc\foo.exe");
    assert_eq!(app.name, "Foo");
    let app = uninstall_app(
        "Tool",
        Some(r"C:\Apps\Tool\"),
        Some(r"C:\Apps\Tool\unins000.exe,0"),
        &yes,
        &tool_dir,
    )
    .unwrap();
    assert_eq!(app.path.as_str(), r"C:\Apps\Tool\Tool.exe");
    let app = uninstall_app(
        "Tool",
        Some(r"C:\Apps\Tool"),
        Some(r"C:\Apps\Tool\tool.ico"),
        &yes,
        &tool_dir,
    )
    .unwrap();
    assert_eq!(app.path.as_str(), r"C:\Apps\Tool\Tool.exe");
    assert!(uninstall_app("Tool", Some(r"C:\Apps\Tool"), None, &no, &tool_dir).is_none());
    assert!(uninstall_app("Tool", None, None, &yes, &tool_dir).is_none());
    assert!(uninstall_app("Tool", Some(""), None, &yes, &tool_dir).is_none());
    // An icon path the path grammar refuses (`..`, relative) falls back to the folder, which
    // may be written quoted.
    for icon in [r"C:\Apps\Tool\bin\..\Tool.exe", "Tool.exe"] {
        let app = uninstall_app(
            "Tool",
            Some(r#""C:\Apps\Tool\""#),
            Some(icon),
            &yes,
            &tool_dir,
        )
        .unwrap();
        assert_eq!(app.path.as_str(), r"C:\Apps\Tool\Tool.exe", "{icon}");
    }
    assert_eq!(icon_path(r"C:\x\a.exe,-101"), r"C:\x\a.exe");
    assert_eq!(icon_path(r#" "C:\x\a.exe" "#), r"C:\x\a.exe");
}

/// REG_EXPAND_SZ expansion: known variables replaced, unknown ones left as written.
#[test]
fn env_expansion() {
    let windir = std::env::var("SystemRoot").unwrap();
    assert_eq!(
        expand_env(r"%SystemRoot%\x.exe"),
        format!(r"{windir}\x.exe")
    );
    assert_eq!(expand_env(r"%systemroot%\x"), format!(r"{windir}\x"));
    assert_eq!(
        expand_env("%VPNTE_NO_SUCH_VAR%\\a%"),
        "%VPNTE_NO_SUCH_VAR%\\a%"
    );
    assert_eq!(expand_env("100%"), "100%");
    assert_eq!(expand_env("%%"), "%%");
}

/// Reads this machine's Uninstall keys (read-only) and checks the shape of the result.
#[test]
#[ignore = "reads the installed-application list of this machine"]
fn discover_smoke() {
    let apps = discover();
    let mut seen = std::collections::HashSet::new();
    for a in &apps {
        assert!(!a.name.trim().is_empty());
        assert!(
            seen.insert(a.path.as_str().to_lowercase()),
            "duplicate path"
        );
    }
}
