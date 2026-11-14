use std::cell::Cell;

use regex::Regex;

use super::*;

fn path(s: &str) -> AppPath {
    AppPath::parse(s).unwrap_or_else(|e| panic!("{s:?}: {e}"))
}

fn re(s: &str) -> Regex {
    Regex::new(s).unwrap()
}

fn app(name: &str, target: SplitTarget, rule: AppRule) -> SplitApp {
    SplitApp {
        id: Uuid::new_v4(),
        name: name.into(),
        target,
        rule,
    }
}

/// AT-06-008 / F-076 (splitTunnelPath.test.ts:11-22): normalisation and refusals.
#[test]
fn path_normalisation() {
    assert_eq!(path("C:/Apps/app.exe").as_str(), r"C:\Apps\app.exe");
    assert_eq!(path(r#" "C:\Apps\\app.exe" "#).as_str(), r"C:\Apps\app.exe");
    assert_eq!(
        path(r"\\srv\share\app.exe").as_str(),
        r"\\srv\share\app.exe"
    );
    for bad in [
        "app.exe",
        "Apps/app.exe",
        r"C:app.exe",
        r"C:\Apps\..\app.exe",
        r"C:\Apps",
        "",
        r"C:\a*b\x.exe",
    ] {
        assert_eq!(AppPath::parse(bad), Err(SplitError::BadPath), "{bad:?}");
    }
}

/// AT-06-008 (splitTunnelPath.test.ts:24-48): exact anchored case-insensitive path regex.
#[test]
fn path_regex() {
    let p = path(r"C:\Program Files (x86)\App+1\app.exe");
    assert_eq!(
        p.regex(),
        r"(?i)^C:\\Program Files \(x86\)\\App\+1\\app\.exe$"
    );
    let r = re(&p.regex());
    assert!(r.is_match(r"c:\program files (x86)\app+1\APP.EXE"));
    assert!(!r.is_match(r"D:\Other\app.exe"));
    assert!(!r.is_match(r"C:\Temp\C:\Program Files (x86)\App+1\app.exe"));
    assert!(!r.is_match(r"C:\Program Files (x86)\App+1\app.exe.bak"));
    assert!(!re(&path(r"C:\a.b\x.exe").regex()).is_match(r"C:\aXb\x.exe"));
}

/// AT-06-008 (splitTunnelPath.test.ts:50-74): stored + canonical long spelling.
#[test]
fn path_spellings() {
    let short = path(r"C:\PROGRA~1\App\app.exe");
    let long = path(r"C:\Program Files\App\app.exe");
    assert_eq!(
        long_spelling(&short, r"C:\Program Files\App\app.exe"),
        Some(long.clone())
    );
    assert_eq!(
        long_spelling(&short, r"\\?\C:\Program Files\App\app.exe"),
        Some(long.clone())
    );
    let x = path(r"C:\x\a.exe");
    assert_eq!(
        long_spelling(&x, r"\\?\UNC\srv\share\a.exe"),
        Some(path(r"\\srv\share\a.exe"))
    );
    assert_eq!(long_spelling(&x, r"C:\X\A.EXE"), None);
    let apps = [app("App", SplitTarget::App(short.clone()), AppRule::Direct)];
    let resolved = resolve_split(&apps, |_| Probe::File {
        canonical: Some(long.clone()),
    });
    assert_eq!(resolved.direct, vec![short.regex(), long.regex()]);
    let any = |p: &str| resolved.direct.iter().any(|r| re(r).is_match(p));
    assert!(any(r"C:\Program Files\App\app.exe"));
    assert!(!any(r"C:\Program Files\Other\app.exe"));
}

/// splitTunnelProcess.test.ts:47-121 with the Rust changes (case kept, `.exe` always,
/// pasted absolute path = app entry) and the §7.6 name vectors.
#[test]
fn process_names() {
    let name = |s: &str| ProcessName::parse(s).unwrap().as_str().to_owned();
    for (raw, want) in [
        ("curl", "curl.exe"),
        ("git", "git.exe"),
        ("yt-dlp", "yt-dlp.exe"),
        (r#""curl.exe""#, "curl.exe"),
        ("'git'", "git.exe"),
        ("/usr/bin/git", "git.exe"),
        ("Curl.EXE", "Curl.EXE"),
        ("Telegram", "Telegram.exe"),
        ("python3.11", "python3.11.exe"),
        ("node.js", "node.js.exe"),
    ] {
        assert_eq!(name(raw), want, "{raw:?}");
    }
    for bad in ["", "   ", "curl test", "a*b", "a|b", "C:curl"] {
        assert_eq!(ProcessName::parse(bad), Err(SplitError::BadName), "{bad:?}");
    }
    assert_eq!(
        ProcessName::parse("CURL.EXE").unwrap(),
        ProcessName::parse("curl").unwrap()
    );
    let r = re(&ProcessName::parse("Telegram").unwrap().regex());
    assert_eq!(r.as_str(), r"(?i)(?:^|\\)Telegram\.exe$");
    assert!(r.is_match(r"C:\Users\X\AppData\Roaming\Telegram Desktop\Telegram.exe"));
    assert!(r.is_match(r"C:\Users\X\AppData\Roaming\Telegram Desktop\telegram.exe"));
    assert!(!r.is_match(r"C:\Users\X\AppData\Roaming\Telegram Desktop\NotTelegram.exe"));
    assert_eq!(
        SplitTarget::parse(r"C:\Windows\System32\curl.exe").unwrap(),
        SplitTarget::App(path(r"C:\Windows\System32\curl.exe"))
    );
    assert!(matches!(
        SplitTarget::parse("curl").unwrap(),
        SplitTarget::Command(_)
    ));
    assert_eq!(
        SplitTarget::parse(r"C:\Windows\curl"),
        Err(SplitError::BadPath)
    );
}

/// splitTunneling.test.ts targets: direct names / paths, `vpn` entries in their own list
/// (B-ST-4), missing files inactive, one probe per app path.
#[test]
fn resolve_targets() {
    assert_eq!(
        resolve_split(&[], |_| Probe::Missing),
        ResolvedSplit::default()
    );
    let ytdlp = SplitTarget::parse("yt-dlp").unwrap();
    let r = resolve_split(&[app("yt-dlp", ytdlp.clone(), AppRule::Direct)], |_| {
        Probe::Missing
    });
    assert_eq!(r.direct, vec![r"(?i)(?:^|\\)yt-dlp\.exe$".to_owned()]);
    assert!(r.vpn.is_empty() && r.inactive.is_empty());
    let r = resolve_split(&[app("yt-dlp", ytdlp, AppRule::Vpn)], |_| Probe::Missing);
    assert!(r.direct.is_empty());
    assert_eq!(r.vpn.len(), 1);
    let exe = path(r"C:\Temp\vpnte\app.exe");
    let calls = Cell::new(0);
    let apps = [
        app("App", SplitTarget::App(exe.clone()), AppRule::Direct),
        app(
            "Off",
            SplitTarget::App(path(r"C:\Off\off.exe")),
            AppRule::None,
        ),
    ];
    let r = resolve_split(&apps, |_| {
        calls.set(calls.get() + 1);
        Probe::File { canonical: None }
    });
    assert_eq!(r.direct, vec![exe.regex()]);
    assert!(
        !r.direct.iter().any(|x| x.contains("(?:^|")),
        "no name rule for an app"
    );
    assert_eq!(calls.get(), 1);
    let r = resolve_split(&apps, |_| Probe::Missing);
    assert!(r.direct.is_empty());
    assert_eq!(
        r.inactive,
        vec![InactiveApp {
            name: "App".into(),
            path: exe.to_string(),
            reason: InactiveReason::FileMissing
        }]
    );
}

/// The real probe: a temp file is a file (and its own canonical spelling), a dir is not,
/// a deleted file is missing.
#[test]
fn probe_real_files() {
    let tmp = crate::test_support::TempDir::new("routing");
    let dir = tmp.path();
    let file = dir.join("app.exe");
    std::fs::write(&file, b"MZ").unwrap();
    let p = path(&file.to_string_lossy());
    assert!(matches!(probe_fs(&p), Probe::File { .. }));
    assert_eq!(
        probe_fs(&path(&format!("{}.dir", dir.display()))),
        Probe::Missing
    );
    std::fs::create_dir_all(dir.join("sub.exe")).unwrap();
    assert_eq!(
        probe_fs(&path(&dir.join("sub.exe").to_string_lossy())),
        Probe::NotAFile
    );
    std::fs::remove_file(&file).unwrap();
    assert_eq!(probe_fs(&p), Probe::Missing);
    // An invalid name (`:` past the drive passes the path grammar, as in the old app) gets no
    // rule and a warning instead of a silent rule that can never match.
    assert_eq!(
        probe_fs(&path(&format!(r"{}\a:b\x.exe", dir.display()))),
        Probe::Missing
    );
}

/// Stored form `{id, name, kind, target, rule}`; an invalid target fails the entry.
#[test]
fn split_app_serde() {
    let a = app("cURL", SplitTarget::parse("curl").unwrap(), AppRule::Direct);
    let json = serde_json::to_value(&a).unwrap();
    assert_eq!(json["kind"], "process");
    assert_eq!(json["target"], "curl.exe");
    assert_eq!(json["rule"], "direct");
    assert_eq!(serde_json::from_value::<SplitApp>(json).unwrap(), a);
    let bad = serde_json::json!({ "id": Uuid::nil(), "name": "x", "kind": "app",
                                  "target": "relative.exe", "rule": "vpn" });
    assert!(serde_json::from_value::<SplitApp>(bad).is_err());
}

/// Third-party cores: one regex per case-insensitive name (33 listed, 30 distinct).
#[test]
fn third_party_cores() {
    assert_eq!(THIRD_PARTY_CORES.len(), 33);
    let regexes = third_party_core_regexes();
    assert_eq!(regexes.len(), 30);
    let any = |p: &str| regexes.iter().any(|r| re(r).is_match(p));
    assert!(any(r"C:\Users\X\AppData\Local\FlClash\FlClash.exe"));
    assert!(any(r"C:\Program Files\Happ\core\xray.exe"));
    assert!(!any(r"C:\Program Files\Mozilla Firefox\firefox.exe"));
}
