use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::*;
use crate::hardening::admit;
use crate::hardening::browser::{BrowserDirs, Browsers};
use crate::hardening::fake::{Fake, reg};
use crate::hardening::location::{CONSENT, Location, POLICY_KEY};
use crate::test_support::TempDir;

const HEADER: &str = "Windows Registry Editor Version 5.00\r\n\r\n";
const HKCU_KEY: &str = r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location";
const HKLM_KEY: &str = r"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors";

/// What `reg export` writes: UTF-16LE with a BOM.
fn utf16(text: &str) -> Vec<u8> {
    let mut out = vec![0xFF, 0xFE];
    for unit in text.encode_utf16() {
        out.extend(unit.to_le_bytes());
    }
    out
}

fn write_reg(path: &Path, body: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, utf16(&format!("{HEADER}{body}"))).unwrap();
}

/// `reg export` escapes `\` and `"`; DWORDs are hex; other types are recognised as such.
#[test]
fn value_lines_parse_like_reg_export() {
    let sz = |name: &str, v: &str| Some((name.to_owned(), RegLine::Sz(v.to_owned())));
    assert_eq!(value_line(r#""Value"="Deny""#), sz("Value", "Deny"));
    assert_eq!(
        value_line(r#""a\\b\"c"="x\\y\"z""#),
        sz(r#"a\b"c"#, r#"x\y"z"#)
    );
    let one = Some(("DisableLocation".to_owned(), RegLine::Dword(1)));
    assert_eq!(value_line(r#""DisableLocation"=dword:00000001"#), one);
    let other = |line: &str| value_line(line).map(|(_, v)| v);
    assert_eq!(other(r#""X"=dword:zz"#), Some(RegLine::Other));
    assert_eq!(other(r#""X"=hex(2):25,00,00,00"#), Some(RegLine::Other));
    assert_eq!(other(r#""X"="unterminated"#), Some(RegLine::Other));
    assert_eq!(other(r#""X"="a" trailing"#), Some(RegLine::Other));
    assert_eq!(value_line(r#"@="default""#), None);
    assert_eq!(value_line("25,00,00"), None);
}

/// The export must carry the version 5 header; UTF-16LE (BOM) and UTF-8 both decode.
#[test]
fn export_text_needs_the_header() {
    assert!(reg_text(&utf16(&format!("{HEADER}[X]"))).is_some());
    assert!(reg_text(format!("\u{feff}{HEADER}[X]").as_bytes()).is_some());
    assert!(reg_text(&utf16("REGEDIT4\r\n[X]")).is_none());
    assert!(reg_text(b"").is_none());
}

/// Spec §7.6: an HKCU location export with per-app subkeys (`…\location\<app>` sections with
/// their own `"Value"`) yields the parent key's value only; the section match ignores case.
#[test]
fn per_app_subkeys_yield_the_parent_value_only() {
    let text = format!(
        "{HEADER}[{HKCU_KEY}\\NonPackaged]\r\n\"Value\"=\"Deny\"\r\n\r\n\
         [{}]\r\n\"Value\"=\"Allow\"\r\n\"LastUsedTimeStart\"=hex(b):00,01\r\n\r\n\
         [{HKCU_KEY}\\Microsoft.WindowsMaps_8wekyb3d8bbwe]\r\n\"Value\"=\"Deny\"\r\n",
        HKCU_KEY.to_uppercase()
    );
    let text = reg_text(&utf16(&text)).unwrap();
    let values = section_values(&text, HKCU_KEY).unwrap();
    assert_eq!(values.get("value"), Some(&RegLine::Sz("Allow".into())));
    assert_eq!(values.len(), 2);
    assert!(section_values(&text, HKLM_KEY).is_none());
}

fn location_manifest(
    dir: &Path,
    hkcu: Option<&Path>,
    hklm: Option<&Path>,
    existed: (bool, bool),
) -> PathBuf {
    fs::create_dir_all(dir).unwrap();
    let path = dir.join("latest-location-backup.json");
    let doc = serde_json::json!({
        "schemaVersion": 0,
        "hkcuBackup": hkcu,
        "hkcuKeyExisted": existed.0,
        "hklmBackup": hklm,
        "hklmKeyExisted": existed.1,
        "createdAt": 1,
    });
    fs::write(&path, doc.to_string()).unwrap();
    path
}

fn location_targets() -> [Target; 3] {
    let policy = |name: &str| reg(RegHive::Hklm, POLICY_KEY, name);
    [
        reg(CONSENT.0, CONSENT.1, CONSENT.2),
        policy("DisableLocation"),
        policy("DisableWindowsLocationProvider"),
    ]
}

/// Our values, as the old app left them.
fn location_applied() -> Fake {
    let fake = Fake::default();
    let [consent, disable, provider] = location_targets();
    fake.set(&consent, Val::Sz("Deny".into()));
    fake.set(&disable, Val::Dword(1));
    fake.set(&provider, Val::Dword(1));
    fake
}

fn sources(browser: Option<PathBuf>, location: Option<PathBuf>) -> LegacySources {
    LegacySources {
        browser_manifest: browser,
        location_manifest: location,
    }
}

/// Spec §7.6 security: an export with extra sections and extra values contributes only the
/// three allowed values; the rollback then restores exactly the old baselines.
#[test]
fn location_exports_contribute_only_our_three_values() {
    let tmp = TempDir::new("hardening");
    let backups = tmp.0.join("privacy-backups");
    let (hkcu, hklm) = (backups.join("hkcu.reg"), backups.join("hklm.reg"));
    let ifeo = r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe";
    write_reg(
        &hkcu,
        &format!(
            "[{HKCU_KEY}]\r\n\"Value\"=\"Allow\"\r\n\r\n[{ifeo}]\r\n\"Debugger\"=\"evil.exe\"\r\n"
        ),
    );
    write_reg(
        &hklm,
        &format!("[{HKLM_KEY}]\r\n\"DisableLocation\"=dword:00000000\r\n\"Evil\"=\"x\"\r\n"),
    );
    let manifest = location_manifest(&backups, Some(&hkcu), Some(&hklm), (true, true));
    let fake = Arc::new(location_applied());
    let journal = Arc::new(Journal::open(&tmp.0, admit));
    let src = sources(None, Some(manifest));
    let report = import(&journal, &tmp.0, &*fake, &src);
    assert_eq!(report.adopted, 3);
    assert!(report.notices.is_empty());
    let records = journal.records(Feature::LocationPrivacy);
    let baselines: Vec<Val> = records.iter().map(|r| r.baseline.clone()).collect();
    let want = [Val::Sz("Allow".into()), Val::Dword(0), Val::Absent];
    assert_eq!(baselines, want);
    assert!(records.iter().all(|r| !r.created));

    let location = Location::new(journal.clone(), fake.clone());
    assert!(location.rollback_blocking().is_complete());
    for (target, want) in location_targets().iter().zip(want) {
        assert_eq!(fake.get(target), want);
    }
    assert_eq!(fake.write_count(), 3);
}

/// Spec §7.6 security: an export outside the backup folder is ignored (that value becomes a
/// leftover notice); a key that did not exist gives `Absent` baselines without any export; a
/// value that no longer holds ours is not adopted.
#[test]
fn location_export_outside_its_folder_is_ignored() {
    let tmp = TempDir::new("hardening");
    let backups = tmp.0.join("privacy-backups");
    let outside = tmp.0.join("elsewhere").join("hkcu.reg");
    write_reg(
        &outside,
        &format!("[{HKCU_KEY}]\r\n\"Value\"=\"Allow\"\r\n"),
    );
    let manifest = location_manifest(&backups, Some(&outside), None, (true, false));
    let fake = Arc::new(location_applied());
    let [_, _, provider] = location_targets();
    fake.set(&provider, Val::Dword(0));
    let journal = Arc::new(Journal::open(&tmp.0, admit));
    let report = import(&journal, &tmp.0, &*fake, &sources(None, Some(manifest)));
    assert_eq!(report.adopted, 1);
    let leftover = Msg::new("automation.hardening.legacy.locationLeftover");
    assert_eq!(report.notices, vec![leftover]);
    let records = journal.records(Feature::LocationPrivacy);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].target, location_targets()[1]);
    assert_eq!(records[0].baseline, Val::Absent);
    assert!(records[0].created);
}

/// The import runs once per data dir; old files are never changed.
#[test]
fn import_runs_once_and_leaves_old_files_alone() {
    let tmp = TempDir::new("hardening");
    let backups = tmp.0.join("privacy-backups");
    let manifest = location_manifest(&backups, None, None, (false, false));
    let before = fs::read(&manifest).unwrap();
    let fake = Arc::new(location_applied());
    let journal = Arc::new(Journal::open(&tmp.0, admit));
    let src = sources(None, Some(manifest.clone()));
    assert_eq!(import(&journal, &tmp.0, &*fake, &src).adopted, 3);
    assert!(tmp.0.join("hardening.json").is_file());
    Location::new(journal.clone(), fake.clone()).rollback_blocking();
    // The user later denies location himself: a second start must not adopt that.
    let [consent, _, _] = location_targets();
    fake.set(&consent, Val::Sz("Deny".into()));
    assert_eq!(
        import(&journal, &tmp.0, &*fake, &src),
        LegacyReport::default()
    );
    assert!(journal.records(Feature::LocationPrivacy).is_empty());
    assert_eq!(fs::read(&manifest).unwrap(), before);
}

/// No manifest (the dev machine: exports without a manifest): nothing adopted, no notice.
#[test]
fn missing_manifests_adopt_nothing() {
    let tmp = TempDir::new("hardening");
    let fake = Fake::default();
    let journal = Journal::open(&tmp.0, admit);
    let src = sources(
        Some(tmp.0.join("none.json")),
        Some(tmp.0.join("none2.json")),
    );
    assert_eq!(
        import(&journal, &tmp.0, &fake, &src),
        LegacyReport::default()
    );
    assert!(!journal.legacy_imported());
}

/// Spec §6.8 browser manifest: the exported value becomes the baseline, a key confirmed absent
/// gives `Absent`, `safeToModify: false` and unknown keys are skipped, a value that is no longer
/// ours is not adopted, old key spellings become the canonical one, and file backups are only
/// reported. The browser rollback then restores the old baselines.
#[test]
fn browser_manifest_becomes_journal_records() {
    let tmp = TempDir::new("hardening");
    let dir = tmp.0.join("browser-hardening");
    let export = dir.join("2026-01-01T00-00-00-000Z").join("chrome.reg");
    write_reg(
        &export,
        "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Google\\Chrome]\r\n\
         \"WebRtcIPHandlingPolicy\"=\"default\"\r\n\"Other\"=\"x\"\r\n",
    );
    let backup = |key: &str, path: Option<&Path>, safe: bool| serde_json::json!({ "key": key, "backupPath": path, "safeToModify": safe });
    let doc = serde_json::json!({
        "schemaVersion": 0,
        "createdAt": 1,
        "registryBackups": [
            backup(r"HKLM\Software\Policies\Google\Chrome", Some(&export), true),
            backup(r"HKCU\Software\Policies\Opera Software\Opera", None, true),
            backup(r"HKLM\Software\Policies\Vivaldi", None, false),
            backup(r"HKLM\Software\Policies\Microsoft\Edge", None, true),
            backup(r"HKLM\SOFTWARE\Evil", None, true),
        ],
        "fileBackups": [{ "path": r"C:\x\Preferences", "backupPath": null, "existed": false }],
    });
    let manifest = dir.join("latest-browser-hardening.json");
    fs::write(&manifest, doc.to_string()).unwrap();

    let ours = Val::Sz("disable_non_proxied_udp".into());
    let webrtc = |hive, key: &str| reg(hive, key, "WebRtcIPHandlingPolicy");
    let chrome = webrtc(RegHive::Hklm, r"SOFTWARE\Policies\Google\Chrome");
    let opera = webrtc(RegHive::Hkcu, r"SOFTWARE\Policies\Opera Software\Opera");
    let vivaldi = webrtc(RegHive::Hklm, r"SOFTWARE\Policies\Vivaldi");
    let edge = webrtc(RegHive::Hklm, r"SOFTWARE\Policies\Microsoft\Edge");
    let fake = Arc::new(Fake::default());
    for target in [&chrome, &opera, &vivaldi] {
        fake.set(target, ours.clone());
    }
    fake.set(&edge, Val::Sz("default".into()));
    let journal = Arc::new(Journal::open(&tmp.0, admit));
    let report = import(&journal, &tmp.0, &*fake, &sources(Some(manifest), None));
    assert_eq!(report.adopted, 2);
    let files = Msg::new("automation.hardening.legacy.browserFiles");
    assert_eq!(report.notices, vec![files]);
    let records = journal.records(Feature::BrowserWebRtc);
    let got: Vec<(Target, Val, bool)> = records
        .into_iter()
        .map(|r| (r.target, r.baseline, r.created))
        .collect();
    let want = vec![
        (chrome.clone(), Val::Sz("default".into()), false),
        (opera.clone(), Val::Absent, true),
    ];
    assert_eq!(got, want);

    let browsers = Browsers::new(journal.clone(), fake.clone(), BrowserDirs::default());
    assert!(browsers.rollback_blocking().unwrap().success);
    assert_eq!(fake.get(&chrome), Val::Sz("default".into()));
    assert_eq!(fake.get(&opera), Val::Absent);
    assert_eq!(fake.get(&vivaldi), ours);
    assert_eq!(fake.get(&edge), Val::Sz("default".into()));
}
