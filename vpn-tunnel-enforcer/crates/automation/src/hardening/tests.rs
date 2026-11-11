use std::sync::Arc;

use super::fake::reg;
use super::{admit, location};
use crate::test_support::TempDir;
use crate::tweaks::journal::{Feature, Journal, Record, RegHive, Val};

const CHROME: &str = r"SOFTWARE\Policies\Google\Chrome";

/// Spec §7.6 security (B1/L1): only our values, each with its type, on our keys.
#[test]
fn allow_list_admits_exactly_our_values() {
    let sz = |s: &str| Val::Sz(s.to_owned());
    // Browser policies: WebRTC on every old key and both hives, DoH only on verified HKLM keys.
    assert!(admit(
        RegHive::Hklm,
        CHROME,
        "WebRtcIPHandlingPolicy",
        &sz("default")
    ));
    assert!(admit(
        RegHive::Hklm,
        &CHROME.to_lowercase(),
        "webrtciphandlingpolicy",
        &Val::Absent
    ));
    assert!(admit(
        RegHive::Hkcu,
        r"Software\Policies\Opera Software\Opera",
        "WebRtcIPHandlingPolicy",
        &sz("x")
    ));
    assert!(admit(
        RegHive::Hklm,
        CHROME,
        "DnsOverHttpsMode",
        &sz("secure")
    ));
    assert!(!admit(
        RegHive::Hkcu,
        CHROME,
        "DnsOverHttpsMode",
        &sz("off")
    ));
    assert!(!admit(
        RegHive::Hklm,
        r"SOFTWARE\Policies\Chromium",
        "DnsOverHttpsMode",
        &sz("off")
    ));
    assert!(!admit(
        RegHive::Hklm,
        CHROME,
        "WebRtcIPHandlingPolicy",
        &Val::Dword(1)
    ));
    assert!(!admit(
        RegHive::Hklm,
        CHROME,
        "WebRtcIPHandlingPolicy",
        &Val::ExpandSz("x".into())
    ));
    assert!(!admit(
        RegHive::Hklm,
        CHROME,
        "WebRtcIPHandlingPolicy",
        &sz(&"x".repeat(300))
    ));
    assert!(!admit(
        RegHive::Hklm,
        CHROME,
        "WebRtcIPHandlingPolicy",
        &sz("a\r\nb")
    ));
    assert!(!admit(
        RegHive::Hklm,
        CHROME,
        "ExtensionInstallForcelist",
        &sz("x")
    ));
    assert!(!admit(
        RegHive::Hklm,
        &format!(r"{CHROME}\Sub"),
        "WebRtcIPHandlingPolicy",
        &sz("x")
    ));
    assert!(!admit(
        RegHive::Hklm,
        &format!(r"{CHROME}\"),
        "WebRtcIPHandlingPolicy",
        &sz("x")
    ));
    // Anything else in the machine, e.g. an IFEO debugger.
    let ifeo =
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe";
    assert!(!admit(RegHive::Hklm, ifeo, "Debugger", &sz(r"C:\evil.exe")));
    // Location: the consent as a string, the policies as DWORDs only.
    let (_, consent, value) = location::CONSENT;
    assert!(admit(RegHive::Hkcu, consent, value, &sz("Allow")));
    assert!(!admit(RegHive::Hklm, consent, value, &sz("Allow")));
    assert!(!admit(RegHive::Hkcu, consent, value, &Val::Dword(0)));
    assert!(admit(
        RegHive::Hklm,
        location::POLICY_KEY,
        "DisableLocation",
        &Val::Dword(7)
    ));
    assert!(admit(
        RegHive::Hklm,
        location::POLICY_KEY,
        "DisableWindowsLocationProvider",
        &Val::Absent
    ));
    assert!(!admit(
        RegHive::Hklm,
        location::POLICY_KEY,
        "DisableLocation",
        &sz("1")
    ));
    assert!(!admit(
        RegHive::Hkcu,
        location::POLICY_KEY,
        "DisableLocation",
        &Val::Dword(1)
    ));
    assert!(!admit(
        RegHive::Hklm,
        location::POLICY_KEY,
        "DisableSensors",
        &Val::Dword(1)
    ));
}

/// Every value the plans write, and its removal, passes the allow-list: a record outside it
/// would be dropped at the next start and its value would stay for good.
#[test]
fn every_planned_value_is_admitted() {
    use super::browser::{Browser, plan};
    let mut planned = location::plan();
    for browser in Browser::ALL {
        assert_eq!(browser.verified(), !plan(browser).is_empty(), "{browser:?}");
        planned.extend(plan(browser));
    }
    assert_eq!(planned.len(), 3 + 5 * 2);
    for (_, target, value) in &planned {
        assert!(super::admissible(target, value), "{target:?}");
        assert!(super::admissible(target, &Val::Absent), "{target:?}");
    }
}

/// Spec §7.6 security: doctored records in `tweaks.json` are dropped at load and never acted on;
/// admitted ones survive.
#[test]
fn doctored_journal_records_are_dropped_at_load() {
    let dir = TempDir::new("hardening");
    let record = |feature, target, baseline, applied| Record {
        feature,
        target,
        baseline,
        applied,
        created: false,
    };
    let ifeo =
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe";
    let records = vec![
        record(
            Feature::BrowserWebRtc,
            reg(RegHive::Hklm, ifeo, "Debugger"),
            Val::Sz(r"C:\evil.exe".into()),
            Val::Absent,
        ),
        record(
            Feature::LocationPrivacy,
            reg(RegHive::Hklm, location::POLICY_KEY, "DisableLocation"),
            Val::Sz("1".into()),
            Val::Dword(1),
        ),
        record(
            Feature::LocationPrivacy,
            reg(RegHive::Hklm, location::POLICY_KEY, "DisableLocation"),
            Val::Absent,
            Val::Dword(1),
        ),
    ];
    let doc = serde_json::json!({ "schemaVersion": 1, "records": records });
    std::fs::write(dir.0.join("tweaks.json"), doc.to_string()).unwrap();
    let journal = Arc::new(Journal::open(&dir.0, admit));
    assert!(journal.records(Feature::BrowserWebRtc).is_empty());
    let kept = journal.records(Feature::LocationPrivacy);
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].baseline, Val::Absent);
    // The file itself no longer holds the dropped records either.
    let text = std::fs::read_to_string(dir.0.join("tweaks.json")).unwrap();
    assert!(!text.contains("Image File Execution Options"));
}
