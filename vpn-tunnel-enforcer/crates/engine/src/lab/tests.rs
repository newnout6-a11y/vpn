use super::*;
use crate::test_support::{TempDir, awg_profile};

const AWG_2: &str = "Jc = 4\nJmin = 40\nJmax = 70\nS1 = 30\nS2 = 40\nH1 = 100-200\nH2 = 300-400\nH3 = 500-600\nH4 = 700-800";

fn write_record(dir: &TempDir, body: &str) {
    let path = record_path(dir.path());
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, body).unwrap();
}

fn record(passed: &[&str], version: &str) -> String {
    serde_json::json!({ "version": version, "passed": passed, "by": "lab" }).to_string()
}

/// AT-12-002: the record must exist, parse, name every required criterion and this version.
#[test]
fn the_record_opens_the_gate_only_when_complete() {
    let dir = TempDir::new("lab-record");
    assert_eq!(load(dir.path()), Err(LabGap::Missing));
    write_record(&dir, "{ not json");
    assert_eq!(load(dir.path()), Err(LabGap::Unreadable));
    write_record(&dir, &record(&REQUIRED[..4], VERSION));
    assert_eq!(load(dir.path()), Err(LabGap::Incomplete));
    write_record(&dir, &record(&REQUIRED, "1.9.9"));
    assert_eq!(load(dir.path()), Err(LabGap::OtherVersion));
    let lower: Vec<String> = REQUIRED.iter().map(|id| id.to_lowercase()).collect();
    let lower: Vec<&str> = lower.iter().map(String::as_str).collect();
    write_record(&dir, &record(&lower, VERSION));
    let ok = load(dir.path()).expect("complete record");
    assert_eq!(ok.by, "lab");
    for gap in [
        LabGap::Missing,
        LabGap::Unreadable,
        LabGap::Incomplete,
        LabGap::OtherVersion,
    ] {
        crate::test_locales::assert_localized(&gap.msg().key);
    }
}

/// AT-12-002 / AT-12-003: AmneziaWG goes to mihomo only through an open gate; a closed gate is
/// a refusal that names the gap, never a start on another engine.
#[test]
fn amneziawg_selects_mihomo_through_the_gate() {
    let awg = awg_profile(AWG_2, "203.0.113.7:51820");
    for pref in [EnginePref::Auto, EnginePref::Mihomo] {
        assert_eq!(
            select(&awg, pref, Ok(())),
            Some(Decision::Selected {
                engine: Engine::Mihomo,
                reason: SelectReason::Amneziawg,
            })
        );
        assert_eq!(
            select(&awg, pref, Err(LabGap::Incomplete)),
            Some(Decision::Rejected(Reject::Lab(LabGap::Incomplete)))
        );
    }
    // Forced sing-box / Xray: the bundled table refuses it as before.
    for pref in [EnginePref::SingBox, EnginePref::Xray] {
        assert_eq!(select(&awg, pref, Ok(())), None);
        assert_eq!(
            crate::xray_config::select_engine(&awg, pref),
            Decision::Rejected(Reject::Amneziawg)
        );
    }
    crate::test_locales::assert_localized(&SelectReason::Amneziawg.msg().key);
}

/// A forced mihomo runs AmneziaWG only; other profiles keep the bundled table under the rest.
#[test]
fn forced_mihomo_refuses_other_protocols() {
    let vless = vpnte_profiles::uri::parse_uri(
        "vless://11111111-2222-3333-4444-555555555555@203.0.113.9:443?security=tls&sni=example.com#v",
    )
    .expect("a vless link");
    assert_eq!(
        select(&vless, EnginePref::Mihomo, Ok(())),
        Some(Decision::Rejected(Reject::MihomoAwgOnly))
    );
    assert_eq!(
        crate::xray_config::select_engine(&vless, EnginePref::Mihomo),
        Decision::Rejected(Reject::MihomoAwgOnly)
    );
    assert_eq!(select(&vless, EnginePref::Auto, Ok(())), None);
    crate::test_locales::assert_localized(&Reject::MihomoAwgOnly.msg().key);
}
