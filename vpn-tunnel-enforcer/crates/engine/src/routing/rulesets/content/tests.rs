//! Content bounds (psmart-b3) on small decompiled sets, and on the bundled files through the
//! engine (skipped quietly where it is missing).
use super::*;
use crate::routing::smart_ru::RULE_SETS;
use crate::test_support::{resources, singbox_exe};

const RELEASE_IPS: &str =
    r#"{"version":1,"rules":[{"ip_cidr":["77.88.0.0/18","5.255.192.0/18","2a02:6b8::/29"]}]}"#;
const RELEASE_NAMES: &str =
    r#"{"version":1,"rules":[{"domain_suffix":["gosuslugi.ru",".psk","emias.info"]}]}"#;

fn ips(cidrs: &[&str]) -> String {
    serde_json::json!({"version": 1, "rules": [{"ip_cidr": cidrs}]}).to_string()
}

fn sites(names: &[&str]) -> String {
    serde_json::json!({"version": 1, "rules": [{"domain_suffix": names}]}).to_string()
}

#[test]
fn a_file_stays_within_four_times_the_release_size() {
    assert!(size_ok(100, 100) && size_ok(25, 100) && size_ok(400, 100));
    assert!(!size_ok(24, 100) && !size_ok(401, 100) && !size_ok(0, 100));
}

/// The direct address set: no default route, no prefix shorter than /8 or /16, at most twice
/// the release's space, no well-known foreign address, plain rules only.
#[test]
fn the_direct_address_set_is_bounded() {
    let ok = [
        "77.88.0.0/18",
        "5.255.192.0/18",
        "2a02:6b8::/29",
        "95.108.128.0/17",
    ];
    assert_eq!(address_bounds(&ips(&ok), RELEASE_IPS), Ok(()));
    for (bad, why) in [
        ("0.0.0.0/0", OutOfBounds::Prefix("0.0.0.0/0".into())),
        ("64.0.0.0/2", OutOfBounds::Prefix("64.0.0.0/2".into())),
        ("::/0", OutOfBounds::Prefix("::/0".into())),
        ("2a00::/15", OutOfBounds::Prefix("2a00::/15".into())),
        ("8.8.8.0/24", OutOfBounds::Foreign("8.8.8.8")),
        (
            "2606:4700:4700::1111",
            OutOfBounds::Foreign("2606:4700:4700::1111"),
        ),
        ("31.0.0.0/16", OutOfBounds::Coverage),
        ("2a03::/27", OutOfBounds::Coverage),
        ("77.88.0.0/33", OutOfBounds::Shape),
        ("not-an-address", OutOfBounds::Shape),
    ] {
        let set = ips(&["77.88.0.0/18", bad]);
        assert_eq!(address_bounds(&set, RELEASE_IPS), Err(why), "{bad}");
    }
    for shape in [
        r#"{"rules":[{"ip_cidr":["77.88.0.0/18"],"invert":true}]}"#,
        r#"{"rules":[{"type":"logical","mode":"or","rules":[{"ip_cidr":["77.88.0.0/18"]}]}]}"#,
        r#"{"rules":[{"ip_cidr":["77.88.0.0/18"],"domain":["x.ru"]}]}"#,
        r#"{"version":1}"#,
        "<html>",
    ] {
        assert_eq!(
            address_bounds(shape, RELEASE_IPS),
            Err(OutOfBounds::Shape),
            "{shape}"
        );
    }
}

/// The gov list: sites under .ru, .su and .рф, or names the release's copy holds; never a
/// whole zone, never a foreign site.
#[test]
fn the_gov_list_names_russian_sites_only() {
    let ok = sites(&[
        "gosuslugi.ru",
        "new.gov.ru",
        "krasnodar.su",
        "xn--80a.xn--p1ai",
        ".psk",
    ]);
    assert_eq!(name_bounds(&ok, RELEASE_NAMES), Ok(()));
    assert_eq!(name_bounds(RELEASE_NAMES, RELEASE_NAMES), Ok(()));
    for bad in [
        "google.com",
        "youtube.com",
        "ru",
        ".su",
        "other.info",
        "ru.evil.com",
    ] {
        let set = sites(&["gosuslugi.ru", bad]);
        let want = bad.trim_start_matches('.').to_owned();
        assert_eq!(
            name_bounds(&set, RELEASE_NAMES),
            Err(OutOfBounds::Zone(want)),
            "{bad}"
        );
    }
    for shape in [
        r#"{"rules":[{"domain_keyword":["gov"]}]}"#,
        r#"{"rules":[{"domain_suffix":["gosuslugi.ru"],"invert":true}]}"#,
        r#"{"rules":[{"domain_regex":[".*"]}]}"#,
    ] {
        assert_eq!(
            name_bounds(shape, RELEASE_NAMES),
            Err(OutOfBounds::Shape),
            "{shape}"
        );
    }
}

/// The release's own files pass their bounds against themselves.
#[tokio::test]
async fn the_bundled_files_pass() {
    let Some(exe) = singbox_exe() else { return };
    let dir = resources();
    for (tag, file, _) in RULE_SETS {
        assert_eq!(
            check(&exe, &dir.join(file), tag, &dir).await,
            Some(true),
            "{file}"
        );
    }
    let missing = dir.join("no-such-reference");
    let geoip = dir.join("geoip-ru.srs");
    assert_eq!(check(&exe, &geoip, GEOIP_RU, &missing).await, None);
}
