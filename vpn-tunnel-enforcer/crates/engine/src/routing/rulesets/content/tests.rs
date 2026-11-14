//! Content bounds (psmart-b3, fixlists-b1/b5, lab F-10) on small decompiled sets, and on the
//! bundled files through the engine (skipped quietly where it is missing).
use super::*;
use crate::routing::smart_ru::RULE_SETS;
use crate::test_support::{resources, singbox_exe};

/// A /10 and a /29: a tenth of the IPv4 copy is 419 430 addresses.
const RELEASE_IPS: &str = r#"{"version":1,"rules":[{"ip_cidr":["95.0.0.0/10","2a02:6b8::/29"]}]}"#;
const RELEASE_NAMES: &str =
    r#"{"version":1,"rules":[{"domain_suffix":["gosuslugi.ru",".psk","emias.info"]}]}"#;

fn ips(cidrs: &[&str]) -> String {
    serde_json::json!({"version": 1, "rules": [{"ip_cidr": cidrs}]}).to_string()
}

fn sites(names: &[&str]) -> String {
    serde_json::json!({"version": 1, "rules": [{"domain_suffix": names}]}).to_string()
}

fn v4(nets: &[&str]) -> Ranges {
    Space::of(&nets.iter().filter_map(|n| cidr(n)).collect::<Vec<_>>()).v4
}

#[test]
fn a_file_stays_within_four_times_the_release_size() {
    assert!(size_ok(100, 100) && size_ok(25, 100) && size_ok(400, 100));
    assert!(!size_ok(24, 100) && !size_ok(401, 100) && !size_ok(0, 100));
}

/// Address space counts every address once, whatever the overlaps.
#[test]
fn address_space_is_counted_exactly() {
    let copy = v4(&["10.0.0.0/24", "10.0.1.0/24", "10.0.0.128/25"]);
    assert_eq!(copy.size(), 512.0);
    assert_eq!(v4(&["10.0.0.0/23"]).minus(&copy).size(), 0.0);
    assert_eq!(v4(&["10.0.0.0/22"]).minus(&copy), v4(&["10.0.2.0/23"]));
    assert_eq!(
        v4(&["10.0.0.0/22"]).minus(&v4(&["10.0.1.0/24"])),
        v4(&["10.0.0.0/24", "10.0.2.0/23"])
    );
    assert_eq!(v4(&["0.0.0.0/0"]).minus(&v4(&["0.0.0.0/0"])).size(), 0.0);
    assert!(v4(&["10.0.0.0/8"]).overlaps(&v4(&["10.200.0.1"])));
    assert!(!v4(&["10.0.0.0/8"]).overlaps(&v4(&["11.0.0.0/8", "9.0.0.0/8"])));
    let all = Space::of(&[cidr("::/0").expect("a network")]).v6;
    assert_eq!(all.size(), 2f64.powi(128));
}

/// fixlists-b1: the direct address set may add a little to the copy, never a foreign
/// provider's network (a crafted set pulling Cloudflare or Google out of the tunnel), and
/// stays plain.
#[test]
fn the_direct_address_set_adds_little_and_nothing_foreign() {
    let ok = [
        "95.0.0.0/11",
        "95.32.0.0/11",
        "77.88.0.0/18",
        "5.255.192.0/18",
    ];
    assert_eq!(address_bounds(&ips(&ok), RELEASE_IPS), Ok(()));
    assert_eq!(address_bounds(RELEASE_IPS, RELEASE_IPS), Ok(()));
    for (bad, why) in [
        ("0.0.0.0/0", OutOfBounds::Coverage),
        ("64.0.0.0/2", OutOfBounds::Coverage),
        ("::/0", OutOfBounds::Coverage),
        ("172.64.0.0/13", OutOfBounds::Coverage),
        ("74.125.0.0/16", OutOfBounds::Foreign("74.125.0.0/16")),
        ("173.194.0.0/16", OutOfBounds::Foreign("173.194.0.0/16")),
        ("104.16.0.0/16", OutOfBounds::Foreign("104.16.0.0/13")),
        ("8.8.8.8", OutOfBounds::Foreign("8.8.8.0/24")),
        ("2a00:1450::/40", OutOfBounds::Foreign("2a00:1450::/32")),
        ("77.88.0.0/33", OutOfBounds::Shape),
        ("not-an-address", OutOfBounds::Shape),
    ] {
        let set = ips(&["95.0.0.0/10", bad]);
        assert_eq!(address_bounds(&set, RELEASE_IPS), Err(why), "{bad}");
    }
    for shape in [
        r#"{"rules":[{"ip_cidr":["95.0.0.0/10"],"invert":true}]}"#,
        r#"{"rules":[{"type":"logical","mode":"or","rules":[{"ip_cidr":["95.0.0.0/10"]}]}]}"#,
        r#"{"rules":[{"ip_cidr":["95.0.0.0/10"],"domain":["x.ru"]}]}"#,
        r#"{"version":1}"#,
        "<html>",
    ] {
        let got = address_bounds(shape, RELEASE_IPS);
        assert_eq!(got, Err(OutOfBounds::Shape), "{shape}");
    }
}

/// Lab F-10: upstream's gov list names regional sites outside the Russian zones; the copy's
/// own names pass whatever their zone, a few new ones pass (logged), many do not, and never a
/// zone or a well-known foreign service (fixlists-b1 for names).
#[test]
fn the_gov_list_takes_a_few_new_foreign_names() {
    let ok = sites(&[
        "gosuslugi.ru",
        "new.gov.ru",
        "krasnodar.su",
        "xn--80a.xn--p1ai",
        ".psk",
        "emias.info",
        "edu22.info",
        "netschool.website",
        "volganet.net",
    ]);
    assert_eq!(name_bounds(&ok, RELEASE_NAMES), Ok(()));
    assert_eq!(name_bounds(RELEASE_NAMES, RELEASE_NAMES), Ok(()));
    let many: Vec<String> = (0..9).map(|i| format!("school{i}.info")).collect();
    let many: Vec<&str> = many.iter().map(String::as_str).collect();
    let got = name_bounds(&sites(&many), RELEASE_NAMES);
    assert_eq!(got, Err(OutOfBounds::ForeignNames(9)));
    for bad in [
        "google.com",
        "youtube.com",
        "rr1.googlevideo.com",
        "googleapis.com",
        "me",
        "ru",
        ".su",
        "com",
    ] {
        let set = sites(&["gosuslugi.ru", bad]);
        let want = bad.trim_start_matches('.').to_owned();
        let got = name_bounds(&set, RELEASE_NAMES);
        assert_eq!(got, Err(OutOfBounds::Zone(want)), "{bad}");
    }
    for shape in [
        r#"{"rules":[{"domain_keyword":["gov"]}]}"#,
        r#"{"rules":[{"domain_suffix":["gosuslugi.ru"],"invert":true}]}"#,
        r#"{"rules":[{"domain_regex":[".*"]}]}"#,
    ] {
        let got = name_bounds(shape, RELEASE_NAMES);
        assert_eq!(got, Err(OutOfBounds::Shape), "{shape}");
    }
}

/// fixlists-b5: a blocked set keeps at least half of the copy (a shrunk one would send
/// blocked Russian sites to the ISP's resolver); its shape is not judged (VPN side).
#[test]
fn a_blocked_set_keeps_most_of_the_copy() {
    let copy = sites(&["tvrain.ru", "echo.msk.ru", "rutracker.org", "linkedin.com"]);
    let half = r#"{"rules":[{"domain_suffix":["rutracker.org","linkedin.com","new.org"]},
        {"domain_regex":["^x"]}]}"#;
    assert_eq!(kept_names(half, &copy), Ok(()));
    let shrunk = sites(&["rutracker.org", "a.org", "b.org", "c.org"]);
    assert_eq!(kept_names(&shrunk, &copy), Err(OutOfBounds::Shrunk));
    let copy = ips(&["91.108.4.0/22", "149.154.160.0/20"]);
    assert_eq!(kept_space(&ips(&["149.154.160.0/20"]), &copy), Ok(()));
    let shrunk = ips(&["91.108.4.0/22", "8.8.8.0/24"]);
    assert_eq!(kept_space(&shrunk, &copy), Err(OutOfBounds::Shrunk));
}

/// The release's own files pass their bounds against themselves; a missing reference judges
/// nothing.
#[tokio::test]
async fn the_bundled_files_pass() {
    let Some(exe) = singbox_exe() else { return };
    let dir = resources();
    for (tag, file, _) in RULE_SETS {
        let got = check(&exe, &dir.join(file), tag, &dir).await;
        assert_eq!(got, Some(true), "{file}");
    }
    let missing = dir.join("no-such-reference");
    let geoip = dir.join("geoip-ru.srs");
    assert_eq!(check(&exe, &geoip, GEOIP_RU, &missing).await, None);
}

/// fixlists-a6: an engine that cannot decompile a file the canaries just passed judges
/// nothing; it never calls the file invalid.
#[tokio::test]
async fn an_engine_fault_is_not_an_invalid_file() {
    let dir = resources();
    let gone = dir.join("no-such-engine.exe");
    for (tag, file, _) in RULE_SETS {
        let path = dir.join(file);
        if path.is_file() {
            assert_eq!(check(&gone, &path, tag, &dir).await, None, "{file}");
        }
    }
}

/// Lab F-10 on the real list: the bundled gov list plus upstream's additions of 14.11.2026
/// passes against the bundled copy.
#[tokio::test]
async fn upstream_gov_additions_pass() {
    let Some(exe) = singbox_exe() else { return };
    let copy = decompile(&exe, &resources().join("geosite-category-gov-ru.srs"))
        .await
        .expect("the bundled gov list decompiles");
    let mut json: Value = serde_json::from_str(&copy).expect("json");
    let added = [
        "edu22.info",
        "netschool.website",
        "volganet.net",
        "cap.ru",
        "yanao.ru",
    ];
    json["rules"]
        .as_array_mut()
        .expect("rules")
        .push(serde_json::json!({ "domain_suffix": added }));
    assert_eq!(name_bounds(&json.to_string(), &copy), Ok(()));
}
