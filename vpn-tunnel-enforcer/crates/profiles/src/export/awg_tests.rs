//! WireGuard / AmneziaWG exports: `.conf` and mihomo round trips keep every parameter, and the
//! share of an AmneziaWG key is its `.conf`. Synthetic configs with fake keys.
use super::*;
use crate::model::{AwgGeneration, Profile};
use crate::{clash, wg_ini};

const PRIV: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
const PUB: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";
const PSK: &str = "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=";
const HPK: &str = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=";

fn conf(interface: &[&str], peer: &[&str]) -> Profile {
    let text = format!(
        "[Interface]\nPrivateKey = {PRIV}\nAddress = 10.8.1.2/32, fd00::2/128\nDNS = 1.1.1.1, 2606:4700:4700::1111\nMTU = 1376\n{}\n[Peer]\nPublicKey = {PUB}\nPresharedKey = {PSK}\nEndpoint = [2001:db8::7]:51820\n{}\n",
        interface.join("\n"),
        peer.join("\n")
    );
    wg_ini::parse_wg_ini(&text)
        .expect("a .conf")
        .expect("valid")
}

fn v1_5() -> Profile {
    conf(
        &[
            "Jc = 4",
            "Jmin = 40",
            "Jmax = 70",
            "S1 = 15",
            "S2 = 18",
            "S3 = 20",
            "H1 = 1020325451",
            "H2 = 3288052141",
            "H3 = 2528465083",
            "H4 = 1766607858",
            "I1 = <b 0xf6ab3267fa><c><b 0xf6ab><t><r 10>",
            "J1 = <b 0xffffffff><c><b 0xf6ab><t><r 10>",
            "J3 = <t><b 0xf6ab><c><r 10>",
            "Itime = 60",
        ],
        &["AllowedIPs = 0.0.0.0/0, ::/0", "PersistentKeepalive = 25"],
    )
}

fn v2_0() -> Profile {
    conf(
        &[
            "Jc = 5",
            "Jmin = 500",
            "Jmax = 501",
            "S1 = 30",
            "S2 = 40",
            "S3 = 50",
            "S4 = 8",
            "H1 = 100000-200000",
            "H2 = 300000-400000",
            "H3 = 500000-600000",
            "H4 = 700000",
            "I1 = <r 2><b 0x8580000100010000>",
            "I2 = <b 0xf6ab3267fa><rc 10><rd 5>",
        ],
        &["AllowedIPs = 0.0.0.0/0", "Reserved = 1, 22, 33"],
    )
}

fn v3_1(keepalive: &str) -> Profile {
    conf(
        &[
            "Jc = 5",
            "Jmin = 10",
            "Jmax = 50",
            "S1 = 12",
            "S2 = 12",
            "S3 = 12",
            "S4 = 12",
            "H1 = 1",
            "H2 = 2",
            "H3 = 3",
            "H4 = 4",
            "I1 = <r 2><b 0x8580><t>",
            &format!("HeaderProtectionKey = {HPK}"),
            "ContentPaddingAddition = 10-100",
            "RekeyAfterTime = 100-120",
            "RekeyTimeout = 3-7",
            "RejectAfterTime = 150-180",
            "KeepaliveTimeout = 5-15",
            "MaxHandshakeAttempts = 15-20",
            "RandomTrailers = on",
            "DisableCookies = off",
        ],
        &["AllowedIPs = 0.0.0.0/0, ::/0", keepalive],
    )
}

/// `.conf` round trip: the exported file reads back as the very same profile, every AmneziaWG
/// parameter and the keepalive range included, for each generation and for plain WireGuard.
#[test]
fn conf_round_trip_keeps_everything() {
    let plain = conf(
        &[],
        &["AllowedIPs = 10.8.1.0/24", "PersistentKeepalive = 25"],
    );
    for p in [
        v1_5(),
        v2_0(),
        v3_1("PersistentKeepalive = 25-35"),
        v3_1(""),
        plain,
    ] {
        let text = export_conf(&p).expect("a .conf");
        let again = wg_ini::parse_wg_ini(&text)
            .expect("a .conf")
            .expect("valid");
        assert_eq!(again, p, "{text}");
    }
    let generations: Vec<_> = [v1_5(), v2_0(), v3_1("")]
        .iter()
        .map(|p| match &p.kind {
            Kind::Amneziawg { awg, .. } => awg.generation,
            _ => panic!(),
        })
        .collect();
    assert_eq!(
        generations,
        [AwgGeneration::V1_5, AwgGeneration::V2_0, AwgGeneration::V3]
    );
    let text = export_conf(&v3_1("PersistentKeepalive = 25-35")).expect("a .conf");
    assert!(text.contains("\nHeaderProtectionKey = AwMD"), "{text}");
    assert!(
        text.contains("\nRandomTrailers = on\nDisableCookies = off\n"),
        "{text}"
    );
    assert!(text.contains("\nEndpoint = [2001:db8::7]:51820\nPersistentKeepalive = 25-35\n"));
}

/// mihomo round trip: the exported entry reads back as the same profile. mihomo has no
/// keepalive range, so a 3.x range comes back as its lower bound (and only that changes).
#[test]
fn mihomo_round_trip_keeps_everything() {
    for p in [v1_5(), v2_0(), v3_1("PersistentKeepalive = 25")] {
        let yaml = export_mihomo(&p).expect("a mihomo entry");
        let report = clash::parse_clash(&yaml).expect("a Clash document");
        assert!(report.skipped.is_empty(), "{:?}\n{yaml}", report.skipped);
        let again = &report.profiles[0];
        assert_eq!((&again.kind, &again.name), (&p.kind, &p.name), "{yaml}");
        assert!(again.notes.is_empty(), "{:?}\n{yaml}", again.notes);
    }
    let ranged = v3_1("PersistentKeepalive = 25-35");
    let yaml = export_mihomo(&ranged).expect("a mihomo entry");
    assert!(yaml.contains("\n    persistent-keepalive: 25\n"), "{yaml}");
    assert!(
        yaml.contains("\n      version: 3\n") && yaml.contains("\n      h1: 1\n"),
        "{yaml}"
    );
    let again = clash::parse_clash(&yaml).expect("Clash").profiles.remove(0);
    let (Kind::Amneziawg { wg, awg }, Kind::Amneziawg { awg: before, .. }) =
        (&again.kind, &ranged.kind)
    else {
        panic!()
    };
    assert_eq!(
        (wg.peers[0].keepalive_s, awg.keepalive_range),
        (Some(25), None)
    );
    let mut before = before.as_ref().clone();
    before.keepalive_range = None;
    assert_eq!(awg.as_ref(), &before);
}

/// An AmneziaWG key is shared as its `.conf` (no link, no engine JSON); mihomo cannot take two
/// addresses of one family.
#[test]
fn shares_and_limits() {
    let p = v2_0();
    assert_eq!(export_uri(&p), None);
    let shared = export_share(&p).expect("shared");
    assert_eq!(shared.text(), export_conf(&p).expect("a .conf"));
    let notice = shared.notice().expect("a notice").key;
    assert_eq!(notice, "profiles.export.sharedAsConf");
    crate::test_locales::assert_localized(&notice);
    assert_eq!(format!("{shared:?}"), "Conf(<hidden>)");
    let mut two = p.clone();
    if let Some(wg) = two.kind.wireguard_mut() {
        wg.local_address.push("10.9.0.2/32".parse().expect("net"));
    }
    assert_eq!(export_mihomo(&two), None);
    assert!(export_conf(&two).is_some());
    let mut dial = p;
    dial.dial.udp_fragment = Some(true);
    assert_eq!((export_conf(&dial), export_mihomo(&dial)), (None, None));
}
