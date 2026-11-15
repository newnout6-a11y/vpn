//! AmneziaWG parameter checks: every bound, the consistency rules and the generations
//! (AT-12-003 step 1: invalid parameters are refused before any start, every field named).
use super::*;
use crate::model::{Awg, AwgGeneration, AwgRange};

use AwgField::*;
use AwgGeneration::{V1_0, V1_5, V2_0, V3};

/// A fake 32-byte key (mihomo's documentation example).
const HPK: &str = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
/// AmneziaVPN's default first signature packet (a DNS answer).
const DNS_I1: &str = "<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>";

fn read(pairs: &[(&str, &str)]) -> Result<Option<Awg>, AwgInvalid> {
    let mut reader = AwgReader::default();
    for (key, value) in pairs {
        if *key == "version" {
            reader.version(value);
        } else {
            assert!(reader.take(key, value), "{key} is an AmneziaWG key");
        }
    }
    reader.finish()
}

fn awg(pairs: &[(&str, &str)]) -> Awg {
    read(pairs).expect("valid").expect("AmneziaWG")
}

fn invalid(pairs: &[(&str, &str)]) -> Vec<AwgField> {
    read(pairs).expect_err("invalid").fields
}

const V1_0_CONF: &[(&str, &str)] = &[
    ("Jc", "4"),
    ("Jmin", "40"),
    ("Jmax", "70"),
    ("S1", "15"),
    ("S2", "18"),
    ("H1", "1020325451"),
    ("H2", "3288052141"),
    ("H3", "2528465083"),
    ("H4", "1766607858"),
];

const V3_1_CONF: &[(&str, &str)] = &[
    ("Jc", "5"),
    ("Jmin", "10"),
    ("Jmax", "50"),
    ("S1", "12"),
    ("S2", "12"),
    ("S3", "12"),
    ("S4", "12"),
    ("H1", "1"),
    ("H2", "2"),
    ("H3", "3"),
    ("H4", "4"),
    ("I1", DNS_I1),
    ("HeaderProtectionKey", HPK),
    ("ContentPaddingAddition", "10-100"),
    ("RekeyAfterTime", "100-120"),
    ("RekeyTimeout", "3-7"),
    ("RejectAfterTime", "150-180"),
    ("KeepaliveTimeout", "5-15"),
    ("MaxHandshakeAttempts", "15-20"),
    ("RandomTrailers", "on"),
    ("DisableCookies", "on"),
];

/// AT-12-003: valid configs of every generation pass and carry their generation.
#[test]
fn valid_configs_of_each_generation() {
    let v1 = awg(V1_0_CONF);
    assert_eq!((v1.generation, v1.jc, v1.s[1]), (V1_0, Some(4), Some(18)));
    assert_eq!(v1.h[1], Some(AwgRange::single(3_288_052_141)));

    let mut v15 = V1_0_CONF.to_vec();
    v15.extend([
        ("I1", "<b 0xf6ab3267fa><c><b 0xf6ab><t><r 10>"),
        ("J1", "<b 0xffffffff><c><b 0xf6ab><t><r 10>"),
        ("J2", "<c><b 0xf6ab><t><wt 1000>"),
        ("Itime", "60"),
    ]);
    let v15 = awg(&v15);
    assert_eq!((v15.generation, v15.itime), (V1_5, Some(60)));

    let v2 = awg(&[
        ("Jc", "5"),
        ("Jmin", "500"),
        ("Jmax", "501"),
        ("S1", "30"),
        ("S2", "40"),
        ("S3", "50"),
        ("S4", "8"),
        ("H1", "100000-200000"),
        ("H2", "300000-400000"),
        ("H3", "500000-600000"),
        ("H4", "700000-800000"),
        ("I1", DNS_I1),
        ("I2", "<b 0xf6ab3267fa><r 100>"),
        ("I3", ""),
    ]);
    assert_eq!(v2.generation, V2_0);
    assert_eq!(v2.i[2], None, "a blank chain is absent");

    let v3 = awg(V3_1_CONF);
    assert_eq!(v3.generation, V3);
    assert_eq!(v3.timers[0], AwgRange::parse("100-120"));
    assert_eq!(
        (v3.random_trailers, v3.disable_cookies),
        (Some(true), Some(true))
    );
    assert_eq!(validate(&v3), Ok(()));
}

/// All mechanisms off (zero sizes, standard headers, switches off) is plain WireGuard.
#[test]
fn everything_off_is_plain_wireguard() {
    let plain = [
        ("Jc", "0"),
        ("Jmin", "40"),
        ("S1", "0"),
        ("H1", "1"),
        ("H2", "2"),
        ("H3", "0"),
        ("I1", " "),
        ("RandomTrailers", "off"),
    ];
    assert_eq!(read(&plain), Ok(None));
    assert_eq!(read(&[]), Ok(None));
}

/// AT-12-003: each bound refuses exactly its field; the value next to it passes.
#[test]
fn each_bound_names_its_field() {
    let with = |extra: &[(&'static str, &'static str)]| {
        let mut pairs = V1_0_CONF.to_vec();
        pairs.retain(|(k, _)| !extra.iter().any(|(e, _)| e == k));
        pairs.extend_from_slice(extra);
        read(&pairs)
    };
    let refused = |extra: &[(&'static str, &'static str)]| with(extra).expect_err("refused").fields;
    assert!(with(&[("Jc", "128")]).is_ok());
    assert_eq!(refused(&[("Jc", "129")]), [Jc]);
    assert!(with(&[("Jmin", "70"), ("Jmax", "70")]).is_ok());
    assert_eq!(refused(&[("Jmin", "71")]), [Jmin, Jmax]);
    assert!(with(&[("Jmax", "65534")]).is_ok());
    assert_eq!(refused(&[("Jmax", "65535")]), [Jmax]);
    assert!(with(&[("S1", "65386")]).is_ok());
    assert_eq!(refused(&[("S1", "65387")]), [S1]);
    assert_eq!(refused(&[("S2", "65443")]), [S2]);
    // Before 3.x init (148 + S1) and response (92 + S2) must differ in size.
    assert_eq!(refused(&[("S1", "15"), ("S2", "71")]), [S1, S2]);
    assert_eq!(refused(&[("H2", "1020325451")]), [H1, H2]);
    assert_eq!(
        refused(&[("Jc", "x"), ("H3", "10-5"), ("S2", "-1")]),
        [Jc, S2, H3]
    );
}

#[test]
fn header_ranges_must_not_overlap() {
    let ranges = |h1: &'static str, h2: &'static str| {
        read(&[
            ("H1", h1),
            ("H2", h2),
            ("H3", "900-999"),
            ("H4", "1000-2000"),
        ])
    };
    assert!(ranges("5-10", "11-20").is_ok());
    assert_eq!(
        ranges("5-10", "10-20").expect_err("overlap").fields,
        [H1, H2]
    );
    // 2001-3000 vs H4 1000-2000 touch only at their ends: still apart.
    assert!(ranges("5-10", "2001-3000").is_ok());
    // An absent H2 is type 2 on the wire: 3.x H3 = 2 collides with it, the legacy code reads
    // 2 as "standard" and does not.
    assert_eq!(
        invalid(&[
            ("H3", "2"),
            ("S1", "12"),
            ("HeaderProtectionKey", HPK),
            ("S2", "12"),
            ("S3", "12"),
            ("S4", "12")
        ]),
        [H2, H3]
    );
    assert_eq!(
        read(&[("Jc", "3"), ("H3", "2")]).map(|a| a.is_some()),
        Ok(true)
    );
}

#[test]
fn signature_chains_parse_as_their_implementation_does() {
    let i1 = |chain: &'static str| read(&[("I1", chain)]).map(|a| a.is_some());
    let v3_i1 = |chain: &'static str| {
        let mut pairs = V3_1_CONF.to_vec();
        pairs.retain(|(k, _)| *k != "I1");
        pairs.push(("I1", chain));
        read(&pairs).map(|a| a.is_some())
    };
    for good in [
        "<b 0x12><t><r 1000><rc 4><rd 3>",
        " <c> <b 0XAbC> ",
        "<wt 5000><b 0x>",
    ] {
        assert_eq!(i1(good), Ok(true), "{good}");
    }
    for bad in [
        "<b 0xzz>",
        "<b 12>",
        "<r 1001>",
        "<t><t>",
        "<c><c>",
        "<wt 5001>",
        "<x>",
        "<b 0x12>junk",
        "<r 10",
        "<r>",
        "<b 0x12 34>",
    ] {
        assert_eq!(i1(bad).expect_err(bad).fields, [I1], "{bad}");
    }
    for good in ["<b 12ab><t><t>", "<b 0x12><r 5000><d><ds><dz 2>"] {
        assert_eq!(v3_i1(good), Ok(true), "{good}");
    }
    for bad in ["<c>", "<wt 10>", "<b 0x123>", "<b 0X12>", "<b >"] {
        assert_eq!(v3_i1(bad).expect_err(bad).fields, [I1], "{bad}");
    }
}

/// 3.x: header protection needs a 32-byte key and S1-S4 >= 12 (the nonce comes from the
/// prefix); padding fits 16 bits; keys must not expire before the rekey.
#[test]
fn v3_rules() {
    let v3 = |change: &[(&'static str, &'static str)]| {
        let mut pairs = V3_1_CONF.to_vec();
        pairs.retain(|(k, _)| !change.iter().any(|(c, _)| c == k));
        pairs.extend(change.iter().copied().filter(|(_, v)| !v.is_empty()));
        read(&pairs).map(|a| a.is_some())
    };
    let refused = |change: &[(&'static str, &'static str)]| v3(change).expect_err("refused").fields;
    assert_eq!(
        refused(&[("HeaderProtectionKey", "c2hvcnQ=")]),
        [HeaderProtectionKey]
    );
    assert_eq!(refused(&[("S2", "11"), ("S4", "")]), [S2, S4]);
    // Unpadded base64 is accepted and stored padded, as mihomo decodes it.
    let unpadded = HPK.trim_end_matches('=');
    let stored = awg(&[
        ("HeaderProtectionKey", unpadded),
        ("S1", "12"),
        ("S2", "12"),
        ("S3", "12"),
        ("S4", "12"),
    ]);
    assert_eq!(stored.header_protection_key.as_deref(), Some(HPK));
    assert_eq!(v3(&[("ContentPaddingAddition", "0-65535")]), Ok(true));
    assert_eq!(
        refused(&[("ContentPaddingAddition", "0-65536")]),
        [ContentPaddingAddition]
    );
    assert_eq!(
        refused(&[("RekeyAfterTime", "100-150")]),
        [RekeyAfterTime, RejectAfterTime]
    );
    assert_eq!(
        refused(&[("RekeyAfterTime", "200"), ("RejectAfterTime", "")]),
        [RekeyAfterTime]
    );
    assert_eq!(
        refused(&[("RejectAfterTime", "100"), ("RekeyAfterTime", "")]),
        [RejectAfterTime]
    );
    assert_eq!(
        v3(&[("RekeyAfterTime", "0"), ("RejectAfterTime", "")]),
        Ok(true)
    );
    assert_eq!(refused(&[("RandomTrailers", "maybe")]), [RandomTrailers]);
    // 3.x compares sizes no more: equal S values are the recommended form.
    assert_eq!(v3(&[]), Ok(true));
}

/// A generation that matches the keys present: 1.5-only keys never mix with 2.0 / 3.x ones,
/// mihomo's `version` agrees with the keys, and a stored generation is checked again.
#[test]
fn generation_matches_the_keys() {
    assert_eq!(invalid(&[("J1", "<t>"), ("H1", "5-10")]), [H1]);
    assert_eq!(
        invalid(&[("Itime", "60"), ("RandomTrailers", "on")]),
        [Itime]
    );
    assert_eq!(
        invalid(&[("version", "2"), ("RandomTrailers", "on")]),
        [Version]
    );
    assert_eq!(
        invalid(&[("version", "3"), ("J2", "<t>"), ("Jc", "3")]),
        [J2]
    );
    assert_eq!(invalid(&[("version", "three")]), [Version]);
    // `version: 3` alone selects 3.x for keys any generation has.
    assert_eq!(awg(&[("version", "3"), ("Jc", "3")]).generation, V3);

    let mut stored = awg(V1_0_CONF);
    stored.s[2] = Some(20);
    stored.h[3] = AwgRange::parse("5-9");
    stored.i[4] = Some("<t>".into());
    assert_eq!(
        validate(&stored).expect_err("1.0 keys only").fields,
        [S3, H4, I5]
    );
    stored.generation = implied_generation(&stored);
    assert_eq!((stored.generation, validate(&stored)), (V2_0, Ok(())));
}

#[test]
fn implied_generations() {
    let of = |pairs: &[(&str, &str)]| implied_generation(&awg(pairs));
    assert_eq!(of(&[("Jc", "3")]), V1_0);
    assert_eq!(of(&[("I1", "<t>")]), V1_5);
    assert_eq!(of(&[("I1", "<t>"), ("S3", "20")]), V2_0);
    assert_eq!(of(&[("J1", "<t>"), ("S3", "20")]), V1_5);
    assert_eq!(of(&[("H1", "5-6")]), V2_0);
    assert_eq!(of(&[("KeepaliveTimeout", "5-15")]), V3);
}

/// One refusal names every invalid field, in parameter order, under one message key.
#[test]
fn one_refusal_lists_every_field() {
    let err = invalid(&[
        ("Jc", "500"),
        ("H4", "7"),
        ("H1", "7"),
        ("I2", "<q>"),
        ("S1", "x"),
    ]);
    let err = AwgInvalid::of(err).expect("invalid");
    assert_eq!(err.names(), "Jc, S1, H1, H4, I2");
    let msg = err.msg();
    assert_eq!(msg.key, "profiles.awg.invalid");
    crate::test_locales::assert_localized(&msg.key);
    let app: vpnte_base::AppError = err.into();
    assert_eq!(app.kind, vpnte_base::ErrorKind::Validation);
}

#[test]
fn ranges_and_names() {
    assert_eq!(
        AwgRange::parse(" 5 - 10 "),
        Some(AwgRange { min: 5, max: 10 })
    );
    assert_eq!(
        AwgRange::parse("7").map(|r| r.to_string()),
        Some("7".into())
    );
    assert_eq!(
        AwgRange::parse("7-7").map(|r| r.to_string()),
        Some("7".into())
    );
    for bad in ["", "-", "5-", "-5", "10-5", "+5", "4294967296", "1-2-3"] {
        assert_eq!(AwgRange::parse(bad), None, "{bad:?}");
    }
    let json = serde_json::to_string(&AwgRange::parse("100-120")).expect("serialize");
    assert_eq!(json, "\"100-120\"");
    assert_eq!(HeaderProtectionKey.yaml_name(), "header-protection-key");
    assert_eq!(Jmin.yaml_name(), "jmin");
    assert_eq!(MaxHandshakeAttempts.yaml_name(), "max-handshake-attempts");
    for key in [
        "HeaderProtectionKey",
        "header-protection-key",
        "HEADER_PROTECTION_KEY",
    ] {
        assert_eq!(AwgField::from_key(key), Some(HeaderProtectionKey), "{key}");
    }
    assert_eq!(AwgField::from_key("version"), None);
    assert_eq!(AwgField::from_key("PersistentKeepalive"), None);
    assert_eq!(AwgField::from_key("i6"), None);
}
