//! Shadowsocks: SIP002, legacy base64, plugins (P-09, P-35).
use super::*;
use crate::model::{Note, SsPlugin};

fn method_password(profile: &Profile) -> (&str, &str) {
    match &profile.kind {
        Kind::Shadowsocks {
            method, password, ..
        } => (method, password),
        other => panic!("not shadowsocks: {other:?}"),
    }
}

fn plugin(profile: &Profile) -> Option<&SsPlugin> {
    match &profile.kind {
        Kind::Shadowsocks { plugin, .. } => plugin.as_ref(),
        other => panic!("not shadowsocks: {other:?}"),
    }
}

/// §7.2 smoke: legacy whole-base64 and SIP002 base64 userinfo.
#[test]
fn legacy_and_sip002() {
    let legacy = ok("ss://YWVzLTEyOC1nY206cGFzc0BleGFtcGxlLm5ldDo4Mzg4#legacy-ss");
    assert_eq!(method_password(&legacy), ("aes-128-gcm", "pass"));
    assert_eq!(
        (legacy.server.clone(), legacy.port, legacy.name.as_str()),
        (domain("example.net"), 8388, "legacy-ss")
    );
    let sip002 = ok("ss://YWVzLTI1Ni1nY206cGFzcw==@example.net:8388#sip002-ss");
    assert_eq!(method_password(&sip002), ("aes-256-gcm", "pass"));
    assert!(sip002.tls.is_none() && sip002.notes.is_empty());
}

/// AT-04-003, AT-04-004, P-09: a SIP002 `/` before `?`/`#`, the obfs-local plugin, and no second decode after base64.
#[test]
fn sip002_slash_plugin_and_single_decode() {
    let slash = ok("ss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:8388/#n");
    assert_eq!((slash.server.clone(), slash.port), (ip("1.2.3.4"), 8388));
    let obfs = ok(
        "ss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:8388/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dexample.com#n",
    );
    let expected = SsPlugin {
        name: "obfs-local".into(),
        opts: "obfs=http;obfs-host=example.com".into(),
    };
    assert_eq!(plugin(&obfs), Some(&expected));
    let literal = ok("ss://YWVzLTI1Ni1nY206cCU0MXNz@h.example:8388#n");
    assert_eq!(method_password(&literal), ("aes-256-gcm", "p%41ss"));
}

/// P-35: percent-encoded base64 padding is decoded before the base64 test.
#[test]
fn percent_encoded_padding() {
    let p = ok("ss://YWVzLTI1Ni1nY206cGFzcw%3D%3D@h.example:8388#n");
    assert_eq!(method_password(&p), ("aes-256-gcm", "pass"));
}

/// Plain SIP002 userinfo (Shadowsocks 2022 keys): `+` and `=` survive.
#[test]
fn plain_userinfo_2022_key() {
    let p = ok("ss://2022-blake3-aes-128-gcm:YctPZ6U7xPPcU%2Bgp3u%2BeLQ%3D%3D@h.example:8388#k");
    assert_eq!(
        method_password(&p),
        ("2022-blake3-aes-128-gcm", "YctPZ6U7xPPcU+gp3u+eLQ==")
    );
    let raw_plus = ok("ss://2022-blake3-aes-128-gcm:Yct+gp3u+eLQ==@h.example:8388");
    assert_eq!(method_password(&raw_plus).1, "Yct+gp3u+eLQ==");
}

#[test]
fn plugins() {
    let v2ray = ok(
        "ss://YWVzLTI1Ni1nY206cGFzcw==@h.example:443?plugin=v2ray-plugin%3Btls%3Bhost%3Dcdn.example",
    );
    assert_eq!(
        plugin(&v2ray),
        Some(&SsPlugin {
            name: "v2ray-plugin".into(),
            opts: "tls;host=cdn.example".into()
        })
    );
    let simple = ok("ss://YWVzLTI1Ni1nY206cGFzcw==@h.example:443?plugin=simple-obfs;obfs=tls");
    assert_eq!(plugin(&simple).map(|p| p.name.as_str()), Some("obfs-local"));
    let kcp = err("ss://YWVzLTI1Ni1nY206cGFzcw==@h.example:443?plugin=kcptun%3Bmode%3Dfast");
    assert_eq!(kcp, SkipReason::UnsupportedPlugin("kcptun".into()));
}

#[test]
fn ipv6_credentials_and_errors() {
    let v6 = ok("ss://YWVzLTI1Ni1nY206cGFzcw==@[2001:db8::1]:8388#v6");
    assert_eq!(v6.server, ip("2001:db8::1"));
    let none = ok("ss://none:@h.example:8388");
    assert_eq!(method_password(&none), ("none", ""));
    assert_eq!(none.notes, vec![Note::Unencrypted]);
    assert_eq!(
        err("ss://aes-256-gcm:@h.example:8388"),
        SkipReason::MissingCredential
    );
    assert_eq!(err("ss://@h.example:8388"), SkipReason::MissingCredential);
    assert!(is_invalid(&err("ss://!!!")));
    assert!(is_invalid(&err("ss://YWVzLTI1Ni1nY206cGFzcw==@h.example")));
    assert!(is_invalid(&err("ss://bm90LWNyZWRlbnRpYWxz@h.example:8388")));
}
