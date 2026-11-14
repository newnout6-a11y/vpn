//! Naive, AnyTLS, ShadowTLS, SOCKS, HTTP (P-02, P-07, P-11).
use super::*;
use crate::model::{Ech, Note};

/// §7.1 naive URI.
#[test]
fn naive_uri() {
    let p = ok("naive://user:pass@naive.example.com:443?sni=front.example.com#Naive%20Node");
    assert_eq!(
        (kind_label(&p), p.name.as_str(), p.port),
        ("naive", "Naive Node", 443)
    );
    assert_eq!(p.server, domain("naive.example.com"));
    let Kind::Naive {
        username,
        password,
        quic,
        ..
    } = &p.kind
    else {
        panic!("not naive")
    };
    assert_eq!(
        (username.as_str(), password.as_str(), *quic),
        ("user", "pass", false)
    );
    assert_eq!(
        p.tls.and_then(|t| t.server_name).as_deref(),
        Some("front.example.com")
    );
    assert!(p.notes.is_empty());
}

/// §7.1 naive insecure (CHANGED): kept in the profile with a note, never applied.
#[test]
fn naive_insecure_kept_with_note() {
    let p =
        ok("naive://user:pass@naive.example.com:443?sni=front.example.com&allowInsecure=1#Naive");
    assert!(p.tls.is_some_and(|t| t.insecure));
    assert_eq!(p.notes, vec![Note::NaiveInsecureIgnored]);
}

/// §7.1 ECH params (and the caps naive-ech line).
#[test]
fn naive_ech_params() {
    let p = ok(
        "naive://user:pass@naive.example.com:443?sni=front.example.com&ech=1&echConfig=abc,def&echQueryServerName=cloudflare-ech.com#Naive%20ECH",
    );
    let expected = Ech {
        config_lines: vec!["abc".into(), "def".into()],
        query_server_name: Some("cloudflare-ech.com".into()),
    };
    assert_eq!(p.tls.and_then(|t| t.ech), Some(expected));
    let single = ok(
        "naive://user:pass@naive.example.com:443?sni=front.example.com&ech=1&echConfig=abc#Naive%20ECH",
    );
    assert_eq!(
        single.tls.and_then(|t| t.ech).map(|e| e.config_lines),
        Some(vec!["abc".to_owned()])
    );
}

/// ECH in Xray form (`name+DNS URL`, `+` literal), a bare flag, and a dropped local file path (P-33).
#[test]
fn ech_variants() {
    let xray = ok("naive://u:p@h.example?ech=cloudflare-ech.com+https%3A%2F%2F1.1.1.1%2Fdns-query");
    let ech = xray.tls.and_then(|t| t.ech).expect("ech");
    assert_eq!(
        (ech.query_server_name.as_deref(), ech.config_lines.len()),
        (Some("cloudflare-ech.com"), 0)
    );
    let flag = ok("naive://u:p@h.example?ech=true").tls.and_then(|t| t.ech);
    assert_eq!(flag, Some(Ech::default()));
    assert_eq!(
        ok("naive://u:p@h.example?ech=0").tls.and_then(|t| t.ech),
        None
    );
    let path = ok("naive://u:p@h.example?echConfigPath=C%3A%5Cech.pem");
    assert_eq!(
        path.notes,
        vec![Note::FileReferenceDropped("echConfigPath".into())]
    );
    assert_eq!(path.tls.and_then(|t| t.ech), None);
    // Xray's `echConfigList` is one value (DNS query or base64), never a list of configs; an
    // empty name before `+` is not a query name.
    let ech = |line: &str| ok(line).tls.and_then(|t| t.ech).expect("ech");
    let list = ech("naive://u:p@h.example?echConfigList=q.example%2Budp%3A%2F%2F1.1.1.1");
    assert_eq!(
        (list.query_server_name.as_deref(), list.config_lines.len()),
        (Some("q.example"), 0)
    );
    let config = ech("naive://u:p@h.example?echConfigList=AF7%2BDQBa");
    assert_eq!(config.config_lines, vec!["AF7+DQBa".to_owned()]);
    assert_eq!(
        ech("naive://u:p@h.example?ech=%2Bhttps%3A%2F%2F1.1.1.1%2Fdns-query"),
        Ech::default()
    );
}

/// §7.3 new schemes: `naive+https` / `naive+quic`; default port, headers, concurrency.
#[test]
fn naive_variants() {
    let https = ok("naive+https://user:pass@h.example:443#N");
    assert!(matches!(https.kind, Kind::Naive { quic: false, .. }));
    let quic = ok("naive+quic://user:pass@h.example:443#N");
    assert!(matches!(quic.kind, Kind::Naive { quic: true, .. }));
    let extra =
        ok("naive://u:p@h.example?extra-headers=X-A%3A%201%0D%0AX-B%3A2&insecure-concurrency=4");
    assert_eq!(extra.port, 443);
    let Kind::Naive {
        extra_headers,
        insecure_concurrency,
        ..
    } = &extra.kind
    else {
        panic!("not naive")
    };
    assert_eq!(
        extra_headers,
        &vec![
            ("X-A".to_owned(), "1".to_owned()),
            ("X-B".to_owned(), "2".to_owned())
        ]
    );
    assert_eq!(*insecure_concurrency, Some(4));
    assert!(is_invalid(&err(
        "naive://u:p@h.example?security=reality&pbk=k"
    )));
}

/// §7.1 anytls + passwordless vector.
#[test]
fn anytls_vector() {
    let p = ok("anytls://secret@any.example.com:443?sni=front.example.com#AnyTLS");
    assert!(matches!(&p.kind, Kind::Anytls { password, .. } if password == "secret"));
    assert_eq!(
        p.tls.and_then(|t| t.server_name).as_deref(),
        Some("front.example.com")
    );
    assert_eq!(
        err("anytls://any.example.com:443?sni=front.example.com#AnyTLS"),
        SkipReason::MissingCredential
    );
}

/// P-07: idle parameters become durations: `*_ms` names count milliseconds, others seconds.
#[test]
fn anytls_idle_parameters() {
    let p = ok(
        "anytls://secret@any.example.com:443?sni=x&idle_session_check_interval_ms=30000&idle-timeout=60&min-idle=2",
    );
    let Kind::Anytls {
        idle_check_s,
        idle_timeout_s,
        min_idle,
        ..
    } = &p.kind
    else {
        panic!("not anytls")
    };
    assert_eq!(
        (*idle_check_s, *idle_timeout_s, *min_idle),
        (Some(30), Some(60), Some(2))
    );
    let units = ok("anytls://s@h.example?idleCheckInterval=1m&idle_session_timeout=90s");
    assert!(matches!(
        units.kind,
        Kind::Anytls {
            idle_check_s: Some(60),
            idle_timeout_s: Some(90),
            ..
        }
    ));
}

/// P-11: standalone ShadowTLS links (with or without a password) are skipped.
#[test]
fn shadowtls_needs_inner() {
    for line in [
        "shadowtls://secret@shadow.example.com:443?version=3&sni=front.example.com#ShadowTLS",
        "shadowtls://shadow.example.com:443?version=3&sni=front.example.com#ShadowTLS",
    ] {
        assert_eq!(err(line), SkipReason::ShadowTlsNeedsInner);
    }
}

fn socks_creds(profile: &Profile) -> (Option<&str>, Option<&str>) {
    match &profile.kind {
        Kind::Socks { username, password } => (username.as_deref(), password.as_deref()),
        other => panic!("not socks: {other:?}"),
    }
}

/// §7.3 new schemes: Happ SOCKS links in both base64 forms; plain and IPv6 forms.
#[test]
fn socks_links() {
    let b64_user = ok("socks://dXNlcjpwYXNz@1.2.3.4:1080#S");
    assert_eq!(socks_creds(&b64_user), (Some("user"), Some("pass")));
    assert_eq!(
        (b64_user.server.clone(), b64_user.port),
        (ip("1.2.3.4"), 1080)
    );
    assert_eq!(b64_user.notes, vec![Note::Unencrypted]);
    let b64_all = ok("socks://dXNlcjpwYXNzQDEuMi4zLjQ6MTA4MA==#S");
    assert_eq!(socks_creds(&b64_all), (Some("user"), Some("pass")));
    assert_eq!(
        (b64_all.server.clone(), b64_all.port, b64_all.name.as_str()),
        (ip("1.2.3.4"), 1080, "S")
    );
    let v6 = ok("socks5://[2001:db8::1]:1080");
    assert_eq!(
        (v6.server.clone(), socks_creds(&v6), v6.name.as_str()),
        (ip("2001:db8::1"), (None, None), "SOCKS")
    );
    assert_eq!(
        socks_creds(&ok("socks://alice@h.example:1080")),
        (Some("alice"), None)
    );
    assert!(is_invalid(&err("socks://h.example")));
}

/// Proxy lines as the exporter writes them (§7.1 "proxy lines"); web addresses are not proxies.
#[test]
fn http_links() {
    let p = ok("http://user:pa%3Ass@proxy.example.com:8080");
    assert!(
        matches!(&p.kind, Kind::Http { username: Some(u), password: Some(pw) } if u == "user" && pw == "pa:ss")
    );
    assert_eq!(
        (p.name.as_str(), p.notes.clone()),
        ("HTTP", vec![Note::Unencrypted])
    );
    let tls = ok("https://user:pass@naive.example.com:443");
    assert!(tls.tls.is_some() && tls.notes.is_empty());
    assert_eq!(tls.name, "HTTPS");
    assert!(is_invalid(&err("https://provider.example/sub/abc")));
    assert!(is_invalid(&err("http://example.com")));
}
