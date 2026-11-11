//! Rules shared by every scheme (§3.3): scheme detection, names, authority, ports, secrecy.
use super::*;
use crate::model::Source;

const ID: &str = "00000000-0000-4000-8000-000000000002";

#[test]
fn unknown_schemes_name_only_the_scheme() {
    assert_eq!(
        err("ssr://c2VjcmV0"),
        SkipReason::UnknownScheme("ssr".into())
    );
    assert_eq!(
        err("socks4://h.example:1080"),
        SkipReason::UnknownScheme("socks4".into())
    );
    assert_eq!(
        err("just text with SECRET"),
        SkipReason::UnknownScheme(String::new())
    );
    assert_eq!(
        err("SECRET value://x"),
        SkipReason::UnknownScheme(String::new())
    );
}

/// The scheme is case-insensitive; the trimmed line (BOM and whitespace removed) is the source.
#[test]
fn scheme_case_and_trimmed_source() {
    let line = format!("VLESS://{ID}@h.example:443?security=tls#N");
    let p = ok(&format!("\u{feff}  {line} \r\n"));
    assert_eq!((kind_label(&p), p.source), ("vless", Source::Uri(line)));
}

/// Names: decoded once, control characters -> spaces, trimmed, capped; defaults per protocol.
#[test]
fn names() {
    let base = format!("vless://{ID}@h.example:443");
    assert_eq!(ok(&format!("{base}#%0A%20Foo%09Bar%20")).name, "Foo Bar");
    assert_eq!(
        ok(&format!("{base}#%F0%9F%87%A9%F0%9F%87%AA%20DE")).name,
        "🇩🇪 DE"
    );
    assert_eq!(ok(&format!("{base}#100%")).name, "100%");
    assert_eq!(ok(&format!("{base}#a%FFb")).name, "a%FFb");
    assert_eq!(ok(&format!("{base}#a#b")).name, "a#b");
    assert_eq!(
        ok(&format!("{base}#{}", "x".repeat(300)))
            .name
            .chars()
            .count(),
        256
    );
    for (line, name) in [
        (base.clone(), "VLESS"),
        (format!("{base}#%20"), "VLESS"),
        ("trojan://p@h.example:443".to_owned(), "Trojan"),
        ("tuic://u:p@h.example:443".to_owned(), "TUIC"),
        ("anytls://p@h.example".to_owned(), "AnyTLS"),
        ("wg://k@h.example?publicKey=p".to_owned(), "WireGuard"),
        ("ss://none:@h.example:1".to_owned(), "Shadowsocks"),
        ("hy2://p@h.example".to_owned(), "Hysteria2"),
    ] {
        assert_eq!(ok(&line).name, name, "{line}");
    }
}

/// The Happ description suffix: base64 text, else kept raw; an empty title falls back.
#[test]
fn happ_description() {
    let p = ok(&format!(
        "vless://{ID}@h.example:443#?serverdescription=plain%20words"
    ));
    assert_eq!(
        (p.name.as_str(), p.description.as_deref()),
        ("VLESS", Some("plain words"))
    );
}

/// P-26: ports are decimal digits 1..=65535 only.
#[test]
fn ports() {
    for bad_port in [
        "0x1BB", "1e3", "443.0", "0", "65536", "-1", "+443", "", "443 ",
    ] {
        let line = format!("vless://{ID}@h.example:{bad_port}?security=tls");
        assert!(is_invalid(&err(&line)), "{bad_port:?}");
    }
    assert_eq!(ok(&format!("vless://{ID}@h.example:65535")).port, 65535);
    assert_eq!(ok(&format!("vless://{ID}@h.example:1")).port, 1);
    assert!(is_invalid(&err(&format!("vless://{ID}@h.example"))));
}

/// AT-04-004: IPv6 in brackets stored unbracketed (IPv4-mapped too), IPv4 typed, domains kept
/// as given; unbalanced brackets, double ports and zone ids are rejected.
#[test]
fn hosts() {
    assert_eq!(
        ok(&format!("vless://{ID}@[2001:db8::7]:443")).server,
        ip("2001:db8::7")
    );
    assert_eq!(
        ok(&format!("vless://{ID}@192.0.2.9:443")).server,
        ip("192.0.2.9")
    );
    assert_eq!(
        ok(&format!("vless://{ID}@Mixed.Example.COM:443")).server,
        domain("Mixed.Example.COM")
    );
    assert_eq!(ok(&format!("vless://{ID}@[::1]:443")).server, ip("::1"));
    let mapped = ok(&format!("vless://{ID}@[::ffff:1.2.3.4]:443"));
    assert_eq!(
        (mapped.server.to_string(), mapped.port),
        ("::ffff:1.2.3.4".to_owned(), 443)
    );
    for bad_host in [
        "2001:db8::7:443",
        "[2001:db8::7",
        "2001:db8::7]:443",
        "[2001:db8::1]:443:8443",
        "h.example:443:8443",
        "[fe80::1%25eth0]:443",
        "[fe80::1%eth0]:443",
        "[nope]:443",
        "999.1.1.1:443",
        "h ost:443",
        ":443",
    ] {
        assert!(
            is_invalid(&err(&format!("vless://{ID}@{bad_host}"))),
            "{bad_host}"
        );
    }
    // A path after the authority is ignored, as in the old URL-based parsers.
    assert_eq!(
        ok(&format!(
            "vless://{ID}@h.example:443/some/path?security=tls"
        ))
        .port,
        443
    );
}

/// AT-04-003, P-08, K1: one decode, `+` literal, case-insensitive names, first alias wins.
#[test]
fn query_rules() {
    let p = ok(&format!(
        "vless://{ID}@h.example:443?SECURITY=tls&SNI=a.example&serverName=b.example&type=ws&path=%2Fa+b%2520"
    ));
    assert_eq!(
        p.tls.and_then(|t| t.server_name).as_deref(),
        Some("a.example")
    );
    assert!(
        matches!(p.transport, Some(crate::model::Transport::Ws { ref path, .. }) if path == "/a+b%20")
    );
    let empty_first = ok(&format!(
        "vless://{ID}@h.example:443?security=tls&sni=&peer=c.example"
    ));
    assert_eq!(
        empty_first.tls.and_then(|t| t.server_name).as_deref(),
        Some("c.example")
    );
}

/// Skip reasons never carry credentials or other link values.
#[test]
fn skip_reasons_do_not_leak_values() {
    for line in [
        "trojan://SECRET-PASS@h.example:99999",
        "vless://SECRET-ID@h.example:443?security=SECRET",
        "vless://SECRET-ID@h.example:443?type=SECRET%20X",
        "ss://SECRET-PASS@h.example:8388",
        "vmess://SECRET",
        "hy2://SECRET-PASS@h.example:443?obfs=SECRET",
        "wg://SECRET:SECRET@h.example?reserved=SECRET",
        "naive://SECRET:SECRET@SECRET%20HOST",
        "ss://YWVzLTI1Ni1nY206cGFzcw==@h.example:443?plugin=SECRET%20plugin",
    ] {
        let reason = format!("{:?}", err(line));
        assert!(!reason.contains("SECRET"), "{line} -> {reason}");
    }
}

/// §7.1 "mixed lines" at the line level (the text pipeline splits the lines) and P-01 / P-02:
/// no line gets an ALPN or uTLS default from the parser.
#[test]
fn mixed_lines_in_order() {
    let lines = [
        "vless://00000000-0000-4000-8000-000000000001@vless.example.com:443?security=tls#VLESS",
        "tuic://550e8400-e29b-41d4-a716-446655440000:secret@tuic.example.com:443?sni=front.example.com&congestion_control=bbr&udp_relay_mode=native#TUIC",
        "naive://user:pass@naive.example.com:443?sni=front.example.com#Naive%20Node",
    ];
    let profiles: Vec<Profile> = lines.iter().map(|line| ok(line)).collect();
    let labels: Vec<&str> = profiles.iter().map(kind_label).collect();
    assert_eq!(labels, ["vless", "tuic", "naive"]);
    for p in &profiles {
        let tls = p.tls.as_ref().expect("tls");
        assert!(
            tls.alpn.is_empty() && tls.fingerprint.is_none(),
            "{}",
            p.name
        );
    }
}
