use serde_json::json;

use super::*;

fn ok(s: &str) -> DnsAddr {
    s.parse()
        .unwrap_or_else(|e| panic!("{s:?} must be valid: {e}"))
}

fn err(s: &str) -> DnsAddrError {
    s.parse::<DnsAddr>().expect_err(s)
}

/// dnsProfiles.test.ts plain IPv4 / IPv6 vectors; B-DNS-3 moves unusable addresses to invalid.
#[test]
fn plain_addresses() {
    for s in [
        "1.1.1.1",
        "8.8.8.8",
        "192.168.1.1",
        "10.64.0.1",
        "100.64.0.2",
    ] {
        assert!(matches!(ok(s), DnsAddr::Plain(_)), "{s}");
    }
    for s in [
        "256.1.1.1",
        "01.1.1.1",
        "1.1.1",
        "1.1.1.1.1",
        "1.1.1.a",
        "1.1.1.1:53",
    ] {
        assert_eq!(err(s), DnsAddrError::Invalid, "{s}");
    }
    for s in [
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "2001:db8::1",
        "1234::",
        "::ffff:1.2.3.4",
    ] {
        assert!(matches!(ok(s), DnsAddr::Plain(_)), "{s}");
    }
    for s in [
        "2001::db8::1",
        "2001:db8:85a3:0000:0000:8a2e:0370:7334:extra",
        "2001:db8:85a3:0000:0000:8a2e:0370:gggg",
        "fe80::1%14",
    ] {
        assert_eq!(err(s), DnsAddrError::Invalid, "{s}");
    }
    for s in [
        "0.0.0.0",
        "255.255.255.255",
        "224.0.0.1",
        "127.0.0.1",
        "169.254.1.1",
        "::",
        "::1",
        "fe80::",
    ] {
        assert_eq!(err(s), DnsAddrError::UnusableIp, "{s}");
    }
}

/// DoH / DoT vectors (old + B-DNS-3 / B-DNS-10 additions).
#[test]
fn doh_and_dot_addresses() {
    for s in [
        "https://dns.cloudflare.com",
        "https://dns.google",
        "https://doh.opendns.com/dns-query",
    ] {
        assert!(matches!(ok(s), DnsAddr::Doh { .. }), "{s}");
    }
    assert_eq!(err("https://"), DnsAddrError::DohHost);
    assert_eq!(err("https://localhost"), DnsAddrError::DohHost);
    for s in ["tls://dns.cloudflare.com", "tls://dns.google"] {
        assert!(matches!(ok(s), DnsAddr::Dot { .. }), "{s}");
    }
    assert_eq!(err("tls://"), DnsAddrError::DotHost);
    assert_eq!(err("tls://localhost"), DnsAddrError::DotHost);
    assert_eq!(err(""), DnsAddrError::Required);
    assert_eq!(err("   "), DnsAddrError::Required);
    assert_eq!(err("not-a-dns-address"), DnsAddrError::Invalid);
    assert_eq!(err("http://dns.google"), DnsAddrError::Scheme);
    assert_eq!(err("ftp://dns.google"), DnsAddrError::Scheme);
    assert!(matches!(ok("HTTPS://dns.google"), DnsAddr::Doh { .. }));
    assert_eq!(err("https://dns.google:abc/x"), DnsAddrError::Port);
    assert_eq!(err("https://dns.google:0"), DnsAddrError::Port);
    assert_eq!(err("https://dns.google:70000"), DnsAddrError::Port);
    assert_eq!(err("https://999.1.1.1/dns-query"), DnsAddrError::DohHost);
    assert_eq!(err("https://127.0.0.1/dns-query"), DnsAddrError::UnusableIp);
    assert_eq!(
        err("https://2606:4700::1111/dns-query"),
        DnsAddrError::DohHost
    );
    assert_eq!(err("tls://dns.google/path"), DnsAddrError::Path);
    assert_eq!(err("https://dns.google/a b"), DnsAddrError::Path);
    // sing-box escapes `path` as a URL path: a query would arrive as `%3F…`, a bad escape
    // stops the engine (dns/transport/https.go → Go url.setPath).
    for s in [
        "https://dns.example/q?token=abc",
        "https://dns.example/dns-query#x",
        "https://dns.example/a%zz",
        "https://dns.example/a%4",
        "https://dns.example/путь",
    ] {
        assert_eq!(err(s), DnsAddrError::Path, "{s}");
    }
    assert!(matches!(
        ok("https://dns.example/a%2Fb/dns-query"),
        DnsAddr::Doh { .. }
    ));
    assert!(matches!(
        ok("https://[2606:4700::1111]/dns-query"),
        DnsAddr::Doh { .. }
    ));
    assert!(matches!(
        ok("https://1.1.1.1/dns-query"),
        DnsAddr::Doh { .. }
    ));
}

/// Display is the persisted form: it parses back to the same address.
#[test]
fn display_round_trips() {
    for s in [
        "1.1.1.1",
        "2001:db8::1",
        "https://dns.google",
        "https://dns.example:8443/abc123/dns-query",
        "https://[2606:4700::1111]/dns-query",
        "tls://dns.example:443",
        "tls://1.1.1.1",
    ] {
        assert_eq!(ok(s).to_string(), s);
        assert_eq!(ok(&ok(s).to_string()), ok(s));
    }
    assert_eq!(ok("HTTPS://DNS.Google/").to_string(), "https://dns.google");
    assert_eq!(ok("tls://dns.google/").to_string(), "tls://dns.google");
}

/// Server mapping (tunControllerConfig.test.ts:612-692); `dns-backup` is gone (B-DNS-9).
#[test]
fn remote_server_mapping() {
    assert_eq!(
        remote_server(None),
        json!({ "type": "https", "tag": "dns-remote", "server": "1.1.1.1", "path": "/dns-query",
                "detour": "proxy-out", "tls": { "server_name": "cloudflare-dns.com" } })
    );
    let quad9 = find_profile(&[], "builtin-quad9").unwrap();
    assert_eq!(
        remote_server(Some(&quad9.primary)),
        json!({ "type": "tcp", "tag": "dns-remote", "server": "9.9.9.9", "detour": "proxy-out" })
    );
    assert_eq!(
        remote_server(Some(&ok("https://dns.google:443/dns-query"))),
        json!({ "type": "https", "tag": "dns-remote", "server": "8.8.8.8", "server_port": 443,
                "path": "/dns-query", "detour": "proxy-out", "tls": { "server_name": "dns.google" } })
    );
    assert_eq!(
        remote_server(Some(&ok("https://custom-dns.example.com:443/dns-query"))),
        json!({ "type": "https", "tag": "dns-remote", "server": "custom-dns.example.com",
                "server_port": 443, "path": "/dns-query", "detour": "proxy-out",
                "tls": { "server_name": "custom-dns.example.com" } })
    );
    assert_eq!(
        remote_server(Some(&ok("tls://dns.google:853"))),
        json!({ "type": "tls", "tag": "dns-remote", "server": "dns.google", "server_port": 853,
                "detour": "proxy-out", "tls": { "server_name": "dns.google" } })
    );
    assert_eq!(
        remote_server(Some(&ok("tls://dns.example:443"))),
        json!({ "type": "tls", "tag": "dns-remote", "server": "dns.example", "server_port": 443,
                "detour": "proxy-out", "tls": { "server_name": "dns.example" } })
    );
    assert_eq!(
        remote_server(Some(&ok("tls://dns.google"))),
        json!({ "type": "tls", "tag": "dns-remote", "server": "dns.google", "detour": "proxy-out",
                "tls": { "server_name": "dns.google" } })
    );
    assert_eq!(
        remote_server(Some(&ok("https://dns.adguard-dns.com/dns-query"))),
        json!({ "type": "https", "tag": "dns-remote", "server": "dns.adguard-dns.com",
                "path": "/dns-query", "detour": "proxy-out",
                "tls": { "server_name": "dns.adguard-dns.com" } })
    );
    assert_eq!(
        remote_server(Some(&ok("https://[2606:4700::1111]/dns-query"))),
        json!({ "type": "https", "tag": "dns-remote", "server": "2606:4700::1111",
                "path": "/dns-query", "detour": "proxy-out" })
    );
    let q = remote_server(Some(&ok("https://dns.example/abc123")));
    assert_eq!(q["path"], "/abc123");
}

/// Built-in table verbatim, ids reserved, lookup order built-ins then custom.
#[test]
fn builtin_profiles_verbatim() {
    let b = builtin_profiles();
    let rows: Vec<(String, String, String, String)> = b
        .iter()
        .map(|p| {
            let sec = p
                .secondary
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_default();
            (p.id.clone(), p.name.clone(), p.primary.to_string(), sec)
        })
        .collect();
    let want = [
        ("builtin-cloudflare", "Cloudflare", "1.1.1.1", "1.0.0.1"),
        ("builtin-google", "Google", "8.8.8.8", "8.8.4.4"),
        ("builtin-quad9", "Quad9", "9.9.9.9", "149.112.112.112"),
        ("builtin-adguard", "AdGuard", "94.140.14.14", "94.140.15.15"),
    ];
    for (row, w) in rows.iter().zip(want) {
        assert_eq!(
            (
                row.0.as_str(),
                row.1.as_str(),
                row.2.as_str(),
                row.3.as_str()
            ),
            w
        );
    }
    assert!(b.iter().all(DnsProfile::is_builtin));
    assert!(find_profile(&[], "dns-1-abc").is_none());
}
