//! Findings vectors (live-probe §7.1, §7.2, §7.14, §7.15).
use serde_json::json;

use super::{arg, msg, patched};
use crate::live::evaluate_findings;
use crate::live::model::{Evidence, Finding, FindingCode as C, LiveCheck, Severity};
use crate::live::throughput::summarize_throughput;
use crate::live_stages::Text;

fn codes(findings: &[Finding]) -> Vec<C> {
    findings.iter().map(|f| f.code).collect()
}

fn find(findings: &[Finding], code: C) -> &Finding {
    findings
        .iter()
        .find(|f| f.code == code)
        .unwrap_or_else(|| panic!("no {code:?} in {:?}", codes(findings)))
}

/// AT-05-002 (liveServerProbe.test.ts:319-436): DNS change and multi-IP.
#[test]
fn dns_multi_ip_and_change() {
    let cur = patched(json!({"host": "example.com", "dns": {"a": ["2.2.2.2", "3.3.3.3"]}}));
    let prev = patched(json!({"dns": {"a": ["1.1.1.1"]}}));
    let f = evaluate_findings(&cur, Some(&prev));
    assert!(codes(&f).contains(&C::DnsMultiIp));
    let changed = msg(&find(&f, C::DnsChanged).detail);
    assert_eq!(arg(changed, "previous"), "1.1.1.1");
    assert_eq!(arg(changed, "current"), "2.2.2.2, 3.3.3.3");
}

/// B-14: one address per family is a normal dual-stack host.
#[test]
fn dual_stack_is_not_multi_ip() {
    let one_each = patched(json!({"dns": {"a": ["1.1.1.1"], "aaaa": ["2606:4700::1"]}}));
    assert!(!codes(&evaluate_findings(&one_each, None)).contains(&C::DnsMultiIp));
    let two_v4 = patched(json!({"dns": {"a": ["1.1.1.1", "1.0.0.1"]}}));
    assert!(codes(&evaluate_findings(&two_v4, None)).contains(&C::DnsMultiIp));
}

/// AT-05-002: certificate expiry thresholds and the SAN mismatch.
#[test]
fn tls_expiry_and_san() {
    let soon = patched(
        json!({"host": "vpn.example.com", "tls": {"status": "ok", "durationMs": 9,
        "daysRemaining": 15, "hostnameVerified": false, "sans": ["other.example.com"]}}),
    );
    let f = evaluate_findings(&soon, None);
    assert_eq!(find(&f, C::TlsExpiring).severity, Severity::Warning);
    let san = msg(&find(&f, C::TlsSanMismatch).detail);
    assert_eq!(arg(san, "names"), "other.example.com");
    let expired = patched(
        json!({"tls": {"status": "ok", "durationMs": 9, "daysRemaining": 3,
        "hostnameVerified": true, "validTo": "Jan  1 00:00:00 2027 GMT"}}),
    );
    let f = evaluate_findings(&expired, None);
    assert_eq!(find(&f, C::TlsExpiring).severity, Severity::Error);
    assert!(!codes(&f).contains(&C::TlsSanMismatch));
}

/// B-19 / B-15: an untrusted chain is an info; a trusted leaf renewed for the same names is not
/// worth a finding, any other fingerprint change is an info.
#[test]
fn tls_trust_and_fingerprint() {
    let tls = |fp: &str, authorized: bool, sans: &[&str]| {
        patched(
            json!({"tls": {"status": "ok", "durationMs": 9, "fingerprint": fp,
            "authorized": authorized, "authorizationError": "DEPTH_ZERO_SELF_SIGNED_CERT",
            "sans": sans}}),
        )
    };
    let f = evaluate_findings(&tls("AA", false, &["a.example"]), None);
    let untrusted = find(&f, C::TlsUntrusted);
    assert_eq!(untrusted.severity, Severity::Info);
    assert_eq!(
        arg(msg(&untrusted.detail), "error"),
        "DEPTH_ZERO_SELF_SIGNED_CERT"
    );
    let renewed = tls("BB", true, &["a.example"]);
    let f = evaluate_findings(&renewed, Some(&tls("AA", true, &["a.example"])));
    assert!(!codes(&f).contains(&C::TlsFingerprintChanged));
    let other = tls("BB", true, &["b.example"]);
    let f = evaluate_findings(&other, Some(&tls("AA", true, &["a.example"])));
    assert_eq!(find(&f, C::TlsFingerprintChanged).severity, Severity::Info);
}

/// AT-05-002: latency, jitter and connection failures.
#[test]
fn latency_jitter_loss() {
    let cur = patched(
        json!({"latency": {"min": 200, "avg": 320, "median": 310, "max": 450,
        "jitter": 55, "loss": 0.25, "samples": [200, 310, 450], "samplesAttempted": 4}}),
    );
    let f = evaluate_findings(&cur, None);
    assert_eq!(find(&f, C::LatencyHigh).severity, Severity::Warning);
    assert_eq!(find(&f, C::JitterHigh).severity, Severity::Warning);
    let loss = find(&f, C::PacketLoss);
    assert_eq!(loss.severity, Severity::Warning);
    assert_eq!(loss.evidence["lossPct"], Evidence::Num(25.0));
}

/// B-03: a TCP endpoint that refuses is an error finding, not only a stage colour.
#[test]
fn tcp_unreachable() {
    let cur = patched(json!({"reachability": {"status": "error", "durationMs": 9,
        "error": "ECONNREFUSED", "tcpReachable": false, "port": 443}, "latency": null}));
    let f = evaluate_findings(&cur, None);
    let unreachable = find(&f, C::TcpUnreachable);
    assert_eq!(unreachable.severity, Severity::Error);
    assert_eq!(arg(msg(&unreachable.detail), "error"), "ECONNREFUSED");
}

/// B-14: the server's own port is not news; other open ports are.
#[test]
fn open_ports_exclude_own_port() {
    let own = patched(
        json!({"openPorts": [{"port": 443, "open": true, "state": "open", "service": "HTTPS"}]}),
    );
    assert!(!codes(&evaluate_findings(&own, None)).contains(&C::PortOpen));
    let more = patched(json!({"openPorts": [
        {"port": 443, "open": true, "state": "open", "service": "HTTPS"},
        {"port": 8080, "open": true, "state": "open", "service": "HTTP-alt"}]}));
    let f = evaluate_findings(&more, None);
    assert_eq!(
        arg(msg(&find(&f, C::PortOpen).detail), "ports"),
        "8080 (HTTP-alt)"
    );
}

/// B-06: a private (RFC 1918) server gets an info finding.
#[test]
fn private_target() {
    let lan = patched(json!({"host": "10.0.0.5", "dns": {"a": ["10.0.0.5"]}}));
    let f = evaluate_findings(&lan, None);
    assert_eq!(
        arg(msg(&find(&f, C::PrivateTarget).detail), "ip"),
        "10.0.0.5"
    );
    let public = patched(json!({"dns": {"a": ["203.0.113.10"]}}));
    assert!(!codes(&evaluate_findings(&public, None)).contains(&C::PrivateTarget));
}

/// AT-05-002 + B-08: ASN change, shared /24, and the exit country against the server's geo
/// country (ISO2 both), for any profile.
#[test]
fn asn_cidr_and_exit_country() {
    let asn = |n: &str, code: &str| json!({"asn": n, "org": "Example", "network": "", "country": "Germany", "countryCode": code});
    let cur = patched(json!({"asn": asn("AS200", "NL"),
        "infrastructure": {"status": "ok", "sharedCidrWithProfiles": ["Node A", "Node B"]},
        "egress": {"status": "ok", "durationMs": 9, "country": "DE", "reflectors": []}}));
    let prev = patched(json!({"asn": asn("AS100", "NL")}));
    let f = evaluate_findings(&cur, Some(&prev));
    let changed = msg(&find(&f, C::AsnChanged).detail);
    assert_eq!(
        (arg(changed, "previous"), arg(changed, "current")),
        ("AS100", "AS200")
    );
    assert_eq!(
        find(&f, C::CidrSharedWithProfile).evidence["sharedCount"],
        Evidence::Num(2.0)
    );
    let mismatch = find(&f, C::EgressCountryMismatch);
    assert_eq!(mismatch.severity, Severity::Warning);
    assert_eq!(mismatch.evidence["egress"], Evidence::from("DE"));
    let same = patched(json!({"asn": asn("AS200", "DE"),
        "egress": {"status": "ok", "durationMs": 9, "country": "de", "reflectors": []}}));
    assert!(!codes(&evaluate_findings(&same, None)).contains(&C::EgressCountryMismatch));
}

/// liveServerProbe.extended.test.ts:284-393.
#[test]
fn extended_vectors() {
    let geo = patched(
        json!({"dns": {"discrepancies": ["Google DoH resolves … (GeoDNS / split-horizon detected)"]}}),
    );
    let f = evaluate_findings(&geo, None);
    let d = find(&f, C::DnsResolverDiscrepancy);
    assert_eq!(d.severity, Severity::Info);
    assert!(matches!(&d.detail, Text::Legacy(s) if s.contains("GeoDNS")));

    let auth = patched(
        json!({"handshake": {"status": "auth_failed", "durationMs": 9,
        "protocol": "vless", "error": "VLESS credentials rejected"}}),
    );
    let f = evaluate_findings(&auth, None);
    let failed = find(&f, C::TunnelHandshakeFailed);
    assert_eq!(failed.severity, Severity::Error);
    assert!(arg(msg(&failed.detail), "error").contains("VLESS"));

    let exit = patched(
        json!({"egress": {"status": "ok", "durationMs": 9, "exitIpv4": "95.165.12.34",
        "underlayPath": "route-selected", "reflectors": []}}),
    );
    let f = evaluate_findings(&exit, None);
    assert!(
        f.iter().all(|f| f.code != C::Other),
        "no DIRECT_UNDERLAY_LEAK-like code"
    );

    let hole = patched(
        json!({"pmtu": {"status": "blackhole_suspected", "durationMs": 9,
        "destination": "198.51.100.1", "method": "icmp-df"}}),
    );
    assert_eq!(
        find(&evaluate_findings(&hole, None), C::PmtuBlackholeSuspected).severity,
        Severity::Warning
    );
    let low = patched(json!({"pmtu": {"status": "lower_bound", "durationMs": 9,
        "destination": "198.51.100.1", "method": "icmp-df", "pmtu": 1280}}));
    let f = evaluate_findings(&low, None);
    assert_eq!(arg(msg(&find(&f, C::LowPmtu).detail), "pmtu"), "1280");
}

fn with_speeds(speeds: &[f64]) -> LiveCheck {
    let mut c = patched(json!({}));
    let samples = speeds
        .iter()
        .enumerate()
        .map(|(i, mbps)| crate::live::model::ThroughputSample {
            index: i as u32,
            bytes: 4 * 1024 * 1024,
            duration_ms: 1000,
            throughput_mbps: *mbps,
            ttfb_ms: Some(80),
            stall_count: 0,
            max_inter_chunk_gap_ms: 0,
            complete: true,
        })
        .collect();
    c.throughput = Some(summarize_throughput(
        samples,
        "speed.cloudflare.com/__down",
        3000,
        None,
    ));
    c
}

/// liveServerProbe.extended.test.ts:395-458: a median below 65 % of the previous one.
#[test]
fn throughput_degraded() {
    let f = evaluate_findings(
        &with_speeds(&[8.0, 7.0, 8.0]),
        Some(&with_speeds(&[20.0, 21.0, 19.0])),
    );
    let d = msg(&find(&f, C::ThroughputDegradedFromPrevious).detail);
    assert_eq!((arg(d, "previous"), arg(d, "current")), ("20", "8"));
    let f = evaluate_findings(
        &with_speeds(&[18.0, 17.0, 18.0]),
        Some(&with_speeds(&[20.0, 21.0, 19.0])),
    );
    assert!(!codes(&f).contains(&C::ThroughputDegradedFromPrevious));
}

/// residualReview2.test.ts:182-201: egress failures without a handshake failure.
#[test]
fn egress_findings() {
    let error = patched(json!({"handshake": {"status": "ok", "durationMs": 9},
        "egress": {"status": "error", "durationMs": 9, "reflectors": []}}));
    let f = evaluate_findings(&error, None);
    assert!(codes(&f).contains(&C::EgressVerificationFailed));
    assert!(!codes(&f).contains(&C::TunnelHandshakeFailed));
    let partial = patched(
        json!({"egress": {"status": "partial", "durationMs": 9, "reflectors": [],
        "discrepancy": {"key": "probes.live.egress.discrepancy",
                        "args": [["first", "cloudflare-trace=198.51.100.7"], ["second", "ipify=198.51.100.8"]]}}}),
    );
    let f = evaluate_findings(&partial, None);
    let p = find(&f, C::EgressPartial);
    assert_eq!(
        msg(&p.detail).key,
        "probes.live.egress.discrepancy",
        "B-09: the reason is shown"
    );
}

/// twitchHlsProbe.test.ts:160-236.
#[test]
fn twitch_findings() {
    let media = |risk: bool, reachable: bool, status: &str| {
        patched(
            json!({"mediaStream": {"status": status, "durationMs": 9, "error2000Risk": risk,
            "twitchHlsReachable": reachable, "quicFallbackGuarded": !risk, "testedEndpoints": []}}),
        )
    };
    let f = evaluate_findings(&media(true, true, "warning"), None);
    let risk = find(&f, C::TwitchMediaError2000Risk);
    assert_eq!(risk.severity, Severity::Warning);
    assert_eq!(risk.evidence["error2000Risk"], Evidence::Bool(true));
    assert!(codes(&evaluate_findings(&media(false, true, "ok"), None)).contains(&C::TwitchHlsOk));
    let f = evaluate_findings(&media(false, false, "error"), None);
    assert_eq!(
        find(&f, C::TwitchMediaUnreachable).severity,
        Severity::Warning
    );
}

/// §3.10 tail: split-tunnel conflict and read failure.
#[test]
fn split_tunnel_findings() {
    let conflict = patched(json!({"splitTunnel": {"status": "warning", "enabled": true,
        "duplicateProcessNames": ["browser.exe"], "directRuleCount": 1, "defaultOutbound": "proxy-out"}}));
    let f = evaluate_findings(&conflict, None);
    assert_eq!(
        find(&f, C::SplitTunnelRuleConflict).evidence["duplicateProcessNames"],
        Evidence::from("browser.exe")
    );
    let failed = patched(json!({"splitTunnel": {"status": "error", "error": "rules unreadable"}}));
    let f = evaluate_findings(&failed, None);
    assert_eq!(
        arg(
            msg(&find(&f, C::SplitTunnelDiagnosticsFailed).detail),
            "error"
        ),
        "rules unreadable"
    );
}
