//! Pure parts: history diff, baseline, sanitising, throughput summary and meter, split tunnel,
//! egress aggregation, media verdict, failure classes (live-probe §7.2, §7.9-§7.11, §7.14-§7.15).
use std::time::{Duration, Instant};

use serde_json::json;

use super::{arg, msg, patched, row};
use crate::key_health::{HealthReason, classify_failure};
use crate::live::engine_probe::status_of;
use crate::live::model::{
    EgressStatus, HandshakeStatus, Ipv6Status, MediaEndpoint, MediaStatus, Reflector,
    ReflectorStatus, SplitTunnelStatus, ThroughputSample, ThroughputStatus,
};
use crate::live::reflect::{aggregate_egress, summarize_media};
use crate::live::throughput::{Meter, summarize_throughput};
use crate::live::{
    SplitTunnelRules, diff, is_baseline, sanitize, summarize_split_tunnel, target_key,
};

/// liveServerHistory.test.ts:144-235 and liveServerProbe.extended.test.ts:208-282.
#[test]
fn diff_vectors() {
    let prev = patched(
        json!({"dns": {"a": ["1.2.3.4"]}, "tls": {"status": "ok", "fingerprint": "OLD"},
        "asn": {"asn": "AS111", "org": "", "network": "", "country": "Germany"},
        "latency": {"avg": 50},
        "openPorts": [{"port": 80, "open": true, "state": "open"}, {"port": 443, "open": true, "state": "open"},
                      {"port": 8443, "open": false, "state": "closed"}]}),
    );
    let cur = patched(
        json!({"dns": {"a": ["5.6.7.8"]}, "tls": {"status": "ok", "fingerprint": "NEW"},
        "asn": {"asn": "AS222", "org": "", "network": "", "country": "Netherlands"},
        "latency": {"avg": 150},
        "openPorts": [{"port": 80, "open": false, "state": "closed"}, {"port": 443, "open": true, "state": "open"},
                      {"port": 8443, "open": true, "state": "open"}]}),
    );
    let d = diff(&cur, &prev);
    assert!(
        d.ip_changed && d.tls_cert_changed && d.asn_changed && d.country_changed && d.latency_spike
    );
    assert_eq!(
        (d.previous_ips, d.current_ips),
        (vec!["1.2.3.4".to_owned()], vec!["5.6.7.8".to_owned()])
    );
    assert_eq!(d.previous_tls_fingerprint.as_deref(), Some("OLD"));
    assert_eq!(
        (d.previous_country.as_deref(), d.current_country.as_deref()),
        (Some("Germany"), Some("Netherlands"))
    );
    assert_eq!(
        (d.previous_avg_latency, d.current_avg_latency),
        (Some(50), Some(150))
    );
    assert!(d.ports_changed);
    assert_eq!((d.closed_ports, d.new_open_ports), (vec![80], vec![8443]));
    let flags = diff(&cur, &prev).flags();
    assert_eq!(flags.ip_changed, Some(true));
}

/// Audit defect 6 + second review: untested and timed-out ports are not "closed".
#[test]
fn ports_diff_ignores_lost_probes() {
    let ports = |list: serde_json::Value| patched(json!({ "openPorts": list }));
    let ext = ports(
        json!([{"port": 443, "open": true, "state": "open"}, {"port": 8443, "open": true, "state": "open"}]),
    );
    let basic = ports(json!([{"port": 443, "open": true, "state": "open"}]));
    let d = diff(&basic, &ext);
    assert!(!d.ports_changed && d.closed_ports.is_empty());
    for state in ["timeout", "filtered"] {
        let lost = ports(json!([{"port": 443, "open": false, "state": state}]));
        assert!(diff(&lost, &basic).closed_ports.is_empty(), "{state}");
    }
    let closed = ports(json!([{"port": 443, "open": false, "state": "closed"}]));
    assert_eq!(diff(&closed, &basic).closed_ports, vec![443]);
}

/// liveServerProbe.extended.test.ts:208-282 + extendedReviewFixed.test.ts:158-172.
#[test]
fn handshake_egress_pmtu_diff() {
    let base = patched(json!({"dns": {"a": ["198.51.100.1"]},
        "handshake": {"status": "ok", "protocol": "vmess"},
        "egress": {"status": "ok", "exitIpv4": "198.51.100.42", "reflectors": []},
        "pmtu": {"status": "ok", "destination": "198.51.100.42", "family": 4, "method": "icmp-df", "pmtu": 1500}}));
    let auth = patched(json!({"handshake": {"status": "auth_failed"}}));
    assert!(diff(&auth, &base).handshake_changed);
    let exit =
        patched(json!({"egress": {"status": "ok", "exitIpv4": "203.0.113.88", "reflectors": []}}));
    assert!(diff(&exit, &base).egress_changed);
    let lower = patched(
        json!({"pmtu": {"status": "lower_bound", "destination": "198.51.100.42",
        "family": 4, "method": "icmp-df", "pmtu": 1372}}),
    );
    let d = diff(&lower, &base);
    assert!(d.pmtu_changed);
    assert_eq!((d.previous_pmtu, d.current_pmtu), (Some(1500), Some(1372)));
    let other_method = patched(
        json!({"pmtu": {"status": "lower_bound", "destination": "198.51.100.42",
        "family": 6, "method": "icmp-df", "pmtu": 1400}}),
    );
    let nlmtu = patched(
        json!({"pmtu": {"status": "ok", "destination": "198.51.100.42",
        "family": 4, "method": "interface-nlmtu", "pmtu": 1500}}),
    );
    assert!(!diff(&other_method, &nlmtu).pmtu_changed, "incomparable");
    let skipped = patched(json!({"handshake": {"status": "skipped"}}));
    assert!(
        !diff(&skipped, &base).handshake_changed,
        "skipped says nothing about the server"
    );
}

/// liveServerHistory.test.ts:127-142 + B-18: only a check whose server answered is a baseline.
#[test]
fn baseline_rule() {
    let ok = row("c-1", Some("p-1"), 0);
    assert!(is_baseline(&ok, Some(443)));
    assert!(!is_baseline(&ok, Some(8443)), "other port");
    let dns_only =
        patched(json!({"reachability": {"status": "error", "tcpReachable": false, "port": 443}}));
    assert!(!is_baseline(&dns_only, None));
    let udp = patched(
        json!({"reachability": {"status": "not_checked", "reason": "udp-transport", "port": 443},
        "handshake": {"status": "ok"}}),
    );
    assert!(is_baseline(&udp, None));
    let cancelled = patched(json!({"cancelled": true}));
    assert!(!is_baseline(&cancelled, None));
}

#[test]
fn target_keys() {
    assert_eq!(target_key(Some("p1"), "Host.Example"), "profile:p1");
    assert_eq!(target_key(None, " Host.Example "), "host:host.example");
    assert_eq!(target_key(Some(" "), ""), "global");
}

const UUID: &str = "00000000-0000-4000-8000-000000000000";

/// liveServerProbe.extended.test.ts:164-206 + liveServerHistory.test.ts:81-110: UUIDs leave free
/// text, secret-named evidence goes, constants and numbers stay.
#[test]
fn sanitize_redacts_free_text_only() {
    let mut c = patched(json!({
        "handshake": {"status": "auth_failed", "protocol": "vless",
            "error": format!("Authentication failed for uuid: {UUID} with secret abc"),
            "evidence": {"detail": format!("Client uuid {UUID} rejected by remote server"),
                         "transport": "reality", "inboundPort": 12345}},
        "findings": [{"code": "TUNNEL_HANDSHAKE_FAILED", "severity": "error", "title": "t",
            "detail": {"key": "probes.live.finding.handshakeFailed.detail", "args": [["error", format!("user {UUID}")]]},
            "evidence": {"host": "vpn.example.com", "userUuid": UUID, "privateKey": "k", "serverPassword": "p",
                         "shortId": "ab", "normalValue": 42}}]
    }));
    sanitize(&mut c);
    let h = c.handshake.as_ref().unwrap();
    let error = h.error.as_deref().unwrap();
    assert!(
        error.starts_with("Authentication failed") && !error.contains(UUID),
        "{error}"
    );
    let ev = h.evidence.as_ref().unwrap();
    assert!(!ev.detail.as_deref().unwrap().contains(UUID));
    assert_eq!(
        (
            h.protocol.as_deref(),
            ev.transport.as_deref(),
            ev.inbound_port
        ),
        (Some("vless"), Some("reality"), Some(12345))
    );
    let f = &c.findings[0];
    let keys: Vec<&str> = f.evidence.keys().map(String::as_str).collect();
    assert_eq!(keys, ["host", "normalValue"]);
    assert!(!arg(msg(&f.detail), "error").contains(UUID));
    assert_eq!(c.id, "check-1", "ids are not redacted");
}

/// liveServerHistory.integrity.test.ts:256-285: redirect targets keep scheme, host and decoded
/// path only; credentials in free text are masked.
#[test]
fn sanitize_location_and_secrets() {
    let mut c = patched(json!({
        "error": "ignored legacy field",
        "http": {"status": "ok", "statusCode": 302, "targetPort": 443, "isTls": true,
                 "locationHeader": "https://user:password@redirect.example/login?token=secret#private"},
        "dns": {"error": r"password=PASSWORD_SECRET Bearer TOKEN_SECRET vless://UUID_SECRET@vpn.example:443 C:\Users\private-user\config.json"}
    }));
    sanitize(&mut c);
    assert_eq!(
        c.http.as_ref().unwrap().location_header.as_deref(),
        Some("https://redirect.example/login")
    );
    let dns_error = c.dns.timed.error.clone().unwrap();
    for secret in [
        "PASSWORD_SECRET",
        "TOKEN_SECRET",
        "UUID_SECRET",
        "private-user",
    ] {
        assert!(!dns_error.contains(secret), "{secret} in {dns_error}");
    }
    let encoded = crate::live::sanitize::location(
        "https://redirect.example/password%3DPRIVATE_SECRET/11111111-2222-3333-4444-555555555555",
    );
    assert!(
        !encoded.contains("PRIVATE_SECRET") && !encoded.contains("11111111-2222"),
        "{encoded}"
    );
}

fn sample(i: u32, mbps: f64, gap: u64) -> ThroughputSample {
    ThroughputSample {
        index: i,
        bytes: 4 * 1024 * 1024,
        duration_ms: (4.0 * 1024.0 * 1024.0 * 8.0 / (mbps * 1e6) * 1000.0).round() as u64,
        throughput_mbps: mbps,
        ttfb_ms: Some(80 + u64::from(i)),
        stall_count: u32::from(gap >= 750),
        max_inter_chunk_gap_ms: gap,
        complete: true,
    }
}

/// liveServerProbe.extended.test.ts:395-458 (summarizeThroughputSamples).
#[test]
fn throughput_summary() {
    let t = summarize_throughput(
        vec![sample(0, 10.0, 0), sample(1, 24.0, 0), sample(2, 12.0, 900)],
        "e",
        1,
        None,
    );
    assert_eq!(t.status, ThroughputStatus::Warning);
    assert_eq!(
        (t.median_mbps, t.min_mbps, t.max_mbps),
        (Some(12.0), Some(10.0), Some(24.0))
    );
    assert_eq!(
        (t.variability_pct, t.stall_count, t.max_inter_chunk_gap_ms),
        (Some(117), Some(1), Some(900))
    );
    let t = summarize_throughput(
        vec![sample(0, 2.0, 0), sample(1, 2.1, 0), sample(2, 1.9, 0)],
        "e",
        1,
        None,
    );
    assert_eq!(
        (t.status, t.median_mbps, t.variability_pct),
        (ThroughputStatus::Ok, Some(2.0), Some(10))
    );
    assert_eq!(
        msg(t.detail.as_ref().unwrap()).key,
        "probes.live.throughput.stable"
    );
    let t = summarize_throughput(
        vec![sample(0, 10.0, 0), sample(1, 10.5, 0)],
        "e",
        1,
        Some("sample 3 timed out".into()),
    );
    assert_eq!(t.status, ThroughputStatus::Warning);
    assert_eq!(t.error.as_deref(), Some("sample 3 timed out"));
    assert_eq!(
        msg(t.detail.as_ref().unwrap()).key,
        "probes.live.throughput.partial"
    );
    let none = summarize_throughput(Vec::new(), "e", 1, None);
    assert_eq!(none.status, ThroughputStatus::Skipped);
    assert_eq!(
        summarize_throughput(Vec::new(), "e", 1, Some("x".into())).status,
        ThroughputStatus::Error
    );
}

/// B-10 / B-11: the rate is taken over the body window; a stopped sample keeps its bytes.
#[test]
fn meter_body_window_and_partial() {
    let t0 = Instant::now();
    let mut m = Meter::new(t0);
    m.chunk_at(64 * 1024, t0 + Duration::from_millis(300));
    m.chunk_at(4 * 1024 * 1024 - 64 * 1024, t0 + Duration::from_millis(636));
    let s = m.sample(0, true, t0 + Duration::from_millis(640)).unwrap();
    assert_eq!(s.ttfb_ms, Some(300));
    assert!(
        (s.throughput_mbps - 99.86).abs() < 0.05,
        "{}",
        s.throughput_mbps
    );
    assert_eq!(s.duration_ms, 640);
    let mut m = Meter::new(t0);
    m.chunk_at(1024 * 1024, t0 + Duration::from_millis(300));
    m.chunk_at(1024 * 1024, t0 + Duration::from_millis(1300));
    let s = m.sample(1, false, t0 + Duration::from_secs(8)).unwrap();
    assert_eq!(
        (s.bytes, s.complete, s.stall_count),
        (2 * 1024 * 1024, false, 1)
    );
    assert!(
        Meter::new(t0).sample(2, false, t0).is_none(),
        "no body, no sample"
    );
}

/// liveServerProbe.extended.test.ts:460-481 + B-32 (names compared case-insensitively).
#[test]
fn split_tunnel_summary() {
    let rules = |enabled: bool, direct: &[&str], vpn: &[&str]| SplitTunnelRules {
        enabled,
        direct_names: direct.iter().map(|s| (*s).to_owned()).collect(),
        direct_paths: Vec::new(),
        vpn_names: vpn.iter().map(|s| (*s).to_owned()).collect(),
    };
    let s = summarize_split_tunnel(&rules(true, &[], &[]));
    assert_eq!(
        (s.status, s.default_outbound.as_str(), s.direct_rule_count),
        (SplitTunnelStatus::Ok, "proxy-out", 0)
    );
    assert_eq!(
        msg(s.detail.as_ref().unwrap()).key,
        "probes.live.split.none"
    );
    let s = summarize_split_tunnel(&rules(true, &["browser.exe"], &["browser.exe"]));
    assert_eq!(
        (s.status, s.duplicate_process_names.clone()),
        (SplitTunnelStatus::Warning, vec!["browser.exe".to_owned()])
    );
    assert_eq!(arg(msg(s.detail.as_ref().unwrap()), "names"), "browser.exe");
    let s = summarize_split_tunnel(&rules(true, &["chrome.exe"], &["Chrome.exe"]));
    assert_eq!(s.duplicate_process_names, vec!["chrome.exe".to_owned()]);
    let s = summarize_split_tunnel(&rules(false, &["browser.exe"], &["browser.exe"]));
    assert_eq!((s.status, s.enabled), (SplitTunnelStatus::Skipped, false));
}

fn reflector(source: &str, ip: Option<&str>, status: ReflectorStatus) -> Reflector {
    Reflector {
        source: source.into(),
        family: ip.map(|ip| if ip.contains(':') { 6 } else { 4 }),
        ip: ip.map(str::to_owned),
        country: None,
        duration_ms: 5,
        status,
        error: (status != ReflectorStatus::Ok).then(|| "boom".into()),
    }
}

/// §3.14.3 aggregation with B-09 (stored discrepancy) and B-34 (one IPv6 verdict).
#[test]
fn egress_aggregation() {
    use ReflectorStatus::{Error, Ok, Unsupported};
    let both = aggregate_egress(
        vec![
            reflector("cloudflare-trace", Some("198.51.100.7"), Ok),
            reflector("ipify", Some("198.51.100.8"), Ok),
        ],
        None,
        10,
    );
    assert_eq!(both.status, EgressStatus::Partial);
    let d = msg(both.discrepancy.as_ref().unwrap());
    assert_eq!(arg(d, "first"), "cloudflare-trace=198.51.100.7");
    assert_eq!(arg(d, "second"), "ipify=198.51.100.8");
    let agree = aggregate_egress(
        vec![
            reflector("cloudflare-trace", Some("2001:4860::8"), Ok),
            reflector("ipify", Some("198.51.100.7"), Ok),
            reflector("ipify-v6", None, Error),
        ],
        "198.51.100.7".parse().ok(),
        10,
    );
    assert_eq!(agree.status, EgressStatus::Ok);
    assert_eq!(
        agree.ipv6_status,
        Some(Ipv6Status::Ok),
        "a v6 exit seen by the trace is not overwritten"
    );
    assert_eq!(agree.exit_ipv6.as_deref(), Some("2001:4860::8"));
    assert_eq!(agree.matches_endpoint, Some(true));
    let v4_only = aggregate_egress(
        vec![
            reflector("ipify", Some("198.51.100.7"), Ok),
            reflector("ipify-v6", None, Unsupported),
        ],
        None,
        10,
    );
    assert_eq!(
        (v4_only.status, v4_only.ipv6_status),
        (EgressStatus::Partial, Some(Ipv6Status::Unsupported))
    );
    let none = aggregate_egress(vec![reflector("ipify", None, Error)], None, 10);
    assert_eq!(
        (none.status, none.error.as_deref()),
        (EgressStatus::Error, Some("boom"))
    );
}

/// twitchHlsProbe.test.ts:110-156 + §3.13 status texts.
#[test]
fn media_verdict() {
    let ep = |reachable: bool| MediaEndpoint {
        endpoint: "usher.ttvnw.net (HLS Origin)".into(),
        reachable,
        latency_ms: Some(5),
        protocol: None,
        error: None,
    };
    let guarded = summarize_media(vec![ep(true), ep(true)], true, true, 5);
    assert_eq!(
        (guarded.status, guarded.error2000_risk),
        (MediaStatus::Ok, Some(false))
    );
    assert_eq!(
        msg(guarded.detail.as_ref().unwrap()).key,
        "probes.live.media.guarded"
    );
    let udp = summarize_media(vec![ep(true)], true, false, 5);
    assert_eq!(
        msg(udp.detail.as_ref().unwrap()).key,
        "probes.live.media.udp"
    );
    let risk = summarize_media(vec![ep(true)], false, false, 5);
    assert_eq!(
        (risk.status, risk.error2000_risk),
        (MediaStatus::Warning, Some(true))
    );
    let down = summarize_media(vec![ep(false), ep(false)], true, true, 5);
    assert_eq!(
        (down.status, down.twitch_hls_reachable),
        (MediaStatus::Error, Some(false))
    );
}

/// liveServerProbe.extended.test.ts:147-162 + B-37: failure classes and their handshake status;
/// an auth error inside a debug log full of "tls" words stays an auth failure.
#[test]
fn failure_classes() {
    let class = |err: &str| classify_failure(false, "", err);
    assert_eq!(
        class("user authentication failed: bad key"),
        HealthReason::AuthFailed
    );
    assert_eq!(
        class("wrong uuid in request header"),
        HealthReason::AuthFailed
    );
    assert_eq!(
        class("reality verification failed: invalid server name"),
        HealthReason::TlsFailed
    );
    assert_eq!(
        class("x509: certificate signed by unknown authority"),
        HealthReason::TlsFailed
    );
    assert_eq!(
        class("dial tcp 198.51.100.1:443: i/o timeout"),
        HealthReason::Timeout
    );
    assert_eq!(class("connection refused"), HealthReason::Timeout);
    let log = "outbound/vless[proxy-out]: tls handshake done\ninbound: authentication failed";
    assert_eq!(
        classify_failure(false, log, "socks reply 1: general failure"),
        HealthReason::AuthFailed
    );
    assert_eq!(
        status_of(HealthReason::AuthFailed),
        HandshakeStatus::AuthFailed
    );
    assert_eq!(
        status_of(HealthReason::Hy2AuthFailed),
        HandshakeStatus::AuthFailed
    );
    assert_eq!(status_of(HealthReason::Timeout), HandshakeStatus::Timeout);
    assert_eq!(
        status_of(HealthReason::TlsFailed),
        HandshakeStatus::TransportFailed
    );
    assert_eq!(
        status_of(HealthReason::Hy2UdpBlocked),
        HandshakeStatus::TransportFailed
    );
}

/// B-03 / B-05 (§7.14): a UDP transport skips the TCP, TLS and HTTP probes; a REALITY front
/// skips the direct TLS probe; TLS / HTTP run only in extended mode.
#[test]
fn probe_gating_from_the_profile() {
    use crate::live::CheckMode;
    use crate::live::check::Facts;
    use crate::live_stages::NotCheckedReason as R;
    let facts = Facts::of_profile(&super::engine::target(super::engine::hysteria2()));
    assert!(facts.udp);
    assert_eq!(facts.tls_skip(CheckMode::Extended), Some(R::UdpTransport));
    let mut reality = super::engine::vless();
    if let Some(tls) = reality.tls.as_mut() {
        tls.reality = Some(vpnte_profiles::model::Reality::default());
    }
    let facts = Facts::of_profile(&super::engine::target(reality));
    assert_eq!(facts.tls_skip(CheckMode::Extended), Some(R::Reality));
    let plain = Facts::of_profile(&super::engine::target(super::engine::vless()));
    assert_eq!(
        (plain.tls_applicable, plain.sni.as_deref()),
        (true, Some("vpn.example.test"))
    );
    assert_eq!(plain.tls_skip(CheckMode::Basic), Some(R::BasicMode));
    assert_eq!(plain.tls_skip(CheckMode::Extended), None);
}
