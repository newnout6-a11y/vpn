//! Locale fragments `probes-live.{ru,en}.json`: valid JSON under `probes.live`, identical keys
//! and placeholders, every key the code uses exists, none is unused, and generated messages
//! carry exactly the template's arguments.
use std::collections::BTreeSet;

use regex::Regex;
use serde_json::json;
use vpnte_base::Msg;

use super::patched;
use crate::live::model::{Finding, Reflector, ReflectorStatus};
use crate::live::reflect::{aggregate_egress, summarize_media};
use crate::live::throughput::summarize_throughput;
use crate::live::{SplitTunnelRules, evaluate_findings, summarize_split_tunnel};
use crate::live_stages::Text;
use crate::test_support::{flatten, placeholders};

const RU: &str = include_str!("../../../locales/probes-live.ru.json");
const EN: &str = include_str!("../../../locales/probes-live.en.json");
const SOURCES: [&str; 12] = [
    include_str!("../check/mod.rs"),
    include_str!("../check/direct.rs"),
    include_str!("../check/progress.rs"),
    include_str!("../engine_probe.rs"),
    include_str!("../findings/mod.rs"),
    include_str!("../findings/network.rs"),
    include_str!("../findings/tunnel.rs"),
    include_str!("../history.rs"),
    include_str!("../reflect.rs"),
    include_str!("../runner.rs"),
    include_str!("../split.rs"),
    include_str!("../throughput.rs"),
];

#[test]
fn fragments_match() {
    let (ru, en) = (flatten(RU), flatten(EN));
    assert_eq!(ru.keys().collect::<Vec<_>>(), en.keys().collect::<Vec<_>>());
    for (key, text) in &ru {
        assert!(key.starts_with("probes.live."), "{key}");
        assert_eq!(placeholders(text), placeholders(&en[key]), "{key}");
    }
}

/// Keys referenced in the sources: literal `probes.live.*` keys and finding rules.
fn used_keys() -> BTreeSet<String> {
    let literal = Regex::new(r#""(probes\.live\.[A-Za-z0-9.]+[A-Za-z0-9])""#).unwrap();
    let rule = Regex::new(r#"(?s)C::\w+,\s*Severity::\w+,\s*"(\w+)""#).unwrap();
    let detail = Regex::new(r#"\bdetail\("(\w+)"\)"#).unwrap();
    let with_error = Regex::new(r#"\bdetail_or_error\("(\w+)""#).unwrap();
    let mut keys = BTreeSet::new();
    for src in SOURCES {
        keys.extend(literal.captures_iter(src).map(|c| c[1].to_owned()));
        keys.extend(
            rule.captures_iter(src)
                .map(|c| format!("probes.live.finding.{}.title", &c[1])),
        );
        keys.extend(
            detail
                .captures_iter(src)
                .map(|c| format!("probes.live.finding.{}.detail", &c[1])),
        );
        for c in with_error.captures_iter(src) {
            keys.insert(format!("probes.live.finding.{}.detail", &c[1]));
            keys.insert(format!("probes.live.finding.{}.detailError", &c[1]));
        }
    }
    keys
}

#[test]
fn every_key_exists_and_is_used() {
    let ru = flatten(RU);
    let used = used_keys();
    for key in &used {
        assert!(ru.contains_key(key), "missing {key}");
    }
    for key in ru.keys() {
        assert!(used.contains(key), "unused {key}");
    }
}

fn texts(findings: &[Finding]) -> Vec<Msg> {
    findings
        .iter()
        .flat_map(|f| [&f.title, &f.detail])
        .filter_map(|t| match t {
            Text::Msg(m) => Some(m.clone()),
            Text::Legacy(_) => None,
        })
        .collect()
}

/// Messages the code builds carry exactly the arguments their templates use.
#[test]
fn generated_messages_fill_their_templates() {
    let ru = flatten(RU);
    let mut msgs: Vec<Msg> = Vec::new();
    let rules = |enabled: bool, direct: &[&str], vpn: &[&str]| SplitTunnelRules {
        enabled,
        direct_names: direct.iter().map(|s| (*s).to_owned()).collect(),
        direct_paths: vec![r"C:\Apps\a.exe".into()],
        vpn_names: vpn.iter().map(|s| (*s).to_owned()).collect(),
    };
    for r in [
        rules(false, &[], &[]),
        rules(true, &["a.exe"], &["a.exe"]),
        rules(true, &["a.exe"], &[]),
    ] {
        msgs.extend(
            summarize_split_tunnel(&r)
                .detail
                .iter()
                .filter_map(|t| match t {
                    Text::Msg(m) => Some(m.clone()),
                    Text::Legacy(_) => None,
                }),
        );
    }
    let partial = summarize_throughput(Vec::new(), "e", 1, None);
    assert!(partial.detail.is_none());
    let reflector = |source: &str, ip: &str| Reflector {
        source: source.into(),
        ip: Some(ip.into()),
        family: Some(4),
        country: None,
        duration_ms: 1,
        status: ReflectorStatus::Ok,
        error: None,
    };
    let egress = aggregate_egress(
        vec![
            reflector("a", "95.165.12.34"),
            reflector("b", "95.165.12.35"),
        ],
        None,
        1,
    );
    if let Some(Text::Msg(m)) = egress.discrepancy {
        msgs.push(m);
    }
    for (udp, quic) in [(true, true), (true, false), (false, false)] {
        if let Some(Text::Msg(m)) = summarize_media(Vec::new(), udp, quic, 1).detail {
            msgs.push(m);
        }
    }
    let kitchen_sink = patched(json!({
        "host": "10.0.0.5",
        "dns": {"a": ["10.0.0.5", "10.0.0.6"], "aaaa": []},
        "reachability": {"status": "error", "error": "ECONNREFUSED", "tcpReachable": false, "port": 443},
        "latency": {"min": 600, "avg": 600, "median": 600, "max": 600, "jitter": 50, "loss": 0.6,
                    "samples": [600], "samplesAttempted": 3},
        "tls": {"status": "ok", "daysRemaining": 3, "validTo": "x", "hostnameVerified": false,
                "authorized": false, "fingerprint": "NEW", "sans": ["a"]},
        "http": {"status": "ok", "statusCode": 503, "locationHeader": "https://a.example/x", "targetPort": 443},
        "openPorts": [{"port": 8080, "open": true, "state": "open"}],
        "asn": {"asn": "AS2", "org": "o", "network": "n", "country": "c", "countryCode": "NL"},
        "infrastructure": {"status": "ok", "sharedCidrWithProfiles": ["x"]},
        "handshake": {"status": "auth_failed", "protocol": "vless", "error": "e"},
        "egress": {"status": "error", "error": "e", "country": "DE", "reflectors": []},
        "pmtu": {"status": "blackhole_suspected", "destination": "d", "method": "icmp-df", "pmtu": 1200},
        "throughput": {"status": "warning", "samples": [], "medianMbps": 1.0},
        "mediaStream": {"status": "warning", "error2000Risk": true, "testedEndpoints": []},
        "splitTunnel": {"status": "error", "error": "e"}
    }));
    let previous = patched(
        json!({"dns": {"a": ["10.0.0.9"]}, "tls": {"status": "ok", "fingerprint": "OLD"},
        "asn": {"asn": "AS1", "org": "o", "network": "n", "country": "c"},
        "throughput": {"status": "ok", "samples": [], "medianMbps": 10.0}}),
    );
    msgs.extend(texts(&evaluate_findings(&kitchen_sink, Some(&previous))));
    let failing = patched(json!({
        "egress": {"status": "partial", "error": "e", "reflectors": []},
        "throughput": {"status": "error", "error": "e", "samples": []},
        "mediaStream": {"status": "error", "twitchHlsReachable": false, "error": "e", "testedEndpoints": []},
        "splitTunnel": {"status": "warning"}
    }));
    msgs.extend(texts(&evaluate_findings(&failing, None)));
    assert!(msgs.len() > 40, "{}", msgs.len());
    for m in msgs {
        let template = ru
            .get(m.key.as_ref())
            .unwrap_or_else(|| panic!("missing {}", m.key));
        let args: BTreeSet<&str> = m.args.iter().map(|(k, _)| k.as_ref()).collect();
        assert_eq!(placeholders(template), args, "{}", m.key);
    }
}
