use std::collections::HashMap;
use std::time::Duration;

use parking_lot::Mutex;

use super::*;

type Lookup = Result<Vec<Answer>, String>;

/// Scripted backend; unknown names answer empty, `slow` names answer after 3 s.
#[derive(Default)]
struct Fake {
    a: HashMap<&'static str, Lookup>,
    aaaa: HashMap<&'static str, Lookup>,
    ptr: HashMap<IpAddr, Result<Vec<String>, String>>,
    doh: HashMap<(&'static str, bool), Result<DohResponse, String>>,
    slow: bool,
    calls: Mutex<Vec<String>>,
}

impl DnsBackend for Fake {
    fn lookup(&self, name: &str, v6: bool) -> impl Future<Output = Lookup> + Send {
        self.calls
            .lock()
            .push(format!("{} {name}", if v6 { "AAAA" } else { "A" }));
        let table = if v6 { &self.aaaa } else { &self.a };
        let answer = table.get(name).cloned().unwrap_or(Ok(Vec::new()));
        let slow = self.slow;
        async move {
            if slow {
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
            answer
        }
    }
    fn reverse(&self, ip: IpAddr) -> impl Future<Output = Result<Vec<String>, String>> + Send {
        self.calls.lock().push(format!("PTR {ip}"));
        let answer = self.ptr.get(&ip).cloned().unwrap_or(Ok(Vec::new()));
        async move { answer }
    }
    fn doh(
        &self,
        r: DohResolver,
        name: &str,
        v6: bool,
    ) -> impl Future<Output = Result<DohResponse, String>> + Send {
        self.calls
            .lock()
            .push(format!("DOH {} {name} {v6}", r.id()));
        let answer = self
            .doh
            .get(&(r.id(), v6))
            .cloned()
            .unwrap_or(Ok(DohResponse::default()));
        async move { answer }
    }
}

fn addr(name: &str, ip: &str, ttl: u32) -> Answer {
    Answer {
        name: name.into(),
        data: AnswerData::Addr(ip.parse().unwrap()),
        ttl,
    }
}

fn doh_ok(rtype: u16, values: &[&str]) -> Result<DohResponse, String> {
    let answer = values
        .iter()
        .map(|v| DohAnswer {
            name: "h.example.".into(),
            rtype,
            ttl: Some(300),
            data: (*v).into(),
        })
        .collect();
    Ok(DohResponse {
        status: Some(0),
        ad: Some(false),
        tc: Some(false),
        answer,
    })
}

/// AT-05-001: an IP literal gets PTR only, no forward queries (§7.1).
#[tokio::test]
async fn ip_literal_skips_forward_dns() {
    let ip: IpAddr = "1.2.3.4".parse().unwrap();
    let fake = Fake {
        ptr: HashMap::from([(ip, Ok(vec!["node1.vpnprovider.net".into()]))]),
        ..Fake::default()
    };
    let (dns, reverse) = probe_dns(&fake, "1.2.3.4", true, &CancellationToken::new()).await;
    assert_eq!(dns.timed.status, TimedStatus::Ok);
    assert_eq!(
        (dns.a.clone(), dns.aaaa.len()),
        (vec!["1.2.3.4".to_owned()], 0)
    );
    assert_eq!(reverse, ["node1.vpnprovider.net"]);
    assert_eq!(fake.calls.lock().clone(), ["PTR 1.2.3.4"]);
    assert_eq!(dns.resolvers[0].resolver_id, "system");
    assert_eq!(dns.records[0].kind, DnsRecordType::A);
    // Pre-cancelled literal: still ok, but no PTR.
    let cancel = CancellationToken::new();
    cancel.cancel();
    let fake = Fake::default();
    let (dns, reverse) = probe_dns(&fake, "[2001:db8::1]", false, &cancel).await;
    assert_eq!(
        (dns.timed.status, dns.aaaa.clone()),
        (TimedStatus::Ok, vec!["2001:db8::1".to_owned()])
    );
    assert!(reverse.is_empty() && fake.calls.lock().is_empty());
}

/// AT-05-001: CNAME chain, min TTL, timings and the DoH comparison (§7.1).
#[tokio::test]
async fn resolves_with_cname_and_doh() {
    let host = "myvpn.example.com";
    let cname = Answer {
        name: host.into(),
        data: AnswerData::Cname("edge.cloudflare.com".into()),
        ttl: 300,
    };
    let fake = Fake {
        a: HashMap::from([(
            host,
            Ok(vec![
                cname,
                addr("edge.cloudflare.com", "104.21.5.10", 300),
                addr("edge.cloudflare.com", "104.21.5.11", 120),
            ]),
        )]),
        aaaa: HashMap::from([(
            host,
            Ok(vec![addr("edge.cloudflare.com", "2606:4700::1", 300)]),
        )]),
        doh: HashMap::from([
            (("google-doh", false), doh_ok(1, &["104.21.5.10"])),
            (("cloudflare-doh", false), doh_ok(1, &["104.21.5.11"])),
        ]),
        ..Fake::default()
    };
    let (dns, _) = probe_dns(&fake, host, true, &CancellationToken::new()).await;
    assert_eq!(dns.timed.status, TimedStatus::Ok);
    assert_eq!(dns.a, ["104.21.5.10", "104.21.5.11"]);
    assert_eq!(dns.aaaa, ["2606:4700::1"]);
    assert_eq!(dns.cname_chain, ["edge.cloudflare.com"]);
    assert_eq!(dns.ttl, Some(120));
    assert!(dns.timings.as_ref().unwrap().a_ms.is_some());
    let ids: Vec<&str> = dns
        .resolvers
        .iter()
        .map(|r| r.resolver_id.as_str())
        .collect();
    assert_eq!(ids, ["system", "google-doh", "cloudflare-doh"]);
    assert!(dns.records.iter().any(|r| r.transport == DnsTransport::Doh));
    // Google and Cloudflare disagree with each other but each overlaps the system answer.
    assert_eq!(dns.discrepancies.len(), 1);
    assert_eq!(dns.primary_ip(), Some("104.21.5.10".parse().unwrap()));
}

/// AT-05-001: PTR NXDOMAIN leaves reverseDns empty; AAAA empty is fine (§7.1).
#[tokio::test]
async fn missing_ptr_is_not_an_error() {
    let ip: IpAddr = "1.1.1.1".parse().unwrap();
    let fake = Fake {
        a: HashMap::from([(
            "one.one.one.one",
            Ok(vec![addr("one.one.one.one", "1.1.1.1", 60)]),
        )]),
        ptr: HashMap::from([(ip, Err("ENOTFOUND".into()))]),
        ..Fake::default()
    };
    let (dns, reverse) =
        probe_dns(&fake, "one.one.one.one", false, &CancellationToken::new()).await;
    assert_eq!(dns.timed.status, TimedStatus::Ok);
    assert!(reverse.is_empty());
    assert!(
        !fake.calls.lock().iter().any(|c| c.starts_with("DOH")),
        "basic mode has no DoH"
    );
}

/// AT-00-003: pre-cancelled -> skipped, no resolver touched; cancel mid-query discards
/// late answers (§7.1, §7.7).
#[tokio::test]
async fn cancellation() {
    let cancel = CancellationToken::new();
    cancel.cancel();
    let fake = Fake::default();
    let (dns, _) = probe_dns(&fake, "probe.example", true, &cancel).await;
    assert_eq!(dns.timed.status, TimedStatus::Skipped);
    assert!(dns.timed.error.as_deref().unwrap().contains("Cancelled"));
    assert!(fake.calls.lock().is_empty());

    let fake = Fake {
        slow: true,
        a: HashMap::from([("h.example", Ok(vec![addr("h.example", "192.0.2.7", 60)]))]),
        ..Fake::default()
    };
    let cancel = CancellationToken::new();
    let token = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(30)).await;
        token.cancel();
    });
    let (dns, _) = probe_dns(&fake, "h.example", false, &cancel).await;
    assert_eq!(dns.timed.status, TimedStatus::Error);
    assert_eq!(dns.timed.error.as_deref(), Some(CANCELLED));
    assert!(dns.a.is_empty() && dns.aaaa.is_empty());
}

/// AT-00-003: answers after the 2.5 s query timeout are discarded (§7.7).
#[tokio::test]
async fn late_answers_are_discarded() {
    let fake = Fake {
        slow: true,
        a: HashMap::from([("h.example", Ok(vec![addr("h.example", "192.0.2.7", 60)]))]),
        ..Fake::default()
    };
    let (dns, _) = probe_dns(&fake, "h.example", false, &CancellationToken::new()).await;
    assert_eq!(dns.timed.status, TimedStatus::Error);
    assert_eq!(dns.timed.error.as_deref(), Some(QUERY_TIMEOUT));
    assert!(dns.a.is_empty());
}

/// An unknown name: error from the A query, system resolver marked error.
#[tokio::test]
async fn nxdomain() {
    let fake = Fake {
        a: HashMap::from([("gone.example", Err("ENOTFOUND".into()))]),
        aaaa: HashMap::from([("gone.example", Err("ENOTFOUND".into()))]),
        ..Fake::default()
    };
    let (dns, _) = probe_dns(&fake, "gone.example", false, &CancellationToken::new()).await;
    assert_eq!(
        (dns.timed.status, dns.timed.error.as_deref()),
        (TimedStatus::Error, Some("ENOTFOUND"))
    );
    assert_eq!(dns.resolvers[0].status, ResolverStatus::Error);
    let empty = Fake::default();
    let (dns, _) = probe_dns(&empty, "empty.example", false, &CancellationToken::new()).await;
    assert_eq!(dns.timed.error.as_deref(), Some(NO_RECORDS));
}

/// Discrepancy texts: system vs all DoH, Google vs Cloudflare; private names skip DoH.
#[tokio::test]
async fn discrepancies() {
    let fake = Fake {
        a: HashMap::from([(
            "vpn.example.com",
            Ok(vec![addr("vpn.example.com", "10.0.0.1", 60)]),
        )]),
        doh: HashMap::from([
            (("google-doh", false), doh_ok(1, &["198.51.100.1"])),
            (("cloudflare-doh", false), doh_ok(1, &["198.51.100.2"])),
        ]),
        ..Fake::default()
    };
    let (dns, _) = probe_dns(&fake, "vpn.example.com", true, &CancellationToken::new()).await;
    let keys: Vec<String> = dns
        .discrepancies
        .iter()
        .map(|t| match t {
            Text::Msg(m) => format!(
                "{}|{}",
                m.key,
                m.args
                    .iter()
                    .map(|(_, v)| v.as_str())
                    .collect::<Vec<_>>()
                    .join("|")
            ),
            Text::Legacy(s) => s.clone(),
        })
        .collect();
    assert_eq!(
        keys,
        [
            "probes.liveStages.dns.systemVsDoh|10.0.0.1|198.51.100.1, 198.51.100.2",
            "probes.liveStages.dns.googleVsCloudflare|198.51.100.1|198.51.100.2"
        ]
    );
    let private = Fake::default();
    let _ = probe_dns(&private, "nas.internal", true, &CancellationToken::new()).await;
    assert!(!private.calls.lock().iter().any(|c| c.starts_with("DOH")));
}

fn doh_json(json: &str) -> Result<DohResponse, String> {
    Ok(serde_json::from_str(json).unwrap())
}

/// AT-05-001: queryDoH classification vectors (§7.2, §7.15).
#[test]
fn classifies_doh_answers() {
    let a = doh_json(
        r#"{"Status":0,"AD":true,"Answer":[{"name":"vpn.example.com.","type":1,"TTL":300,"data":"198.51.100.1"},{"name":"vpn.example.com.","type":1,"TTL":300,"data":"198.51.100.2"}]}"#,
    );
    let aaaa = doh_json(
        r#"{"Status":0,"AD":true,"Answer":[{"name":"vpn.example.com.","type":28,"TTL":600,"data":"2001:db8::1"}]}"#,
    );
    let r = classify_doh(DohResolver::Google, a, aaaa, 12);
    assert_eq!(
        (r.status, r.authenticated_data),
        (ResolverStatus::Ok, Some(true))
    );
    let values: Vec<(&str, Option<u32>)> = r
        .records
        .iter()
        .map(|x| (x.value.as_str(), x.ttl))
        .collect();
    assert_eq!(
        values,
        [
            ("198.51.100.1", Some(300)),
            ("198.51.100.2", Some(300)),
            ("2001:db8::1", Some(600))
        ]
    );
    assert_eq!(r.records[0].name, "vpn.example.com");

    let down = || Err::<DohResponse, _>("Network unreachable".to_owned());
    let r = classify_doh(DohResolver::Cloudflare, down(), down(), 5);
    assert_eq!(r.status, ResolverStatus::Error);
    assert!(r.error.as_deref().unwrap().contains("Network unreachable"));
    assert!(r.records.is_empty());

    let servfail = || doh_json(r#"{"Status":2}"#);
    let r = classify_doh(DohResolver::Google, servfail(), servfail(), 5);
    assert_eq!((r.status, r.rcode), (ResolverStatus::Error, Some(2)));
    assert!(r.error.as_deref().unwrap().contains("SERVFAIL"));

    let one =
        r#"{"Status":0,"Answer":[{"name":"h.example.","type":1,"TTL":60,"data":"198.51.100.9"}]}"#;
    let r = classify_doh(
        DohResolver::Google,
        doh_json(one),
        doh_json(r#"{"Status":3}"#),
        5,
    );
    assert_eq!(r.status, ResolverStatus::Partial);
    assert_eq!(
        (r.a_status, r.aaaa_status),
        (Some(FamilyStatus::Ok), Some(FamilyStatus::Nxdomain))
    );

    let r = classify_doh(DohResolver::Google, doh_json(one), servfail(), 5);
    assert_eq!((r.status, r.records.len()), (ResolverStatus::Partial, 1));
    assert_eq!(r.records[0].kind, DnsRecordType::A);
    assert!(r.error.as_deref().unwrap().contains("AAAA: SERVFAIL"));

    let timeout = Err::<DohResponse, _>("DoH request timeout".to_owned());
    let r = classify_doh(DohResolver::Google, timeout, doh_json(r#"{"Status":0}"#), 5);
    assert_eq!(
        (r.a_status, r.status),
        (Some(FamilyStatus::Timeout), ResolverStatus::Error)
    );
    assert_eq!(r.error.as_deref(), Some("DoH request timeout"));

    let empty = classify_doh(DohResolver::Google, doh_json("{}"), doh_json("{}"), 5);
    assert_eq!(
        (empty.status, empty.error.as_deref()),
        (ResolverStatus::Error, Some("No records returned"))
    );
}

/// Old rows deserialise: unknown legacy fields are ignored, `unavailable` reads as not checked.
#[test]
fn reads_legacy_rows() {
    let row = r#"{"status":"ok","durationMs":40,"a":["198.51.100.1"],"aaaa":[],"cnameChain":[],
            "ttl":300,"resolverUsed":"x","records":[{"name":"h","type":"A","value":"198.51.100.1","ttl":300,
            "observedAt":"2026-01-01T00:00:00.000Z","resolverId":"system","transport":"system"}],
            "resolvers":[{"resolverId":"google-doh","resolverName":"Google Public DNS (DoH)","endpoint":"<redacted-url>",
            "status":"partial","durationMs":30,"records":[],"aStatus":"ok","aaaaStatus":"nxdomain"}],
            "discrepancies":["Системный DNS ([a]) не совпадает с публичными DoH ([b])"],"timings":{"aMs":12}}"#;
    let dns: DnsDiagnostics = serde_json::from_str(row).unwrap();
    assert_eq!(dns.timed.status, TimedStatus::Ok);
    assert_eq!(dns.resolvers[0].status, ResolverStatus::Partial);
    assert!(matches!(&dns.discrepancies[0], Text::Legacy(s) if s.starts_with("Системный")));
    let back = serde_json::to_value(&dns).unwrap();
    assert_eq!(back["cnameChain"], serde_json::json!([]));
    assert!(back.get("resolverUsed").is_none());
}
