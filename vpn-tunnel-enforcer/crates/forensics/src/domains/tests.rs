use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use serde_json::json;
use vpnte_core::store::Store;

use super::history::Recent;
use super::*;
use crate::connections::{
    ClashConn, ClashEndpoint, ClashMeta, ClashSnapshot, SourceHealth, parse_snapshot,
};
use crate::test_support::{TempDir, eventually};

fn conn(id: &str, host: &str, up: u64, down: u64) -> ClashConn {
    ClashConn {
        id: id.into(),
        metadata: ClashMeta {
            host: host.into(),
            destination_ip: String::new(),
        },
        upload: up,
        download: down,
        chains: Vec::new(),
    }
}

fn snapshot(conns: Vec<ClashConn>) -> ClashSnapshot {
    ClashSnapshot { connections: conns }
}

fn merge(h: &mut History, conns: Vec<ClashConn>, now: UnixMs) -> bool {
    h.merge_snapshot(&snapshot(conns), now, &mut Vec::new())
}

fn record(h: &History, domain: &str) -> DomainRecord {
    h.list()
        .into_iter()
        .find(|r| r.domain == domain)
        .unwrap_or_else(|| panic!("{domain} not recorded"))
}

fn empty() -> History {
    History::new(DomainsDoc::default())
}

/// trafficConnections.test.ts normalizeHost.
#[test]
fn normalize_host_vectors() {
    let n = |s: &str| normalize_host(s);
    assert_eq!(
        n("  WWW.Example.COM.  ").as_deref(),
        Some("www.example.com")
    );
    assert_eq!(n("example.com:443").as_deref(), Some("example.com"));
    assert_eq!(
        n("[2606:4700:4700::1111]:853").as_deref(),
        Some("2606:4700:4700::1111")
    );
    assert_eq!(n(""), None);
    assert_eq!(n(" . "), None);
    // An unbracketed IPv6 literal keeps its last group (the old code cut it as a ":port").
    assert_eq!(
        n("2606:4700:4700::1111").as_deref(),
        Some("2606:4700:4700::1111")
    );
}

/// trafficConnections.test.ts shouldRecordHost + §7.3 DoH resolvers.
#[test]
fn should_record_vectors() {
    let none = HashSet::new();
    for kept in ["youtube.com", "i.ytimg.com"] {
        assert_eq!(should_record(kept, &none).as_deref(), Some(kept));
    }
    for noise in [
        "13.143.214.3",
        "2606:4700:4700::1111",
        "localhost",
        "printer.local",
        "host.lan",
        "1.0.0.127.in-addr.arpa",
        "_ldap._tcp.dc._msdcs.corp.example",
        "cloudflare-dns.com",
        "dns.google",
        "one.one.one.one",
        "router",
        // Not host names at all (sniffed HTTP Host headers can carry anything).
        "evil host.example.com",
        "x.example.com/<script>",
    ] {
        assert_eq!(should_record(noise, &none), None, "{noise}");
    }
    assert_eq!(
        should_record("пример.рф", &none).as_deref(),
        Some("пример.рф")
    );
    for doh in DOH_INFRA_HOSTS {
        assert_eq!(should_record(doh, &none), None, "{doh}");
    }
    let infra: HashSet<String> = ["vpn.example-server.net".to_owned()].into();
    assert_eq!(should_record("vpn.example-server.net", &infra), None);
    assert_eq!(
        should_record("example-server.net", &infra).as_deref(),
        Some("example-server.net")
    );
}

/// 'adds a new domain with its first connection' and 'accrues only the byte delta'.
#[test]
fn merge_counts_a_visit_then_byte_deltas() {
    let mut h = empty();
    assert!(merge(
        &mut h,
        vec![conn("c1", "github.com", 100, 900)],
        1000
    ));
    let r = record(&h, "github.com");
    assert_eq!((r.connections, r.bytes_up, r.bytes_down), (1, 100, 900));
    assert_eq!((r.first_seen, r.last_seen), (1000, 1000));
    assert!(merge(
        &mut h,
        vec![conn("c1", "github.com", 150, 2000)],
        2000
    ));
    let r = record(&h, "github.com");
    assert_eq!((r.connections, r.bytes_up, r.bytes_down), (1, 150, 2000));
    assert_eq!((r.first_seen, r.last_seen), (1000, 2000));
    // The same counters again: nothing changed.
    assert!(!merge(
        &mut h,
        vec![conn("c1", "github.com", 150, 2000)],
        3000
    ));
}

/// 'counts a brand-new connection id as another visit'.
#[test]
fn new_connection_id_is_another_visit() {
    let mut h = empty();
    let mut hosts = Vec::new();
    h.merge_snapshot(
        &snapshot(vec![conn("c1", "github.com", 10, 10)]),
        1000,
        &mut hosts,
    );
    h.merge_snapshot(
        &snapshot(vec![conn("c2", "github.com", 20, 20)]),
        1500,
        &mut hosts,
    );
    let r = record(&h, "github.com");
    assert_eq!((r.connections, r.bytes_up), (2, 30));
    assert_eq!(hosts, ["github.com", "github.com"]);
}

/// 'drops closed connections from the seen map'.
#[test]
fn closed_connections_leave_the_seen_map() {
    let mut h = empty();
    merge(&mut h, vec![conn("c1", "github.com", 1, 1)], 1000);
    assert!(h.seen.contains_key("c1"));
    let closed = parse_snapshot(br#"{"connections":[]}"#).unwrap();
    assert!(!h.merge_snapshot(&closed, 2000, &mut Vec::new()));
    assert!(!h.seen.contains_key("c1"));
}

/// 'ignores connections with no recordable host'; a `null` list is an empty snapshot.
#[test]
fn unrecordable_hosts_are_ignored() {
    let mut h = empty();
    let conns = vec![
        conn("a", "", 5, 5),
        conn("b", "13.143.214.3", 5, 5),
        conn("c", "cloudflare-dns.com", 5, 5),
        conn("", "github.com", 5, 5),
    ];
    assert!(!merge(&mut h, conns, 1000));
    assert!(h.list().is_empty() && h.seen.is_empty());
    let null = parse_snapshot(br#"{"connections":null}"#).unwrap();
    assert!(!h.merge_snapshot(&null, 1000, &mut Vec::new()));
    assert!(parse_snapshot(b"null").is_err());
}

/// The bounded name maps never exceed their capacity and keep the most recent keys.
#[test]
fn recent_map_is_bounded() {
    let mut map: Recent<u32, u32> = Recent::new(8);
    for i in 0..100 {
        assert!(map.insert(i, i));
        assert!(map.young.len() + map.old.len() <= 8);
    }
    assert_eq!(map.get(&99), Some(99));
    assert_eq!(map.get(&0), None);
    assert!(!map.insert(99, 1));
    assert_eq!(map.get(&99), Some(1));
}

/// Review fix: an address-only flow stays credited to the name it was first matched to, when
/// another name answers with the same (CDN) address and when the name map forgot the address.
#[test]
fn address_only_flow_keeps_its_first_name() {
    let mut h = empty();
    let answer =
        |name: &str, ip: &str| format!("{PREFIX} [42 1ms] dns: exchanged A {name}. 60 IN A {ip}");
    let flow = |down: u64| {
        let mut c = conn("c1", "", 1, down);
        c.metadata.destination_ip = "::ffff:198.51.100.7".into(); // mapped form of the A answer
        vec![c]
    };
    h.observe_log_line(&answer("a.example.org", "198.51.100.7"), 1000);
    assert!(merge(&mut h, flow(100), 1000));
    h.observe_log_line(&answer("b.example.org", "198.51.100.7"), 2000);
    assert!(merge(&mut h, flow(300), 2000));
    // Push 198.51.100.7 out of the bounded name map, then let the name answer again.
    for i in 0..4096u32 {
        let [_, x, y, z] = i.to_be_bytes();
        h.observe_log_line(
            &answer("filler.example.org", &format!("10.{x}.{y}.{z}")),
            3000,
        );
    }
    assert!(merge(&mut h, flow(400), 4000));
    h.observe_log_line(&answer("a.example.org", "198.51.100.7"), 5000);
    assert!(merge(&mut h, flow(500), 5000));
    let a = record(&h, "a.example.org");
    assert_eq!((a.connections, a.bytes_down, a.last_seen), (1, 500, 5000));
    let b = record(&h, "b.example.org");
    assert_eq!((b.connections, b.bytes_down), (0, 0));
}

/// pruneDomains: keep the `max` most recently seen.
#[test]
fn prune_keeps_the_newest() {
    let mut h = empty();
    for i in 0..10 {
        merge(
            &mut h,
            vec![conn(&format!("c{i}"), &format!("d{i}.com"), 1, 1)],
            i,
        );
    }
    h.prune(20);
    assert_eq!(h.list().len(), 10);
    h.prune(3);
    let kept: Vec<String> = h.list().into_iter().map(|r| r.domain).collect();
    assert_eq!(kept, ["d9.com", "d8.com", "d7.com"]);
}

/// NEW: the route-selected outbound is the last element of the reversed chain.
#[test]
fn outbound_is_the_last_chain_element() {
    let mut h = empty();
    let mut c = conn("c1", "github.com", 1, 1);
    c.chains = vec!["proxy-out-a".into(), "proxy-out".into()];
    merge(&mut h, vec![c], 1000);
    assert_eq!(
        record(&h, "github.com").outbound.as_deref(),
        Some("proxy-out")
    );
}

const PREFIX: &str = "+0300 2026-09-25 17:17:06 INFO";

/// trafficHistory.test.ts production lines: INFO answer records are lookups.
#[test]
fn dns_answer_lines_are_recorded() {
    let mut h = empty();
    let lines = [
        "[1657141230 946ms] dns: exchanged A sub.example-provider.cc. 13 IN A 203.0.113.4",
        "[3321415587 5.41s] dns: exchanged A yandex.ru. 7 IN A 213.180.193.56",
        "[3339232011 328ms] dns: cached A example-shop.app. 59 IN A 198.51.100.31",
        "[1 5ms] dns: exchanged AAAA www.youtube.com. 7 IN AAAA 2a00::1",
    ];
    for line in lines {
        assert!(
            h.observe_log_line(&format!("{PREFIX} {line}"), 5000),
            "{line}"
        );
    }
    for domain in [
        "sub.example-provider.cc",
        "yandex.ru",
        "example-shop.app",
        "www.youtube.com",
    ] {
        let r = record(&h, domain);
        assert_eq!((r.lookups, r.connections, r.visits()), (1, 0, 1));
        assert_eq!((r.first_seen, r.last_seen), (5000, 5000));
    }
    // The answered address names a flow whose sniffed host is empty.
    let mut c = conn("c1", "", 10, 20);
    c.metadata.destination_ip = "203.0.113.4".into();
    assert!(merge(&mut h, vec![c], 6000));
    let r = record(&h, "sub.example-provider.cc");
    assert_eq!(
        (r.connections, r.lookups, r.visits(), r.bytes_down),
        (1, 1, 1, 20)
    );
}

/// Lines the old parser matched and the observer ignores: DEBUG summaries and requests (not
/// emitted at `info`), and connection lines (connections come from the Clash snapshot).
#[test]
fn non_answer_lines_are_ignored() {
    let mut h = empty();
    for line in [
        "+0300 2026-09-25 17:17:06 DEBUG [123 0ms] dns: exchanged Example.COM NOERROR 30",
        "+0300 2026-09-25 17:17:06 DEBUG [123 0ms] dns: exchange A chatgpt.com. IN A",
        "+0300 2026-09-25 17:17:06 INFO [5 0ms] inbound/tun[tun-in]: inbound connection to api.ipify.org:80",
        "+0300 2026-09-25 17:17:06 INFO [5 0ms] inbound/tun[tun-in]: inbound connection to 198.51.100.31:443",
        "+0300 2026-09-25 17:17:06 INFO [6 1ms] dns: rejected A ads.example.com. 10 IN A 0.0.0.0",
        "+0300 2026-09-25 17:17:06 INFO [6 1ms] dns: refreshed A old.example.com. 10 IN A 198.51.100.9",
        "+0300 2026-09-25 17:17:06 INFO [6 1ms] dns: exchanged SOA example.com. 300 IN SOA ns.example.com. h.example.com. 1 2 3 4 5",
        "+0300 2026-09-25 17:17:06 INFO [6 1ms] dns: exchanged A one.one.one.one. 300 IN A 1.1.1.1",
    ] {
        assert!(!h.observe_log_line(line, 1000), "{line}");
    }
    assert!(h.list().is_empty());
}

/// NEW (B-21): a CDN canonical name is credited to the name the user asked for.
#[test]
fn cname_chain_credits_the_asked_name() {
    let mut h = empty();
    assert!(!h.observe_log_line(
        &format!("{PREFIX} [7 1ms] dns: exchanged CNAME www.example.com. 300 IN CNAME edge.cdn.example.net."),
        1000
    ));
    assert!(h.observe_log_line(
        &format!("{PREFIX} [7 1ms] dns: exchanged A edge.cdn.example.net. 20 IN A 198.51.100.7"),
        1000
    ));
    assert_eq!(record(&h, "www.example.com").lookups, 1);
    assert!(h.list().iter().all(|r| r.domain != "edge.cdn.example.net"));
    let mut c = conn("c9", "", 1, 2);
    c.metadata.destination_ip = "198.51.100.7".into();
    merge(&mut h, vec![c], 2000);
    assert_eq!(record(&h, "www.example.com").connections, 1);
}

/// NEW (B-21): every record of one exchange is one lookup; ANSI colours are stripped.
#[test]
fn one_exchange_is_one_lookup() {
    let mut h = empty();
    let a = |ctx: &str, ip: &str| {
        format!("{PREFIX} [{ctx} 2ms] dns: exchanged A a.example.org. 60 IN A {ip}")
    };
    assert!(h.observe_log_line(&a("9", "198.51.100.1"), 1000));
    assert!(!h.observe_log_line(&a("9", "198.51.100.2"), 1000));
    assert_eq!(record(&h, "a.example.org").lookups, 1);
    assert!(h.observe_log_line(&a("10", "198.51.100.1"), 2000));
    assert_eq!(record(&h, "a.example.org").lookups, 2);
    let colored = "\x1b[36mINFO\x1b[0m [11 1ms] \x1b[33mdns\x1b[0m: exchanged A b.example.org. 5 IN A 198.51.100.3";
    assert!(h.observe_log_line(colored, 3000));
    assert_eq!(record(&h, "b.example.org").lookups, 1);
}

/// A host that becomes a configured server later is hidden from the list, not deleted.
#[test]
fn later_infra_is_hidden_not_deleted() {
    let mut h = empty();
    merge(
        &mut h,
        vec![conn("c1", "vpn.example-server.net", 1, 1)],
        1000,
    );
    h.set_infra(["VPN.example-server.net:443"]);
    assert!(h.list().is_empty());
    let doc = h.take_doc().unwrap();
    assert!(doc.domains.contains_key("vpn.example-server.net"));
    assert_eq!(h.take_doc(), None); // nothing new since
}

#[test]
fn clear_forgets_records_and_name_maps() {
    let mut h = empty();
    h.observe_log_line(
        &format!("{PREFIX} [1 1ms] dns: exchanged A x.example.org. 5 IN A 198.51.100.5"),
        1000,
    );
    h.clear();
    assert!(h.list().is_empty());
    let mut c = conn("c1", "", 1, 1);
    c.metadata.destination_ip = "198.51.100.5".into();
    assert!(!merge(&mut h, vec![c], 2000));
    assert_eq!(h.take_doc(), Some(DomainsDoc::default()));
}

/// Storage H5: the old `traffic-domains.json` maps `count` to `connections`.
#[test]
fn legacy_document_is_converted() {
    let old = json!({"domains": {
        "github.com": {"domain": "github.com", "firstSeen": 1000, "lastSeen": 2000,
                       "count": 3, "bytesUp": 10, "bytesDown": 20},
        "cloudflare-dns.com": {"lastSeen": 5, "count": 1},
        "Example.ORG.": {"lastSeen": 7.5, "count": -2, "bytesUp": "x"}
    }});
    let doc = DomainsDoc::from_legacy(&old);
    assert_eq!(doc.domains.len(), 2);
    let r = &doc.domains["github.com"];
    assert_eq!(
        (r.connections, r.lookups, r.bytes_up, r.bytes_down),
        (3, 0, 10, 20)
    );
    assert_eq!((r.first_seen, r.last_seen), (1000, 2000));
    let r = &doc.domains["example.org"];
    assert_eq!((r.connections, r.bytes_up, r.last_seen), (0, 0, 7));
    assert_eq!(DomainsDoc::from_legacy(&json!(null)), DomainsDoc::default());
}

/// A Clash API stand-in answering every request with the same response.
async fn mock_clash(status: &'static str, body: &'static str) -> u16 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut head, mut buf) = (Vec::new(), [0u8; 2048]);
                while !head.ends_with(b"\r\n\r\n") {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => head.extend_from_slice(&buf[..n]),
                    }
                }
                let answer = format!(
                    "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(answer.as_bytes()).await;
            });
        }
    });
    port
}

/// The service merges polled snapshots, observes log lines, saves on flush / stop and reloads.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn service_polls_persists_and_reloads() {
    let root = TempDir::new("history-service");
    let store = Arc::new(Store::<DomainsDoc>::open(root.path()));
    let hits = Arc::new(Mutex::new(Vec::<String>::new()));
    let hook: NewConnectionHook = {
        let hits = Arc::clone(&hits);
        Arc::new(move |host: &str| hits.lock().push(host.to_owned()))
    };
    let service = HistoryService::open(Arc::clone(&store), Some(hook));
    let changes = service.changes();
    let port = mock_clash(
        "200 OK",
        r#"{"connections":[{"id":"c1","metadata":{"host":"github.com"},"upload":5,"download":7}]}"#,
    )
    .await;
    let endpoint = ClashEndpoint {
        port,
        secret: "00112233445566778899aabbccddeeff".into(),
    };
    service.start_polling(&endpoint).unwrap();
    eventually(|| service.list().iter().any(|r| r.domain == "github.com")).await;
    assert!(changes.has_changed().unwrap());
    eventually(|| *service.health().borrow() == SourceHealth::Ok).await;
    assert_eq!(*hits.lock(), ["github.com"]);
    service.observe_log_line(&format!(
        "{PREFIX} [3 1ms] dns: exchanged A docs.example.org. 60 IN A 198.51.100.8"
    ));
    service.stop_polling().await.unwrap();
    assert_eq!(*service.health().borrow(), SourceHealth::Idle);
    let saved = store.snapshot();
    assert_eq!(saved.domains["github.com"].connections, 1);
    assert_eq!(saved.domains["docs.example.org"].lookups, 1);
    drop(service);

    let reloaded = HistoryService::open(Arc::clone(&store), None);
    assert_eq!(reloaded.list().len(), 2);
    reloaded.clear().await.unwrap();
    assert!(reloaded.list().is_empty());
    assert!(
        Store::<DomainsDoc>::open(root.path())
            .snapshot()
            .domains
            .is_empty()
    );
}

/// F-089: three failed polls in a row report the source unavailable (HTTP 500 here).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failing_source_is_reported() {
    let root = TempDir::new("history-failing");
    let service = HistoryService::open(Arc::new(Store::open(root.path())), None);
    let port = mock_clash("500 Internal Server Error", "{}").await;
    let endpoint = ClashEndpoint {
        port,
        secret: "x".into(),
    };
    service.start_polling(&endpoint).unwrap();
    let mut health = service.health();
    tokio::time::timeout(
        Duration::from_secs(10),
        health.wait_for(|h| *h == SourceHealth::Unavailable),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(health.borrow().warning().is_some());
    service.stop_polling().await.unwrap();
    assert_eq!(*service.health().borrow(), SourceHealth::Idle);
}
