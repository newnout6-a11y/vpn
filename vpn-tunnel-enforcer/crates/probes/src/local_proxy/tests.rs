use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;

fn lo(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

#[derive(Clone, Copy)]
enum Fake {
    /// Answers CONNECT with 200.
    Http,
    /// Answers the SOCKS5 greeting with "no auth".
    Socks,
    /// Both, by the first byte (a "mixed" inbound).
    Mixed,
    /// A web server: 400 to everything.
    Web,
}

/// A local fake server on an ephemeral port (never one of the real client ports).
async fn fake(kind: Fake) -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 256];
                let Ok(n) = s.read(&mut buf).await else {
                    return;
                };
                if n == 0 {
                    return;
                }
                let socks = buf[0] == 5;
                let reply: &[u8] = match (kind, socks) {
                    (Fake::Socks | Fake::Mixed, true) => &[5, 0],
                    (Fake::Http | Fake::Mixed, false) => {
                        b"HTTP/1.1 200 Connection established\r\n\r\n"
                    }
                    (Fake::Web, _) => b"HTTP/1.1 400 Bad Request\r\n\r\n",
                    _ => return,
                };
                let _ = s.write_all(reply).await;
                let _ = s.read(&mut buf).await;
            });
        }
    });
    addr
}

async fn closed_port() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    listener.local_addr().unwrap()
}

#[test]
fn comments_are_cut_outside_quotes_and_slashes_only_after_space() {
    assert_eq!(strip_comment("port: 1080 # main"), "port: 1080 ");
    assert_eq!(strip_comment("port = 1080 ; ini"), "port = 1080 ");
    assert_eq!(strip_comment("\"name\": \"a#b\""), "\"name\": \"a#b\"");
    assert_eq!(
        strip_comment("listen: socks5://127.0.0.1:1080"),
        "listen: socks5://127.0.0.1:1080"
    );
    assert_eq!(strip_comment("port: 1 // note"), "port: 1 ");
    assert_eq!(strip_comment("// whole line"), "");
}

/// AT-09-010: only `http-port` is a proxy port; comments, `remote_port` and server addresses
/// never become candidates.
#[test]
fn config_lines_yield_only_declared_local_ports() {
    let text =
        "# mixed-port: 9999\nremote_port: 8888\nserver: example.com:7777\nhttp-port: 10808\n";
    let found = config_candidates(text, "config.yaml");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].addr, lo(10808));
    assert_eq!(found[0].hint, Some(ProxyKind::Http));
    assert_eq!(found[0].source, Source::Config("config.yaml".into()));
}

#[test]
fn config_keys_and_listen_forms() {
    let text = r#"
mixed-port: 7890
socks-port: 7891
  "listen_port": 2080,
"listen": "127.0.0.1:2081"
listen: socks5://127.0.0.1:1085
bind = "[::1]:1086"
port: 7890
"#;
    let found = config_candidates(text, "c.json");
    let got: Vec<(u16, Option<ProxyKind>)> =
        found.iter().map(|c| (c.addr.port(), c.hint)).collect();
    assert_eq!(
        got,
        vec![
            (7890, None),
            (7891, Some(ProxyKind::Socks5)),
            (2080, None),
            (2081, None),
            (1085, Some(ProxyKind::Socks5)),
            (1086, None),
        ]
    );
}

#[test]
fn system_values_keep_loopback_only_with_scheme_hints() {
    let src = Source::System("wininet".into());
    let found = proxy_server_candidates(
        "http=127.0.0.1:8080;https=127.0.0.1:8080;socks=localhost:1080",
        &src,
    );
    let got: Vec<(SocketAddr, Option<ProxyKind>)> =
        found.iter().map(|c| (c.addr, c.hint)).collect();
    assert_eq!(
        got,
        vec![
            (lo(8080), Some(ProxyKind::Http)),
            (lo(8080), Some(ProxyKind::Http)),
            (lo(1080), Some(ProxyKind::Socks5))
        ]
    );
    assert!(proxy_server_candidates("proxy.corp.example:3128", &src).is_empty());
    let env = text_candidates(
        "socks5h://127.0.0.1:10808",
        &Source::System("env:ALL_PROXY".into()),
    );
    assert_eq!(env[0].hint, Some(ProxyKind::Socks5));
    let v6 = text_candidates("http://[::1]:8118/", &src);
    assert_eq!(v6[0].addr, SocketAddr::from((Ipv6Addr::LOCALHOST, 8118)));
}

#[test]
fn system_proxy_order_and_proxy_enable_gate() {
    let sp = SystemProxy {
        wininet: Some(WinInet {
            proxy_enable: Some(false),
            proxy_server: Some("127.0.0.1:3128".into()),
            auto_config_url: Some("http://127.0.0.1:10809/pac".into()),
            auto_detect: None,
        }),
        winhttp: Some(Some("127.0.0.1:8888".into())),
        env: vec![("HTTPS_PROXY".into(), "http://127.0.0.1:8118".into())],
    };
    let ports: Vec<u16> = sp.candidates().iter().map(|c| c.addr.port()).collect();
    assert_eq!(ports, vec![8118, 8888, 10809]);
}

fn row(local: SocketAddr, pid: u32, process: &str) -> ListenerRow {
    ListenerRow {
        local,
        pid,
        process: Some(process.into()),
    }
}

#[test]
fn listeners_are_filtered_and_dialled_where_they_accept() {
    let rows = vec![
        row("0.0.0.0:135".parse().unwrap(), 1, "svchost.exe"),
        row("127.0.0.1:5432".parse().unwrap(), 2, "postgres.exe"),
        row("0.0.0.0:7680".parse().unwrap(), 3, "svchost.exe"),
        row("[::1]:9050".parse().unwrap(), 4, "tor.exe"),
        row("[::]:2080".parse().unwrap(), 5, "nekobox.exe"),
        row("0.0.0.0:2080".parse().unwrap(), 5, "nekobox.exe"),
        row("192.168.1.5:3000".parse().unwrap(), 6, "node.exe"),
        row("127.0.0.1:443".parse().unwrap(), 7, "happ.exe"),
        row("127.0.0.1:999".parse().unwrap(), 8, "x.exe"),
        row(
            "127.0.0.1:20000".parse().unwrap(),
            42,
            "vpn-tunnel-enforcer.exe",
        ),
        row("127.0.0.1:20001".parse().unwrap(), 9, "sing-box.exe"),
    ];
    let found = listener_candidates(&rows, &[42], &[20001]);
    let got: Vec<(SocketAddr, Source)> = found.into_iter().map(|c| (c.addr, c.source)).collect();
    assert_eq!(
        got,
        vec![
            (
                "[::1]:9050".parse().unwrap(),
                Source::Listener("tor.exe".into())
            ),
            (lo(2080), Source::Listener("nekobox.exe".into())),
            (lo(443), Source::Listener("happ.exe".into())),
        ]
    );
}

#[test]
fn merge_keeps_the_first_source_and_fills_hints() {
    let cfg = vec![Candidate {
        addr: lo(7890),
        hint: None,
        source: Source::Config("a.yaml".into()),
    }];
    let sys = text_candidates(
        "socks5://127.0.0.1:7890",
        &Source::System("env:ALL_PROXY".into()),
    );
    let merged = merge([cfg, sys, typical_candidates()]);
    assert_eq!(merged[0].source, Source::Config("a.yaml".into()));
    assert_eq!(merged[0].hint, Some(ProxyKind::Socks5));
    assert_eq!(merged.len(), TYPICAL_PORTS.len());
    let mut unique = TYPICAL_PORTS.to_vec();
    unique.dedup();
    assert_eq!(unique.len(), 20);
    assert_eq!(TYPICAL_PORTS[0], 443);
}

#[test]
fn status_line_check() {
    assert!(is_http_200(b"HTTP/1.1 200 Connection established\r\n\r\n"));
    assert!(is_http_200(b"HTTP/1.0 200 OK\r\n"));
    assert!(!is_http_200(
        b"HTTP/1.1 407 Proxy Authentication Required\r\n"
    ));
    assert!(!is_http_200(b"HTTP/1.1 2000\r\n"));
    assert!(!is_http_200(b"SSH-2.0-OpenSSH\r\n"));
}

#[tokio::test]
async fn classification_by_handshake_with_hint_order() {
    let http = fake(Fake::Http).await;
    let socks = fake(Fake::Socks).await;
    let mixed = fake(Fake::Mixed).await;
    let web = fake(Fake::Web).await;
    let closed = closed_port().await;
    assert_eq!(classify(http, None).await, Some(ProxyKind::Http));
    assert_eq!(
        classify(http, Some(ProxyKind::Socks5)).await,
        Some(ProxyKind::Http)
    );
    assert_eq!(classify(socks, None).await, Some(ProxyKind::Socks5));
    // A port that speaks both is reported as its hinted type, otherwise as HTTP (K20).
    assert_eq!(classify(mixed, None).await, Some(ProxyKind::Http));
    assert_eq!(
        classify(mixed, Some(ProxyKind::Socks5)).await,
        Some(ProxyKind::Socks5)
    );
    assert_eq!(classify(web, None).await, None);
    assert_eq!(classify(closed, None).await, None);
}

/// Detector 443 vector, on an ephemeral stand-in: only one typical-port candidate is open and
/// speaks HTTP CONNECT, so it wins as `http`.
#[tokio::test]
async fn pick_takes_the_first_by_priority() {
    let closed = closed_port().await;
    let web = fake(Fake::Web).await;
    let socks = fake(Fake::Socks).await;
    let http = fake(Fake::Http).await;
    let c = |addr, source| Candidate {
        addr,
        hint: None,
        source,
    };
    let list = vec![
        c(closed, Source::Config("a.json".into())),
        c(web, Source::Listener("node.exe".into())),
        c(http, Source::TypicalPort),
        c(socks, Source::TypicalPort),
    ];
    let (winner, kind) = pick(list).await.unwrap();
    assert_eq!(
        (winner.addr, kind, winner.source),
        (http, ProxyKind::Http, Source::TypicalPort)
    );
    assert!(pick(vec![c(closed, Source::TypicalPort)]).await.is_none());
}

struct Rig {
    detector: Arc<LocalProxyDetector>,
    scans: Arc<AtomicUsize>,
    clock: Arc<Mutex<Instant>>,
    gate: Arc<tokio::sync::Semaphore>,
}

/// A detector over a counting fake scan that waits for a permit and a manual clock.
fn rig(result: Option<LocalProxy>, permits: usize) -> Rig {
    let scans = Arc::new(AtomicUsize::new(0));
    let clock = Arc::new(Mutex::new(Instant::now()));
    let gate = Arc::new(tokio::sync::Semaphore::new(permits));
    let (s, g) = (scans.clone(), gate.clone());
    let scan: ScanFn = Arc::new(move || {
        let (s, g, result) = (s.clone(), g.clone(), result.clone());
        Box::pin(async move {
            s.fetch_add(1, Ordering::SeqCst);
            g.acquire().await.unwrap().forget();
            result
        })
    });
    let c = clock.clone();
    let detector = Arc::new(LocalProxyDetector::with_scanner(
        scan,
        Arc::new(move || *c.lock()),
    ));
    Rig {
        detector,
        scans,
        clock,
        gate,
    }
}

fn found(verified: bool) -> Option<LocalProxy> {
    Some(LocalProxy {
        addr: lo(7890),
        kind: ProxyKind::Http,
        source: Source::TypicalPort,
        verified,
        public_ip: verified.then(|| "203.0.113.7".parse().unwrap()),
    })
}

impl Rig {
    fn advance(&self, ms: u64) {
        *self.clock.lock() += Duration::from_millis(ms);
    }
    fn scans(&self) -> usize {
        self.scans.load(Ordering::SeqCst)
    }
}

/// AT-09-010: concurrent detects share one in-flight scan, even with the clock moved past 8 s.
#[tokio::test]
async fn concurrent_detects_share_one_scan() {
    let r = rig(found(true), 0);
    let a = tokio::spawn({
        let d = r.detector.clone();
        async move { d.detect().await }
    });
    tokio::task::yield_now().await;
    r.advance(9_000);
    let b = tokio::spawn({
        let d = r.detector.clone();
        async move { d.detect().await }
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    r.gate.add_permits(10);
    assert_eq!(a.await.unwrap(), found(true));
    assert_eq!(b.await.unwrap(), found(true));
    assert_eq!(r.scans(), 1);
}

/// A negative result is reused for 499 ms and rescanned at 500 ms; a verified one for 8 s.
#[tokio::test]
async fn cache_lifetimes_count_from_completion() {
    let r = rig(None, 100);
    assert_eq!(r.detector.detect().await, None);
    r.advance(499);
    assert_eq!(r.detector.detect().await, None);
    assert_eq!(r.scans(), 1);
    r.advance(1);
    r.detector.detect().await;
    assert_eq!(r.scans(), 2);

    let r = rig(found(true), 100);
    r.detector.detect().await;
    r.advance(7_999);
    r.detector.detect().await;
    assert_eq!(r.scans(), 1);
    r.advance(1);
    r.detector.detect().await;
    assert_eq!(r.scans(), 2);

    // Found but not verified: the short lifetime, so a recovering upstream is seen soon.
    let r = rig(found(false), 100);
    r.detector.detect().await;
    r.advance(500);
    r.detector.detect().await;
    assert_eq!(r.scans(), 2);
}

/// A scan whose caller went away leaves no cache: the next caller scans again.
#[tokio::test]
async fn cancelled_scan_does_not_poison_the_cache() {
    let r = rig(found(true), 0);
    let d = r.detector.clone();
    let first = tokio::spawn(async move { d.detect().await });
    tokio::time::sleep(Duration::from_millis(20)).await;
    first.abort();
    let _ = first.await;
    r.gate.add_permits(10);
    assert_eq!(r.detector.detect().await, found(true));
    assert_eq!(r.scans(), 2);
}

#[tokio::test]
async fn recheck_is_a_local_handshake() {
    let http = fake(Fake::Http).await;
    let r = rig(None, 1);
    let mut known = found(true).unwrap();
    known.addr = http;
    assert!(r.detector.recheck(&known).await);
    known.addr = closed_port().await;
    assert!(!r.detector.recheck(&known).await);
    assert_eq!(r.scans(), 0);
}

#[test]
fn config_scan_reads_top_level_small_files_of_known_dirs() {
    let root = std::env::temp_dir().join(format!("vpnte-probes-cfg-{}", fastrand::u64(..)));
    let happ = root.join("Happ");
    std::fs::create_dir_all(happ.join("nested")).unwrap();
    std::fs::write(happ.join("CONFIG.JSON"), "{\n  \"socks-port\": 11080\n}\n").unwrap();
    std::fs::write(happ.join("nested").join("deep.yaml"), "mixed-port: 11081\n").unwrap();
    std::fs::write(happ.join("notes.txt"), "port: 11082\n").unwrap();
    let big = format!("mixed-port: 11083\n{}", "#".repeat(1024 * 1024));
    std::fs::write(happ.join("big.yaml"), big).unwrap();
    std::fs::create_dir_all(root.join("Unknown Client")).unwrap();
    std::fs::write(root.join("Unknown Client").join("c.yaml"), "port: 11084\n").unwrap();
    let found = scan_configs(std::slice::from_ref(&root));
    std::fs::remove_dir_all(&root).unwrap();
    let got: Vec<(u16, Option<ProxyKind>, Source)> = found
        .into_iter()
        .map(|c| (c.addr.port(), c.hint, c.source))
        .collect();
    assert_eq!(
        got,
        vec![(
            11080,
            Some(ProxyKind::Socks5),
            Source::Config("CONFIG.JSON".into())
        )]
    );
}
