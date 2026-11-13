use std::fs::File;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::*;
use crate::singbox_config::tests::{inputs, lb, slots};
use crate::singbox_config::{Capture, UdpPolicy, build};
use crate::test_support::{TempDir, hidden, singbox_exe};

/// `(action, server)` of each rule; `respond` rules as `(respond, <what they accept>)`.
fn steps(rules: &[Value]) -> Vec<(String, String)> {
    rules
        .iter()
        .map(|r| {
            let action = r["action"].as_str().unwrap().to_owned();
            let what = match r.get("server") {
                Some(server) => server.as_str().unwrap().to_owned(),
                None if r.get("ip_accept_any").is_some() => "address".to_owned(),
                None => r["response_rcode"].as_str().unwrap().to_owned(),
            };
            (action, what)
        })
        .collect()
}

fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
    list.iter()
        .map(|(a, b)| ((*a).to_owned(), (*b).to_owned()))
        .collect()
}

/// ru-2026 Ф9 / p-small (RU-2026 item 10): DoH by IP literal (1.1.1.1, Yandex 77.88.8.8, 9.9.9.9,
/// 8.8.8.8), then TCP/53, then the physical resolver; a foreign DoH NXDOMAIN is final (TLS), a
/// Yandex or TCP one is not. Yandex is second, so a network that cuts foreign resolvers answers
/// after one blackholed step.
#[test]
fn bootstrap_order() {
    let doh = |server| {
        [
            ("evaluate", server),
            ("respond", "address"),
            ("respond", "NXDOMAIN"),
        ]
    };
    let mut expected: Vec<(&str, &str)> = doh("dns-bootstrap").to_vec();
    expected.extend([("evaluate", "dns-bootstrap-yandex"), ("respond", "address")]);
    for server in ["dns-bootstrap-quad9", "dns-bootstrap-google"] {
        expected.extend(doh(server));
    }
    let without_isp = [expected.clone(), vec![("route", "dns-bootstrap-tcp")]].concat();
    expected.extend([
        ("evaluate", "dns-bootstrap-tcp"),
        ("respond", "address"),
        ("route", "dns-bootstrap-isp"),
    ]);
    assert_eq!(steps(&bootstrap_rules(true)), pairs(&expected));
    assert_eq!(steps(&bootstrap_rules(false)), pairs(&without_isp));
    for rule in bootstrap_rules(true) {
        assert_eq!(rule["inbound"], json!(["dns-bootstrap-in"]));
        let evaluated = rule.get("server").is_some();
        assert_eq!(rule.get("timeout").is_some(), evaluated, "{rule}");
        assert_eq!(rule.get("match_response").is_some(), !evaluated, "{rule}");
    }
}

/// Direct servers only (no detour); plain UDP only to the physical resolver.
#[test]
fn bootstrap_servers_are_direct() {
    let isp = Ipv4Addr::new(192, 168, 1, 1);
    let servers = bootstrap_servers(Some(isp));
    let shape: Vec<(&str, &str, &str)> = servers
        .iter()
        .map(|s| {
            (
                s["type"].as_str().unwrap(),
                s["tag"].as_str().unwrap(),
                s["server"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        shape,
        [
            ("https", "dns-bootstrap-yandex", "77.88.8.8"),
            ("https", "dns-bootstrap-quad9", "9.9.9.9"),
            ("https", "dns-bootstrap-google", "8.8.8.8"),
            ("tcp", "dns-bootstrap-tcp", "8.8.8.8"),
            ("udp", "dns-bootstrap-isp", "192.168.1.1"),
        ]
    );
    assert!(
        servers
            .iter()
            .all(|s| s.get("detour").is_none() && s.get("tls").is_none())
    );
    assert_eq!(bootstrap_servers(None).len(), 4);
}

/// The sing-box child of the live test, killed through its own handle (never by image name).
struct Engine(Child);

impl Drop for Engine {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// One UDP question to `port` on loopback: `(rcode, answer count)` of the reply.
fn ask(port: u16, id: u16, name: &str) -> Option<(u8, u16)> {
    let mut q = id.to_be_bytes().to_vec();
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        q.push(u8::try_from(label.len()).unwrap());
        q.extend_from_slice(label.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    sock.send_to(&q, ("127.0.0.1", port)).unwrap();
    let mut buf = [0u8; 1500];
    let n = sock.recv(&mut buf).ok()?;
    (n >= 12 && buf[..2] == id.to_be_bytes())
        .then(|| (buf[3] & 0x0f, u16::from_be_bytes([buf[6], buf[7]])))
}

/// The generated slot-mode config (proxy form: no TUN, loopback only) run by the bundled
/// sing-box, with its first bootstrap step blackholed (TEST-NET-1): `dns-bootstrap-in` still
/// answers a real name within Xray's 4 s through the next step, and a missing one with
/// NXDOMAIN. Run by hand: `cargo test -p vpnte-engine -- --ignored live_bootstrap --nocapture`.
#[test]
#[ignore = "needs internet access"]
fn live_bootstrap_order_answers() {
    if singbox_exe().is_none() {
        return;
    }
    let (proxy, clash, direct, dns) = (free_port(), free_port(), free_port(), free_port());
    let mut i = inputs(slots(UdpPolicy {
        udp: true,
        block_quic: true,
    }));
    i.capture = Capture::Proxy { port: proxy };
    i.listeners.clash_port = clash;
    i.listeners.direct = lb(direct, "direct");
    i.listeners.probe = None;
    i.listeners.dns_bootstrap = Some(dns);
    let mut config = build(&i).unwrap();
    config["log"]["level"] = json!("debug");
    for server in config["dns"]["servers"].as_array_mut().unwrap() {
        if server["tag"] == DNS_BOOTSTRAP {
            server["server"] = json!("192.0.2.1");
        }
    }
    let dir = TempDir::new("dns-bootstrap");
    let log = dir.path().join("sing-box.log");
    let out = File::create(&log).unwrap();
    let mut engine = Engine(
        hidden(Command::new(singbox_exe().unwrap()).args([
            "run",
            "-c",
            "stdin",
            "--disable-color",
        ]))
        .stdin(Stdio::piped())
        .stdout(Stdio::from(out.try_clone().unwrap()))
        .stderr(Stdio::from(out))
        .spawn()
        .unwrap(),
    );
    let mut stdin = engine.0.stdin.take().unwrap();
    stdin.write_all(config.to_string().as_bytes()).unwrap();
    drop(stdin);
    let deadline = Instant::now() + Duration::from_secs(20);
    let ready = SocketAddr::from(([127, 0, 0, 1], proxy));
    while TcpStream::connect_timeout(&ready, Duration::from_millis(200)).is_err() {
        assert!(
            Instant::now() < deadline && engine.0.try_wait().unwrap().is_none(),
            "sing-box did not start:\n{}",
            std::fs::read_to_string(&log).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    let started = Instant::now();
    let found = ask(dns, 0x5151, "example.com");
    let took = started.elapsed();
    let missing = ask(dns, 0x5252, "missing.invalid");
    drop(engine);
    let log = std::fs::read_to_string(&log).unwrap_or_default();
    println!("example.com: {found:?} in {took:?}; missing.invalid: {missing:?}");
    for line in log.lines().filter(|l| l.contains("dns")) {
        println!("{line}");
    }
    assert!(
        found.is_some_and(|(rcode, answers)| rcode == 0 && answers > 0),
        "{found:?}\n{log}"
    );
    assert!(took < Duration::from_secs(4), "{took:?}\n{log}");
    assert_eq!(missing.map(|(rcode, _)| rcode), Some(3), "{log}");
}
