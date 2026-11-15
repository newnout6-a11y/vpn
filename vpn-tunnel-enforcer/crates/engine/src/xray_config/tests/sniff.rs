//! Real-binary sniffing (old xrayEngine.itest.ts:82-164; AT-02-008 / AT-06-001): with route-only
//! sniffing the sniffed name picks the route while the connection still goes to the requested
//! IP and port. Also proves the `loglevel: info` key is honoured (the sniff lines are Info).
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::json;

use super::config::endpoint;
use crate::test_support::{hidden, xray_exe};
use crate::xray_config::{ProxyGraph, build_config};

const NAME: &str = "search.vpnte-sniff.invalid";
const WAIT: Duration = Duration::from_secs(5);

/// Kills and reaps the Xray this test started (also when an assertion panics).
struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn sniffed_name_routes_without_changing_the_destination() {
    let Some(exe) = xray_exe() else {
        return;
    };
    for payload in [http_request(), client_hello(NAME)] {
        let (log, target, received) = run_once(&exe, &payload);
        assert_eq!(received, payload, "the fixture got other bytes");
        let text = log.lock().map(|l| l.join("\n")).unwrap_or_default();
        assert!(
            text.contains(&format!("sniffed domain: {NAME}"))
                && text.contains("taking detour [proxy]"),
            "target {target}; log:\n{text}"
        );
    }
}

/// Starts Xray with the slot config plus a first rule `full:NAME -> proxy`, sends `payload`
/// through the authenticated SOCKS listener to a loopback fixture and returns the Xray log, the
/// fixture address and the bytes the fixture received.
fn run_once(
    exe: &std::path::Path,
    payload: &[u8],
) -> (Arc<Mutex<Vec<String>>>, SocketAddr, Vec<u8>) {
    let fixture = TcpListener::bind("127.0.0.1:0").expect("fixture");
    let target = fixture.local_addr().expect("fixture address");
    let (tx, rx) = mpsc::channel();
    let expected = payload.len();
    std::thread::spawn(move || {
        if let Ok((mut conn, _)) = fixture.accept() {
            let _ = conn.set_read_timeout(Some(WAIT));
            let mut buf = vec![0; expected];
            let _ = tx.send(conn.read_exact(&mut buf).map(|()| buf));
        }
    });

    let port = TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .expect("free port")
        .port();
    let ep = endpoint(port);
    let graph = ProxyGraph::Translated(json!({"tag": "proxy", "protocol": "freedom"}));
    let mut config = build_config(&graph, &ep);
    if let Some(rules) = config["routing"]["rules"].as_array_mut() {
        let rule =
            json!({"type": "field", "domain": [format!("full:{NAME}")], "outboundTag": "proxy"});
        rules.insert(0, rule);
    }
    let mut child = hidden(Command::new(exe).args(["run", "-config", "stdin:"]))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("xray starts");
    let stdin = child.stdin.take();
    let stdout = child.stdout.take();
    let running = Running(child);
    if let Some(mut stdin) = stdin {
        stdin
            .write_all(config.to_string().as_bytes())
            .expect("config written");
    }
    let log = Arc::new(Mutex::new(Vec::new()));
    if let Some(stdout) = stdout {
        let log = Arc::clone(&log);
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if let Ok(mut l) = log.lock() {
                    l.push(line);
                }
            }
        });
    }

    let mut socks = socks_connect(port, target);
    socks.write_all(payload).expect("payload sent");
    let received = rx
        .recv_timeout(WAIT)
        .expect("fixture connected")
        .expect("payload read");
    // Wait for the routing lines before stopping Xray.
    let deadline = Instant::now() + WAIT;
    while Instant::now() < deadline {
        let done = log
            .lock()
            .is_ok_and(|l| l.iter().any(|line| line.contains("taking detour")));
        if done {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    drop(socks);
    drop(running);
    (log, target, received)
}

/// SOCKS5 with username / password (RFC 1929), then CONNECT to `target` (IPv4).
fn socks_connect(port: u16, target: SocketAddr) -> TcpStream {
    let deadline = Instant::now() + WAIT;
    let mut s = loop {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(s) => break s,
            Err(e) => {
                assert!(Instant::now() < deadline, "xray never listened: {e}");
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    };
    s.set_read_timeout(Some(WAIT)).expect("timeout");
    let mut reply = [0u8; 2];
    s.write_all(&[5, 1, 2]).expect("greeting");
    s.read_exact(&mut reply).expect("method");
    assert_eq!(reply, [5, 2], "password auth selected");
    let (user, pass) = ("slot-user", "slot-password");
    let mut auth = vec![1, user.len() as u8];
    auth.extend(user.as_bytes());
    auth.push(pass.len() as u8);
    auth.extend(pass.as_bytes());
    s.write_all(&auth).expect("auth");
    s.read_exact(&mut reply).expect("auth reply");
    assert_eq!(reply, [1, 0], "auth accepted");
    let SocketAddr::V4(v4) = target else {
        panic!("IPv4 fixture expected");
    };
    let mut connect = vec![5, 1, 0, 1];
    connect.extend(v4.ip().octets());
    connect.extend(v4.port().to_be_bytes());
    s.write_all(&connect).expect("connect");
    let mut answer = [0u8; 10];
    s.read_exact(&mut answer).expect("connect reply");
    assert_eq!(answer[1], 0, "connect succeeded");
    s
}

fn http_request() -> Vec<u8> {
    format!("GET /search HTTP/1.1\r\nHost: {NAME}\r\nUser-Agent: vpnte-test\r\n\r\n").into_bytes()
}

/// A minimal TLS 1.3 ClientHello carrying `sni` (enough for Xray's sniffer).
fn client_hello(sni: &str) -> Vec<u8> {
    let name = sni.as_bytes();
    let be16 = |n: usize| u16::try_from(n).expect("small").to_be_bytes();
    let mut ext = vec![0x00, 0x00];
    ext.extend(be16(name.len() + 5));
    ext.extend(be16(name.len() + 3));
    ext.push(0x00);
    ext.extend(be16(name.len()));
    ext.extend(name);
    // supported_versions: TLS 1.3
    ext.extend([0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);
    let mut body = vec![0x03, 0x03];
    body.extend([0x11; 32]);
    body.push(0x00);
    body.extend([0x00, 0x02, 0x13, 0x01, 0x01, 0x00]);
    body.extend(be16(ext.len()));
    body.extend(ext);
    let mut handshake = vec![0x01];
    handshake.extend(&u32::try_from(body.len()).expect("small").to_be_bytes()[1..]);
    handshake.extend(body);
    let mut record = vec![0x16, 0x03, 0x01];
    record.extend(be16(handshake.len()));
    record.extend(handshake);
    record
}
