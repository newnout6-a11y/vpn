//! Live loopback test of proxy capture: the bundled sing-box runs a proxy-capture config and a
//! local HTTP server is fetched through the mixed port as an HTTP proxy (absolute-form GET and
//! CONNECT) and as SOCKS5. Loopback only: no internet, no TUN, no system proxy. The upstream is
//! a dead loopback port, so a fetch succeeds only through the private-destination rule.
//! Skipped quietly without the binary.
use std::fs::File;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;
use vpnte_base::types::ProxyKind;
use vpnte_core::net::HostPort;

use super::tests::{inputs, lb};
use super::*;
use crate::tags::PROXY_IN;
use crate::test_support::{TempDir, hidden, singbox_exe};

const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// The sing-box child of this test, killed through its own handle (never by image name).
struct Engine(Child);

impl Drop for Engine {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// `N` distinct free loopback ports (all bound at once, then released).
fn free_ports<const N: usize>() -> [u16; N] {
    let held: Vec<TcpListener> = (0..N)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    std::array::from_fn(|n| held[n].local_addr().unwrap().port())
}

/// Answers `count` requests with `vpnte-ok:<request target>`, then stops.
fn http_server(count: usize) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming().take(count) {
            let Ok(mut s) = stream else { continue };
            let _ = s.set_read_timeout(Some(IO_TIMEOUT));
            let head = read_head(&mut s);
            let target = head.split(' ').nth(1).unwrap_or_default().to_owned();
            let body = format!("vpnte-ok:{target}");
            let _ = write!(
                s,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    port
}

/// Reads up to the end of an HTTP head (byte by byte: nothing after it is consumed).
fn read_head(s: &mut TcpStream) -> String {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") && s.read(&mut byte).is_ok_and(|n| n == 1) {
        head.push(byte[0]);
    }
    String::from_utf8_lossy(&head).into_owned()
}

/// Reads a response until it carries `expect`, the peer closes, or the timeout hits.
fn read_until(s: &mut TcpStream, expect: &str) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    while !String::from_utf8_lossy(&buf).contains(expect) {
        match s.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

fn connect(port: u16) -> TcpStream {
    let s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
    s
}

/// `GET http://127.0.0.1:<srv>/http` to the proxy itself.
fn via_http_proxy(proxy: u16, srv: u16) -> String {
    let mut s = connect(proxy);
    write!(
        s,
        "GET http://127.0.0.1:{srv}/http HTTP/1.1\r\nHost: 127.0.0.1:{srv}\r\n\
         Proxy-Connection: close\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    read_until(&mut s, "/http")
}

/// `CONNECT 127.0.0.1:<srv>`, then `GET /connect` through the tunnel.
fn via_http_connect(proxy: u16, srv: u16) -> String {
    let mut s = connect(proxy);
    write!(
        s,
        "CONNECT 127.0.0.1:{srv} HTTP/1.1\r\nHost: 127.0.0.1:{srv}\r\n\r\n"
    )
    .unwrap();
    let head = read_head(&mut s);
    assert!(
        head.starts_with("HTTP/1.1 200"),
        "CONNECT answered {head:?}"
    );
    get(&mut s, srv, "/connect")
}

/// SOCKS5 without authentication, CONNECT to 127.0.0.1:<srv>, then `GET /socks`.
fn via_socks5(proxy: u16, srv: u16) -> String {
    let mut s = connect(proxy);
    s.write_all(&[5, 1, 0]).unwrap();
    let mut reply = [0u8; 2];
    s.read_exact(&mut reply).unwrap();
    assert_eq!(reply, [5, 0], "method selection");
    let [hi, lo] = srv.to_be_bytes();
    s.write_all(&[5, 1, 0, 1, 127, 0, 0, 1, hi, lo]).unwrap();
    let mut head = [0u8; 4];
    s.read_exact(&mut head).unwrap();
    assert_eq!(head[..2], [5, 0], "CONNECT reply {head:?}");
    let rest = match head[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        _ => {
            let mut len = [0u8; 1];
            s.read_exact(&mut len).unwrap();
            usize::from(len[0]) + 2
        }
    };
    s.read_exact(&mut vec![0u8; rest]).unwrap();
    get(&mut s, srv, "/socks")
}

fn get(s: &mut TcpStream, srv: u16, path: &str) -> String {
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{srv}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    read_until(s, &format!("vpnte-ok:{path}"))
}

/// Starts sing-box with `config` on stdin, its output in `log`, and waits until `port` accepts.
fn start(config: &Value, log: &std::path::Path, port: u16) -> Engine {
    let exe = singbox_exe().unwrap();
    let out = File::create(log).unwrap();
    let mut engine = Engine(
        hidden(Command::new(exe).args(["run", "-c", "stdin", "--disable-color"]))
            .stdin(Stdio::piped())
            .stdout(Stdio::from(out.try_clone().unwrap()))
            .stderr(Stdio::from(out))
            .spawn()
            .unwrap(),
    );
    // Closing stdin ends the config.
    let mut stdin = engine.0.stdin.take().unwrap();
    stdin.write_all(config.to_string().as_bytes()).unwrap();
    drop(stdin);
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
            return engine;
        }
        let exited = engine.0.try_wait().unwrap();
        if exited.is_some() || Instant::now() > deadline {
            let log = std::fs::read_to_string(log).unwrap_or_default();
            panic!("sing-box not listening on {addr} ({exited:?}):\n{log}");
        }
        thread::sleep(Duration::from_millis(100));
    }
}

/// NOADMIN.md §2: an unelevated sing-box with the proxy-capture config serves HTTP and SOCKS5
/// clients on the mixed port without authentication.
#[test]
fn live_proxy_capture_serves_http_and_socks5() {
    if singbox_exe().is_none() {
        return;
    }
    let [proxy, clash, direct, dead] = free_ports::<4>();
    let mut i = inputs(Upstream::LocalProxy {
        addr: HostPort::parse(&format!("127.0.0.1:{dead}")).unwrap(),
        kind: ProxyKind::Socks5,
        creds: None,
    });
    i.capture = Capture::Proxy { port: proxy };
    i.listeners.clash_port = clash;
    i.listeners.direct = lb(direct, "direct");
    i.listeners.probe = None;
    let config = build(&i).unwrap();
    let dir = TempDir::new("proxy-capture");
    let log = dir.path().join("sing-box.log");
    let srv = http_server(3);
    let engine = start(&config, &log, proxy);
    let results = [
        ("/http", via_http_proxy(proxy, srv)),
        ("/connect", via_http_connect(proxy, srv)),
        ("/socks", via_socks5(proxy, srv)),
    ];
    drop(engine);
    let log = std::fs::read_to_string(&log).unwrap_or_default();
    for (path, response) in results {
        assert!(
            response.starts_with("HTTP/1.1 200") && response.contains(path),
            "{path}: {response:?}\nsing-box log:\n{log}"
        );
    }
    assert!(log.contains(PROXY_IN), "no {PROXY_IN} in the log:\n{log}");
}
