//! Loopback dials through a real sing-box pair: `check` cannot see a dial failure. P-01 (profiles
//! §7.3): uTLS on a QUIC outbound breaks every dial, so one HY2 profile is dialed for real; and
//! the stealth record fragment would break a ShadowTLS v3 chain. Servers use a throw-away
//! self-signed certificate; the client is the emitted fragment behind a mixed inbound; the
//! target is an echo listener inside the test. Loopback only.
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::Path;
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::check::{command, sing_box};
use super::tests::{hy2, tls};
use super::{EmitPolicy, emit_singbox};

/// A started engine, killed (and reaped) when dropped, also on panic.
struct Engine(Child);

impl Drop for Engine {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn run(exe: &Path, config: &Value) -> Engine {
    let child = command(exe, &["run", "-c", "stdin", "--disable-color"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sing-box");
    // Owned before anything can panic, so the child is killed on every path.
    let mut engine = Engine(child);
    let mut stdin = engine.0.stdin.take().expect("stdin");
    stdin
        .write_all(config.to_string().as_bytes())
        .expect("write config");
    drop(stdin);
    engine
}

/// `sing-box generate tls-keypair localhost` -> (key PEM, certificate PEM).
fn keypair(exe: &Path) -> (String, String) {
    let out = command(exe, &["generate", "tls-keypair", "localhost"])
        .output()
        .expect("keypair");
    let text = String::from_utf8_lossy(&out.stdout);
    let block = |label: &str| {
        let begin = format!("-----BEGIN {label}-----");
        let end = format!("-----END {label}-----");
        let start = text.find(&begin).expect("begin");
        let stop = text[start..].find(&end).expect("end") + start + end.len();
        text[start..stop].to_owned()
    };
    (block("PRIVATE KEY"), block("CERTIFICATE"))
}

fn free_tcp_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .expect("port")
        .port()
}

fn free_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .and_then(|s| s.local_addr())
        .expect("port")
        .port()
}

/// Echoes one connection back; returns its port.
fn echo_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("echo bind");
    let port = listener.local_addr().expect("echo addr").port();
    std::thread::spawn(move || {
        for mut conn in listener.incoming().flatten() {
            let mut buf = [0u8; 64];
            if let Ok(n) = conn.read(&mut buf) {
                let _ = conn.write_all(&buf[..n]);
            }
        }
    });
    port
}

/// HTTP CONNECT through the client's mixed inbound, then one echo round trip.
fn round_trip(mixed: u16, target: u16) -> std::io::Result<Vec<u8>> {
    let mut conn = TcpStream::connect(("127.0.0.1", mixed))?;
    conn.set_read_timeout(Some(Duration::from_secs(5)))?;
    write!(
        conn,
        "CONNECT 127.0.0.1:{target} HTTP/1.1\r\nHost: 127.0.0.1:{target}\r\n\r\n"
    )?;
    let mut reader = BufReader::new(conn.try_clone()?);
    let mut status = String::new();
    reader.read_line(&mut status)?;
    if !status.contains(" 200") {
        return Err(std::io::Error::other(status));
    }
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 || line == "\r\n" {
            break;
        }
    }
    conn.write_all(b"ping")?;
    let mut reply = [0u8; 4];
    reader.read_exact(&mut reply)?;
    Ok(reply.to_vec())
}

/// Retries the round trip while the engines start (no readiness signal on a UDP listener).
fn dial(mixed: u16, target: u16, within: Duration) -> std::io::Result<Vec<u8>> {
    let deadline = Instant::now() + within;
    loop {
        match round_trip(mixed, target) {
            Ok(reply) => return Ok(reply),
            Err(e) if Instant::now() >= deadline => return Err(e),
            Err(_) => std::thread::sleep(Duration::from_millis(200)),
        }
    }
}

fn wait_listening(port: u16, within: Duration) -> bool {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

fn client_config(outbounds: &[Value], mixed: u16) -> Value {
    let mut outbounds = outbounds.to_vec();
    outbounds.push(json!({ "type": "direct", "tag": "direct" }));
    json!({
        "log": { "level": "error" },
        "inbounds": [{ "type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": mixed }],
        "outbounds": outbounds,
        "route": { "final": "proxy-out" },
    })
}

/// Expects the client on `mixed` to start and then fail every round trip.
fn assert_cannot_dial(mixed: u16, target: u16, why: &str) {
    assert!(
        wait_listening(mixed, Duration::from_secs(10)),
        "client did not start"
    );
    for _ in 0..3 {
        assert!(round_trip(mixed, target).is_err(), "{why}");
    }
}

/// P-01 run live: the emitted Hysteria2 outbound (no uTLS) carries traffic; the same outbound
/// with the uTLS block the old app forced on every TLS outbound passes `check` but cannot dial.
#[test]
#[ignore = "starts two sing-box processes on loopback"]
fn hy2_dials_without_utls_and_fails_with_it() {
    let Some(exe) = sing_box() else { return };
    let (key, cert) = keypair(&exe);
    let (hy2_port, target) = (free_udp_port(), echo_server());
    let _server = run(
        &exe,
        &json!({
            "log": { "level": "error" },
            "inbounds": [{ "type": "hysteria2", "tag": "hy2-in", "listen": "127.0.0.1", "listen_port": hy2_port,
                           "users": [{ "password": "secret" }],
                           "tls": { "enabled": true, "certificate": cert, "key": key } }],
            "outbounds": [{ "type": "direct", "tag": "direct" }],
        }),
    );
    let p = tls_profile_on(hy2_port, &cert);
    let stealth = EmitPolicy {
        tls_compat: true,
        ..EmitPolicy::default()
    };
    let fragment = emit_singbox(&p, "proxy-out", &stealth).expect("emit");
    let outbound = fragment.outbounds()[0].clone();
    assert!(outbound["tls"].get("utls").is_none());

    let mixed = free_tcp_port();
    {
        let _client = run(&exe, &client_config(fragment.outbounds(), mixed));
        let reply = dial(mixed, target, Duration::from_secs(15)).expect("dial through hysteria2");
        assert_eq!(reply, b"ping");
    }

    let mut forced = outbound;
    forced["tls"]["utls"] = json!({ "enabled": true, "fingerprint": "chrome" });
    let mixed = free_tcp_port();
    let _client = run(&exe, &client_config(&[forced], mixed));
    assert_cannot_dial(mixed, target, "uTLS on QUIC unexpectedly dialed");
}

/// The stealth policy on a Shadowsocks + ShadowTLS v3 chain: the emitted chain (uTLS, no record
/// fragment) carries traffic; with `record_fragment` the v3 server sees a split ClientHello,
/// fails its HMAC check and relays the client to the camouflage server instead.
#[test]
#[ignore = "starts two sing-box processes on loopback"]
fn shadowtls_v3_dials_without_record_fragment_and_fails_with_it() {
    let Some(exe) = sing_box() else { return };
    let (key, cert) = keypair(&exe);
    let (st_port, ss_port, camouflage) = (free_tcp_port(), free_tcp_port(), free_tcp_port());
    let target = echo_server();
    let ss_key = "AAAAAAAAAAAAAAAAAAAAAA==";
    let _server = run(
        &exe,
        &json!({
            "log": { "level": "error" },
            "inbounds": [
                { "type": "shadowtls", "tag": "st-in", "listen": "127.0.0.1", "listen_port": st_port,
                  "version": 3, "users": [{ "name": "u", "password": "st-pass" }],
                  "handshake": { "server": "127.0.0.1", "server_port": camouflage }, "detour": "ss-in" },
                { "type": "shadowsocks", "tag": "ss-in", "listen": "127.0.0.1", "listen_port": ss_port,
                  "method": "2022-blake3-aes-128-gcm", "password": ss_key },
                { "type": "http", "tag": "camouflage-in", "listen": "127.0.0.1", "listen_port": camouflage,
                  "tls": { "enabled": true, "certificate": cert, "key": key } }],
            "outbounds": [{ "type": "direct", "tag": "direct" }],
        }),
    );
    let mut p = tls_profile_on(st_port, &cert);
    p.kind = crate::model::Kind::Shadowsocks {
        method: "2022-blake3-aes-128-gcm".into(),
        password: ss_key.into(),
        plugin: None,
        shadowtls: Some(crate::model::ShadowTlsLayer {
            version: 3,
            password: "st-pass".into(),
            server_name: "localhost".into(),
        }),
        uot: None,
    };
    let stealth = EmitPolicy {
        tls_compat: true,
        ..EmitPolicy::default()
    };
    let chain = emit_singbox(&p, "proxy-out", &stealth).expect("emit");
    assert!(chain.outbounds()[1]["tls"].get("record_fragment").is_none());

    let mixed = free_tcp_port();
    {
        let _client = run(&exe, &client_config(chain.outbounds(), mixed));
        let reply = dial(mixed, target, Duration::from_secs(15)).expect("dial through shadowtls");
        assert_eq!(reply, b"ping");
    }

    let mut forced = chain.outbounds().to_vec();
    forced[1]["tls"]["record_fragment"] = json!(true);
    let mixed = free_tcp_port();
    let _client = run(&exe, &client_config(&forced, mixed));
    assert_cannot_dial(
        mixed,
        target,
        "a split ClientHello unexpectedly passed ShadowTLS v3",
    );
}

/// A loopback profile on `port` that trusts the throw-away certificate for `localhost`.
fn tls_profile_on(port: u16, cert: &str) -> crate::model::Profile {
    let mut p = hy2("127.0.0.1");
    p.port = port;
    p.tls = Some(crate::model::Tls {
        certificate_pem: Some(cert.to_owned()),
        ..tls("localhost")
    });
    p
}
