//! The REAL unelevated proxy capture on loopback (NOADMIN.md §2): the bundled sing-box through
//! [`RealEngines`] and [`ProxyCapture`], upstream = a helper sing-box SOCKS proxy that alone
//! knows `upstream.test` (its own hosts DNS), and a local HTTP server fetched through the mixed
//! port. A 200 therefore proves mixed inbound -> engine routing -> upstream -> destination.
//! Loopback sockets and our own children only (each stopped through its own handle); skipped
//! quietly when the engine binary is missing.
use std::net::{Ipv4Addr, TcpListener as StdListener};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{AdaptiveMode, EnginePref, KillSwitchLevel, ProxyKind};
use vpnte_engine::singbox_process::SingBoxProcess;

use super::{FakeInputs, World};
use crate::api::{CaptureKind, Mode, Origin, Runtime, StartRequest, StopOptions};
use crate::runtime::{ProxyCapture, RealEngines, RuntimeDeps, Timings, TunnelHandle};

const RESOURCES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../resources");
const BODY: &str = "vpnte-live-ok";

/// Canonical path without the `\\?\` prefix (the form the engines are launched from).
fn canonical(p: &Path) -> Option<PathBuf> {
    let full = std::fs::canonicalize(p).ok()?;
    let text = full.to_string_lossy();
    Some(PathBuf::from(text.strip_prefix(r"\\?\").unwrap_or(&text)))
}

/// The upstream: a SOCKS proxy straight out that resolves `upstream.test` to loopback itself.
fn helper_config(port: u16) -> Vec<u8> {
    serde_json::json!({
        "log": { "level": "info" },
        "dns": { "servers": [{
            "type": "hosts", "tag": "hosts", "predefined": { "upstream.test": "127.0.0.1" }
        }] },
        "inbounds": [{ "type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": port }],
        "outbounds": [{ "type": "direct", "tag": "direct", "domain_resolver": "hosts" }]
    })
    .to_string()
    .into_bytes()
}

/// One-shot HTTP server: answers every request with [`BODY`]; returns the request heads seen.
async fn http_server(listener: TcpListener, seen: Arc<parking_lot::Mutex<Vec<String>>>) {
    while let Ok((mut stream, _)) = listener.accept().await {
        let seen = seen.clone();
        tokio::spawn(async move {
            let mut head = Vec::new();
            let mut buf = [0u8; 1024];
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => head.extend_from_slice(&buf[..n]),
                }
            }
            seen.lock()
                .push(String::from_utf8_lossy(&head).into_owned());
            let reply = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{BODY}",
                BODY.len()
            );
            let _ = stream.write_all(reply.as_bytes()).await;
        });
    }
}

/// `GET http://upstream.test:<port>/` through the HTTP side of the mixed inbound.
async fn fetch_via(mixed: u16, port: u16) -> std::io::Result<String> {
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, mixed)).await?;
    let request = format!(
        "GET http://upstream.test:{port}/ HTTP/1.1\r\nHost: upstream.test:{port}\r\n\
         Connection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    let mut response = String::new();
    stream.read_to_string(&mut response).await?;
    Ok(response)
}

/// Stops our children whatever happened (each through its own handle).
struct Guard {
    runtime: Option<TunnelHandle>,
    helper: Option<SingBoxProcess>,
}

impl Drop for Guard {
    fn drop(&mut self) {
        let (runtime, helper) = (self.runtime.take(), self.helper.take());
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                if let Some(runtime) = runtime {
                    runtime.stop(StopOptions::default()).await;
                }
                if let Some(helper) = helper {
                    let _ = helper.terminate(Duration::from_secs(5)).await;
                }
            });
        });
    }
}

/// NOADMIN.md §2, unelevated: a Soft-mode engine run (proxy capture, local-proxy upstream)
/// serves HTTP through its mixed port via the upstream, and its stop frees the port.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_proxy_capture_through_a_local_upstream() {
    let (Some(singbox), Some(xray)) = (
        canonical(&Path::new(RESOURCES).join("sing-box.exe")),
        canonical(&Path::new(RESOURCES).join("xray.exe")),
    ) else {
        eprintln!("skipped: engine binaries missing under {RESOURCES}");
        return;
    };
    vpnte_base::http::init_tls();
    let mut guard = Guard {
        runtime: None,
        helper: None,
    };
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let http_port = listener.local_addr().unwrap().port();
    let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
    tokio::spawn(http_server(listener, seen.clone()));

    let helper_port = vpnte_engine::ports::alloc_port(false, &[]).expect("free port");
    let helper =
        SingBoxProcess::spawn(&singbox, &helper_config(helper_port), None).expect("helper spawn");
    let ready = helper
        .wait_ready(Duration::from_secs(20), &CancellationToken::new())
        .await;
    guard.helper = Some(helper);
    ready.expect("helper ready");

    let runtime = TunnelHandle::spawn(RuntimeDeps {
        engines: Arc::new(RealEngines::new(singbox, xray, None)),
        tun: None,
        proxy: Arc::new(ProxyCapture::new()),
        inputs: Arc::new(FakeInputs(World::new())),
        failover: None,
        confirmations: None,
        timings: Timings::default(),
    });
    guard.runtime = Some(runtime.clone());
    let req = StartRequest {
        mode: Mode::LocalProxy {
            addr: format!("127.0.0.1:{helper_port}"),
            kind: ProxyKind::Socks5,
        },
        capture: CaptureKind::Proxy,
        kill_switch: KillSwitchLevel::Off,
        public_wifi: false,
        stealth: false,
        adaptive: AdaptiveMode::Baseline,
        engine: EnginePref::Auto,
        origin: Origin::User,
    };
    runtime
        .start(req, CancellationToken::new())
        .await
        .expect("unelevated proxy-capture start");
    let status = runtime.status().borrow().clone();
    assert_eq!(status.capture, Some(CaptureKind::Proxy));
    let mixed = status
        .session
        .and_then(|s| s.proxy_port)
        .expect("mixed port published");

    let response = tokio::time::timeout(Duration::from_secs(15), fetch_via(mixed, http_port))
        .await
        .expect("fetch in time")
        .expect("fetch through the mixed port");
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.ends_with(BODY), "{response}");
    let heads = seen.lock().clone();
    assert!(
        heads.iter().any(|h| h.contains("upstream.test")),
        "the destination saw the request by name (resolved by the upstream): {heads:?}"
    );

    let receipt = runtime.stop(StopOptions::default()).await;
    assert!(receipt.ok && receipt.runtime_stopped, "{receipt:?}");
    guard.runtime = None;
    assert!(
        StdListener::bind((Ipv4Addr::LOCALHOST, mixed)).is_ok(),
        "the mixed port is free after the stop"
    );
}

/// Shadowsocks 2022 PSK of the local test server (16 fixed bytes, not a secret).
const SS_KEY: &str = "AQIDBAUGBwgJCgsMDQ4PEA==";
const SS_METHOD: &str = "2022-blake3-aes-128-gcm";
/// SIP002 userinfo: base64url of `SS_METHOD:SS_KEY`.
const SS_USERINFO: &str = "MjAyMi1ibGFrZTMtYWVzLTEyOC1nY206QVFJREJBVUdCd2dKQ2dzTURRNFBFQT09";

/// The "VPN server": a Shadowsocks 2022 inbound straight out. `upstream.test` is known only to
/// it (its own hosts DNS); every other name goes through the system resolver, which the Xray
/// slot's egress proof needs.
fn server_config(port: u16) -> Vec<u8> {
    serde_json::json!({
        "log": { "level": "info" },
        "dns": { "servers": [
            { "type": "hosts", "tag": "hosts", "predefined": { "upstream.test": "127.0.0.1" } },
            { "type": "local", "tag": "local" }
        ] },
        "inbounds": [{
            "type": "shadowsocks", "tag": "in", "listen": "127.0.0.1", "listen_port": port,
            "method": SS_METHOD, "password": SS_KEY
        }],
        "outbounds": [
            { "type": "direct", "tag": "to-test", "domain_resolver": "hosts" },
            { "type": "direct", "tag": "direct", "domain_resolver": "local" }
        ],
        "route": {
            "rules": [{ "domain": ["upstream.test"], "outbound": "to-test" }],
            "final": "direct"
        }
    })
    .to_string()
    .into_bytes()
}

/// NOADMIN.md §2, the main no-admin mode: a server from the list in proxy capture. The
/// destination name is known only to the server, so a 200 proves mixed inbound -> our engine
/// -> the server's protocol -> destination; the session reports the engine that ran.
async fn proxy_capture_over_a_server(pref: EnginePref, expected: vpnte_base::types::Engine) {
    let (Some(singbox), Some(xray)) = (
        canonical(&Path::new(RESOURCES).join("sing-box.exe")),
        canonical(&Path::new(RESOURCES).join("xray.exe")),
    ) else {
        eprintln!("skipped: engine binaries missing under {RESOURCES}");
        return;
    };
    vpnte_base::http::init_tls();
    let mut guard = Guard {
        runtime: None,
        helper: None,
    };
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let http_port = listener.local_addr().unwrap().port();
    let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
    tokio::spawn(http_server(listener, seen.clone()));

    let server_port = vpnte_engine::ports::alloc_port(false, &[]).expect("free port");
    let server =
        SingBoxProcess::spawn(&singbox, &server_config(server_port), None).expect("server spawn");
    let ready = server
        .wait_ready(Duration::from_secs(20), &CancellationToken::new())
        .await;
    guard.helper = Some(server);
    ready.expect("server ready");

    let uri = format!("ss://{SS_USERINFO}@127.0.0.1:{server_port}#Local%20SS");
    let profile = vpnte_profiles::uri::parse_uri(&uri).expect("test key parses");
    let runtime = TunnelHandle::spawn(RuntimeDeps {
        engines: Arc::new(RealEngines::new(singbox, xray, None)),
        tun: None,
        proxy: Arc::new(ProxyCapture::new()),
        inputs: Arc::new(FakeInputs(World::new())),
        failover: None,
        confirmations: None,
        timings: Timings::default(),
    });
    guard.runtime = Some(runtime.clone());
    let req = StartRequest {
        mode: Mode::DirectVpn {
            profile: crate::api::VpnProfile {
                id: "local-ss".into(),
                profile: Arc::new(profile),
                device: None,
                engine: pref,
            },
        },
        capture: CaptureKind::Proxy,
        kill_switch: KillSwitchLevel::Off,
        public_wifi: false,
        stealth: false,
        adaptive: AdaptiveMode::Baseline,
        engine: pref,
        origin: Origin::User,
    };
    runtime
        .start(req, CancellationToken::new())
        .await
        .expect("unelevated start over a server");
    let status = runtime.status().borrow().clone();
    assert_eq!(status.capture, Some(CaptureKind::Proxy));
    assert_eq!(status.engine.map(|e| e.kind), Some(expected));
    let mixed = status
        .session
        .and_then(|s| s.proxy_port)
        .expect("mixed port published");

    let response = tokio::time::timeout(Duration::from_secs(15), fetch_via(mixed, http_port))
        .await
        .expect("fetch in time")
        .expect("fetch through the mixed port");
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.ends_with(BODY), "{response}");
    assert!(
        seen.lock().iter().any(|h| h.contains("upstream.test")),
        "the destination saw the request by the name only the server resolves"
    );

    let receipt = runtime.stop(StopOptions::default()).await;
    assert!(receipt.ok && receipt.runtime_stopped, "{receipt:?}");
    guard.runtime = None;
    assert!(
        StdListener::bind((Ipv4Addr::LOCALHOST, mixed)).is_ok(),
        "the mixed port is free after the stop"
    );
}

/// Like its Xray sibling since p-live2 (lab F-4): a native start proves its exit through
/// public echo services before it counts as started, so it needs a plain way out (CI).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs internet: a native start proves its exit through public echo services"]
async fn live_proxy_capture_over_a_server_with_singbox() {
    proxy_capture_over_a_server(EnginePref::SingBox, vpnte_base::types::Engine::SingBox).await;
}

/// The Xray slot proves its egress through public IP echo services before the session counts
/// as started, so the server needs a plain way out: CI runs ignored tests with direct internet.
/// Behind another VPN's TUN the server's direct dial leaves by the physical interface and may
/// be dropped (seen on the development machine).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs internet: the Xray slot proves its egress through public echo services"]
async fn live_proxy_capture_over_a_server_with_xray() {
    proxy_capture_over_a_server(EnginePref::Xray, vpnte_base::types::Engine::Xray).await;
}
