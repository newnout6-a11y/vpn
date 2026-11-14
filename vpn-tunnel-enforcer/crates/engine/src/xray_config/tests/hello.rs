//! The ClientHello the bundled Xray sends, read by a loopback listener and reduced to JA4's
//! first two parts (FoxIO): lab finding F-6 and owner decision T1a. A plain TLS key that Auto
//! now runs on Xray sends Chrome 155 (GREASE, `t13d1517h2_8daaf6152771`), not sing-box's
//! Chrome 133 (`t13d1516h2`); a provider graph without a fingerprint gets Xray's default, the
//! same hello. The lab's `t13d1715h2_5b57614c22b0` is Xray's Firefox preset: Firefox sends no
//! GREASE, so "no GREASE" there is not Go's own TLS. Skipped quietly without resources/xray.exe.
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::Duration;

use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{ClientDevice, Engine, EnginePref};
use vpnte_core::net::HostPort;
use vpnte_core::socks5;
use vpnte_profiles::model::Profile;

use super::config::imported;
use super::*;
use crate::slot::{Slot, SlotEndpoint};
use crate::test_support::xray_exe;
use crate::xray_config::{
    Decision, ProxyGraph, SelectReason, build_config, proxy_graph, select_engine,
};
use crate::xray_process::{SlotLaunch, XraySupervisor};

/// JA4 a and b of Chrome 155 as the pinned Xray 26.11.9 sends it (refraction utls Chrome_Auto).
const CHROME_155: (&str, &str) = ("t13d1517h2", "8daaf6152771");
/// The lab's capture (F-6): Xray's Firefox preset.
const FIREFOX_148: (&str, &str) = ("t13d1715h2", "5b57614c22b0");

/// What one ClientHello says.
#[derive(Debug, PartialEq)]
struct Hello {
    grease: bool,
    /// TLS 1.3, SNI, cipher and extension counts without GREASE, first and last ALPN character.
    a: String,
    /// First 12 hex digits of SHA-256 over the sorted cipher list.
    b: String,
}

fn grease(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a
}

fn u16_at(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]))
}

/// The hello in `record` (one TLS record holding the whole ClientHello).
fn parse(record: &[u8]) -> Option<Hello> {
    // Record header, handshake header, legacy version, random; then the session id.
    let mut i = 5 + 4 + 2 + 32;
    i += 1 + usize::from(*record.get(i)?);
    let n = usize::from(u16_at(record, i)?);
    let ciphers: Vec<u16> = (0..n / 2)
        .filter_map(|k| u16_at(record, i + 2 + 2 * k))
        .collect();
    i += 2 + n;
    i += 1 + usize::from(*record.get(i)?);
    let end = i + 2 + usize::from(u16_at(record, i)?);
    i += 2;
    let (mut exts, mut alpn) = (Vec::new(), String::new());
    while i + 4 <= end {
        let (kind, len) = (u16_at(record, i)?, usize::from(u16_at(record, i + 2)?));
        if kind == 16 {
            let l = usize::from(*record.get(i + 6)?);
            alpn = String::from_utf8_lossy(record.get(i + 7..i + 7 + l)?).into_owned();
        }
        exts.push(kind);
        i += 4 + len;
    }
    let real = |v: &[u16]| v.iter().copied().filter(|v| !grease(*v)).count();
    let mut sorted: Vec<String> = ciphers
        .iter()
        .filter(|c| !grease(**c))
        .map(|c| format!("{c:04x}"))
        .collect();
    sorted.sort();
    let digest = hex::encode(Sha256::digest(sorted.join(",").as_bytes()));
    let (first, last) = (alpn.chars().next()?, alpn.chars().last()?);
    Some(Hello {
        grease: ciphers.iter().chain(&exts).any(|v| grease(*v)),
        a: format!("t13d{:02}{:02}{first}{last}", real(&ciphers), real(&exts)),
        b: digest[..12].to_owned(),
    })
}

/// The first ClientHello Xray sends for `graph` when a SOCKS client asks for a site; the
/// server is the loopback `listener`.
async fn hello_of(exe: PathBuf, graph: &ProxyGraph, listener: TcpListener) -> Hello {
    let ep = SlotEndpoint::allocate(&[]).unwrap();
    let launch = SlotLaunch {
        config: build_config(graph, &ep).to_string().into_bytes(),
        dial_target: None,
    };
    let (tx, _events) = mpsc::channel(16);
    let mut sup = XraySupervisor::new(exe, None, tx);
    let cancel = CancellationToken::new();
    sup.start(Slot::A, ep.clone(), launch, &cancel)
        .await
        .unwrap();
    let proxy = (Ipv4Addr::LOCALHOST, ep.port()).into();
    let site = HostPort::new("example.com", 443).unwrap();
    let limit = Duration::from_secs(5);
    let mut client = socks5::connect(proxy, Some(ep.creds()), &site, limit)
        .await
        .unwrap();
    client.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
    let accepted = tokio::time::timeout(Duration::from_secs(10), listener.accept()).await;
    let (mut server, _) = accepted.expect("Xray dials the server").unwrap();
    let mut record = vec![0u8; 5];
    server.read_exact(&mut record).await.unwrap();
    let len = usize::from(u16::from_be_bytes([record[3], record[4]]));
    record.resize(5 + len, 0);
    server.read_exact(&mut record[5..]).await.unwrap();
    sup.stop_all().await.unwrap();
    parse(&record).expect("a ClientHello")
}

/// A plain TLS VLESS key: Auto runs it on Xray, which sends Chrome 155.
#[tokio::test]
async fn a_plain_tls_key_sends_chrome_155_on_xray() {
    let Some(exe) = xray_exe() else {
        eprintln!("skipped: no resources/xray.exe");
        return;
    };
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let p = Profile {
        server: ip("127.0.0.1"),
        port: listener.local_addr().unwrap().port(),
        tls: tls("example.com"),
        ..profile(vless())
    };
    let xray = Decision::Selected {
        engine: Engine::Xray,
        reason: SelectReason::TlsHello,
    };
    assert_eq!(select_engine(&p, EnginePref::Auto), xray);
    let graph = proxy_graph(&p, ClientDevice::Pc).unwrap();
    let hello = hello_of(exe, &graph, listener).await;
    assert!(hello.grease, "{hello:?}");
    assert_eq!((hello.a.as_str(), hello.b.as_str()), CHROME_155);
}

/// A provider graph (Xray JSON) without a fingerprint gets Xray's default: Chrome 155. With the
/// provider's `firefox` it is exactly the lab's capture of F-6.
#[tokio::test]
async fn a_provider_graph_sends_a_browser_hello() {
    let Some(exe) = xray_exe() else {
        eprintln!("skipped: no resources/xray.exe");
        return;
    };
    for (fingerprint, want, grease) in [
        (None, CHROME_155, true),
        (Some("firefox"), FIREFOX_148, false),
    ] {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let mut settings = json!({"serverName": "example.com"});
        if let Some(fp) = fingerprint {
            settings["fingerprint"] = json!(fp);
        }
        // `sockopt` has no typed field: the outbound stays a provider graph.
        let doc = json!({"outbounds": [{"tag": "proxy", "protocol": "vless",
            "settings": {"vnext": [{"address": "127.0.0.1",
                "port": listener.local_addr().unwrap().port(),
                "users": [{"id": UUID, "encryption": "none"}]}]},
            "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": settings,
                "sockopt": {"tcpKeepAliveIdle": 30}}}]});
        let p = imported(&doc);
        assert!(p.native_xray.is_some());
        let graph = proxy_graph(&p, ClientDevice::Pc).unwrap();
        let hello = hello_of(exe.clone(), &graph, listener).await;
        assert_eq!(hello.grease, grease, "{fingerprint:?}: {hello:?}");
        assert_eq!(
            (hello.a.as_str(), hello.b.as_str()),
            want,
            "{fingerprint:?}"
        );
    }
}
