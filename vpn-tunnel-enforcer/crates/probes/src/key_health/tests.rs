//! Key health tests (servers §7 vectors 30-35; keyHealthChecker.test.ts, AT-00-001, AT-00-003).
//! Engine tests run the bundled engines on loopback only and skip quietly without them.
use std::net::IpAddr;
use std::time::Duration;

use serde_json::json;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use vpnte_base::ErrorKind;
use vpnte_base::types::{ClientDevice, Creds, Engine, EnginePref, Loopback};
use vpnte_profiles::model::Profile;
use vpnte_profiles::uri::parse_uri;

use super::destinations::Destination;
use super::*;
use crate::test_support::resources;

const CA: &[u8] = include_bytes!("../egress/testdata/ca.der");
const LEAF: &[u8] = include_bytes!("../egress/testdata/leaf.der");
const LEAF_KEY: &[u8] = include_bytes!("../egress/testdata/leaf.key.der");
/// Fake Reality key (43 base64url characters), never a real one.
const FAKE_PBK: &str = "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVIkT4E7RoLJS0";

/// Probe context for loopback tests (tunnel down), `None` when the engine is not bundled.
fn ctx(pref: EnginePref) -> Option<ProbeCtx> {
    let ctx = ProbeCtx {
        singbox_exe: resources().join("sing-box.exe"),
        xray_exe: resources().join("xray.exe"),
        engine_pref: pref,
        device: ClientDevice::Pc,
        net: NetPath::default(),
        dns_bootstrap_in: None,
    };
    let exe = if pref == EnginePref::Xray {
        &ctx.xray_exe
    } else {
        &ctx.singbox_exe
    };
    exe.exists().then_some(ctx)
}

fn hy2_classify(log: &str, err: &str) -> HealthReason {
    classify_failure(true, log, err)
}

/// Vector 30 (keyHealthChecker.test.ts:104-172).
#[test]
fn classify_vectors() {
    use HealthReason::*;
    assert_eq!(
        hy2_classify("client: authentication failed: wrong password", ""),
        Hy2AuthFailed
    );
    assert_eq!(
        hy2_classify("hysteria2: salamander obfs password mismatch", ""),
        Hy2AuthFailed
    );
    assert_eq!(
        hy2_classify("timeout: no recent network activity", ""),
        Hy2UdpBlocked
    );
    assert_eq!(
        hy2_classify("", "context deadline exceeded during QUIC handshake"),
        Hy2UdpBlocked
    );
    assert_eq!(
        hy2_classify("decode config at /outbounds/0: unknown field gecko", ""),
        Hy2ConfigFailed
    );
    assert_eq!(hy2_classify("", ""), Hy2HandshakeFailed);
    assert_eq!(hy2_classify("tls: bad certificate", ""), Hy2TlsFailed);
    assert_eq!(
        classify_failure(false, "authentication failed", ""),
        AuthFailed
    );
    assert_eq!(
        classify_failure(false, "reality verification failed", ""),
        TlsFailed
    );
    assert_eq!(
        classify_failure(false, "context deadline exceeded", ""),
        Timeout
    );
    assert_eq!(
        classify_failure(false, "decode config: unknown field", ""),
        ConfigFailed
    );
    assert_eq!(classify_failure(false, "", ""), HandshakeFailed);
    assert_eq!(
        classify_failure(false, "EOF", "connection reset"),
        HandshakeFailed
    );
}

/// AT-00-001: live-probe §7 cross-slice vectors (liveServerProbe.extended.test.ts:147-162), the
/// contract `live` relies on for its handshake verdict.
#[test]
fn classify_live_probe_vectors() {
    use HealthReason::*;
    let cases = [
        ("user authentication failed: bad key", AuthFailed),
        ("wrong uuid in request header", AuthFailed),
        (
            "reality verification failed: invalid server name",
            TlsFailed,
        ),
        ("x509: certificate signed by unknown authority", TlsFailed),
        ("dial tcp 198.51.100.1:443: i/o timeout", Timeout),
        ("connection refused", Timeout),
    ];
    for (err, want) in cases {
        assert_eq!(classify_failure(false, "", err), want, "{err}");
    }
}

/// AT-00-001 (B-37 and the hy2 `auth` word): a "tls" substring elsewhere in the debug log no
/// longer hides a rejected key, and an untrusted hy2 certificate is not a wrong password.
#[test]
fn classify_order_fixes() {
    use HealthReason::*;
    let log = "DEBUG outbound/naive[proxy-out]: tls handshake done\n\
               ERROR connection: unexpected status: 407 Proxy Authentication Required";
    assert_eq!(classify_failure(false, log, ""), AuthFailed);
    assert_eq!(
        classify_failure(false, "remote error: tls: handshake failure", ""),
        TlsFailed
    );
    let untrusted = "CRYPTO_ERROR 0x12a (local): tls: failed to verify certificate: \
                     x509: certificate signed by unknown authority";
    assert_eq!(hy2_classify(untrusted, ""), Hy2TlsFailed);
    assert_eq!(
        hy2_classify("auth failed, status code: 404", ""),
        Hy2AuthFailed
    );
    // The real rejection text of sing-quic (hysteria2/client.go, `authenticateAndWrap`).
    assert_eq!(
        hy2_classify("", "authentication failed, status code: 404"),
        Hy2AuthFailed
    );
    assert_eq!(
        classify_failure(false, "", "x509: certificate signed by unknown authority"),
        TlsFailed
    );
}

/// Vector 31 (keyHealthChecker.test.ts:174-210) plus the public-IP and ISO filters.
#[test]
fn trace_vectors() {
    let fr = "fl=29f1\nh=1.1.1.1\nip=185.220.101.5\nts=1700000000.1\nvisit_scheme=https\nloc=FR\ntls=TLSv1.3\n";
    assert_eq!(
        parse_trace(fr),
        (Some("185.220.101.5".parse().unwrap()), Iso2::new("FR"))
    );
    let v6: IpAddr = "2a02:26f7:b000::1".parse().unwrap();
    assert_eq!(
        parse_trace("ip=2a02:26f7:b000::1\nloc=DE\n"),
        (Some(v6), Iso2::new("DE"))
    );
    assert_eq!(parse_trace(""), (None, None));
    assert_eq!(
        parse_trace("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
        (None, None)
    );
    assert_eq!(
        parse_trace("ip=10.0.0.1\nloc=NL\n"),
        (None, Iso2::new("NL"))
    );
    assert_eq!(parse_trace("ip=8.8.8.8\nloc=XX\n").1, None);
    // live-probe §7 (liveServerProbe.extended.test.ts:133-145).
    assert_eq!(
        parse_trace(
            "fl=1f1\nh=www.cloudflare.com\nip=198.41.214.162\nuag=x\nloc=DE\nsliver=none\n"
        ),
        (Some("198.41.214.162".parse().unwrap()), Iso2::new("DE"))
    );
    assert_eq!(parse_trace("error 502 Bad Gateway"), (None, None));
}

/// Stored reason strings are the old ones (and the server list's).
#[test]
fn reason_wire_names() {
    assert_eq!(
        serde_json::to_value(HealthReason::Hy2UdpBlocked).unwrap(),
        json!("hy2-udp-blocked")
    );
    assert_eq!(
        serde_json::to_value(HealthReason::NoOutbound).unwrap(),
        json!("no-outbound")
    );
    assert_eq!(
        HealthReason::TlsFailed.msg().key,
        "probes.keyHealth.reason.tlsFailed"
    );
}

fn reality() -> Profile {
    let link = format!(
        "vless://11111111-2222-4333-8444-555555555555@203.0.113.10:443?security=reality&pbk={FAKE_PBK}&sid=ab12&sni=www.example.com&fp=chrome&flow=xtls-rprx-vision&type=tcp#R"
    );
    parse_uri(&link).unwrap()
}

fn listen() -> Loopback {
    Loopback {
        port: 50123,
        creds: Some(Creds {
            user: "probe-user".into(),
            pass: "fake-probe-pass".into(),
        }),
    }
}

/// Vector 32: detour through `mixed-direct-in` while the TUN runs, physical binding otherwise.
#[test]
fn probe_config_shapes() {
    let direct = Loopback {
        port: 53648,
        creds: Some(Creds {
            user: "direct-user".into(),
            pass: "fake-direct-pass".into(),
        }),
    };
    let tun = probe_config(
        &reality(),
        &listen(),
        ClientDevice::Pc,
        &Uplink::Detour(direct),
    )
    .unwrap();
    assert_eq!(tun["route"]["final"], "proxy-out");
    assert_eq!(tun["route"]["auto_detect_interface"], true);
    let proxy = &tun["outbounds"][0];
    assert_eq!(proxy["tag"], "proxy-out");
    assert_eq!(proxy["uuid"], "11111111-2222-4333-8444-555555555555");
    assert_eq!(proxy["tls"]["reality"]["public_key"], FAKE_PBK);
    assert_eq!(proxy["detour"], "probe-direct-out");
    assert!(proxy.get("bind_interface").is_none());
    assert_eq!(
        tun["outbounds"][1],
        json!({ "type": "socks", "tag": "probe-direct-out", "server": "127.0.0.1", "server_port": 53648,
                "version": "5", "username": "direct-user", "password": "fake-direct-pass" })
    );
    assert_eq!(
        tun["inbounds"][0],
        json!({ "type": "mixed", "tag": "probe-in", "listen": "127.0.0.1", "listen_port": 50123,
                "users": [{ "username": "probe-user", "password": "fake-probe-pass" }] })
    );
    assert_eq!(tun["log"]["level"], "debug");
    assert!(tun.get("dns").is_none(), "IP server: no bootstrap DNS");

    let off = probe_config(
        &reality(),
        &listen(),
        ClientDevice::Pc,
        &Uplink::Bind(Some("Wi-Fi".into())),
    )
    .unwrap();
    assert_eq!(off["outbounds"][0]["bind_interface"], "Wi-Fi");
    assert!(off["outbounds"][0].get("detour").is_none());
    assert_eq!(
        off["outbounds"][1],
        json!({ "type": "direct", "tag": "probe-direct-out" })
    );
}

/// A hostname server gets the direct bootstrap resolver; a ShadowTLS chain detours only its
/// dialing hop.
#[test]
fn probe_config_dns_and_chains() {
    let named =
        parse_uri("trojan://fake-pass@trojan.example.com:443?sni=trojan.example.com#T").unwrap();
    let config = probe_config(&named, &listen(), ClientDevice::Pc, &Uplink::Bind(None)).unwrap();
    assert_eq!(
        config["dns"],
        json!({ "servers": [{ "type": "local", "tag": "dns-bootstrap" }], "strategy": "ipv4_only" })
    );
    assert_eq!(config["route"]["default_domain_resolver"], "dns-bootstrap");
    assert_eq!(
        config["outbounds"][0]["domain_resolver"]["server"],
        "dns-bootstrap"
    );
    assert!(config["outbounds"][0].get("bind_interface").is_none());
}

/// Every generated shape passes `sing-box check` (skipped without the bundled engine).
#[tokio::test]
async fn probe_configs_pass_singbox_check() {
    let exe = resources().join("sing-box.exe");
    if !exe.exists() {
        return;
    }
    let direct = Loopback {
        port: 53648,
        creds: Some(Creds {
            user: "u1".into(),
            pass: "p1-fake".into(),
        }),
    };
    let profiles = [
        reality(),
        parse_uri("trojan://fake-pass@trojan.example.com:443?sni=trojan.example.com#T").unwrap(),
        parse_uri("hysteria2://fake-pass@hy.example.com:8443?sni=hy.example.com#H").unwrap(),
        parse_uri("ss://YWVzLTI1Ni1nY206ZmFrZS1wYXNz@198.51.100.7:8388#S").unwrap(),
    ];
    for p in &profiles {
        for route in [
            Uplink::Detour(direct.clone()),
            Uplink::Bind(Some("Wi-Fi".into())),
            Uplink::Bind(None),
        ] {
            let config = probe_config(p, &listen(), ClientDevice::Pc, &route).unwrap();
            let bytes = serde_json::to_vec(&config).unwrap();
            let checked = vpnte_engine::singbox_process::check_config(&exe, &bytes).await;
            assert!(checked.is_ok(), "{} {route:?}: {checked:?}", p.kind.label());
        }
    }
}

/// A closed loopback port (bound, then released).
async fn closed_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

/// A profile sing-box rejects at start: an unknown field in its outbound.
fn with_unknown_field(mut p: Profile) -> Profile {
    p.singbox_extra.insert("gecko".into(), json!(1));
    p
}

/// Vector 34: an engine that exits right after start is a verdict, not an error; a missing
/// engine is an error.
#[tokio::test]
async fn engine_exit_is_a_verdict() {
    let Some(ctx) = ctx(EnginePref::Auto) else {
        return;
    };
    let cancel = CancellationToken::new();
    let port = closed_port().await;
    let socks = with_unknown_field(parse_uri(&format!("socks://127.0.0.1:{port}#S")).unwrap());
    let health = check_profile(&socks, &ctx, &cancel).await.unwrap();
    assert!(!health.online);
    assert_eq!(health.reason, Some(HealthReason::ConfigFailed));
    assert_eq!(health.engine, Some(Engine::SingBox));
    let link = format!("hysteria2://fake-pass@127.0.0.1:{port}?sni=example.com#H");
    let hy2 = with_unknown_field(parse_uri(&link).unwrap());
    let health = check_profile(&hy2, &ctx, &cancel).await.unwrap();
    assert_eq!(health.reason, Some(HealthReason::Hy2ConfigFailed));

    let missing = ProbeCtx {
        singbox_exe: resources().join("no-such-engine.exe"),
        ..ctx.clone()
    };
    assert!(check_profile(&socks, &missing, &cancel).await.is_err());
}

/// An upstream that refuses connections: the engine runs, every destination fails, offline.
#[tokio::test]
async fn refused_upstream_is_offline() {
    let Some(ctx) = ctx(EnginePref::Auto) else {
        return;
    };
    let port = closed_port().await;
    let socks = parse_uri(&format!("socks://127.0.0.1:{port}#S")).unwrap();
    let health = check_profile(&socks, &ctx, &CancellationToken::new())
        .await
        .unwrap();
    assert!(!health.online && health.reason.is_some(), "{health:?}");
    assert_eq!(health.engine, Some(Engine::SingBox));
}

/// The Xray path (preference Xray, plain Shadowsocks): engine up, upstream refused, offline.
#[tokio::test]
async fn xray_probe_runs() {
    let Some(ctx) = ctx(EnginePref::Xray) else {
        return;
    };
    let port = closed_port().await;
    let ss = parse_uri(&format!(
        "ss://YWVzLTI1Ni1nY206ZmFrZS1wYXNz@127.0.0.1:{port}#S"
    ))
    .unwrap();
    let health = check_profile(&ss, &ctx, &CancellationToken::new())
        .await
        .unwrap();
    assert!(!health.online && health.reason.is_some(), "{health:?}");
    assert_eq!(health.engine, Some(Engine::Xray));
}

/// What the fake upstream answers for a CONNECT host: delay (ms) and body.
type Answer = fn(&str) -> (u64, String);

/// A fake SOCKS5 upstream (no auth) that terminates TLS with the test certificate and answers
/// each request with `answer(host)`.
async fn upstream(answer: Answer) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _ = serve(s, answer).await;
            });
        }
    });
    port
}

async fn serve(mut s: TcpStream, answer: Answer) -> std::io::Result<()> {
    let mut greet = [0; 3];
    s.read_exact(&mut greet).await?;
    s.write_all(&[5, 0]).await?;
    let mut head = [0; 5];
    s.read_exact(&mut head).await?;
    let mut name = vec![0; head[4] as usize + 2];
    s.read_exact(&mut name).await?;
    let host = String::from_utf8_lossy(&name[..name.len() - 2]).into_owned();
    s.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 80]).await?;
    vpnte_base::http::init_tls();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(LEAF_KEY.to_vec().into());
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![LEAF.to_vec().into()], key)
        .map_err(std::io::Error::other)?;
    let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config));
    let tls = acceptor.accept(s).await?;
    respond(tls, answer(&host)).await
}

async fn respond<S>(mut s: S, (delay, body): (u64, String)) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = vec![0; 4096];
    let mut seen = Vec::new();
    while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = s.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        seen.extend_from_slice(&buf[..n]);
    }
    tokio::time::sleep(Duration::from_millis(delay)).await;
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    s.write_all(head.as_bytes()).await?;
    s.write_all(body.as_bytes()).await?;
    s.shutdown().await
}

fn trust_test_ca(b: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
    b.tls_certs_only([reqwest::Certificate::from_der(CA).unwrap()])
}

const TEST_DESTINATIONS: [Destination; 2] = [
    Destination {
        url: "https://cloudflare.com/cdn-cgi/trace",
        trace: true,
    },
    Destination {
        url: "https://api.ipify.org/",
        trace: false,
    },
];

fn slow_trace(host: &str) -> (u64, String) {
    if host == "cloudflare.com" {
        (300, "fl=1\nip=8.8.8.8\nloc=DE\n".to_owned())
    } else {
        (0, String::new())
    }
}

/// End to end on loopback: probe engine → fake upstream → TLS destinations. The fast non-trace
/// answer wins, the trace (later, within the grace) still yields the exit IP and country.
#[tokio::test]
async fn online_with_trace_grace() {
    let Some(ctx) = ctx(EnginePref::Auto) else {
        return;
    };
    let port = upstream(slow_trace).await;
    let socks = parse_uri(&format!("socks://127.0.0.1:{port}#S")).unwrap();
    let cancel = CancellationToken::new();
    let health = probe_with(&socks, &ctx, &TEST_DESTINATIONS, trust_test_ca, &cancel)
        .await
        .unwrap();
    assert!(health.online, "{health:?}");
    assert_eq!(health.egress_ip, Some("8.8.8.8".parse().unwrap()));
    assert_eq!(health.country, Iso2::new("DE"));
    assert!(
        health.rtt_ms.is_some_and(|ms| (1..300).contains(&ms)),
        "{health:?}"
    );
    assert_eq!(health.reason, None);
}

fn never(_: &str) -> (u64, String) {
    (5_000, String::new())
}

/// Cancellation before or during a probe is an error (never "offline").
#[tokio::test]
async fn cancellation_is_an_error() {
    let Some(ctx) = ctx(EnginePref::Auto) else {
        return;
    };
    let port = upstream(never).await;
    let socks = parse_uri(&format!("socks://127.0.0.1:{port}#S")).unwrap();
    let gone = CancellationToken::new();
    gone.cancel();
    let err = check_profile(&socks, &ctx, &gone).await.unwrap_err();
    assert_eq!(err.kind, ErrorKind::Cancelled);
    let later = CancellationToken::new();
    let trigger = later.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(1500)).await;
        trigger.cancel();
    });
    let err = probe_with(&socks, &ctx, &TEST_DESTINATIONS, trust_test_ca, &later)
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Cancelled);
}

/// Vector 35: an empty batch is `GroupNotFoundOrEmpty`; unreadable rows are `no-outbound`;
/// a batch whose probes all fail to set up returns the setup error.
#[tokio::test]
async fn batches() {
    let Some(ctx) = ctx(EnginePref::Auto) else {
        return;
    };
    let cancel = CancellationToken::new();
    let empty: Vec<(u32, Option<Profile>)> = Vec::new();
    assert!(matches!(
        check_many(empty, &ctx, &cancel).await,
        Err(HealthError::GroupNotFoundOrEmpty)
    ));
    let rows = check_many(vec![(7u32, None)], &ctx, &cancel).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (rows[0].0, rows[0].1.reason),
        (7, Some(HealthReason::NoOutbound))
    );
    let port = closed_port().await;
    let socks = parse_uri(&format!("socks://127.0.0.1:{port}#S")).unwrap();
    let missing = ProbeCtx {
        singbox_exe: resources().join("no-such-engine.exe"),
        ..ctx.clone()
    };
    let failed = check_many(
        vec![(1u32, Some(socks.clone())), (2, Some(socks))],
        &missing,
        &cancel,
    )
    .await;
    assert!(matches!(failed, Err(HealthError::Setup(_))));
    let gone = CancellationToken::new();
    gone.cancel();
    let cancelled = check_many(vec![(1u32, None)], &ctx, &gone).await;
    assert!(matches!(cancelled, Err(HealthError::Cancelled)));
}

/// The same endpoint with a credential the server cannot know.
fn scrambled(mut p: Profile) -> Profile {
    const FAKE_ID: &str = "00000000-1111-4222-8333-444444444444";
    match &mut p.kind {
        Kind::Vless { uuid, .. } | Kind::Vmess { uuid, .. } => *uuid = FAKE_ID.into(),
        Kind::Tuic { uuid, password, .. } => {
            *uuid = FAKE_ID.into();
            *password = "fake-password".into();
        }
        Kind::Trojan { password }
        | Kind::Shadowsocks { password, .. }
        | Kind::Hysteria2 { password, .. }
        | Kind::Naive { password, .. }
        | Kind::Anytls { password, .. } => *password = "fake-password-0000".into(),
        _ => {}
    }
    if let Some(Kind::Shadowsocks { .. }) = Some(&p.kind) {
        // 2022 methods need a base64 key of the method's size: keep the shape, change the bytes.
        if let Kind::Shadowsocks {
            method, password, ..
        } = &mut p.kind
            && method.starts_with("2022-")
        {
            *password = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into();
        }
    }
    p
}

/// Vector 33 (keyHealthChecker.live.test.ts, opt-in): a working key (share link in the
/// environment variable `VPNTE_LIVE_KEY`, never stored in the repository) is online; the same
/// endpoint with a random credential is offline.
#[tokio::test]
#[ignore = "needs the internet and a real key in VPNTE_LIVE_KEY"]
async fn live_key_online_and_scrambled_offline() {
    let Ok(link) = std::env::var("VPNTE_LIVE_KEY") else {
        return;
    };
    let Some(ctx) = ctx(EnginePref::Auto) else {
        return;
    };
    let key = parse_uri(link.trim()).unwrap();
    let cancel = CancellationToken::new();
    let health = check_profile(&key, &ctx, &cancel).await.unwrap();
    assert!(health.online, "{health:?}");
    let fake = check_profile(&scrambled(key), &ctx, &cancel).await.unwrap();
    assert!(!fake.online, "{fake:?}");
}

/// The package's locale fragments are valid JSON with identical keys, and every key this
/// package returns exists in both.
#[test]
fn locale_fragments_cover_every_key() {
    use crate::egress::EgressError;
    use crate::geo::VerifyReject;
    let mut keys = Vec::new();
    for text in [
        include_str!("../../locales/probes-servers.ru.json"),
        include_str!("../../locales/probes-servers.en.json"),
    ] {
        keys.push(
            crate::test_support::flatten(text)
                .into_keys()
                .collect::<Vec<_>>(),
        );
    }
    assert_eq!(keys[0], keys[1], "ru and en key sets differ");
    let mut used: Vec<String> = [
        HealthReason::NoOutbound,
        HealthReason::ConfigFailed,
        HealthReason::TlsFailed,
        HealthReason::AuthFailed,
        HealthReason::Timeout,
        HealthReason::HandshakeFailed,
        HealthReason::Hy2ConfigFailed,
        HealthReason::Hy2AuthFailed,
        HealthReason::Hy2UdpBlocked,
        HealthReason::Hy2TlsFailed,
        HealthReason::Hy2HandshakeFailed,
    ]
    .iter()
    .map(|r| r.msg().key.into_owned())
    .collect();
    for reject in [
        VerifyReject::GeoDisabled,
        VerifyReject::InvalidIp,
        VerifyReject::Superseded,
        VerifyReject::SwitchInProgress,
        VerifyReject::NoActiveProfile,
        VerifyReject::ResolveFailed,
        VerifyReject::LookupFailed,
    ] {
        used.push(reject.msg().key.into_owned());
    }
    for err in [EgressError::Validation, EgressError::Network] {
        used.push(vpnte_base::AppError::from(err).user_msg().key.into_owned());
    }
    used.push(
        vpnte_base::AppError::from(HealthError::GroupNotFoundOrEmpty)
            .user_msg()
            .key
            .into_owned(),
    );
    used.sort();
    assert_eq!(used, keys[0], "every key is used and every used key exists");
}
