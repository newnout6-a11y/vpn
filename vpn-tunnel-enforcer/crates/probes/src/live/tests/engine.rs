//! Engine stage through a fake probe inbound (live-probe §7.3, §7.8, §7.14 B-04 / B-09).
use std::time::{Duration, Instant};

use serde_json::Map;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{ClientDevice, EnginePref, Loopback};
use vpnte_profiles::model::{DialPrefs, Host, Kind, Profile, Source, Tls};

use super::socks::{Reply, fake_socks, http};
use crate::key_health::HealthReason;
use crate::live::engine_probe::{EngineInput, EngineStage, assemble, measure, run_engine_probe};
use crate::live::model::{
    EgressStatus, EngineRoute, HandshakeStatus, Ipv6Status, MediaStatus, ReflectorStatus,
    ThroughputStatus,
};
use crate::live::wire::Wire;
use crate::live::{EngineSetup, ProfileTarget, TunnelState, TunnelView};

pub(crate) fn vless() -> Profile {
    Profile {
        name: "Profile 1".into(),
        description: None,
        server: Host::Domain("vpn.example.test".into()),
        port: 443,
        kind: Kind::Vless {
            uuid: "00000000-0000-4000-8000-000000000000".into(),
            flow: None,
            packet_encoding: None,
            encryption: None,
        },
        tls: Some(Tls {
            server_name: Some("vpn.example.test".into()),
            alpn: vec!["h2".into()],
            ..Tls::default()
        }),
        transport: None,
        mux: None,
        dial: DialPrefs::default(),
        native_xray: None,
        singbox_extra: Map::new(),
        source: Source::Json,
        notes: Vec::new(),
    }
}

/// A Hysteria2 key (QUIC: a UDP transport) with fake credentials.
pub(crate) fn hysteria2() -> Profile {
    Profile {
        kind: Kind::Hysteria2 {
            password: "fake-pass".into(),
            obfs: None,
            ports: Vec::new(),
            hop_interval_s: None,
            hop_interval_max_s: None,
            up_mbps: None,
            down_mbps: None,
            bbr_profile: None,
        },
        ..vless()
    }
}

pub(crate) fn target(profile: Profile) -> ProfileTarget {
    ProfileTarget {
        id: "p1".into(),
        profile,
        country: None,
        device: ClientDevice::Pc,
        eligible: true,
    }
}

/// Engines that must never start in these tests.
pub(crate) fn no_engines() -> EngineSetup {
    EngineSetup {
        singbox_exe: "Z:\\missing\\sing-box.exe".into(),
        xray_exe: "Z:\\missing\\xray.exe".into(),
        engine_pref: EnginePref::Auto,
        dns_bootstrap_in: None,
    }
}

/// Our tunnel runs the checked profile; `probe` = its `live-check-in`.
fn self_probe(probe: Option<Loopback>) -> TunnelView {
    TunnelView {
        state: TunnelState::Up,
        active_profile_id: Some("p1".into()),
        live_check_in: probe,
        mixed_direct_in: Some(Loopback {
            port: 1,
            creds: None,
        }),
        tun_luid: None,
    }
}

async fn run(tunnel: &TunnelView, throughput: bool, cancel: &CancellationToken) -> EngineStage {
    let t = target(vless());
    let setup = no_engines();
    let wire = Wire::plain();
    let input = EngineInput {
        target: &t,
        tunnel,
        setup: &setup,
        wire: &wire,
        endpoint_ip: None,
        throughput,
        deadline: None,
    };
    run_engine_probe(input, cancel).await
}

/// liveServerProbe.handshake.test.ts:94-128: the self-probe measures the running tunnel through
/// its own inbound, never a second engine; one reflector suffices for the handshake.
#[tokio::test]
async fn self_probe_through_live_check_in() {
    let fake = fake_socks(|host| match host {
        "1.1.1.1" => Reply::Close,
        "api.ipify.org" => http("200 OK", b"95.165.12.34"),
        "api6.ipify.org" => Reply::Refuse(3),
        _ => Reply::Refuse(5),
    })
    .await;
    let stage = run(
        &self_probe(Some(fake.inbound.clone())),
        true,
        &CancellationToken::new(),
    )
    .await;
    let h = &stage.handshake;
    assert_eq!(h.status, HandshakeStatus::Ok);
    assert_eq!(h.route, Some(EngineRoute::ActiveTunnel));
    let ev = h.evidence.as_ref().unwrap();
    assert_eq!(
        (ev.transport.as_deref(), ev.alpn.as_deref()),
        (Some("vless"), Some("h2"))
    );
    assert_eq!(ev.inbound_port, Some(fake.inbound.port));
    let r = &stage.egress.reflectors;
    assert_eq!(r[0].source, "cloudflare-trace");
    assert_eq!(
        r[0].error.as_deref(),
        Some("probe destination closed without HTTP response")
    );
    assert_eq!(
        (r[1].status, r[1].ip.as_deref()),
        (ReflectorStatus::Ok, Some("95.165.12.34"))
    );
    assert_eq!(
        r[2].status,
        ReflectorStatus::Unsupported,
        "B-17: SOCKS reply 3"
    );
    assert_eq!(stage.egress.status, EgressStatus::Partial);
    assert_eq!(stage.egress.ipv6_status, Some(Ipv6Status::Unsupported));
    assert_eq!(stage.media.status, MediaStatus::Error);
    let t = stage.throughput.as_ref().unwrap();
    assert_eq!(
        (t.status, t.route),
        (ThroughputStatus::Error, Some(EngineRoute::ActiveTunnel))
    );
    let mut seen = fake.targets.lock().clone();
    seen.sort();
    for host in [
        "1.1.1.1:443",
        "api.ipify.org:443",
        "api6.ipify.org:443",
        "usher.ttvnw.net:443",
        "static.twitchcdn.net:443",
        "speed.cloudflare.com:443",
    ] {
        assert!(
            seen.iter().any(|s| s == host),
            "{host} not dialled: {seen:?}"
        );
    }
}

/// liveServerProbe.handshake.test.ts:169-187: no probe inbound on the running tunnel → nothing
/// is dialled and no engine starts.
#[tokio::test]
async fn self_probe_without_inbound_is_skipped() {
    let stage = run(&self_probe(None), true, &CancellationToken::new()).await;
    assert_eq!(stage.handshake.status, HandshakeStatus::Skipped);
    assert!(stage.handshake.error.is_none(), "no engine was tried");
    assert_eq!(stage.egress.status, EgressStatus::Skipped);
    assert_eq!(stage.media.status, MediaStatus::Skipped);
    let t = stage.throughput.unwrap();
    assert_eq!(
        (t.status, t.duration_ms, t.samples.len()),
        (ThroughputStatus::Skipped, 0, 0)
    );
    assert_eq!(t.route, Some(EngineRoute::ActiveTunnel));
}

/// A key the engine setting does not run (forced Xray, TUIC: Xray has no client) was never
/// tried: the stage is skipped with the engine-setting note, never a failed handshake.
#[tokio::test]
async fn an_engine_setting_refusal_is_no_handshake_verdict() {
    let uri = "tuic://00000000-0000-4000-8000-000000000001:fake-pass@tuic.example.test:443\
               ?sni=tuic.example.test#T";
    let t = target(vpnte_profiles::uri::parse_uri(uri).unwrap());
    let setup = EngineSetup {
        engine_pref: EnginePref::Xray,
        ..no_engines()
    };
    let input = EngineInput {
        target: &t,
        tunnel: &TunnelView::down(),
        setup: &setup,
        wire: &Wire::plain(),
        endpoint_ip: None,
        throughput: false,
        deadline: None,
    };
    let stage = run_engine_probe(input, &CancellationToken::new()).await;
    assert_eq!(stage.handshake.status, HandshakeStatus::Skipped);
    assert!(stage.handshake.error.is_none(), "nothing was tried");
    let note = Some(HealthReason::EngineSetting.msg().into());
    assert_eq!(stage.handshake.note, note);
    assert_eq!(stage.egress.status, EgressStatus::Skipped);
}

/// B-04: CONNECTs that succeed without a status line coming back prove nothing; the verdict
/// comes from the engine log.
#[tokio::test]
async fn connect_alone_is_no_handshake() {
    let fake = fake_socks(|_| Reply::Close).await;
    let wire = Wire::plain();
    let cancel = CancellationToken::new();
    let m = measure(&wire, &fake.inbound, None, None, &cancel).await;
    let log = "outbound/vless[proxy-out]: tls handshake\nvless: authentication failed";
    let stage = assemble(
        m,
        &vless(),
        None,
        EngineRoute::PhysicalDirect,
        fake.inbound.port,
        log,
    );
    let h = &stage.handshake;
    assert_eq!(h.status, HandshakeStatus::AuthFailed);
    let ev = h.evidence.as_ref().unwrap();
    assert_eq!(
        (ev.socks_connect_ok, ev.detail.as_deref()),
        (Some(true), Some("auth-failed"))
    );
    assert_eq!(
        h.error.as_deref(),
        Some("probe destination closed without HTTP response")
    );
    assert_eq!(stage.egress.status, EgressStatus::Error);
    let m = measure(&wire, &fake.inbound, None, None, &cancel).await;
    let stage = assemble(
        m,
        &vless(),
        None,
        EngineRoute::PhysicalDirect,
        fake.inbound.port,
        "",
    );
    assert_eq!(stage.handshake.status, HandshakeStatus::TransportFailed);
}

/// B-09 through the wire: two reflectors with different IPv4 exits → partial with the reason.
#[tokio::test]
async fn reflectors_disagree() {
    let fake = fake_socks(|host| match host {
        "1.1.1.1" => http("200 OK", b"fl=1\nip=95.165.12.34\nloc=DE\n"),
        "api.ipify.org" => http("200 OK", b"95.165.12.35"),
        _ => Reply::Refuse(4),
    })
    .await;
    let m = measure(
        &Wire::plain(),
        &fake.inbound,
        None,
        None,
        &CancellationToken::new(),
    )
    .await;
    let stage = assemble(
        m,
        &vless(),
        "95.165.12.34".parse().ok(),
        EngineRoute::PhysicalDirect,
        1,
        "",
    );
    assert_eq!(stage.handshake.status, HandshakeStatus::Ok);
    let e = &stage.egress;
    assert_eq!(
        (e.status, e.country.as_deref()),
        (EgressStatus::Partial, Some("DE"))
    );
    assert!(e.discrepancy.is_some());
    assert_eq!(e.matches_endpoint, Some(true));
}

/// §7.8 (304-323) + B-10: three sequential 4 MiB samples; body bytes alone prove the handshake
/// (reflectors blocked at the exit).
#[tokio::test]
async fn throughput_samples_prove_the_handshake() {
    let body = vec![0u8; 4 * 1024 * 1024];
    let speed = http("200 OK", &body);
    let fake = fake_socks(move |host| match host {
        "speed.cloudflare.com" => speed.clone(),
        _ => Reply::Close,
    })
    .await;
    let m = measure(
        &Wire::plain(),
        &fake.inbound,
        Some(EngineRoute::PhysicalDirect),
        None,
        &CancellationToken::new(),
    )
    .await;
    let stage = assemble(m, &vless(), None, EngineRoute::PhysicalDirect, 1, "");
    assert_eq!(stage.handshake.status, HandshakeStatus::Ok);
    let t = stage.throughput.unwrap();
    assert_eq!(t.samples.len(), 3);
    assert!(
        t.samples
            .iter()
            .all(|s| s.bytes == 4 * 1024 * 1024 && s.complete)
    );
    assert!(t.median_mbps.is_some_and(|m| m > 0.0));
    let speed_dials = fake
        .targets
        .lock()
        .iter()
        .filter(|t| t.starts_with("speed."))
        .count();
    assert_eq!(speed_dials, 3);
}

/// AT-00-003 (§7.8 166-178): a cancel reaches the requests through the self-probe at once.
#[tokio::test]
async fn cancel_returns_promptly() {
    let fake = fake_socks(|_| Reply::Hang).await;
    let cancel = CancellationToken::new();
    let tunnel = self_probe(Some(fake.inbound.clone()));
    let started = Instant::now();
    let stop = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        stop.cancel();
    });
    let stage = run(&tunnel, true, &cancel).await;
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(stage.handshake.status, HandshakeStatus::Skipped);
    assert_eq!(stage.handshake.error.as_deref(), Some("Cancelled"));
}

/// The temporary engine path with the bundled sing-box (skipped when it is not there): the
/// profile is a SOCKS key whose "server" is the fake, so every probe crosses a real engine;
/// the engine is stopped before the stage returns.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn temporary_singbox_engine() {
    let resources = crate::test_support::resources();
    let singbox = resources.join("sing-box.exe");
    if !singbox.exists() {
        return;
    }
    let fake = fake_socks(|host| match host {
        "1.1.1.1" => http("200 OK", b"fl=1\nip=95.165.12.34\nloc=NL\n"),
        "api.ipify.org" => http("200 OK", b"95.165.12.34"),
        _ => Reply::Refuse(4),
    })
    .await;
    let creds = super::socks::creds();
    let mut profile = vless();
    profile.server = Host::Ip([127, 0, 0, 1].into());
    profile.port = fake.inbound.port;
    profile.tls = None;
    profile.kind = Kind::Socks {
        username: Some(creds.user),
        password: Some(creds.pass),
    };
    let t = target(profile);
    let setup = EngineSetup {
        singbox_exe: singbox,
        xray_exe: resources.join("xray.exe"),
        engine_pref: EnginePref::Auto,
        dns_bootstrap_in: None,
    };
    let wire = Wire::plain();
    let tunnel = TunnelView::down();
    let input = EngineInput {
        target: &t,
        tunnel: &tunnel,
        setup: &setup,
        wire: &wire,
        endpoint_ip: None,
        throughput: false,
        deadline: None,
    };
    let stage = run_engine_probe(input, &CancellationToken::new()).await;
    let h = &stage.handshake;
    assert_eq!(h.status, HandshakeStatus::Ok, "{h:?}");
    assert_eq!(h.route, Some(EngineRoute::PhysicalDirect));
    assert_ne!(
        h.evidence.as_ref().unwrap().inbound_port,
        Some(fake.inbound.port),
        "went through the engine"
    );
    assert_eq!(stage.egress.status, EgressStatus::Ok);
    assert_eq!(stage.egress.exit_ipv4.as_deref(), Some("95.165.12.34"));
    assert_eq!(stage.egress.country.as_deref(), Some("NL"));
    let seen = fake.targets.lock().clone();
    assert!(
        seen.contains(&"api.ipify.org:443".to_owned()),
        "names resolve at the exit: {seen:?}"
    );
}

/// extendedReviewFixed.test.ts:56-66: a non-2xx reflector is an error entry, yet its status line
/// still proves the tunnel carried bytes.
#[tokio::test]
async fn non_2xx_reflector() {
    let fake = fake_socks(|host| match host {
        "api.ipify.org" => http("503 Service Unavailable", b""),
        _ => Reply::Refuse(4),
    })
    .await;
    let m = measure(
        &Wire::plain(),
        &fake.inbound,
        None,
        None,
        &CancellationToken::new(),
    )
    .await;
    let stage = assemble(m, &vless(), None, EngineRoute::PhysicalDirect, 1, "");
    let ipify = &stage.egress.reflectors[1];
    assert_eq!(
        (ipify.status, ipify.error.as_deref()),
        (ReflectorStatus::Error, Some("reflector returned HTTP 503"))
    );
    assert_eq!(ipify.family, Some(4));
    assert_eq!(stage.handshake.status, HandshakeStatus::Ok);
    assert_eq!(stage.egress.status, EgressStatus::Error);
}
