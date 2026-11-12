//! Tests of the probe discipline: the handshake budget on a hand-driven clock, the classifier
//! table, endpoint keys and the locale fragment; the transfer check against a scripted SOCKS
//! server in `transfer.rs`.
use std::time::Duration;

use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use vpnte_base::ErrorKind;
use vpnte_profiles::uri::parse_uri;

use super::budget::HandshakeBudget;
use super::*;
use crate::key_health::HealthReason;

mod transfer;

const NO_WAIT: Duration = Duration::ZERO;
const MINUTE_PLUS: Duration = Duration::from_secs(61);

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

fn sni(name: &str) -> Endpoint {
    Endpoint::server_name(name)
}

/// Fact (a): at most 3 new handshakes per 60 s per endpoint, 400 ms apart; the 4th waits for
/// the first to leave the window or is deferred, and a deferral reserves nothing.
#[test]
fn budget_spaces_and_caps_handshakes_per_endpoint() {
    let b = HandshakeBudget::default();
    let t0 = Instant::now();
    let e = sni("www.example.com");
    let slots: Vec<_> = (0..3)
        .map(|_| b.reserve_at(&e, t0, MINUTE_PLUS).unwrap())
        .collect();
    assert_eq!(slots, vec![t0, t0 + ms(400), t0 + ms(800)]);
    let err = b.reserve_at(&e, t0, Duration::from_secs(30)).unwrap_err();
    assert_eq!(
        err,
        BudgetError::Deferred {
            retry_after: WINDOW
        }
    );
    // Nothing was reserved by the refusal: the same slot is still the next one.
    assert_eq!(b.reserve_at(&e, t0, MINUTE_PLUS).unwrap(), t0 + WINDOW);
    // The window slides: the next one waits for the second reservation to leave it.
    assert_eq!(
        b.reserve_at(&e, t0, Duration::from_secs(70)).unwrap(),
        t0 + ms(400) + WINDOW
    );
    // Another endpoint has its own budget.
    assert_eq!(b.reserve_at(&sni("other.example.com"), t0, NO_WAIT), Ok(t0));
}

/// Spacing alone: a second handshake 100 ms after the first waits until 400 ms; a slow caller
/// that comes back later than that is not delayed.
#[test]
fn budget_keeps_the_gap_and_frees_up_with_time() {
    let b = HandshakeBudget::default();
    let t0 = Instant::now();
    let e = Endpoint::host_port("203.0.113.9", 8443);
    assert_eq!(b.reserve_at(&e, t0, NO_WAIT), Ok(t0));
    assert_eq!(
        b.reserve_at(&e, t0 + ms(100), NO_WAIT),
        Err(BudgetError::Deferred {
            retry_after: ms(300)
        })
    );
    assert_eq!(b.reserve_at(&e, t0 + ms(100), ms(300)), Ok(t0 + ms(400)));
    assert_eq!(b.reserve_at(&e, t0 + ms(5000), NO_WAIT), Ok(t0 + ms(5000)));
    // Three within the minute: the next free slot is 60 s after the first.
    let later = t0 + WINDOW + ms(1);
    assert_eq!(b.reserve_at(&e, later, NO_WAIT), Ok(later));
}

/// A freeze verdict holds the endpoint quiet (~120 s freeze, redialling inside it extends it).
#[test]
fn hold_keeps_an_endpoint_quiet() {
    let b = HandshakeBudget::default();
    let t0 = Instant::now();
    let e = sni("frozen.example.com");
    b.hold_at(&e, t0, FREEZE_BACKOFF);
    b.hold_at(&e, t0, Duration::from_secs(10)); // a shorter hold never shortens it
    assert_eq!(
        b.reserve_at(&e, t0, NO_WAIT),
        Err(BudgetError::Deferred {
            retry_after: FREEZE_BACKOFF
        })
    );
    assert_eq!(
        b.reserve_at(&e, t0, FREEZE_BACKOFF),
        Ok(t0 + FREEZE_BACKOFF)
    );
}

/// A slot given back by a cancelled wait does not make the budget forget the three handshakes
/// already in the window (they still bound the next one).
#[tokio::test]
async fn a_released_slot_keeps_the_window() {
    let b = HandshakeBudget::default();
    let e = sni("release.example.com");
    let t0 = Instant::now();
    for _ in 0..3 {
        b.reserve_at(&e, t0, MINUTE_PLUS).unwrap();
    }
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    let err = b.acquire(&e, MINUTE_PLUS, &cancelled).await.unwrap_err();
    assert_eq!(err, BudgetError::Cancelled);
    let wait = b.wait_for(&e);
    assert!(wait > Duration::from_secs(58), "{wait:?}");
}

/// A cancelled wait gives its slot back; an exhausted budget answers `Deferred` as a
/// `Conflict` with the seconds to wait.
#[tokio::test]
async fn acquire_returns_a_cancelled_slot_and_maps_the_error() {
    let b = HandshakeBudget::default();
    let e = sni("cancel.example.com");
    let live = CancellationToken::new();
    b.acquire(&e, NO_WAIT, &live).await.unwrap();
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    let err = b.acquire(&e, ms(1000), &cancelled).await.unwrap_err();
    assert_eq!(err, BudgetError::Cancelled);
    let wait = b.wait_for(&e);
    assert!(
        wait <= ms(400) && wait > ms(200),
        "slot given back: {wait:?}"
    );
    let err: vpnte_base::AppError = b.acquire(&e, NO_WAIT, &live).await.unwrap_err().into();
    assert_eq!(err.kind, ErrorKind::Conflict);
    let msg = err.user_msg();
    assert_eq!(msg.key, "probes.discipline.deferred");
}

/// The budget key: the TLS server name when one is sent (any case), the server's domain when
/// TLS names none, `host:port` without a name (no TLS, an IP server, SNI disabled); a loopback
/// server (a local proxy) is not budgeted.
#[test]
fn endpoint_keys_follow_the_server_name() {
    let key = |uri: &str| Endpoint::of(&parse_uri(uri).unwrap()).map(|e| e.as_str().to_owned());
    let reality = "vless://00000000-0000-4000-8000-000000000001@203.0.113.5:443?security=reality\
                   &sni=WWW.Example.COM&pbk=fake-public-key&sid=ab#R";
    assert_eq!(key(reality).as_deref(), Some("sni:www.example.com"));
    assert_eq!(
        key("trojan://fake-pass@Trojan.Example.com:443#T").as_deref(),
        Some("sni:trojan.example.com")
    );
    assert_eq!(
        key("hysteria2://fake-pass@hy.example.com:8443?sni=cover.example.net#H").as_deref(),
        Some("sni:cover.example.net")
    );
    assert_eq!(
        key("ss://YWVzLTI1Ni1nY206ZmFrZS1wYXNz@198.51.100.7:8388#S").as_deref(),
        Some("198.51.100.7:8388")
    );
    assert_eq!(key("socks://127.0.0.1:10808#Local"), None);
    let mut no_sni = parse_uri("trojan://fake-pass@198.51.100.8:443#T").unwrap();
    let of = |p: &vpnte_profiles::model::Profile| Endpoint::of(p).map(|e| e.as_str().to_owned());
    assert_eq!(of(&no_sni).as_deref(), Some("198.51.100.8:443"));
    if let Some(tls) = no_sni.tls.as_mut() {
        tls.server_name = Some("cover.example.org".into());
        tls.disable_sni = true;
    }
    assert_eq!(of(&no_sni).as_deref(), Some("198.51.100.8:443"));
}

fn obs() -> Observations {
    Observations::default()
}

fn stalled(bytes: u64) -> Option<Transfer> {
    Some(Transfer::Stalled { bytes })
}

/// The classifier table: one row per field signature (facts b, c, d of the brief and the
/// REALITY mismatch), unsure cases stay `not-verified`.
#[test]
fn classifier_names_each_signature() {
    use Reaction as R;
    use Verdict as V;
    let failed = |reason| Observations {
        transfer: Some(Transfer::NoData),
        failure: Some(reason),
        ..obs()
    };
    let cases: Vec<(&str, Observations, V, R)> = vec![
        (
            "deferred",
            Observations {
                deferred: true,
                ..obs()
            },
            V::Deferred,
            R::RetryLater,
        ),
        (
            "64 KiB passed",
            Observations {
                transfer: Some(Transfer::Complete {
                    bytes: 70_000,
                    ms: 900,
                }),
                ..obs()
            },
            V::Healthy,
            R::None,
        ),
        (
            "16 KiB freeze",
            Observations {
                transfer: stalled(16 * 1024),
                ..obs()
            },
            V::Frozen,
            R::SwitchServer,
        ),
        (
            "band low edge",
            Observations {
                transfer: stalled(12 * 1024),
                ..obs()
            },
            V::Frozen,
            R::SwitchServer,
        ),
        (
            "band high edge",
            Observations {
                transfer: stalled(24 * 1024),
                ..obs()
            },
            V::Frozen,
            R::SwitchServer,
        ),
        (
            "stall at 40 KiB",
            Observations {
                transfer: stalled(40 * 1024),
                ..obs()
            },
            V::Stalled,
            R::RetryLater,
        ),
        (
            "stall at 4 KiB",
            Observations {
                transfer: stalled(4 * 1024),
                ..obs()
            },
            V::Stalled,
            R::RetryLater,
        ),
        (
            "http error after data",
            Observations {
                transfer: Some(Transfer::Failed {
                    bytes: 5000,
                    error: "http status 429".into(),
                }),
                ..obs()
            },
            V::NotVerified,
            R::RetryLater,
        ),
        (
            "auth",
            failed(HealthReason::AuthFailed),
            V::KeyRejected,
            R::SwitchServer,
        ),
        (
            "config",
            failed(HealthReason::ConfigFailed),
            V::NotVerified,
            R::None,
        ),
        (
            "real certificate",
            Observations {
                real_certificate: true,
                failure: Some(HealthReason::TlsFailed),
                ..obs()
            },
            V::HandshakeFailed,
            R::TryAnotherFingerprint,
        ),
        (
            "tls fails over working tcp",
            Observations {
                tcp: Seen::Answered,
                icmp: Seen::Answered,
                ..failed(HealthReason::TlsFailed)
            },
            V::HandshakeFailed,
            R::TryAnotherFingerprint,
        ),
        (
            "handshake hangs over working tcp",
            Observations {
                tcp: Seen::Answered,
                ..failed(HealthReason::Timeout)
            },
            V::HandshakeFailed,
            R::RetryLater,
        ),
        (
            "ip ban: icmp yes, tcp silent",
            Observations {
                tcp: Seen::Silent,
                icmp: Seen::Answered,
                ..failed(HealthReason::Timeout)
            },
            V::IpBanned,
            R::SwitchServer,
        ),
        (
            "nothing answers",
            Observations {
                tcp: Seen::Silent,
                icmp: Seen::Silent,
                ..failed(HealthReason::Timeout)
            },
            V::Offline,
            R::SwitchServer,
        ),
        (
            "port closed",
            Observations {
                tcp: Seen::Refused,
                icmp: Seen::Answered,
                ..failed(HealthReason::Timeout)
            },
            V::Refused,
            R::SwitchServer,
        ),
        (
            "the engine saw the reset, no reach evidence",
            failed(HealthReason::ConnectionRefused),
            V::Refused,
            R::SwitchServer,
        ),
        (
            "no reach evidence",
            failed(HealthReason::Timeout),
            V::NotVerified,
            R::RetryLater,
        ),
    ];
    for (name, o, verdict, reaction) in cases {
        let got = classify(&o);
        assert_eq!((got.verdict, got.reaction), (verdict, reaction), "{name}");
    }
}

/// Fact (d) and the ban over UDP: a QUIC transport that fails while the address answers TCP is
/// "UDP blocked" (prefer TCP); silence on TCP too with ICMP answering is a ban.
#[test]
fn classifier_separates_udp_blocks_from_bans() {
    let udp = |tcp, icmp, reason| Observations {
        udp_transport: true,
        transfer: Some(Transfer::NoData),
        failure: Some(reason),
        tcp,
        icmp,
        ..obs()
    };
    let hs = HealthReason::Hy2HandshakeFailed;
    let cases = [
        (
            udp(Seen::Refused, Seen::Answered, hs),
            Verdict::UdpBlocked,
            Reaction::PreferTcpTransport,
        ),
        (
            udp(Seen::Answered, Seen::NotRun, hs),
            Verdict::UdpBlocked,
            Reaction::PreferTcpTransport,
        ),
        (
            udp(Seen::Silent, Seen::Answered, hs),
            Verdict::IpBanned,
            Reaction::SwitchServer,
        ),
        (
            udp(Seen::Silent, Seen::Silent, hs),
            Verdict::Offline,
            Reaction::SwitchServer,
        ),
        (
            udp(Seen::NotRun, Seen::NotRun, HealthReason::Hy2UdpBlocked),
            Verdict::UdpBlocked,
            Reaction::PreferTcpTransport,
        ),
        (
            udp(Seen::NotRun, Seen::NotRun, hs),
            Verdict::NotVerified,
            Reaction::RetryLater,
        ),
        (
            udp(Seen::NotRun, Seen::NotRun, HealthReason::Hy2AuthFailed),
            Verdict::KeyRejected,
            Reaction::SwitchServer,
        ),
        // A TLS failure inside QUIC: the datagrams passed, the handshake is the problem.
        (
            udp(Seen::Refused, Seen::Answered, HealthReason::Hy2TlsFailed),
            Verdict::HandshakeFailed,
            Reaction::TryAnotherFingerprint,
        ),
    ];
    for (i, (o, verdict, reaction)) in cases.into_iter().enumerate() {
        let got = classify(&o);
        assert_eq!((got.verdict, got.reaction), (verdict, reaction), "case {i}");
    }
}

/// Engine log lines of a REALITY / version mismatch (sing-box #4520, Xray) are recognised.
#[test]
fn real_certificate_lines_are_recognised() {
    assert!(real_certificate(
        "ERROR outbound/vless: REALITY: received real certificate"
    ));
    assert!(real_certificate("reality verification failed"));
    assert!(!real_certificate("tls: handshake failure"));
}

/// Every verdict and reaction has ru + en text; the wire names match the server list's.
#[test]
fn verdict_texts_and_wire_names() {
    let en =
        crate::test_support::flatten(include_str!("../../../locales/probe-discipline.en.json"));
    let ru =
        crate::test_support::flatten(include_str!("../../../locales/probe-discipline.ru.json"));
    assert_eq!(en.keys().collect::<Vec<_>>(), ru.keys().collect::<Vec<_>>());
    let verdicts = [
        Verdict::Healthy,
        Verdict::Frozen,
        Verdict::Stalled,
        Verdict::HandshakeFailed,
        Verdict::KeyRejected,
        Verdict::IpBanned,
        Verdict::UdpBlocked,
        Verdict::Offline,
        Verdict::Deferred,
        Verdict::NotVerified,
    ];
    for v in verdicts {
        let key = v.msg().key.into_owned();
        assert!(en.contains_key(&key), "{key}");
    }
    let reactions = [
        Reaction::SwitchServer,
        Reaction::TryAnotherFingerprint,
        Reaction::PreferTcpTransport,
        Reaction::RetryLater,
    ];
    for r in reactions {
        let key = r.msg().expect("text").key.into_owned();
        assert!(en.contains_key(&key), "{key}");
    }
    assert!(Reaction::None.msg().is_none());
    assert!(en.contains_key("probes.discipline.deferred"));
    assert!(en.contains_key("probes.discipline.liveDeferred"));
    let wire = serde_json::to_value(Verdict::IpBanned).unwrap();
    assert_eq!(wire, serde_json::json!("ip-banned"));
}
