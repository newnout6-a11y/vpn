//! RU audit item 9: the network-mode classifier against fakes for every mode, the stage lines,
//! the runner's order, the QUIC probe on loopback and the DNS canary.
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use vpnte_core::resolve::DohByName;

use super::quic::{PROBE_LEN, is_negotiation, probe, probe_packet};
use super::stun;
use super::*;
use crate::discipline::{Reach, Seen, Transfer};

const OK: HostFacts = HostFacts {
    tcp: Outcome::Ok,
    tls: Outcome::Ok,
};
const SILENT: HostFacts = HostFacts {
    tcp: Outcome::Silent,
    tls: Outcome::NotRun,
};

/// An open network: every reference answers, 64 KiB arrive, QUIC and STUN answer.
fn open() -> Facts {
    Facts {
        system_dns: Outcome::Ok,
        doh_foreign: Outcome::Ok,
        doh_ru: Outcome::Ok,
        ru: vec![OK, OK],
        foreign: vec![OK, OK],
        transfer: Some(Transfer::Complete {
            bytes: 70_000,
            ms: 300,
        }),
        quic: vec![Outcome::Ok, Outcome::Ok],
        stun: vec![Outcome::Ok, Outcome::Ok],
        servers: Vec::new(),
    }
}

const MUTE: [Outcome; 2] = [Outcome::Silent, Outcome::Silent];

fn modes(f: &Facts) -> Vec<Mode> {
    classify(f).0
}

#[test]
fn open_network() {
    assert_eq!(classify(&open()), (Vec::new(), Summary::Open));
}

/// Mobile whitelist: Russian hosts pass TLS, foreign ones are dropped (or reset at TLS).
#[test]
fn whitelist() {
    let mut f = Facts {
        foreign: vec![SILENT, SILENT],
        transfer: None,
        quic: MUTE.to_vec(),
        stun: MUTE.to_vec(),
        doh_foreign: Outcome::Failed,
        ..open()
    };
    assert_eq!(classify(&f), (vec![Mode::Whitelist], Summary::Restricted));
    // UDP silence under a whitelist is the whitelist, not a UDP fact for the reactions.
    assert_eq!(udp_evidence(&f), UdpEvidence::Unclear);
    // An SNI whitelist: TCP connects, the handshake is cut.
    let reset = HostFacts {
        tcp: Outcome::Ok,
        tls: Outcome::Reset,
    };
    f.foreign = vec![reset, reset];
    assert_eq!(modes(&f), [Mode::Whitelist]);
}

/// Review b1/a2 (rule R1): UDP is dropped only when QUIC on 443 AND STUN on other ports are
/// silent while foreign TCP works; QUIC silence alone is a QUIC / port filter, not a UDP block.
#[test]
fn udp_blocked() {
    let f = Facts {
        quic: MUTE.to_vec(),
        stun: MUTE.to_vec(),
        ..open()
    };
    assert_eq!(classify(&f), (vec![Mode::UdpBlocked], Summary::Restricted));
    assert_eq!(udp_evidence(&f), UdpEvidence::Dropped);
    // One host of each kind unresolved, the others silent: still the signature.
    let f = Facts {
        quic: vec![Outcome::NotRun, Outcome::Silent],
        stun: vec![Outcome::Silent, Outcome::NotRun],
        ..open()
    };
    assert_eq!(modes(&f), [Mode::UdpBlocked]);
    // QUIC on 443 silent, STUN answers: UDP passes (Hysteria2 with Salamander, WireGuard work).
    let quic_cut = Facts {
        quic: MUTE.to_vec(),
        ..open()
    };
    assert_eq!(classify(&quic_cut), (Vec::new(), Summary::NotVerified));
    assert_eq!(udp_evidence(&quic_cut), UdpEvidence::Passes);
    let udp = line(&quic_cut, StepKind::Udp);
    assert_eq!(
        (udp.status, udp.detail.key.as_ref()),
        (StepStatus::Warn, "probes.netmode.step.udp.quicCut")
    );
    // QUIC silent and STUN not run: no proof either way.
    let f = Facts {
        quic: MUTE.to_vec(),
        stun: vec![Outcome::NotRun; 2],
        ..open()
    };
    assert_eq!(classify(&f), (Vec::new(), Summary::NotVerified));
    assert_eq!(udp_evidence(&f), UdpEvidence::Unclear);
    // An ICMP port-unreachable is not silence: no verdict, and not open either.
    let f = Facts {
        quic: vec![Outcome::Reset, Outcome::Silent],
        stun: MUTE.to_vec(),
        ..open()
    };
    assert_eq!(classify(&f), (Vec::new(), Summary::NotVerified));
    assert_eq!(udp_evidence(&f), UdpEvidence::Unclear);
    assert_eq!(udp_evidence(&open()), UdpEvidence::Passes);
}

#[test]
fn doh_blocked() {
    let f = Facts {
        doh_foreign: Outcome::Failed,
        ..open()
    };
    assert_eq!(modes(&f), [Mode::DohBlocked]);
    // Without a working system resolver it is not "only DoH" that fails.
    let f = Facts {
        system_dns: Outcome::Failed,
        doh_foreign: Outcome::Failed,
        ..open()
    };
    assert_eq!(modes(&f), Vec::<Mode>::new());
}

/// A banned server address: ICMP answers, TCP is dropped, while the network itself works.
#[test]
fn server_blocked() {
    let banned = Reach {
        icmp: Seen::Answered,
        tcp: Seen::Silent,
    };
    let alive = Reach {
        icmp: Seen::Answered,
        tcp: Seen::Answered,
    };
    let refused = Reach {
        icmp: Seen::Answered,
        tcp: Seen::Refused,
    };
    let f = Facts {
        servers: vec![alive, banned],
        ..open()
    };
    assert_eq!(modes(&f), [Mode::ServerBlocked]);
    // A closed port is a stopped server, not a ban.
    let f = Facts {
        servers: vec![refused],
        ..open()
    };
    assert_eq!(modes(&f), Vec::<Mode>::new());
}

#[test]
fn freeze() {
    let f = Facts {
        transfer: Some(Transfer::Stalled { bytes: 16 * 1024 }),
        ..open()
    };
    assert_eq!(classify(&f), (vec![Mode::Freeze], Summary::Restricted));
    // A stall outside the band is no freeze signature.
    let f = Facts {
        transfer: Some(Transfer::Stalled { bytes: 40 * 1024 }),
        ..open()
    };
    assert_eq!(classify(&f), (Vec::new(), Summary::NotVerified));
}

#[test]
fn offline_and_several_modes() {
    let f = Facts {
        ru: vec![SILENT, SILENT],
        foreign: vec![SILENT, SILENT],
        transfer: None,
        quic: MUTE.to_vec(),
        stun: MUTE.to_vec(),
        system_dns: Outcome::Silent,
        ..open()
    };
    assert_eq!(classify(&f), (Vec::new(), Summary::Offline));
    assert_eq!(
        udp_evidence(&f),
        UdpEvidence::Unclear,
        "offline proves nothing about UDP"
    );
    let f = Facts {
        transfer: Some(Transfer::Stalled { bytes: 14_000 }),
        quic: MUTE.to_vec(),
        stun: MUTE.to_vec(),
        ..open()
    };
    assert_eq!(
        modes(&f),
        [Mode::Freeze, Mode::UdpBlocked],
        "most limiting first"
    );
}

fn line(f: &Facts, kind: StepKind) -> Step {
    steps(f, false)
        .into_iter()
        .find(|s| s.kind == kind)
        .unwrap()
}

/// The page's lines: stage order, plain keys, counts as arguments.
#[test]
fn stage_lines() {
    let f = open();
    let kinds: Vec<StepKind> = steps(&f, false).iter().map(|s| s.kind).collect();
    use StepKind as K;
    assert_eq!(
        kinds,
        [K::Dns, K::Tcp, K::Tls, K::Bytes, K::Udp],
        "no servers asked"
    );
    assert_eq!(line(&f, K::Dns).detail.key, "probes.netmode.step.dns.ok");
    let tls = line(&f, K::Tls);
    assert_eq!(
        (tls.status, tls.detail.key.as_ref()),
        (StepStatus::Ok, "probes.netmode.step.tls")
    );
    let wl = Facts {
        foreign: vec![SILENT, SILENT],
        transfer: None,
        doh_foreign: Outcome::Failed,
        ..open()
    };
    assert_eq!(line(&wl, K::Tcp).status, StepStatus::Warn);
    assert_eq!(line(&wl, K::Bytes).status, StepStatus::NotRun);
    assert_eq!(
        line(&wl, K::Dns).detail.key,
        "probes.netmode.step.dns.dohForeignCut"
    );
    let frozen = Facts {
        transfer: Some(Transfer::Stalled { bytes: 16 * 1024 }),
        quic: MUTE.to_vec(),
        stun: MUTE.to_vec(),
        ..open()
    };
    let bytes = line(&frozen, K::Bytes);
    assert_eq!(
        (bytes.status, bytes.detail.key.as_ref()),
        (StepStatus::Fail, "probes.netmode.step.bytes.frozen")
    );
    assert_eq!(
        line(&frozen, K::Udp).detail.key,
        "probes.netmode.step.udp.blocked"
    );
}

/// A scripted network: answers by host, records the order of the probes.
struct Scripted {
    foreign: HostFacts,
    udp: Outcome,
    log: Mutex<Vec<String>>,
}

impl Scripted {
    fn note(&self, what: String) {
        self.log.lock().unwrap().push(what);
    }
}

impl NetProbe for Scripted {
    async fn system_dns(&self, name: &str) -> Outcome {
        self.note(format!("dns {name}"));
        Outcome::Ok
    }
    async fn doh(&self, resolver: DohByName, _: &str) -> Outcome {
        self.note(format!("doh {resolver:?}"));
        Outcome::Ok
    }
    async fn https(&self, host: &str) -> HostFacts {
        self.note(format!("https {host}"));
        if refs::FOREIGN_HOSTS.contains(&host) {
            self.foreign
        } else {
            OK
        }
    }
    async fn transfer(&self) -> Option<Transfer> {
        self.note("transfer".into());
        Some(Transfer::Complete {
            bytes: 70_000,
            ms: 1,
        })
    }
    async fn quic(&self, host: &str) -> Outcome {
        self.note(format!("quic {host}"));
        self.udp
    }
    async fn stun(&self, host: &str, port: u16) -> Outcome {
        self.note(format!("stun {host}:{port}"));
        self.udp
    }
    async fn reach(&self, dst: std::net::SocketAddr) -> Reach {
        self.note(format!("reach {dst}"));
        Reach::default()
    }
}

/// Stages run in order; the transfer is skipped when no foreign handshake passed.
#[tokio::test]
async fn gather_runs_the_stages_in_order() {
    let net = Scripted {
        foreign: OK,
        udp: Outcome::Ok,
        log: Mutex::default(),
    };
    let servers = vec!["203.0.113.9:443".parse().unwrap()];
    let facts = gather(&net, &servers, &CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(classify(&facts), (Vec::new(), Summary::Open));
    let log = net.log.lock().unwrap().clone();
    let at = |p: &str| log.iter().position(|l| l.starts_with(p)).unwrap();
    assert!(at("dns") < at("https") && at("https") < at("transfer"));
    assert!(at("transfer") < at("quic") && at("quic") < at("reach"));
    assert!(at("transfer") < at("stun") && at("stun") < at("reach"));

    let blocked = Scripted {
        foreign: SILENT,
        udp: Outcome::Silent,
        log: Mutex::default(),
    };
    let facts = gather(&blocked, &[], &CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(facts.transfer, None);
    assert!(!blocked.log.lock().unwrap().iter().any(|l| l == "transfer"));
    assert_eq!(report(&facts, false).modes, [Mode::Whitelist]);

    let cancel = CancellationToken::new();
    cancel.cancel();
    assert!(gather(&net, &[], &cancel).await.is_err());
}

/// The probe datagram is a padded long header with a reserved version; only a negotiation
/// packet echoing our source id counts as the answer.
#[test]
fn quic_probe_packet() {
    let (dcid, scid) = ([1u8; 8], [2u8; 8]);
    let p = probe_packet(dcid, scid);
    assert_eq!(p.len(), PROBE_LEN);
    assert_eq!(p[0] & 0xc0, 0xc0);
    assert_eq!(p[1..5], [0x1a, 0x2a, 0x3a, 0x4a]);
    let mut vn = vec![0x80, 0, 0, 0, 0, 8];
    vn.extend_from_slice(&scid);
    vn.push(8);
    vn.extend_from_slice(&dcid);
    vn.extend_from_slice(&[0, 0, 0, 1]);
    assert!(is_negotiation(&vn, &scid));
    assert!(!is_negotiation(&vn, &dcid), "another probe's answer");
    vn[4] = 1;
    assert!(!is_negotiation(&vn, &scid), "not version 0");
}

/// A loopback QUIC server that answers with version negotiation; then silence.
#[tokio::test]
async fn quic_probe_on_loopback() {
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();
    let answer = tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        let (n, from) = server.recv_from(&mut buf).await.unwrap();
        let mut vn = vec![0x80, 0, 0, 0, 0, 8];
        vn.extend_from_slice(&buf[15..23]);
        vn.push(8);
        vn.extend_from_slice(&buf[6..14]);
        vn.extend_from_slice(&[0, 0, 0, 1]);
        server.send_to(&vn, from).await.unwrap();
        n
    });
    assert_eq!(probe(addr, None, Duration::from_secs(2)).await, Outcome::Ok);
    assert_eq!(answer.await.unwrap(), PROBE_LEN);
    let quiet = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let silent = probe(
        quiet.local_addr().unwrap(),
        None,
        Duration::from_millis(200),
    )
    .await;
    assert_eq!(silent, Outcome::Silent);
}

/// Review b5: a non-loopback target without an uplink address of its family is not probed (an
/// unbound socket would follow our TUN, or another client's, and measure that tunnel).
#[tokio::test]
async fn udp_probes_never_leave_unbound() {
    let far: std::net::SocketAddr = "192.0.2.1:443".parse().unwrap();
    let limit = Duration::from_millis(50);
    assert_eq!(probe(far, None, limit).await, Outcome::NotRun);
    assert_eq!(stun::probe(far, None, limit).await, Outcome::NotRun);
    let v6: IpAddr = "2001:db8::1".parse().unwrap();
    assert_eq!(
        probe(far, Some(v6), limit).await,
        Outcome::NotRun,
        "wrong family"
    );
}

/// The STUN Binding Request: 20 bytes, the magic cookie, our transaction id; a success or error
/// response with our id answers it, anything else does not.
#[test]
fn stun_request_and_response() {
    let txid = [7u8; 12];
    let req = stun::request(txid);
    assert_eq!(req[..8], [0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42]);
    assert_eq!(req[8..], txid);
    let mut ok = req.to_vec();
    ok[0..2].copy_from_slice(&[0x01, 0x01]);
    assert!(stun::is_response(&ok, &txid));
    ok[1] = 0x11;
    assert!(
        stun::is_response(&ok, &txid),
        "an error response is an answer too"
    );
    assert!(
        !stun::is_response(&ok, &[8u8; 12]),
        "another request's answer"
    );
    assert!(!stun::is_response(&req, &txid), "our own request echoed");
    assert!(!stun::is_response(&ok[..19], &txid));
}

/// A loopback STUN server answers the probe; a quiet one leaves it silent.
#[tokio::test]
async fn stun_probe_on_loopback() {
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        let (n, from) = server.recv_from(&mut buf).await.unwrap();
        let mut reply = buf[..n].to_vec();
        reply[0..2].copy_from_slice(&[0x01, 0x01]);
        server.send_to(&reply, from).await.unwrap();
    });
    assert_eq!(
        stun::probe(addr, None, Duration::from_secs(2)).await,
        Outcome::Ok
    );
    let quiet = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let limit = Duration::from_millis(200);
    assert_eq!(
        stun::probe(quiet.local_addr().unwrap(), None, limit).await,
        Outcome::Silent
    );
}

/// A resolver with fixed answers per (name, family).
struct Answers(Vec<(&'static str, bool, Vec<IpAddr>)>);

impl CanaryLookup for Answers {
    async fn lookup(&self, name: &str, v6: bool) -> Result<Vec<IpAddr>, String> {
        let hit = self.0.iter().find(|(n, f, _)| *n == name && *f == v6);
        hit.map(|(_, _, a)| a.clone())
            .ok_or_else(|| "ENOTFOUND".into())
    }
}

/// RU audit item 11: AAAA records mean another resolver answered; our engine returns none.
#[tokio::test]
async fn dns_canary_states() {
    let v4: IpAddr = "203.0.113.5".parse().unwrap();
    let v6: IpAddr = "2001:db8::5".parse().unwrap();
    let engine = Answers(
        CANARY_NAMES
            .iter()
            .flat_map(|n| [(*n, false, vec![v4]), (*n, true, vec![])])
            .collect(),
    );
    assert_eq!(dns_canary(&engine).await, Canary::Captured);
    let leaky = Answers(vec![
        (CANARY_NAMES[0], false, vec![v4]),
        (CANARY_NAMES[1], true, vec![v6]),
    ]);
    assert_eq!(dns_canary(&leaky).await, Canary::Escaped);
    assert_eq!(dns_canary(&Answers(Vec::new())).await, Canary::NoAnswer);
    assert_eq!(
        Canary::NotCaptured.verdict(),
        vpnte_base::types::Verdict::NotChecked
    );
    assert_eq!(Canary::Captured.verdict(), vpnte_base::types::Verdict::Ok);
}

/// The live canary through the Windows DNS client (needs internet; meaningful in a TUN session).
#[tokio::test]
#[ignore = "needs internet"]
async fn live_canary_answers() {
    assert_ne!(dns_canary(&WireLookup).await, Canary::NoAnswer);
}

/// The whole check on the real network (needs internet).
#[tokio::test]
#[ignore = "needs internet"]
async fn live_network_mode() {
    // The UDP probes bind the physical address: a non-loopback socket only where allowed.
    if std::env::var_os("VPNTE_LAN_TESTS").is_none() {
        return;
    }
    let probe = LiveProbe::new(None, None).await.unwrap();
    let facts = gather(&probe, &[], &CancellationToken::new())
        .await
        .unwrap();
    let r = report(&facts, probe.via_session());
    assert_ne!(r.summary, Summary::Offline, "{facts:?}");
}

/// Every key this package emits exists in its fragment (and the item 6 keys too).
#[test]
fn locale_keys_exist() {
    let ru = crate::test_support::flatten(include_str!("../../locales/probes-netmode.ru.json"));
    let mut keys: Vec<String> = Vec::new();
    for mode in [
        Mode::Whitelist,
        Mode::UdpBlocked,
        Mode::DohBlocked,
        Mode::ServerBlocked,
        Mode::Freeze,
    ] {
        keys.push(mode.msg().key.into_owned());
        keys.push(mode.advice().key.into_owned());
    }
    for summary in [Summary::Open, Summary::Offline, Summary::NotVerified] {
        let r = NetReport {
            at: 0,
            via_session: false,
            steps: Vec::new(),
            modes: Vec::new(),
            summary,
            udp: UdpEvidence::Unclear,
        };
        keys.push(r.headline().key.into_owned());
    }
    let reset = HostFacts {
        tcp: Outcome::Ok,
        tls: Outcome::Reset,
    };
    let variants = [
        open(),
        Facts {
            system_dns: Outcome::NotRun,
            transfer: None,
            quic: vec![Outcome::NotRun],
            stun: vec![Outcome::NotRun],
            ..open()
        },
        Facts {
            doh_foreign: Outcome::Failed,
            doh_ru: Outcome::Failed,
            transfer: Some(Transfer::NoData),
            ..open()
        },
        Facts {
            doh_foreign: Outcome::Failed,
            transfer: Some(Transfer::Stalled { bytes: 40_000 }),
            ..open()
        },
        Facts {
            system_dns: Outcome::Failed,
            transfer: Some(Transfer::Stalled { bytes: 16_000 }),
            ..open()
        },
        Facts {
            system_dns: Outcome::Failed,
            doh_foreign: Outcome::Failed,
            doh_ru: Outcome::Failed,
            foreign: vec![reset],
            transfer: Some(Transfer::Failed {
                bytes: 1,
                error: "x".into(),
            }),
            quic: vec![Outcome::Silent, Outcome::Reset],
            servers: vec![Reach::default()],
            ..open()
        },
        Facts {
            quic: MUTE.to_vec(),
            stun: MUTE.to_vec(),
            ..open()
        },
        Facts {
            quic: MUTE.to_vec(),
            ..open()
        },
        Facts {
            stun: MUTE.to_vec(),
            ..open()
        },
    ];
    for f in &variants {
        for tun in [false, true] {
            keys.extend(steps(f, tun).into_iter().map(|s| s.detail.key.into_owned()));
        }
    }
    for c in [
        Canary::Captured,
        Canary::Escaped,
        Canary::NoAnswer,
        Canary::NotCaptured,
    ] {
        keys.push(c.msg().key.into_owned());
    }
    keys.push(
        crate::key_health::HealthReason::ConnectionRefused
            .msg()
            .key
            .into_owned(),
    );
    keys.push(crate::discipline::Verdict::Refused.msg().key.into_owned());
    for key in &keys {
        assert!(ru.contains_key(key), "missing {key}");
    }
    for key in ru.keys() {
        assert!(keys.contains(key), "unused {key}");
    }
}

/// Real QUIC servers answer the probe datagram with version negotiation (needs internet and a
/// network that passes UDP 443): guards the packet format against real servers.
#[tokio::test]
#[ignore = "needs internet"]
async fn live_quic_probe_answers() {
    // Binds UDP on the physical address: a non-loopback socket only where allowed.
    if std::env::var_os("VPNTE_LAN_TESTS").is_none() {
        return;
    }
    let (path, _) = crate::live_stages::route_uplink(None).unwrap();
    let mut seen = Vec::new();
    for host in refs::QUIC_HOSTS {
        let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host, 443))
            .await
            .unwrap()
            .collect();
        for addr in addrs
            .into_iter()
            .filter(std::net::SocketAddr::is_ipv4)
            .take(1)
        {
            let unbound = probe(addr, None, Duration::from_secs(2)).await;
            let bound = probe(addr, path.source_for(addr.ip()), Duration::from_secs(2)).await;
            seen.push((host, addr, unbound, bound));
        }
    }
    // The product probes from the physical uplink (another client's TUN may drop QUIC on the OS
    // route: seen on the development machine, unbound Silent / bound Ok for both hosts).
    assert!(seen.iter().any(|s| s.3 == Outcome::Ok), "{seen:?}");
}
