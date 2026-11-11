use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};

use parking_lot::Mutex;

use super::*;

const DST: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1));

fn reply(status: EchoStatus, from: Option<IpAddr>, rtt: Option<u32>) -> EchoReply {
    EchoReply {
        status,
        from,
        rtt_ms: rtt,
    }
}

/// AT-05-001: hop lines of imported rows are cleaned like the old UI did (§7.12).
#[test]
fn sanitizes_legacy_hops() {
    let cases = [
        (
            "1  <1 \u{FFFD}\u{FFFD}  <1 \u{FFFD}\u{FFFD}  <1 \u{FFFD}\u{FFFD}  13.143.252.2",
            "1 <1 ms <1 ms <1 ms 13.143.252.2",
        ),
        (
            "  1    <1 мс    <1 мс    <1 мс  13.143.252.2",
            "1 <1 ms <1 ms <1 ms 13.143.252.2",
        ),
        (
            "  2    14 мс    18 мс    12 мс  10.0.0.1",
            "2 14 ms 18 ms 12 ms 10.0.0.1",
        ),
        (
            "  1    <1 ms    <1 ms    <1 ms  13.143.252.2",
            "1 <1 ms <1 ms <1 ms 13.143.252.2",
        ),
        (
            "  1  * * * Превышен интервал ожидания для запроса.",
            "1 * * * Request timed out.",
        ),
        (
            "  2  * * * Request timed out.",
            "2 * * * Request timed out.",
        ),
    ];
    for (input, expected) in cases {
        assert_eq!(sanitize_hop_line(input), expected, "{input}");
    }
}

/// AT-05-001 / B-13: one probe per TTL; lines stop at the target; reach only from an echo
/// reply of the target itself.
#[tokio::test]
async fn traces_until_the_target() {
    let cancel = CancellationToken::new();
    let hop = IpAddr::from([10, 0, 0, 1]);
    let trace = trace_with(DST, ProbeRoute::Physical, &cancel, |ttl| async move {
        Ok(match ttl {
            1 => reply(EchoStatus::TtlExpired, Some(hop), Some(0)),
            2 => reply(EchoStatus::TimedOut, None, None),
            _ => reply(EchoStatus::Success, Some(DST), Some(12)),
        })
    })
    .await;
    assert_eq!(trace.timed.status, TimedStatus::Ok);
    assert_eq!(
        trace.hop_details,
        [
            "1 <1 ms 10.0.0.1",
            "2 * Request timed out.",
            "3 12 ms 192.0.2.1"
        ]
    );
    assert_eq!(
        (trace.hops, trace.reached_target, trace.command_finished),
        (Some(3), Some(true), Some(true))
    );
    assert_eq!(trace.route_method.as_deref(), Some("icmp"));
    assert_eq!(trace.timed.route, Some(ProbeRoute::Physical));
}

/// Silent path: all 8 hops listed, target not reached (audit second review).
#[tokio::test]
async fn silent_path_is_not_reached() {
    let cancel = CancellationToken::new();
    let trace = trace_with(DST, ProbeRoute::Os, &cancel, |_| async {
        Ok(reply(EchoStatus::TimedOut, None, None))
    })
    .await;
    assert_eq!(trace.hop_details.len(), 8);
    assert!(trace.hop_details[0].contains("Request timed out"));
    assert_eq!(trace.reached_target, Some(false));
    assert_eq!(trace.timed.status, TimedStatus::Ok);
}

/// AT-00-003: a cancel keeps the hops measured so far, `commandFinished` false (§7.7).
#[tokio::test]
async fn cancelled_trace_keeps_partial_hops() {
    let cancel = CancellationToken::new();
    let token = cancel.clone();
    let trace = trace_with(DST, ProbeRoute::Os, &cancel, |ttl| {
        let token = token.clone();
        async move {
            if ttl == 1 {
                return Ok(reply(
                    EchoStatus::TtlExpired,
                    Some(IpAddr::from([192, 0, 2, 2])),
                    Some(1),
                ));
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            token.cancel();
            std::future::pending().await
        }
    })
    .await;
    assert_eq!(trace.timed.status, TimedStatus::Skipped);
    assert_eq!(trace.command_finished, Some(false));
    assert_eq!(trace.hop_details, ["1 1 ms 192.0.2.2"]);
    assert_eq!(trace.reached_target, Some(false));
}

/// An ICMP layer that cannot send at all is an error, not "ok with no hops".
#[tokio::test]
async fn icmp_failure_is_an_error() {
    let cancel = CancellationToken::new();
    let trace = trace_with(DST, ProbeRoute::Os, &cancel, |_| async {
        Err(IcmpError::Join)
    })
    .await;
    assert_eq!(trace.timed.status, TimedStatus::Error);
    assert!(trace.hop_details.is_empty());
}

fn rungs(list: &[(u16, RungOutcome)]) -> PmtuObservation {
    PmtuObservation {
        control_ok: true,
        rungs: list.to_vec(),
    }
}

fn arg(m: &Msg, name: &str) -> Option<String> {
    m.args
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.clone())
}

/// AT-05-007 / B-12: PMTU classification vectors (§7.14, §7.15).
#[test]
fn classifies_ladders() {
    use RungOutcome::{Accepted as A, TimedOut as T, TooBig as B};
    // 1472/1464/1440 silent twice, 1400 accepted, no PacketTooBig -> blackhole, 1428.
    let v = classify_pmtu(
        false,
        Some(&rungs(&[
            (1472, T),
            (1464, T),
            (1440, T),
            (1400, A),
            (1360, A),
        ])),
        None,
    );
    assert_eq!(
        (v.status, v.pmtu, v.method),
        (
            PmtuStatus::BlackholeSuspected,
            Some(1428),
            PmtuMethod::IcmpDf
        )
    );
    // 1472 too big, 1464 accepted, no timeouts -> exact 1492, max 1500.
    let v = classify_pmtu(
        false,
        Some(&rungs(&[(1472, B), (1464, A), (1440, A)])),
        None,
    );
    assert_eq!(
        (v.status, v.pmtu, v.max_tested),
        (PmtuStatus::Ok, Some(1492), Some(1500))
    );
    assert_eq!(v.detail.key, "probes.liveStages.pmtu.confirmed");
    // Top rung accepted -> lower bound 1500, upper edge unknown.
    let v = classify_pmtu(false, Some(&rungs(&[(1472, A)])), None);
    assert_eq!(
        (v.status, v.pmtu, v.min_tested, v.max_tested),
        (PmtuStatus::LowerBound, Some(1500), Some(1500), None)
    );
    assert_eq!(v.detail.key, "probes.liveStages.pmtu.atLeast");
    // IPv6: 48-byte headers; 1372 accepted, 1380 too big -> exact 1420.
    let v = classify_pmtu(true, Some(&rungs(&[(1380, B), (1372, A)])), None);
    assert_eq!((v.status, v.pmtu), (PmtuStatus::Ok, Some(1420)));
    // 1372 accepted, 1472 too big -> range [1400 .. 1500].
    let v = classify_pmtu(false, Some(&rungs(&[(1472, B), (1372, A)])), None);
    assert_eq!(
        (v.status, v.pmtu, v.min_tested, v.max_tested),
        (PmtuStatus::LowerBound, Some(1400), Some(1400), Some(1500))
    );
    assert_eq!(
        (arg(&v.detail, "pmtu"), arg(&v.detail, "max")),
        (Some("1400".into()), Some("1500".into()))
    );
    // Superseded old vector: 1372 accepted, larger rungs silent, no too-big -> blackhole 1400.
    let v = classify_pmtu(
        false,
        Some(&rungs(&[(1472, T), (1440, T), (1372, A)])),
        None,
    );
    assert_eq!(
        (v.status, v.pmtu),
        (PmtuStatus::BlackholeSuspected, Some(1400))
    );
    // A lost larger rung next to a PacketTooBig is not a blackhole.
    let v = classify_pmtu(
        false,
        Some(&rungs(&[(1472, B), (1464, T), (1440, A)])),
        None,
    );
    assert_eq!(v.status, PmtuStatus::LowerBound);
}

/// Control ping / ICMP failures fall back to the interface MTU (§3.19).
#[test]
fn fallbacks() {
    let blocked = PmtuObservation {
        control_ok: false,
        rungs: Vec::new(),
    };
    let v = classify_pmtu(false, Some(&blocked), Some(1500));
    assert_eq!(
        (v.status, v.method, v.pmtu),
        (
            PmtuStatus::IcmpBlocked,
            PmtuMethod::InterfaceNlmtu,
            Some(1500)
        )
    );
    let v = classify_pmtu(false, Some(&blocked), None);
    assert_eq!(
        (v.status, v.method, v.pmtu),
        (PmtuStatus::IcmpBlocked, PmtuMethod::Fallback, None)
    );
    let v = classify_pmtu(false, None, Some(1400));
    assert_eq!(
        (v.status, v.method, v.pmtu),
        (
            PmtuStatus::LowerBound,
            PmtuMethod::InterfaceNlmtu,
            Some(1400)
        )
    );
    assert_eq!(arg(&v.detail, "mtu"), Some("1400".into()));
    let v = classify_pmtu(false, None, None);
    assert_eq!(
        (v.status, v.detail.key.as_ref()),
        (PmtuStatus::Skipped, "probes.liveStages.pmtu.undetermined")
    );
    let silent = rungs(&[(1472, RungOutcome::TimedOut), (1252, RungOutcome::TimedOut)]);
    let v = classify_pmtu(false, Some(&silent), Some(1500));
    assert_eq!(
        (v.status, v.method),
        (PmtuStatus::BlackholeSuspected, PmtuMethod::InterfaceNlmtu)
    );
}

/// B-12: silent rungs are asked twice before they count; the runner fills the row.
#[tokio::test]
async fn ladder_retries_silent_rungs() {
    let asked: Mutex<HashMap<u16, u32>> = Mutex::default();
    let cancel = CancellationToken::new();
    let pmtu = pmtu_with(
        DST,
        Some(1500),
        Some("Ethernet".into()),
        ProbeRoute::Physical,
        &cancel,
        |payload, _| {
            *asked.lock().entry(payload).or_default() += 1;
            let status = if payload > 1400 {
                EchoStatus::TimedOut
            } else {
                EchoStatus::Success
            };
            async move { Ok(reply(status, Some(DST), Some(5))) }
        },
    )
    .await;
    assert_eq!(
        (pmtu.status, pmtu.pmtu),
        (PmtuStatus::BlackholeSuspected, Some(1428))
    );
    assert_eq!(
        (pmtu.family, pmtu.destination.as_str()),
        (Some(4), "192.0.2.1")
    );
    assert_eq!(pmtu.interface_alias.as_deref(), Some("Ethernet"));
    assert_eq!(pmtu.route, Some(ProbeRoute::Physical));
    let asked = asked.lock();
    assert_eq!((asked[&1472], asked[&1400], asked[&32]), (2, 1, 1));
}

/// A failed control ping (ICMP error) keeps the error text and falls back.
#[tokio::test]
async fn control_error_and_cancel() {
    let calls = AtomicU32::new(0);
    let cancel = CancellationToken::new();
    let pmtu = pmtu_with(DST, None, None, ProbeRoute::Os, &cancel, |_, _| {
        calls.fetch_add(1, Ordering::Relaxed);
        async { Err(IcmpError::Join) }
    })
    .await;
    assert_eq!(
        (pmtu.status, calls.load(Ordering::Relaxed)),
        (PmtuStatus::Skipped, 1)
    );
    assert!(pmtu.error.is_some());
    cancel.cancel();
    let pmtu = pmtu_with(DST, None, None, ProbeRoute::Os, &cancel, |_, _| async {
        Ok(reply(EchoStatus::Success, None, None))
    })
    .await;
    assert_eq!(
        (pmtu.status, pmtu.error.as_deref()),
        (PmtuStatus::Skipped, Some(CANCELLED))
    );
}

/// Live loopback smoke test through the real ICMP API (unelevated).
#[tokio::test]
async fn loopback_trace_and_pmtu() {
    let lo = IpAddr::from([127, 0, 0, 1]);
    let cancel = CancellationToken::new();
    let trace = trace_route(lo, &ProbePath::Os, &cancel).await;
    assert_eq!(trace.reached_target, Some(true), "{trace:?}");
    assert_eq!(trace.hop_details.len(), 1);
    let pmtu = probe_pmtu(lo, &ProbePath::Os, None, &cancel).await;
    assert_eq!(
        (pmtu.status, pmtu.pmtu),
        (PmtuStatus::LowerBound, Some(1500)),
        "{pmtu:?}"
    );
}
