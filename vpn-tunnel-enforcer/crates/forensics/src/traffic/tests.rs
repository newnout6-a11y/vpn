use super::*;
use crate::test_support::eventually;

const A: u128 = 0xA;
const B: u128 = 0xB;

/// Replays `(identity, rx, tx)` samples one second apart from t = 1000.
fn replay(samples: &[(u128, u64, u64)]) -> Vec<TrafficStats> {
    let mut state = RateState::started("Ethernet 5", 0);
    samples
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let t = 1000 * (i as i64 + 1);
            state.on_sample(Some(*s), "Ethernet 5", t, t)
        })
        .collect()
}

/// trafficMonitor.test.ts 'smooths an isolated burst' / 'reports relative variation'.
#[test]
fn smoothing_and_burstiness_vectors() {
    assert!((smooth(10.0, 100.0, 0.35) - 41.5).abs() < 1e-9);
    assert_eq!(smooth(0.0, 100.0, 0.35), 100.0);
    assert_eq!(smooth(f64::NAN, -5.0, 0.35), 0.0);
    assert_eq!(burstiness(&[100.0, 100.0, 100.0]), 0);
    assert_eq!(burstiness(&[50.0, 100.0, 150.0]), 41);
    assert_eq!(burstiness(&[0.0, 0.0]), 0);
    assert_eq!(burstiness(&[5.0]), 0);
}

/// 'computes download/upload bps': the first sample is the baseline.
#[test]
fn first_sample_is_the_baseline() {
    let s = replay(&[(A, 1_000_000, 500_000), (A, 2_000_000, 700_000)]);
    assert_eq!(
        (s[0].down_bps, s[0].up_bps, s[0].adapter_found),
        (0.0, 0.0, true)
    );
    assert_eq!((s[1].down_bps, s[1].up_bps), (1_000_000.0, 200_000.0));
    assert_eq!(s[1].smooth_down_bps, s[1].down_bps);
    assert_eq!(s[1].smooth_up_bps, s[1].up_bps);
    assert_eq!((s[1].down_burst_pct, s[1].up_burst_pct), (0, 0));
    assert_eq!(s[1].started_at_ms, Some(0));
}

/// AT-07-009 / AT-07-012: uint64 deltas stay exact above 2^53.
#[test]
fn deltas_are_exact_above_2_pow_53() {
    let s = replay(&[
        (A, 9_007_199_254_740_993, 4_294_967_297),
        (A, 9_007_199_254_740_994, 4_294_967_299),
    ]);
    assert_eq!((s[1].down_bps, s[1].up_bps), (1.0, 2.0));
    assert_eq!((s[1].session_down, s[1].session_up), (1, 2));
    assert_eq!(s[1].total_down, 9_007_199_254_740_994);
}

/// 'resets the baseline when the adapter is recreated or counters go back'.
#[test]
fn identity_change_or_decrease_starts_a_new_baseline() {
    let s = replay(&[(A, 10_000, 0), (B, 20_000, 0), (B, 1, 0)]);
    let last = &s[2];
    assert!(last.adapter_found);
    assert_eq!(
        (last.session_down, last.down_bps, last.total_down),
        (0, 0.0, 1)
    );
}

/// B-25: session bytes and peaks survive an engine restart that recreates the adapter.
#[test]
fn session_bytes_survive_an_adapter_reset() {
    let s = replay(&[(A, 1000, 0), (A, 3000, 0), (B, 500, 0), (B, 1500, 0)]);
    let session: Vec<u64> = s.iter().map(|x| x.session_down).collect();
    assert_eq!(session, [0, 2000, 2000, 3000]);
    assert!(s[1..].iter().all(|x| x.peak_down_bps == 2000.0));
}

/// 'never replays the read and clears stale healthy status': a failed read keeps running.
#[test]
fn failed_read_reports_not_found_and_keeps_totals() {
    let mut state = RateState::started("Ethernet 5", 0);
    state.on_sample(Some((A, 100, 100)), "Ethernet 5", 1000, 1000);
    state.on_sample(Some((A, 5000, 3000)), "Ethernet 5", 2000, 2000);
    let s = state.on_sample(None, "Ethernet 5", 3000, 3000);
    assert!(s.running && !s.adapter_found);
    assert_eq!(
        (s.down_bps, s.smooth_down_bps, s.up_burst_pct),
        (0.0, 0.0, 0)
    );
    assert_eq!(
        (s.session_down, s.total_down, s.peak_down_bps),
        (4900, 5000, 4900.0)
    );
    // The base survives the gap: the next delta spans both seconds.
    let s = state.on_sample(Some((A, 7000, 3000)), "Ethernet 5", 4000, 4000);
    assert_eq!((s.down_bps, s.session_down), (1000.0, 6900));
    assert_eq!(state.last_traffic, 4000);
    // A wall clock stepped back an hour does not change the measured interval.
    let s = state.on_sample(Some((A, 8000, 3000)), "Ethernet 5", 4000 - 3_600_000, 5000);
    assert_eq!((s.down_bps, s.peak_down_bps), (1000.0, 4900.0));
}

/// AT-07-009 'refuses invalid aliases' before any OS call.
#[test]
fn invalid_aliases_are_refused() {
    let long = "a".repeat(257);
    for alias in ["", "   ", "a\0b", "\n", long.as_str()] {
        let err = TunIf::new(alias, 7).unwrap_err();
        assert_eq!(err.user_msg().key, "forensics.traffic.invalidAdapter");
    }
    assert_eq!(TunIf::new(&"a".repeat(256), 7).unwrap().luid, 7);
    assert_eq!(TunIf::new("Ethernet 5", 7).unwrap().alias, "Ethernet 5");
}

/// watchdogTrafficRecovery.test.ts, traffic part (maxAge 45 000 ms).
#[test]
fn watchdog_traffic_vectors() {
    let stats = |running, down_bps, up_bps| TrafficStats {
        running,
        down_bps,
        up_bps,
        ..TrafficStats::default()
    };
    let now = 1_000_000;
    assert!(!recent_traffic(&stats(false, 0.0, 0.0), 0, now, 45_000));
    assert!(recent_traffic(&stats(true, 4500.0, 200.0), 0, now, 45_000));
    assert!(recent_traffic(&stats(true, 100.0, 2048.0), 0, now, 45_000));
    assert!(!recent_traffic(&stats(true, 512.0, 128.0), 0, now, 45_000));
    assert!(!recent_traffic(
        &stats(false, 50_000.0, 50_000.0),
        0,
        now,
        45_000
    ));
    assert!(recent_traffic(
        &stats(false, 0.0, 0.0),
        now - 5_000,
        now,
        45_000
    ));
    assert!(!recent_traffic(
        &stats(false, 0.0, 0.0),
        now - 50_000,
        now,
        45_000
    ));
}

/// The proxy-down recovery rule uses the smoothed rate, else the raw one.
#[test]
fn live_traffic_rule() {
    let mut s = TrafficStats {
        running: true,
        down_bps: 4000.0,
        ..TrafficStats::default()
    };
    assert!(s.shows_live_traffic());
    s.smooth_down_bps = 900.0;
    assert!(!s.shows_live_traffic());
    s.running = false;
    s.smooth_down_bps = 5000.0;
    assert!(!s.shows_live_traffic());
}

/// 'does not overlap pending reads or publish after stop': a read that settles after a
/// stop / start is dropped; the next sample comes from the new run.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn late_read_after_restart_is_dropped() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let (gate_tx, gate_rx) = std::sync::mpsc::channel::<u64>();
    let gate = Arc::new(Mutex::new(gate_rx));
    let reads = Arc::new(AtomicUsize::new(0));
    let reader: Reader = {
        let (gate, reads) = (gate.clone(), reads.clone());
        Arc::new(move |luid| {
            reads.fetch_add(1, Ordering::SeqCst);
            let rx = gate.lock().recv().unwrap_or(0);
            Ok(Some(IfCounters {
                luid,
                guid: A,
                in_octets: rx,
                out_octets: 0,
                in_packets: 0,
                out_packets: 0,
                in_discards: 0,
                in_errors: 0,
                out_discards: 0,
                out_errors: 0,
                up: true,
            }))
        })
    };
    let sampler = RateSampler::with_reader(reader, Duration::from_millis(20));
    let (_tun_tx, tun) = watch::channel(Some(TunIf::new("Ethernet 5", 7).unwrap()));
    sampler.start(tun.clone());
    sampler.start(tun.clone()); // idempotent
    eventually(|| reads.load(Ordering::SeqCst) == 1).await;
    sampler.stop();
    assert!(!sampler.is_running());
    sampler.start(tun.clone());
    gate_tx.send(111).unwrap(); // settles the stale read of the first run
    tokio::time::sleep(Duration::from_millis(150)).await;
    let s = sampler.current();
    assert_eq!((s.running, s.adapter_found, s.total_down), (true, false, 0));
    gate_tx.send(222).unwrap();
    eventually(|| sampler.current().total_down == 222).await;
    assert_eq!(sampler.current().adapter, "Ethernet 5");
    sampler.stop();
    drop(gate_tx); // release a read that may be waiting, so the runtime can shut down
    let s = sampler.current();
    assert_eq!((s.running, s.total_down, s.started_at_ms), (false, 0, None));
    assert_eq!(sampler.last_traffic_ms(), 0);
}
