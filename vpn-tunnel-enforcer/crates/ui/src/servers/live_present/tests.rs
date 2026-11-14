use vpnte_base::i18n::{Lang, lookup};

use super::*;
use crate::servers::live_model::{Handshake, LiveMode, Stage};

fn ru(key: &str) -> String {
    crate::test_locales::init_locales();
    lookup(Lang::Ru, key, &[], None)
}

fn check(id: &str) -> LiveCheck {
    LiveCheck {
        id: id.into(),
        host: "vpn.mock.net".into(),
        port: 443,
        mode: LiveMode::Extended,
        ..LiveCheck::default()
    }
}

fn with_throughput(id: &str, status: StageStatus, median: Option<f64>) -> LiveCheck {
    LiveCheck {
        throughput: Some(Throughput {
            status,
            median_mbps: median,
            route: Some(ThroughputRoute::PhysicalDirect),
            ..Throughput::default()
        }),
        ..check(id)
    }
}

/// §7.3 `routeDiagnosticStatus`.
#[test]
fn unfinished_route_is_a_warning() {
    let mut route = RouteDiag {
        status: StageStatus::Ok,
        duration_ms: 10,
        hops: Some(1),
        reached_target: Some(false),
        ..RouteDiag::default()
    };
    assert_eq!(route_status(&route), StageStatus::Warning);
    route.reached_target = Some(true);
    assert_eq!(route_status(&route), StageStatus::Ok);
    assert_eq!(Dot::from(route_status(&route)), Dot::Ok);
}

/// §7.3 `formatThroughputRouteLabel`, Russian wording kept verbatim.
#[test]
fn throughput_route_labels() {
    let label = |r, compact| throughput_route_key(Some(r), compact).map(ru);
    assert_eq!(
        label(ThroughputRoute::PhysicalDirect, false).as_deref(),
        Some("через профиль; к его endpoint — по физической сети (вне TUN)")
    );
    assert_eq!(
        label(ThroughputRoute::PhysicalDirect, true).as_deref(),
        Some("профиль / физ. сеть")
    );
    assert_eq!(
        label(ThroughputRoute::ActiveTunnel, false).as_deref(),
        Some("через уже работающий активный туннель")
    );
    assert_eq!(
        label(ThroughputRoute::ActiveTunnel, true).as_deref(),
        Some("активный туннель")
    );
    assert_eq!(
        label(ThroughputRoute::DirectDetour, true).as_deref(),
        Some("профиль / обход TUN")
    );
    assert_eq!(throughput_route_key(None, false), None);
}

/// §7.3 `handshakeChangeLabel`, `formatInterfaceAlias`, `interfaceAliasTitle`.
#[test]
fn handshake_and_alias_labels() {
    assert_eq!(
        ru(handshake_change_key(Some(HandshakeStatus::Ok))),
        "Handshake восстановлен"
    );
    assert_eq!(
        ru(handshake_change_key(Some(HandshakeStatus::TransportFailed))),
        "Статус handshake изменился"
    );
    assert_eq!(
        interface_alias(Some("Ethernet"), None),
        AliasText::Name("Ethernet")
    );
    assert_eq!(interface_alias(None, Some(12)), AliasText::Index(Some(12)));
    crate::test_locales::init_locales();
    assert_eq!(
        lookup(
            Lang::En,
            "ui.servers.live.alias.index",
            &[("index", "12".into())],
            None
        ),
        "Index 12"
    );
    assert_eq!(
        interface_alias(Some("Ethernet\u{FFFD}"), Some(3)),
        AliasText::Corrupted
    );
    assert_eq!(
        ru("ui.servers.live.alias.corrupted"),
        "Имя повреждено в старой проверке"
    );
    assert!(ru("ui.servers.live.alias.corruptedTitle").contains("старой ошибки кодировки"));
}

/// §7.3 `sanitizeHopLine` vectors.
#[test]
fn hop_lines_are_normalised() {
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
    for (raw, clean) in cases {
        assert_eq!(sanitize_hop_line(raw), clean, "{raw:?}");
    }
}

/// §7.3 `formatInfrastructureError`: never the raw "status code 429" text.
#[test]
fn infrastructure_errors_are_worded() {
    let rate = "Превышен лимит запросов к сервису геолокации (429). Повторите попытку позже.";
    for raw in [
        "Request failed with status code 429",
        "RateLimited",
        "rate-limit hit",
    ] {
        assert_eq!(
            infrastructure_error(raw),
            Some(InfraError::RateLimited),
            "{raw}"
        );
    }
    assert_eq!(ru("ui.servers.live.infra.rateLimited"), rate);
    assert_eq!(
        infrastructure_error("getaddrinfo ENOTFOUND ipapi.co"),
        Some(InfraError::Unreachable)
    );
    assert_eq!(
        ru("ui.servers.live.infra.unreachable"),
        "Не удалось подключиться к сервису геолокации."
    );
    assert_eq!(
        infrastructure_error("User aborted probe"),
        Some(InfraError::Cancelled)
    );
    assert_eq!(ru("ui.servers.live.infra.cancelled"), "Проверка отменена");
    assert_eq!(
        infrastructure_error("  odd  "),
        Some(InfraError::Raw("odd".into()))
    );
    assert_eq!(infrastructure_error(" "), None);
}

#[test]
fn progress_caption_and_bar() {
    let p = |completed, status| LiveProgress {
        stage: Stage::Tls,
        status,
        completed,
        total: 13,
        elapsed_ms: 1500,
    };
    let (step, total, pct) = progress_step(&p(2, ProgressStatus::Running));
    assert_eq!((step, total), (3, 13));
    assert!((pct - 300.0 / 13.0).abs() < 1e-9);
    assert_eq!(
        progress_step(&p(0, ProgressStatus::Completed)),
        (0, 13, 5.0)
    );
    assert_eq!(progress_step(&p(13, ProgressStatus::Running)).0, 13);
}

/// §7.4 "Defect 9" and L-8 (no empty parentheses).
#[test]
fn loss_text_counts_only_when_known() {
    let mut l = LatencyStats {
        loss: 0.2,
        samples: vec![30, 31, 32, 33],
        attempted: Some(5),
        succeeded: Some(4),
        ..LatencyStats::default()
    };
    assert_eq!(loss_text(&l), "20% (1/5)");
    l.succeeded = None;
    assert_eq!(loss_text(&l), "20% (1/5)");
    l.attempted = None;
    assert_eq!(loss_text(&l), "20%");
}

#[test]
fn pmtu_threshold_and_tls_days() {
    let p = |status, pmtu| PmtuDiag {
        status,
        pmtu,
        min_tested: None,
        max_tested: None,
        method: crate::servers::live_model::PmtuMethod::IcmpDf,
        detail: None,
        error: None,
    };
    assert_eq!(
        pmtu_verdict(&p(PmtuStatus::LowerBound, Some(1420))).1,
        Tone::Ok
    );
    assert_eq!(
        pmtu_verdict(&p(PmtuStatus::LowerBound, Some(1400))).1,
        Tone::Warn
    );
    assert_eq!(pmtu_verdict(&p(PmtuStatus::LowerBound, None)).1, Tone::Warn);
    assert_eq!(pmtu_verdict(&p(PmtuStatus::Skipped, None)).1, Tone::Unknown);
    assert_eq!(
        pmtu_verdict(&p(PmtuStatus::BlackholeSuspected, None)).1,
        Tone::Fail
    );
    assert_eq!(tls_days_tone(7), Tone::Fail);
    assert_eq!(tls_days_tone(30), Tone::Warn);
    assert_eq!(tls_days_tone(102), Tone::Ok);
}

#[test]
fn throughput_checklist_thresholds() {
    let t = Throughput {
        status: StageStatus::Ok,
        variability_pct: Some(39.9),
        stall_count: Some(0),
        max_gap_ms: Some(750),
        ..Throughput::default()
    };
    assert_eq!(
        throughput_checklist(&t),
        [Some(true), Some(true), Some(false), Some(true)]
    );
    let unknown = Throughput {
        error: Some("cut".into()),
        ..Throughput::default()
    };
    assert_eq!(
        throughput_checklist(&unknown),
        [None, None, None, Some(false)]
    );
}

/// §7.4 "Defect 3": history merges by id, newest first, capped at 20.
#[test]
fn history_merges_by_id() {
    let old: Vec<LiveCheck> = (0..25).map(|i| check(&format!("c{i}"))).collect();
    let merged = history_merge(&old[..1], check("c99"));
    assert_eq!(
        merged.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(),
        ["c99", "c0"]
    );
    let again = history_merge(&merged, check("c0"));
    assert_eq!(
        again.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(),
        ["c0", "c99"]
    );
    assert_eq!(history_merge(&old, check("new")).len(), HISTORY_CAP);
}

/// §3.15 labels and route summary; B-3 order (verdict, then median, unknown last).
#[test]
fn batch_rows_label_sort_and_summarise() {
    let stable = with_throughput("a", StageStatus::Ok, Some(40.0));
    let fast = with_throughput("b", StageStatus::Ok, Some(90.5));
    let shaky = with_throughput("c", StageStatus::Warning, Some(120.0));
    let reachable = LiveCheck {
        handshake: Some(Handshake {
            status: HandshakeStatus::Ok,
            duration_ms: None,
            protocol: None,
            evidence: None,
            error: None,
        }),
        ..check("d")
    };
    let dead = check("e");
    assert_eq!(batch_label(&shaky), BatchLabel::Unstable);
    assert_eq!(batch_label(&reachable), BatchLabel::Reachable);
    assert_eq!(batch_label(&dead), BatchLabel::Failed);
    // a handshake alone is not shown as working; a stalled body is a probe error, not «reachable»
    assert_eq!(BatchLabel::Reachable.tone(), Tone::Neutral);
    let stalled = LiveCheck {
        handshake: reachable.handshake.clone(),
        ..with_throughput("f", StageStatus::Timeout, None)
    };
    assert_eq!(batch_label(&stalled), BatchLabel::ProbeError);
    let mut rows = vec![&dead, &shaky, &stable, &reachable, &fast];
    batch_sort(&mut rows);
    let ids: Vec<&str> = rows.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(ids, ["b", "a", "c", "d", "e"]);
    assert_eq!(
        route_summary([&stable, &fast]),
        RouteSummary::Single(ThroughputRoute::PhysicalDirect)
    );
    let mut other = stable.clone();
    if let Some(t) = other.throughput.as_mut() {
        t.route = Some(ThroughputRoute::ActiveTunnel);
    }
    assert_eq!(route_summary([&stable, &other]), RouteSummary::Mixed);
    assert_eq!(route_summary([&dead]), RouteSummary::Unknown);
    assert_eq!(format_mbps(Some(12.345)), "12.35 Mbps");
    assert_eq!(format_mbps(Some(f64::NAN)), "—");
    assert_eq!(format_mbps(None), "—");
}

/// B-1: the 13th server is refused; search covers name, host and port.
#[test]
fn batch_selection_and_search() {
    let mut selected: Vec<String> = (0..12).map(|i| format!("s{i}")).collect();
    assert!(!batch_toggle(&mut selected, "s12"));
    assert!(batch_toggle(&mut selected, "s3"));
    assert!(batch_toggle(&mut selected, "s12"));
    assert_eq!(selected.len(), 12);
    let servers = vec![
        ServerView {
            id: "1".into(),
            name: "Riga-2".into(),
            host: "lv.example".into(),
            port: 443,
            ..ServerView::default()
        },
        ServerView {
            id: "2".into(),
            name: "Oslo".into(),
            host: "no.example".into(),
            port: 8443,
            ..ServerView::default()
        },
    ];
    assert_eq!(batch_filter(&servers, " riga ").len(), 1);
    assert_eq!(batch_filter(&servers, "8443")[0].id, "2");
    assert_eq!(batch_filter(&servers, "").len(), 2);
    let p = BatchProgress {
        profile_id: "1".into(),
        index: 0,
        total: 4,
        status: ProgressStatus::Running,
        stage: None,
        median_mbps: None,
    };
    assert_eq!(batch_bar(&p), 4.0);
    assert_eq!(
        batch_bar(&BatchProgress {
            status: ProgressStatus::Completed,
            ..p
        }),
        25.0
    );
}
