//! Report builders: import report and skipped lines, refresh outcome, export files, latency
//! statistics, key-health mapping.
use vpnte_base::types::ClientDevice;
use vpnte_base::{AppError, ErrorKind, Msg};
use vpnte_core::secret::Secret;
use vpnte_probes::discipline::{Classification, Reaction, Verdict};
use vpnte_probes::key_health::{self, HealthReason as ProbeReason, KeyCheck};
use vpnte_profiles::countries::Iso2;
use vpnte_profiles::export::Shared as SharedKey;
use vpnte_profiles::model::{SkipReason, Skipped, SubscriptionMeta};
use vpnte_servers::model::{
    CountrySource, FetchOutcome, FetchState, GroupId, GroupKind, HealthReason, ProfileId,
    ServerGroup,
};
use vpnte_servers::refresh::{AddOutcome, RefreshReport};
use vpnte_servers::store::AddReport;
use vpnte_ui::servers::{FetchError, KeyHealthReason, RefreshOutcome};

use super::super::checks::{key_health_view, updates};
use super::super::detail::latency_stats;
use super::super::export::{keys_file, safe_name, stamp};
use super::super::import::{outcome, report, skipped_lines};
use super::super::project::{reason_code, same_wire};

/// A fake key list: two valid links around an unsupported scheme and a broken link.
pub(super) const PASTE: &str = "vless://11111111-2222-3333-4444-555555555555@good.example.net:443?security=tls&sni=good.example.net#ok\n\
\n\
ssr://bad.example.net:1\n\
trojan://secret@second.example.net:443#two\n\
vless://broken\n";

/// Import report: skipped entries name their pasted line.
#[test]
fn skipped_entries_name_their_pasted_line() {
    let parsed = vpnte_servers::parse::parse_text(PASTE).expect("parse");
    assert_eq!(parsed.profiles.len(), 2, "{:?}", parsed.skipped);
    let lines = skipped_lines(Some(PASTE), &parsed.skipped);
    let numbers: Vec<u32> = lines.iter().map(|l| l.line).collect();
    assert_eq!(numbers, [3, 5]);
    assert!(
        lines
            .iter()
            .all(|l| l.reason.key.starts_with("profiles.caps.skip."))
    );
    // Entries that map to no pasted line (a fetched body, a JSON document) are numbered in order.
    let fetched = skipped_lines(None, &parsed.skipped);
    assert_eq!(fetched.iter().map(|l| l.line).collect::<Vec<_>>(), [1, 2]);
    let odd = [Skipped {
        excerpt: "proxies".into(),
        reason: SkipReason::Duplicate,
    }];
    assert_eq!(skipped_lines(Some(PASTE), &odd)[0].line, 1);
}

#[test]
fn import_report_counts_and_names_the_group() {
    let added = AddOutcome::Added {
        report: AddReport {
            group: GroupId::from("keys"),
            added: vec![ProfileId::from("a"), ProfileId::from("b")],
            restored: vec![ProfileId::from("c")],
            duplicates: 3,
            selected: None,
        },
        skipped: Vec::new(),
        providers: Vec::new(),
    };
    let title = |id: &GroupId| format!("title of {id}");
    let r = report(&added, "vless://x", false, title);
    assert_eq!(r.group_name, "title of keys");
    assert!(!r.subscription);
    assert_eq!((r.added, r.updated, r.unchanged), (2, 1, 3));
    let refreshed = AddOutcome::Refreshed {
        group: GroupId::from("sub"),
        report: refresh_report(),
    };
    let r = report(&refreshed, "https://sub.example.net/x", true, title);
    assert_eq!(r.group_name, "title of sub");
    assert!(r.subscription && r.skipped.is_empty());
    assert_eq!((r.added, r.updated, r.unchanged), (1, 5, 0));
}

fn refresh_report() -> RefreshReport {
    RefreshReport {
        added: vec![ProfileId::from("n")],
        updated: 4,
        restored: 1,
        archived: 2,
        pending_absent: 0,
        partial: false,
    }
}

fn subscription(fetch: FetchState, expires_at: Option<i64>) -> ServerGroup {
    ServerGroup {
        id: GroupId::from("sub"),
        name: String::new(),
        kind: GroupKind::Subscription {
            url: Secret::new("https://sub.example.net/token"),
            device: ClientDevice::Pc,
        },
        imported_at: 1,
        refresh_override_min: None,
        fetch,
        info: SubscriptionMeta {
            expires_at,
            ..SubscriptionMeta::default()
        },
        send_hwid: true,
        headers: None,
        fallback: None,
        moved_at: None,
        controls: Default::default(),
    }
}

/// A failed fetch is an answer with its typed reason; busy and stale records stay errors.
#[test]
fn refresh_outcome_reads_the_recorded_failure() {
    let started = 1_000;
    let failed = FetchState {
        last_attempt_at: Some(started + 5),
        last_outcome: Some(FetchOutcome::Http(503)),
        ..FetchState::default()
    };
    let group = subscription(failed, None);
    let net = || {
        Err(AppError::msg(
            ErrorKind::Network,
            Msg::new("servers.fetch.http"),
        ))
    };
    assert_eq!(
        outcome(net(), Some(&group), started, 2_000).unwrap(),
        RefreshOutcome::Failed(FetchError::Http(503))
    );
    let busy = Err(AppError::conflict(Msg::new("core.ops.busy")));
    let err = outcome(busy, Some(&group), started, 2_000).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Conflict);
    let err = outcome(net(), Some(&group), started + 10, 2_000).unwrap_err();
    assert_eq!(
        err.kind,
        ErrorKind::Network,
        "an older record is not this attempt's"
    );
    let done = outcome(Ok(refresh_report()), Some(&group), started, 2_000).unwrap();
    let expected = RefreshOutcome::Refreshed {
        added: 1,
        updated: 5,
        removed: 2,
        expired: false,
    };
    assert_eq!(done, expected);
    let lapsed = subscription(FetchState::default(), Some(1_500));
    let done = outcome(Ok(refresh_report()), Some(&lapsed), started, 2_000).unwrap();
    assert!(matches!(
        done,
        RefreshOutcome::Refreshed { expired: true, .. }
    ));
}

/// Bulk export: a text list with the old header, or one JSON array as soon as a key needs JSON.
#[test]
fn key_files_keep_the_old_formats() {
    let now = 1_794_388_320_123; // 2026-11-11T09:12:00.123Z
    assert_eq!(stamp(now), "2026-11-11T09-12-00");
    let links = [
        Some(SharedKey::Uri("vless://a@one.example.net:443".into())),
        None,
        Some(SharedKey::Uri("trojan://b@two.example.net:443".into())),
    ];
    let file = keys_file(&links, now).expect("exportable");
    assert!(!file.json);
    assert_eq!((file.exported, file.skipped), (2, 1));
    assert_eq!(
        file.body,
        "# VPN keys exported by VPN Tunnel Enforcer\n# Profiles: 2 exported, 1 skipped\n\
         # Generated: 2026-11-11T09:12:00.123Z\n\nvless://a@one.example.net:443\n\
         trojan://b@two.example.net:443\n"
    );
    let mixed = [
        Some(SharedKey::Uri("vless://a@one.example.net:443".into())),
        Some(SharedKey::Json(
            serde_json::json!({"remarks": "x", "outbounds": []}),
        )),
    ];
    let file = keys_file(&mixed, now).expect("exportable");
    assert!(file.json);
    let parsed: serde_json::Value = serde_json::from_str(&file.body).expect("one JSON array");
    assert_eq!(parsed[0], "vless://a@one.example.net:443");
    assert_eq!(parsed[1]["remarks"], "x");
    assert!(keys_file(&[None, None], now).is_none());
}

#[test]
fn file_names_drop_reserved_characters() {
    assert_eq!(
        safe_name("NL: Amsterdam <fast> 1", "vless"),
        "NL-Amsterdam-fast-1"
    );
    assert_eq!(safe_name("a/b\\c|d?e*f\"g", "vless"), "abcdefg");
    assert_eq!(safe_name("  \t ", "trojan"), "trojan");
    assert_eq!(safe_name(&"x".repeat(80), "vless").len(), 60);
}

#[test]
fn latency_statistics_of_samples() {
    let stats = latency_stats(&[Some(10), None, Some(20), Some(30), None]).expect("answers");
    assert_eq!(
        (stats.min, stats.avg, stats.median, stats.max),
        (10, 20, 20, 30)
    );
    assert_eq!(stats.jitter, 8, "population standard deviation, rounded");
    assert!((stats.loss - 0.4).abs() < 1e-9);
    assert_eq!(stats.samples, [10, 20, 30]);
    assert_eq!((stats.attempted, stats.succeeded), (Some(5), Some(3)));
    assert!(latency_stats(&[None, None]).is_none());
    assert!(latency_stats(&[]).is_none());
}

const PROBE_REASONS: [ProbeReason; 11] = [
    ProbeReason::NoOutbound,
    ProbeReason::ConfigFailed,
    ProbeReason::TlsFailed,
    ProbeReason::AuthFailed,
    ProbeReason::Timeout,
    ProbeReason::HandshakeFailed,
    ProbeReason::Hy2ConfigFailed,
    ProbeReason::Hy2AuthFailed,
    ProbeReason::Hy2UdpBlocked,
    ProbeReason::Hy2TlsFailed,
    ProbeReason::Hy2HandshakeFailed,
];

/// The probes' and the list's health reasons share wire names; the page knows every code.
#[test]
fn health_reasons_cross_every_layer() {
    for reason in PROBE_REASONS {
        let stored: HealthReason = same_wire(reason).expect("same wire name");
        let code = reason_code(stored).expect("code");
        assert_eq!(reason_code(reason).as_deref(), Some(code.as_str()));
        let shown = KeyHealthReason::from_code(&code);
        assert!(!matches!(shown, KeyHealthReason::Other(_)), "{code}");
    }
}

/// Verdicts land with the identity taken before the probe and the trace's exit country.
#[test]
fn health_updates_keep_identity_and_trace_country() {
    let ip = "203.0.113.5".parse().ok();
    let alive = key_health::KeyHealth {
        online: true,
        at: 9,
        rtt_ms: Some(120),
        reason: None,
        egress_ip: ip,
        country: Iso2::new("NL"),
        engine: None,
    };
    let dead = key_health::KeyHealth::offline(ProbeReason::Hy2UdpBlocked, None);
    let check = |health| KeyCheck {
        health,
        verdict: Classification {
            verdict: Verdict::Healthy,
            reaction: Reaction::None,
        },
    };
    let checked = vec![
        ((ProfileId::from("a"), Some([1; 16])), check(alive.clone())),
        ((ProfileId::from("sealed"), None), check(dead.clone())),
    ];
    let stored = updates(&checked);
    assert_eq!(stored.len(), 1, "a sealed key has no identity to match");
    let update = &stored[0];
    assert_eq!((update.id.as_str(), update.identity), ("a", [1; 16]));
    assert!(update.record.online && update.record.rtt_ms == Some(120));
    let country = update.country.expect("trace country");
    assert_eq!((country.iso2.as_str(), country.ip), ("NL", ip));
    assert_eq!(country.source, CountrySource::HealthTrace);
    let shown = key_health_view(&dead);
    assert!(!shown.online);
    assert_eq!(shown.reason, Some(KeyHealthReason::Hy2UdpBlocked));
    assert_eq!(key_health_view(&alive).latency_ms, Some(120));
}

/// subs-b10: a Mihomo provider the redirect rules refused reads as refused in the import report,
/// not as an unusable answer it never gave.
#[test]
fn refused_providers_read_as_refused() {
    use vpnte_servers::subscription::{ProviderFailure, ProviderFetch};

    let provider = |name: &str, servers, failed| ProviderFetch {
        name: name.into(),
        servers,
        failed,
    };
    let added = AddOutcome::Added {
        report: AddReport {
            group: GroupId::from("sub"),
            added: vec![ProfileId::from("a")],
            restored: Vec::new(),
            duplicates: 0,
            selected: None,
        },
        skipped: Vec::new(),
        providers: vec![
            provider("lan", 0, Some(ProviderFailure::Refused)),
            provider(
                "down",
                0,
                Some(ProviderFailure::Fetch(FetchOutcome::Http(503))),
            ),
            provider("ok", 2, None),
        ],
    };
    let r = report(
        &added,
        "https://sub.example.net/feed",
        true,
        |id: &GroupId| id.to_string(),
    );
    let errors: Vec<Option<FetchError>> = r.providers.iter().map(|p| p.error).collect();
    assert_eq!(
        errors,
        [Some(FetchError::Refused), Some(FetchError::Http(503)), None]
    );
}
