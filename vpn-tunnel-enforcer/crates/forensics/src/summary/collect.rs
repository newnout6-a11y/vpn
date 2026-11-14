//! One streaming pass over a session directory (ETW rows, app events, pktmon counters, manifest).
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::net::IpAddr;
use std::path::Path;

use serde_json::{Map, Value};
use vpnte_base::types::now_ms;
use vpnte_winnet::adapters;

use super::counters::{self, PacketMetric};
use super::{
    Check, Counts, EvidenceSet, Finding, Summary, SummaryCtx, SummaryWarning, TCP_MIN, TOP_N, Top,
};
use crate::capture::manifest::{self, MANIFEST_FILE, SessionManifest};
use crate::capture::pktmon::{COUNTERS_FILE, DROP_COUNTERS_FILE};
use crate::capture::{APP_EVENTS_FILE, LIVE_COUNTERS_FILE, PktmonState};
use crate::etw::digest::{TopMap, remote_endpoint, text_field};
use crate::etw::{EVENTS_FILE, EVENTS_PREV_FILE};

/// Counter files are small; anything larger is not pktmon output and is not parsed.
const COUNTERS_MAX_BYTES: u64 = 8 * 1024 * 1024;
/// Distinct names tracked for the top lists (further names are not counted).
const TOP_KEYS_MAX: usize = 8192;

/// App events that mean the engine failed (typed, B-33: a user stop is not a failure).
const ENGINE_FAILURES: [&str; 5] = [
    "engine-start-failed",
    "engine-crash-restart",
    "engine-restart-exhausted",
    "engine-start-timeout",
    "engine-exited-killswitch-active",
];

#[derive(Default)]
struct Collector {
    counts: Counts,
    evidence: EvidenceSet,
    warnings: BTreeSet<SummaryWarning>,
    metrics: Vec<PacketMetric>,
    domains: TopMap,
    remotes: TopMap,
    /// Largest loss / drop figures reported by health rows.
    health_lost: u64,
    health_dropped: u64,
    app_events_seen: bool,
    traffic_test_passed: bool,
    dns_test_passed: bool,
    leak_test_seen: bool,
    counters_seen: bool,
}

pub(super) fn run(dir: &Path, ctx: &SummaryCtx) -> Summary {
    let mut c = Collector::default();
    for file in [EVENTS_PREV_FILE, EVENTS_FILE] {
        c.read_ndjson(dir, file, Collector::etw_row);
    }
    c.app_events_seen = dir.join(APP_EVENTS_FILE).is_file();
    c.read_ndjson(dir, APP_EVENTS_FILE, Collector::app_row);
    for file in [COUNTERS_FILE, LIVE_COUNTERS_FILE, DROP_COUNTERS_FILE] {
        c.read_counters(dir, file, ctx);
    }
    let manifest = manifest::read_manifest(dir);
    c.finish(dir, manifest)
}

impl Collector {
    /// Streams one NDJSON artefact; a missing file is not a problem, an unreadable one is.
    fn read_ndjson(
        &mut self,
        dir: &Path,
        name: &str,
        mut on_row: impl FnMut(&mut Self, &Map<String, Value>, &str, u64),
    ) {
        let file = match File::open(dir.join(name)) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(_) => {
                self.warnings.insert(SummaryWarning::ArtifactUnreadable);
                return;
            }
        };
        let mut reader = BufReader::new(file);
        let mut buf = Vec::new();
        let mut line_no = 0u64;
        loop {
            buf.clear();
            match reader.read_until(b'\n', &mut buf) {
                Ok(0) => break,
                Ok(_) => {}
                Err(_) => {
                    self.warnings.insert(SummaryWarning::ArtifactUnreadable);
                    break;
                }
            }
            line_no += 1;
            let mut line = buf.as_slice();
            if line_no == 1 {
                line = crate::strip_bom(line);
            }
            let line = line.trim_ascii();
            if line.is_empty() {
                continue;
            }
            match serde_json::from_slice::<Map<String, Value>>(line) {
                Ok(row) => on_row(self, &row, name, line_no),
                Err(_) => self.counts.malformed_lines += 1,
            }
        }
    }

    /// One row of `events.ndjson` (row shape: `etw::session`).
    fn etw_row(&mut self, row: &Map<String, Value>, artifact: &str, line: u64) {
        self.counts.events += 1;
        let category = text_field(row, "category").unwrap_or("other");
        if category == "health" {
            self.health_lost = self.health_lost.max(u64_of(row, "eventsLost"));
            let dropped = u64_of(row, "backpressureDropped") + u64_of(row, "writeErrors");
            self.health_dropped = self.health_dropped.max(dropped);
            return;
        }
        if category == "lifecycle" {
            return;
        }
        self.counts.data_events += 1;
        *self
            .counts
            .per_category
            .entry(category.to_string())
            .or_default() += 1;
        let event = text_field(row, "event").unwrap_or_default();
        if event == "unparsed" {
            self.counts.unparsed += 1;
        }
        if category == "dns" {
            self.counts.dns_rows += 1;
        }
        if category == "wfp" && event == "block" {
            self.counts.wfp_block_rows += 1;
        }
        if let Some(name) = text_field(row, "queryName") {
            self.domains.bump(name, TOP_KEYS_MAX);
        }
        if let Some(remote) = remote_endpoint(row) {
            self.remotes.bump(&remote, TOP_KEYS_MAX);
        }
        if category == "tcp" {
            let check = match text_field(row, "reason") {
                Some("reset-observed") => Some((Check::RemoteResetLikely, &mut self.counts.resets)),
                Some("timeout-or-retransmit-observed") => {
                    Some((Check::TimeoutOrPacketLossLikely, &mut self.counts.losses))
                }
                Some("mtu-or-fragmentation-observed") => {
                    Some((Check::MtuIssueLikely, &mut self.counts.mtu))
                }
                _ => None,
            };
            if let Some((check, count)) = check {
                *count += 1;
                let reason = text_field(row, "reason").unwrap_or_default();
                self.evidence
                    .add(check, artifact, Some(line), reason, &row_text(row));
            }
        }
        // A connection whose local end is our TUN address was routed through the tunnel: a real
        // observation that also works for ETW-only sessions (no pktmon counters).
        let tun_local = matches!(category, "tcp" | "afd")
            && text_field(row, "localAddress")
                .and_then(|a| a.parse::<IpAddr>().ok())
                .is_some_and(is_tun_address);
        if tun_local && !self.evidence.has(Check::TunPathConfirmed) {
            self.evidence.add(
                Check::TunPathConfirmed,
                artifact,
                Some(line),
                "tun-local-address",
                &row_text(row),
            );
        }
    }

    /// One row of `app-events.ndjson` (`capture::ForensicEvent` rows).
    fn app_row(&mut self, row: &Map<String, Value>, artifact: &str, line: u64) {
        self.counts.app_events += 1;
        let event = text_field(row, "event").unwrap_or_default();
        let details = row.get("details").unwrap_or(&Value::Null);
        let failed = ENGINE_FAILURES.contains(&event)
            || (event == "engine-exited" && row.get("userInitiated") == Some(&Value::Bool(false)));
        if failed {
            self.evidence.add(
                Check::SingBoxFailureLikely,
                artifact,
                Some(line),
                event,
                &row_text(row),
            );
        }
        if event == "engine-exited-killswitch-active" {
            self.evidence.add(
                Check::KillSwitchBlockedTraffic,
                artifact,
                Some(line),
                event,
                &row_text(row),
            );
        }
        match event {
            "leak-self-test-result" => self.self_test(details, artifact, line, row),
            "leak-diagnostics-result" => self.leak_diagnostics(details, artifact, line, row),
            _ => {}
        }
    }

    /// `leak-self-test-result` details: `physicalAdapterReached`, `publicIpMismatch`,
    /// `dnsLeakDetected` (TFS:457-477, kept).
    fn self_test(&mut self, details: &Value, artifact: &str, line: u64, row: &Map<String, Value>) {
        self.leak_test_seen = true;
        let flag = |keys: [&str; 2]| keys.iter().find_map(|k| details.get(*k)?.as_bool());
        let physical = flag(["physicalAdapterReached", "physical_adapter_reached"]);
        let mismatch = flag(["publicIpMismatch", "public_ip_mismatch"]);
        match (physical, mismatch) {
            (Some(true), _) | (_, Some(true)) => self.evidence.add(
                Check::TrafficLeakDetected,
                artifact,
                Some(line),
                "leak-self-test",
                &row_text(row),
            ),
            (Some(false), Some(false)) => self.traffic_test_passed = true,
            _ => {}
        }
        match flag(["dnsLeakDetected", "dns_leak_detected"]) {
            Some(true) => self.evidence.add(
                Check::DnsLeakDetected,
                artifact,
                Some(line),
                "leak-self-test",
                &row_text(row),
            ),
            Some(false) => self.dns_test_passed = true,
            None => {}
        }
    }

    /// `leak-diagnostics-result` details: items `{id, label, status}`; traffic items have ids
    /// matching `direct-public|ipv4|proxy`, DNS items `dns` in id or label (TFS:457-477).
    fn leak_diagnostics(
        &mut self,
        details: &Value,
        artifact: &str,
        line: u64,
        row: &Map<String, Value>,
    ) {
        let Some(items) = details.get("items").and_then(Value::as_array) else {
            return;
        };
        for item in items {
            let text = |k: &str| {
                item.get(k)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_ascii_lowercase()
            };
            let (id, label, status) = (text("id"), text("label"), text("status"));
            let failed = matches!(status.as_str(), "fail" | "failed" | "error");
            let passed = matches!(status.as_str(), "pass" | "passed" | "ok" | "success");
            let traffic = ["direct-public", "ipv4", "proxy"]
                .iter()
                .any(|w| id.contains(w));
            let dns = id.contains("dns") || label.contains("dns");
            for (applies, check) in [
                (traffic, Check::TrafficLeakDetected),
                (dns, Check::DnsLeakDetected),
            ] {
                if !applies {
                    continue;
                }
                self.leak_test_seen = true;
                if failed {
                    let reason = format!("leak-diagnostics:{id}");
                    self.evidence
                        .add(check, artifact, Some(line), &reason, &row_text(row));
                } else if passed && check == Check::TrafficLeakDetected {
                    self.traffic_test_passed = true;
                } else if passed {
                    self.dns_test_passed = true;
                }
            }
        }
    }

    /// A pktmon counters file: flattened into metrics; packets on the TUN component confirm the
    /// tunnel path. A UTF-8 BOM is tolerated (B-05).
    fn read_counters(&mut self, dir: &Path, name: &str, ctx: &SummaryCtx) {
        let path = dir.join(name);
        let Ok(meta) = std::fs::metadata(&path) else {
            return;
        };
        let mut bytes = Vec::new();
        let read = meta.len() <= COUNTERS_MAX_BYTES
            && File::open(&path)
                .and_then(|mut f| f.read_to_end(&mut bytes))
                .is_ok();
        let body = crate::strip_bom(&bytes);
        let parsed = read
            .then(|| serde_json::from_slice::<Value>(body).ok())
            .flatten();
        let Some(root) = parsed else {
            self.warnings.insert(SummaryWarning::ArtifactUnreadable);
            return;
        };
        self.counters_seen = true;
        self.metrics.extend(counters::flatten_counters(&root, name));
        if name == DROP_COUNTERS_FILE || self.evidence.has(Check::TunPathConfirmed) {
            return;
        }
        if let Some((component, packets)) = counters::tun_packets(&root, ctx.tun_alias.as_deref()) {
            let text = format!("{component}: {packets} packets");
            self.evidence.add(
                Check::TunPathConfirmed,
                name,
                None,
                "tun-component-packets",
                &text,
            );
        }
    }
}

impl Collector {
    /// Verdicts, insufficiency and warnings from what was collected.
    fn finish(mut self, dir: &Path, manifest: Option<SessionManifest>) -> Summary {
        let m = manifest.as_ref();
        if m.is_none() {
            self.warnings.insert(SummaryWarning::ManifestMissing);
        }
        let stats = m.and_then(|m| m.etw_stats.as_ref());
        let lost = stats
            .and_then(|s| s.loss.as_ref())
            .map_or(0, |l| u64::from(l.events_lost));
        let dropped = stats.map_or(0, |s| {
            s.digest.backpressure_dropped + s.digest.write_errors.max(s.writer.write_errors)
        });
        self.counts.events_lost = lost.max(self.health_lost);
        self.counts.rows_dropped = dropped.max(self.health_dropped);
        self.counts.packet_metrics = self.metrics.len() as u64;
        if let Some(reason) = m.and_then(|m| m.stop_reason.as_deref())
            && reason.to_ascii_lowercase().contains("killswitch")
        {
            self.evidence.add(
                Check::KillSwitchBlockedTraffic,
                MANIFEST_FILE,
                None,
                "stop-reason",
                reason,
            );
        }
        if m.is_some_and(|m| m.app_events_dropped > 0) {
            self.warnings.insert(SummaryWarning::AppEventsDropped);
        }
        let pktmon_ran =
            m.is_some_and(|m| matches!(m.pktmon, PktmonState::Running | PktmonState::Stopped));
        if !pktmon_ran {
            self.warnings.insert(SummaryWarning::PktmonNotRun);
        } else if !self.counters_seen {
            self.warnings.insert(SummaryWarning::NoCounters);
        }
        let etw_data = self.counts.data_events > 0;
        if self.counts.events == 0 {
            self.warnings.insert(SummaryWarning::EtwNotRun);
        } else if !etw_data {
            self.warnings.insert(SummaryWarning::EtwNoData);
        }
        let lossy = self.counts.events_lost > 0 || self.counts.rows_dropped > 0;
        if lossy {
            self.warnings.insert(SummaryWarning::EtwEventsLost);
        }
        if self.counts.malformed_lines > 0 {
            self.warnings.insert(SummaryWarning::MalformedLines);
        }
        if !self.leak_test_seen {
            self.warnings.insert(SummaryWarning::NoLeakTest);
        }
        self.warnings.insert(SummaryWarning::NoWfpDropSource);

        let ev = &self.evidence;
        let observed = |check: Check, negative: bool| {
            if ev.has(check) {
                Finding::Detected
            } else if negative {
                Finding::NotDetected
            } else {
                Finding::Unknown
            }
        };
        let tcp = |count: u64| {
            if count >= TCP_MIN {
                Finding::Detected
            } else if etw_data {
                Finding::NotDetected
            } else {
                Finding::Unknown
            }
        };
        let verdicts: std::collections::BTreeMap<Check, Finding> = [
            (
                Check::TrafficLeakDetected,
                observed(Check::TrafficLeakDetected, self.traffic_test_passed),
            ),
            (
                Check::DnsLeakDetected,
                observed(Check::DnsLeakDetected, self.dns_test_passed),
            ),
            (
                Check::TunPathConfirmed,
                observed(Check::TunPathConfirmed, false),
            ),
            (
                Check::KillSwitchBlockedTraffic,
                observed(Check::KillSwitchBlockedTraffic, false),
            ),
            (Check::WindowsFirewallBlockedTraffic, Finding::Unknown),
            (Check::RemoteResetLikely, tcp(self.counts.resets)),
            (Check::TimeoutOrPacketLossLikely, tcp(self.counts.losses)),
            (Check::MtuIssueLikely, tcp(self.counts.mtu)),
            (
                Check::SingBoxFailureLikely,
                observed(Check::SingBoxFailureLikely, self.app_events_seen),
            ),
        ]
        .into_iter()
        .collect();
        let insufficient_evidence = lossy
            || !pktmon_ran
            || verdicts
                .iter()
                .any(|(check, f)| check.answerable() && *f == Finding::Unknown);
        // Evidence is kept only where it supports a detected verdict (a single reset below the
        // threshold stays in the counts).
        let evidence = self
            .evidence
            .0
            .into_iter()
            .filter(|(check, list)| {
                !list.is_empty() && verdicts.get(check) == Some(&Finding::Detected)
            })
            .collect();
        let session_id = m.map(|m| m.session_id.clone()).unwrap_or_else(|| {
            dir.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default()
        });
        Summary {
            schema_version: super::SCHEMA_VERSION,
            generated_at: now_ms(),
            session_id,
            mode: m.and_then(|m| m.mode),
            target: m.and_then(|m| m.target.clone()),
            engine: m.and_then(|m| m.engine.clone()),
            running: m.is_some_and(|m| m.running),
            verdicts,
            insufficient_evidence,
            evidence,
            counts: self.counts,
            top: Top {
                domains: self.domains.top(TOP_N),
                remotes: self.remotes.top(TOP_N),
            },
            warnings: self.warnings.into_iter().collect(),
            packet_metrics: self.metrics,
        }
    }
}

fn u64_of(row: &Map<String, Value>, key: &str) -> u64 {
    row.get(key).and_then(Value::as_u64).unwrap_or(0)
}

/// The row as compact JSON (evidence text; clipped by the evidence set).
fn row_text(row: &Map<String, Value>) -> String {
    serde_json::to_string(row).unwrap_or_default()
}

/// Own TUN addresses: the IPv4 /24 of the old and new TUN and our dual-stack IPv6 /126.
fn is_tun_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(_) => adapters::is_own_tun_address(ip),
        IpAddr::V6(v6) => adapters::TUN_V6.contains(&v6),
    }
}
