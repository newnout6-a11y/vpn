//! The archive's sections, in the old order (DX:204-409): settings, logs, system, runtime,
//! recovery state, snapshots, forensics, README and manifest.
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{UnixMs, now_ms};
use vpnte_base::{AppError, AppResult};
use vpnte_core::logging::{self, TAIL_MAX_BYTES};
use vpnte_core::redact::REDACTED;
use vpnte_core::settings::Settings;

use super::archive::{Archive, Partial};
use super::redaction::{Policy, Redactor};
use super::{
    ExportInputs, ExportProgress, ExportResult, ExportStage, NoticeSink, RecoveryRead, system,
    texts,
};
use crate::capture::store;
use crate::etw::writer::rfc3339_ms;
use crate::summary::{self, PACKET_METRICS_FILE, SUMMARY_FILE, SummaryCtx};

/// Snapshots newer than this (and not older than the last app start) are exported.
const SNAPSHOT_WINDOW_MS: UnixMs = 2 * 60 * 60 * 1000;
const SNAPSHOT_MAX: usize = 40;
/// Exported when no snapshot falls into the window.
const SNAPSHOT_FALLBACK: usize = 12;
const MANIFEST_SCHEMA: u32 = 3;
const FORENSICS_DIR: &str = "traffic-forensics";

/// Writes the whole archive into a partial file next to `dest` (blocking). The returned
/// [`Partial`] is renamed over `dest` by the caller's commit; dropping it removes the file.
pub(super) fn write(
    dest: &Path,
    inputs: ExportInputs,
    live: Option<PathBuf>,
    progress: watch::Sender<ExportProgress>,
    notices: Option<NoticeSink>,
    cancel: CancellationToken,
) -> AppResult<(Partial, ExportResult)> {
    let (partial, file) = Partial::create(dest, notices)?;
    let now = now_ms();
    let user = inputs
        .user_name
        .clone()
        .or_else(|| std::env::var("USERNAME").ok());
    let redactor = Redactor::new(user.as_deref());
    let mut a = Archive::new(file, redactor, cancel, progress, zip_time());

    a.stage(ExportStage::Settings)?;
    a.json(
        "settings.json",
        settings_json(&inputs.settings)?,
        Policy::Config,
    )?;

    a.stage(ExportStage::Logs)?;
    if let Some(dir) = &inputs.logs_dir {
        log_tails(&mut a, dir)?;
    }

    a.stage(ExportStage::System)?;
    let info = system::system_info(
        &rfc3339_ms(now),
        &inputs.app_version,
        &inputs.engine_versions,
    );
    a.json("system-info.json", info, Policy::Data)?;
    match inputs.system_diagnostics {
        Some(diag) => a.json("system-diagnostics.json", diag, Policy::Data)?,
        None => tracing::warn!("diagnostics export: system diagnostics unavailable, skipped"),
    }

    a.stage(ExportStage::Runtime)?;
    for (engine, config) in inputs.engine_configs {
        a.json(
            &format!("runtime-{}.json", safe_name(&engine)),
            config,
            Policy::Config,
        )?;
    }
    if let Some(dir) = &inputs.logs_dir {
        engine_logs(&mut a, dir)?;
    }

    a.stage(ExportStage::Recovery)?;
    let mut statuses = Vec::new();
    for item in inputs.recovery {
        let status = match item.read {
            RecoveryRead::Trusted(v) => {
                a.json(&safe_name(&item.file), v, Policy::Data)?;
                "trusted-and-redacted"
            }
            RecoveryRead::Absent => "absent",
            RecoveryRead::Untrusted => "unavailable-or-untrusted",
        };
        statuses.push(json!({ "artifact": item.artifact, "status": status }));
    }
    if !statuses.is_empty() {
        a.json(
            "recovery-artifacts-status.json",
            Value::Array(statuses),
            Policy::Data,
        )?;
    }

    a.stage(ExportStage::Snapshots)?;
    if let Some(dir) = &inputs.snapshots_dir {
        snapshots(&mut a, dir, now)?;
    }

    a.stage(ExportStage::Forensics)?;
    let session = match &inputs.capture {
        Some(capture) => forensics(&mut a, capture.root(), live.as_deref(), &inputs.summary_ctx)?,
        None => None,
    };

    a.stage(ExportStage::Finishing)?;
    a.bytes("README.txt", texts::readme(&rfc3339_ms(now)).as_bytes())?;
    let manifest = json!({
        "schemaVersion": MANIFEST_SCHEMA,
        "createdAt": rfc3339_ms(now),
        "appVersion": inputs.app_version,
        "platform": "windows",
        "arch": std::env::consts::ARCH,
        "redaction": texts::policy(session.is_some()),
        "excluded": a.excluded,
        "entries": a.entries,
    });
    let manifest = crate::pretty_json(&manifest).map_err(AppError::internal)?;
    a.bytes("diagnostics-manifest.json", &manifest)?;
    let result = ExportResult {
        path: dest.to_path_buf(),
        entries: a.entries.len(),
        excluded: a.excluded.iter().map(|e| e.name.clone()).collect(),
        forensics_session: session,
    };
    a.finish()?;
    Ok((partial, result))
}

/// Settings without the pseudonym key and the sealed proxy credentials (never serialized, so no
/// DPAPI call happens here); a proxy host that is not local is a proxy value (§10.6 «B»).
fn settings_json(settings: &Settings) -> AppResult<Value> {
    let mut s = settings.clone();
    s.log_key = None;
    let had_credentials = s
        .proxy_override
        .as_mut()
        .is_some_and(|p| p.credentials.take().is_some());
    let mut v = serde_json::to_value(&s).map_err(AppError::internal)?;
    if let Some(proxy) = v.get_mut("proxyOverride").and_then(Value::as_object_mut) {
        if had_credentials {
            proxy.insert("credentials".into(), REDACTED.into());
        }
        let local = proxy
            .get("host")
            .and_then(Value::as_str)
            .is_some_and(is_local_host);
        if !local && proxy.contains_key("host") {
            proxy.insert("host".into(), REDACTED.into());
        }
    }
    Ok(v)
}

fn is_local_host(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// An archive file name from outside: `[A-Za-z0-9._-]` kept, anything else (separators, `..`)
/// becomes `_`.
fn safe_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    match cleaned.trim_matches('.') {
        "" => "_".to_string(),
        s => s.to_string(),
    }
}

/// Local civil time for the entries' DOS timestamps.
fn zip_time() -> zip::DateTime {
    let now = jiff::Zoned::now();
    zip::DateTime::from_date_and_time(
        now.year().try_into().unwrap_or(1980),
        now.month().try_into().unwrap_or(1),
        now.day().try_into().unwrap_or(1),
        now.hour().try_into().unwrap_or(0),
        now.minute().try_into().unwrap_or(0),
        now.second().try_into().unwrap_or(0),
    )
    .unwrap_or_default()
}

/// `app-log.json`: the tail (≤ 1 MiB, whole lines) of every log file, as the logger wrote them
/// (already redacted) and scrubbed again.
fn log_tails(a: &mut Archive, dir: &Path) -> AppResult<()> {
    let files = logging::list(dir).unwrap_or_else(|e| {
        tracing::warn!("diagnostics export: logs not listed: {e}");
        Vec::new()
    });
    let mut out = Vec::new();
    for file in &files {
        a.check()?;
        match logging::tail(dir, file, TAIL_MAX_BYTES) {
            Ok(t) => out.push(json!({
                "name": t.name, "size": t.size, "truncated": t.truncated, "content": t.content,
            })),
            Err(e) => tracing::warn!("diagnostics export: {} unreadable: {e}", file.file_name()),
        }
    }
    a.json("app-log.json", json!({ "files": out }), Policy::Log)
}

/// Engine logs in full as `runtime-<file>` (the old runtime-*.log entries), current and previous.
fn engine_logs(a: &mut Archive, dir: &Path) -> AppResult<()> {
    let files = logging::list(dir).unwrap_or_default();
    for file in files.iter().filter(|f| f.stem != logging::APP_STEM) {
        let name = file.file_name();
        a.file(&format!("runtime-{name}"), &dir.join(&name), Policy::Log)?;
    }
    Ok(())
}

/// `snapshots/`: the selection of DX:270-312, written oldest first.
fn snapshots(a: &mut Archive, dir: &Path, now: UnixMs) -> AppResult<()> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(());
    };
    let found: Vec<(String, Option<UnixMs>)> = entries
        .flatten()
        .filter_map(|e| {
            let meta = e.metadata().ok().filter(|m| m.is_file())?;
            let name = e.file_name().to_str()?.to_string();
            let json = name.to_ascii_lowercase().ends_with(".json");
            json.then(|| (name, store::mtime_ms(&meta)))
        })
        .collect();
    for name in select_snapshots(&found, now) {
        a.file(&format!("snapshots/{name}"), &dir.join(&name), Policy::Data)?;
    }
    Ok(())
}

/// Newest first: time from the name (else mtime) within 2 h and not older than the newest
/// `*-app-start.json`, at most 40; none → the newest 12. Returned oldest first.
pub(super) fn select_snapshots(files: &[(String, Option<UnixMs>)], now: UnixMs) -> Vec<String> {
    let mut timed: Vec<(UnixMs, &str)> = files
        .iter()
        .map(|(name, mtime)| (snapshot_time(name).or(*mtime).unwrap_or(0), name.as_str()))
        .collect();
    timed.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.cmp(a.1)));
    let app_start = timed
        .iter()
        .filter(|(_, n)| n.ends_with("-app-start.json"))
        .map(|(t, _)| *t)
        .max()
        .unwrap_or(0);
    let mut picked: Vec<&(UnixMs, &str)> = timed
        .iter()
        .filter(|(t, _)| *t > 0 && now - t <= SNAPSHOT_WINDOW_MS && *t >= app_start)
        .take(SNAPSHOT_MAX)
        .collect();
    if picked.is_empty() {
        picked = timed.iter().take(SNAPSHOT_FALLBACK).collect();
    }
    picked.reverse();
    picked.into_iter().map(|(_, n)| (*n).to_string()).collect()
}

/// `snapshot-2026-11-11T07-20-30-123Z-<kind>.json` → its UTC time.
fn snapshot_time(name: &str) -> Option<UnixMs> {
    static NAME: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"^snapshot-(\d{4}-\d{2}-\d{2}T\d{2})-(\d{2})-(\d{2})-(\d{3}Z)-")
            .expect("snapshot name pattern compiles")
    });
    let c = NAME.captures(name)?;
    let iso = format!("{}:{}:{}.{}", &c[1], &c[2], &c[3], &c[4]);
    iso.parse::<jiff::Timestamp>()
        .ok()
        .map(|t| t.as_millisecond())
}

/// Raw packet captures are never exported: they hold whole payloads (TF:1240-1249).
fn is_raw_capture(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    [".etl", ".etl.tmp", ".pcapng", ".pcapng.tmp"]
        .iter()
        .any(|ext| n.ends_with(ext))
        || n == "pktmon-trace.txt"
}

/// `traffic-forensics/`: the latest session only (the running one when `live` is set), every
/// file but raw captures, pseudonymized; the summary is recomputed into the archive when the
/// session runs or never got one. Nothing is written into the session itself (AT-00-003).
fn forensics(
    a: &mut Archive,
    root: &Path,
    live: Option<&Path>,
    ctx: &SummaryCtx,
) -> AppResult<Option<String>> {
    let sessions = store::list_sessions(root);
    let latest = match live {
        Some(dir) => sessions.iter().find(|s| s.dir == dir),
        None => sessions.last(),
    };
    let Some(session) = latest else {
        return Ok(None);
    };
    let base = format!("{FORENSICS_DIR}/sessions/{}", session.id);
    let regenerate = live.is_some() || !session.dir.join(SUMMARY_FILE).is_file();
    for file in &session.files {
        let name = format!("{base}/{}", file.name);
        if is_raw_capture(&file.name) {
            a.skip(&name, "raw-capture");
            continue;
        }
        if regenerate && (file.name == SUMMARY_FILE || file.name == PACKET_METRICS_FILE) {
            continue;
        }
        a.file(&name, &session.dir.join(&file.name), Policy::Forensics)?;
    }
    if regenerate {
        a.check()?;
        match summary::summarize(&session.dir, ctx) {
            Ok(s) => {
                let doc = serde_json::to_value(&s).map_err(AppError::internal)?;
                let metrics =
                    serde_json::to_value(&s.packet_metrics).map_err(AppError::internal)?;
                a.json(&format!("{base}/{SUMMARY_FILE}"), doc, Policy::Forensics)?;
                a.json(
                    &format!("{base}/{PACKET_METRICS_FILE}"),
                    metrics,
                    Policy::Forensics,
                )?;
            }
            Err(e) => tracing::warn!("diagnostics export: summary of {} failed: {e}", session.id),
        }
    }
    let index: Vec<Value> = sessions
        .iter()
        .map(|s| {
            let m = s.manifest.as_ref();
            json!({
                "id": s.id,
                "bytes": s.bytes,
                "running": m.is_some_and(|m| m.running),
                "startedAt": m.map(|m| m.started_at),
                "stoppedAt": m.and_then(|m| m.stopped_at),
                "stopReason": m.and_then(|m| m.stop_reason.clone()),
            })
        })
        .collect();
    let latest_doc = json!({
        "sessionId": session.id,
        "running": live.is_some(),
        "included": format!("sessions/{}/", session.id),
        "sessions": index,
    });
    a.json(
        &format!("{FORENSICS_DIR}/latest-session.json"),
        latest_doc,
        Policy::Forensics,
    )?;
    let hosts = a.redactor.hosts_replaced();
    a.bytes(
        &format!("{FORENSICS_DIR}/REDACTION.txt"),
        texts::redaction(hosts).as_bytes(),
    )?;
    tracing::info!(
        "diagnostics export: staged pseudonymized forensics session {} ({hosts} host names replaced)",
        session.id
    );
    Ok(Some(session.id.clone()))
}
