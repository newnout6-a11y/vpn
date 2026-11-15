//! System snapshots: the network state needed to debug "the app says VPN is up but my browser
//! still shows the real IP", written to `<data dir>\snapshots\snapshot-<iso>-<reason>.json`
//! (the name format the diagnostics export parses). Every section is captured on its own (an
//! error is recorded in its place, never aborts the snapshot), captures are serialized FIFO, a
//! periodic capture is skipped while another runs, and only the 60 newest files are kept.
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde::Serialize;
use serde_json::{Map, Value, json};
use tokio_util::sync::CancellationToken;
use vpnte_winnet::adapters::{self, Adapter, AdapterStatus, Family, Route};
use vpnte_winnet::process::{self, Transport};
use vpnte_winnet::registry::{Access, Hive, Key, View};

use super::sysinfo;
use crate::local_proxy::SystemProxy;

/// Directory under the data root.
pub const SNAPSHOTS_DIRNAME: &str = "snapshots";
/// Newest files kept (every directory entry counts, stray temp files included).
pub const MAX_RETAINED: usize = 60;
/// Interval of the periodic capture while the app runs (one constant, no parameter: B-SN-4).
pub const PERIODIC_INTERVAL: Duration = Duration::from_secs(5 * 60);
/// Proxy ports whose listener owner is recorded (the usual local client ports).
pub const WATCHED_PORTS: [u16; 2] = [10808, 10809];

/// Why a snapshot was taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SnapshotReason {
    AppStart,
    TunPreStart,
    TunPostStart,
    TunStartFailed,
    TunPostStop,
    Periodic,
    Manual,
    LeakDetected,
}

impl SnapshotReason {
    /// Wire name, also the file name suffix.
    pub fn as_str(self) -> &'static str {
        match self {
            SnapshotReason::AppStart => "app-start",
            SnapshotReason::TunPreStart => "tun-pre-start",
            SnapshotReason::TunPostStart => "tun-post-start",
            SnapshotReason::TunStartFailed => "tun-start-failed",
            SnapshotReason::TunPostStop => "tun-post-stop",
            SnapshotReason::Periodic => "periodic",
            SnapshotReason::Manual => "manual",
            SnapshotReason::LeakDetected => "leak-detected",
        }
    }
}

/// `<data root>\snapshots` (also cleared by the maintenance "clear diagnostics" action).
pub fn dir(data_root: &Path) -> PathBuf {
    data_root.join(SNAPSHOTS_DIRNAME)
}

/// `snapshot-2026-11-11T02-35-07-123Z-manual.json`: ISO time with `:` and `.` replaced by `-`.
pub fn file_name(ts: jiff::Timestamp, reason: SnapshotReason) -> String {
    let iso = ts.strftime("%Y-%m-%dT%H-%M-%S-%3fZ").to_string();
    format!("snapshot-{iso}-{}.json", reason.as_str())
}

fn section<T>(read: windows::core::Result<T>, ok: impl FnOnce(T) -> Value) -> Value {
    match read {
        Ok(v) => ok(v),
        Err(e) => json!({ "error": e.message() }),
    }
}

fn status_word(s: AdapterStatus) -> &'static str {
    match s {
        AdapterStatus::Up => "up",
        AdapterStatus::Disconnected => "disconnected",
        AdapterStatus::NotPresent => "not-present",
        AdapterStatus::Disabled => "disabled",
    }
}

fn adapter_json(a: &Adapter) -> Value {
    let unicast: Vec<Value> = a
        .addresses
        .iter()
        .map(|u| json!({ "ip": u.ip.to_string(), "prefixLen": u.prefix_len, "dadState": u.dad_state, "temporary": u.temporary }))
        .collect();
    json!({
        "alias": a.alias,
        "description": a.description,
        "ifIndex": a.if_index,
        "ifType": a.if_type,
        "luid": format!("{:#x}", a.luid),
        "status": status_word(a.status),
        "physical": a.physical,
        "hidden": a.hidden,
        "mtuV4": adapters::interface_mtu(a.luid, Family::V4).ok().flatten(),
        "ipv4Enabled": a.ipv4_enabled,
        "ipv6Enabled": a.ipv6_enabled,
        "unicast": unicast,
        "gateways": a.gateways.iter().map(IpAddr::to_string).collect::<Vec<_>>(),
        "dns": a.dns.iter().map(IpAddr::to_string).collect::<Vec<_>>(),
        "dnsStatic": a.dns_static,
    })
}

fn route_json(r: &Route) -> Value {
    json!({
        "destination": r.destination.to_string(),
        "nextHop": r.next_hop.map(|h| h.to_string()),
        "ifIndex": r.if_index,
        "metric": r.metric,
        "protocol": r.protocol,
    })
}

/// NRPT rules (name resolution policy) from the registry: local and group-policy ones.
fn nrpt_rules() -> Value {
    let mut out = Vec::new();
    for (scope, path) in [
        (
            "local",
            r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig",
        ),
        (
            "policy",
            r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig",
        ),
    ] {
        let key = match Key::open(Hive::LocalMachine, path, Access::Read, View::Native) {
            Ok(Some(k)) => k,
            Ok(None) => continue,
            Err(e) => return json!({ "error": e.message() }),
        };
        for name in key.subkey_names().unwrap_or_default() {
            let Ok(Some(rule)) = key.open_subkey(&name, Access::Read) else {
                continue;
            };
            out.push(json!({
                "scope": scope,
                "rule": name,
                "namespaces": rule.multi_string("Name").ok().flatten(),
                "dnsServers": rule.string("GenericDNSServers").ok().flatten(),
            }));
        }
    }
    Value::Array(out)
}

fn listener_json(port: u16) -> Value {
    let hosts = [
        IpAddr::from([127, 0, 0, 1]),
        IpAddr::from([0, 0, 0, 0]),
        IpAddr::from([0u16; 8]),
    ];
    match process::listener_owner(Transport::Tcp, port, &hosts) {
        Ok(Some(o)) => json!({
            "pid": o.pid,
            "local": o.local.to_string(),
            "image": o.image.as_ref().and_then(|p| p.file_name()).map(|n| n.to_string_lossy().into_owned()),
        }),
        // No listener is a normal answer, not an error.
        Ok(None) => json!({ "empty": true }),
        Err(e) => json!({ "error": e.message() }),
    }
}

/// Public addresses in every string become pseudonyms (private / LAN addresses stay: support
/// needs them); the DNS cache is never captured (B-SN-1).
pub fn redact_ips(v: &mut Value) {
    match v {
        Value::String(s) => {
            if let std::borrow::Cow::Owned(r) = vpnte_core::redact::ips(s) {
                *s = r;
            }
        }
        Value::Array(items) => items.iter_mut().for_each(redact_ips),
        Value::Object(map) => map.values_mut().for_each(redact_ips),
        _ => {}
    }
}

/// Builds the snapshot document (blocking reads). `app` holds the app's own sections
/// (protection status, engine supervisor state, monitor evidence) and is merged in last.
pub fn collect(
    reason: SnapshotReason,
    ts: jiff::Timestamp,
    app_version: &str,
    app: Map<String, Value>,
) -> Value {
    let os = sysinfo::os_info();
    let sp = SystemProxy::read();
    let mut doc = json!({
        "reason": reason.as_str(),
        "ts": ts.to_string(),
        "hostname": os.hostname,
        "os": { "product": os.product, "displayVersion": os.display_version, "build": os.build, "arch": os.arch },
        "appVersion": app_version,
        "elevated": vpnte_winnet::elevation::is_elevated(),
        "memMb": { "total": os.mem_total_mb, "free": os.mem_free_mb },
        "adapters": section(adapters::inventory(), |list| list.iter().map(adapter_json).collect()),
        "routesV4": section(adapters::routes(Family::V4), |r| r.iter().map(route_json).collect()),
        "routesV6": section(adapters::routes(Family::V6), |r| r.iter().map(route_json).collect()),
        "nrptRules": nrpt_rules(),
        "winhttpProxy": match &sp.winhttp {
            Some(p) => json!(p),
            None => json!({ "error": "unreadable" }),
        },
        "wininetProxy": sp.wininet.as_ref().map_or(json!({ "error": "unreadable" }), |w| json!(w)),
        "listeners": WATCHED_PORTS.iter().map(|p| (p.to_string(), listener_json(*p))).collect::<Map<_, _>>(),
    });
    if let Value::Object(map) = &mut doc {
        map.extend(app);
    }
    redact_ips(&mut doc);
    doc
}

/// Keeps the `keep` newest entries of `dir` by modification time; errors are logged at debug.
pub fn prune(dir: &Path, keep: usize) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut files: Vec<(std::time::SystemTime, PathBuf)> = entries
        .filter_map(Result::ok)
        .filter_map(|e| Some((e.metadata().ok()?.modified().ok()?, e.path())))
        .collect();
    files.sort_by_key(|f| std::cmp::Reverse(f.0));
    for (_, path) in files.into_iter().skip(keep) {
        if let Err(e) = std::fs::remove_file(&path) {
            tracing::debug!(error = %e, "snapshot prune failed");
        }
    }
}

/// App sections merged into every snapshot (protection status, engines, monitor), as JSON.
pub type AppState = Arc<dyn Fn() -> Map<String, Value> + Send + Sync>;
/// The collector (the real one is [`collect`]); replaceable in tests.
pub type Collector = Arc<dyn Fn(SnapshotReason, jiff::Timestamp) -> Value + Send + Sync>;

/// Writes snapshots one at a time, plus the periodic timer.
pub struct Snapshotter {
    dir: PathBuf,
    collector: Collector,
    queue: tokio::sync::Mutex<()>,
    pending: AtomicUsize,
    periodic: parking_lot::Mutex<Option<CancellationToken>>,
}

struct Pending<'a>(&'a AtomicUsize);

impl Drop for Pending<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Snapshotter {
    /// Snapshots under `<data_root>\snapshots` with the real collector.
    pub fn new(data_root: &Path, app_version: String, app_state: AppState) -> Arc<Self> {
        let collector: Collector =
            Arc::new(move |reason, ts| collect(reason, ts, &app_version, app_state()));
        Self::with_collector(dir(data_root), collector)
    }

    /// Snapshots in `dir` from a custom collector.
    pub fn with_collector(dir: PathBuf, collector: Collector) -> Arc<Self> {
        Arc::new(Self {
            dir,
            collector,
            queue: tokio::sync::Mutex::new(()),
            pending: AtomicUsize::new(0),
            periodic: parking_lot::Mutex::new(None),
        })
    }

    /// The snapshots directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Captures and writes one snapshot; the path, or `None` when skipped (a periodic capture
    /// while another runs: no backlog) or the write failed. Captures run in call order; a
    /// caller that goes away before the write leaves nothing behind.
    pub async fn capture(&self, reason: SnapshotReason) -> Option<PathBuf> {
        if reason == SnapshotReason::Periodic && self.pending.load(Ordering::SeqCst) > 0 {
            tracing::debug!("skipped periodic snapshot while capture is in progress");
            return None;
        }
        self.pending.fetch_add(1, Ordering::SeqCst);
        let _pending = Pending(&self.pending);
        let _turn = self.queue.lock().await;
        let ts = jiff::Timestamp::now();
        let collector = self.collector.clone();
        let doc = tokio::task::spawn_blocking(move || collector(reason, ts))
            .await
            .ok()?;
        let path = self.dir.join(file_name(ts, reason));
        let dir = self.dir.clone();
        let target = path.clone();
        let written = tokio::task::spawn_blocking(move || {
            let mut bytes = serde_json::to_vec_pretty(&doc).map_err(std::io::Error::other)?;
            bytes.push(b'\n');
            vpnte_core::store::write_atomic(&target, &bytes)?;
            prune(&dir, MAX_RETAINED);
            Ok::<_, std::io::Error>(())
        })
        .await;
        match written {
            Ok(Ok(())) => {
                tracing::debug!(reason = reason.as_str(), "wrote snapshot");
                Some(path)
            }
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "failed to write snapshot");
                None
            }
            Err(_) => None,
        }
    }

    /// Starts the 5-minute periodic capture (runtime; a second call is a no-op). The timer holds
    /// the snapshotter weakly: dropping the last handle ends it even without `stop_periodic`.
    pub fn start_periodic(self: &Arc<Self>) {
        let mut slot = self.periodic.lock();
        if slot.is_some() {
            return;
        }
        let cancel = CancellationToken::new();
        *slot = Some(cancel.clone());
        let this = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval_at(
                tokio::time::Instant::now() + PERIODIC_INTERVAL,
                PERIODIC_INTERVAL,
            );
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = tick.tick() => {
                        let Some(this) = this.upgrade() else { break };
                        this.capture(SnapshotReason::Periodic).await;
                    }
                }
            }
        });
    }

    /// Stops the periodic capture (a running capture finishes).
    pub fn stop_periodic(&self) {
        if let Some(cancel) = self.periodic.lock().take() {
            cancel.cancel();
        }
    }
}
