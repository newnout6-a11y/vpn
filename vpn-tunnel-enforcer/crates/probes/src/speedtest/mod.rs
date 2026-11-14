//! Speed test (monitoring §3.11, §4.8): latency, multi-stream download and upload through the
//! tunnel in time-boxed rounds, an egress check before and after the transfers, and a history
//! of 50. Rounds stop at their byte budget or their time box (B-ST-3), so a static 100 MB file
//! costs no more than a sized Cloudflare stream; cancelling drops every stream at once.
mod history;
mod maths;
mod rounds;
#[cfg(test)]
pub(crate) mod tests;
#[cfg(test)]
pub(crate) mod testsrv;

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use futures_util::future::BoxFuture;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use url::Url;
use vpnte_base::types::{UnixMs, now_ms};
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use vpnte_core::ops::{FeatureKind, OperationRegistry, RunOpts};
use vpnte_core::store::Store;

pub use history::{MAX_HISTORY, SpeedTests};
pub use maths::{Egress, EgressRef, egress_verdict, latency_ms, mbps, percent};

/// Phase of a running test, as the progress bar shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SpeedPhase {
    #[default]
    Latency,
    Download,
    Upload,
    Complete,
    Error,
}

impl SpeedPhase {
    /// Label of the phase (`probes.speed.phase.*`).
    pub fn msg(self) -> Msg {
        Msg::new(match self {
            SpeedPhase::Latency => "probes.speed.phase.latency",
            SpeedPhase::Download => "probes.speed.phase.download",
            SpeedPhase::Upload => "probes.speed.phase.upload",
            SpeedPhase::Complete => "probes.speed.phase.complete",
            SpeedPhase::Error => "probes.speed.phase.error",
        })
    }
}

/// One progress frame (duplicates are not sent).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SpeedProgress {
    pub percent: u8,
    pub phase: SpeedPhase,
}

/// Why the result deserves a warning about its transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TransportWarning {
    /// Every HTTPS download server failed; the figure comes from a plain-HTTP fallback (B-ST-4).
    PlainHttp,
}

impl TransportWarning {
    /// The warning shown with the result.
    pub fn msg(self) -> Msg {
        match self {
            TransportWarning::PlainHttp => Msg::new("probes.speed.warning.plainHttp"),
        }
    }
}

/// One finished test, as shown and stored.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpeedResult {
    pub id: String,
    pub timestamp: UnixMs,
    pub download_mbps: f64,
    /// `None` when the upload could not be measured (download and latency are kept).
    #[serde(default)]
    pub upload_mbps: Option<f64>,
    pub latency_ms: u32,
    /// Name of the download server that produced the figure ("Cloudflare", "OVH", "Tele2").
    pub server_name: String,
    /// Display name of the connected profile; `None` = unknown.
    #[serde(default)]
    pub profile_used: Option<String>,
    #[serde(default)]
    pub egress: Egress,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_warning: Option<TransportWarning>,
}

/// One download server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadTarget {
    pub name: String,
    pub url: Url,
    /// Accepts `bytes=<n>` (Cloudflare `__down`); otherwise a large static file is read up to
    /// the byte budget, with a cache-buster per stream.
    pub sized: bool,
    /// A plain-HTTP fallback: a result from it carries [`TransportWarning::PlainHttp`].
    pub plain_http: bool,
}

/// A transfer round: parallel streams, each up to `bytes_per_stream`, the whole round at most
/// `time_box` after its first byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Round {
    pub streams: usize,
    pub bytes_per_stream: u64,
    pub time_box: Duration,
}

/// Endpoints and limits of a run ([`Plan::standard`] in production; tests shrink it).
#[derive(Debug, Clone, PartialEq)]
pub struct Plan {
    /// Tried in order; the first with samples gives the latency.
    pub latency_urls: Vec<Url>,
    /// HTTPS servers first, then the plain-HTTP fallbacks.
    pub download: Vec<DownloadTarget>,
    pub upload_url: Url,
    pub download_probe: Round,
    pub download_sustained: Round,
    /// A probe at or above this runs the sustained round.
    pub download_fast_mbps: f64,
    pub upload_probe: Round,
    pub upload_sustained: Round,
    pub upload_fast_mbps: f64,
    /// A round that ended before its time box must have moved at least this much (B-ST-2).
    pub min_round_bytes: u64,
    /// Per latency request.
    pub latency_timeout: Duration,
    /// Whole latency phase.
    pub latency_budget: Duration,
    /// Until the first byte of a round arrives (or the first upload byte is taken).
    pub setup_timeout: Duration,
    /// Whole run (B-ST-7).
    pub run_budget: Duration,
}

const MIB: u64 = 1024 * 1024;

impl Plan {
    /// The production endpoints and limits.
    pub fn standard() -> Plan {
        let url = |s: &str| Url::parse(s).expect("static URL");
        let target = |name: &str, u: &str, sized: bool, plain_http: bool| DownloadTarget {
            name: name.to_owned(),
            url: url(u),
            sized,
            plain_http,
        };
        Plan {
            latency_urls: [
                "https://speed.cloudflare.com/__down?bytes=0",
                "https://www.google.com/generate_204",
                "https://connectivitycheck.gstatic.com/generate_204",
                "https://detectportal.firefox.com/success.txt",
                "https://1.1.1.1/",
            ]
            .into_iter()
            .map(url)
            .collect(),
            download: vec![
                target(
                    "Cloudflare",
                    "https://speed.cloudflare.com/__down",
                    true,
                    false,
                ),
                target("OVH", "https://proof.ovh.net/files/100Mb.dat", false, false),
                target(
                    "Tele2",
                    "https://speedtest.tele2.net/100MB.zip",
                    false,
                    false,
                ),
                // Plain-HTTP fallbacks (B-ST-4). `http://proof.ovh.net/...` was dropped: it
                // answers 301 to HTTPS (checked 2026-11-11), so it is no plain-HTTP path.
                target(
                    "thinkbroadband",
                    "http://ipv4.download.thinkbroadband.com/100MB.zip",
                    false,
                    true,
                ),
                target("Tele2", "http://speedtest.tele2.net/100MB.zip", false, true),
            ],
            upload_url: url("https://speed.cloudflare.com/__up"),
            download_probe: Round {
                streams: 2,
                bytes_per_stream: 10 * MIB,
                time_box: Duration::from_secs(4),
            },
            download_sustained: Round {
                streams: 6,
                bytes_per_stream: 50 * MIB,
                time_box: Duration::from_secs(8),
            },
            download_fast_mbps: 80.0,
            upload_probe: Round {
                streams: 4,
                bytes_per_stream: 2 * MIB,
                time_box: Duration::from_secs(4),
            },
            upload_sustained: Round {
                streams: 20,
                bytes_per_stream: 4 * MIB,
                time_box: Duration::from_secs(8),
            },
            upload_fast_mbps: 40.0,
            min_round_bytes: MIB,
            latency_timeout: Duration::from_secs(3),
            latency_budget: Duration::from_secs(20),
            setup_timeout: Duration::from_secs(8),
            run_budget: Duration::from_secs(90),
        }
    }
}

/// The connection a run is bound to (from the tunnel runtime).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Connection {
    /// TUN interface address: every request binds to it, so the figures are provably through
    /// the tunnel; `None` = unbound (still on the TUN routes).
    pub tun_v4: Option<Ipv4Addr>,
    /// Display name of the connected profile.
    pub profile: Option<String>,
}

/// Address family of an egress sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpFamily {
    V4,
    V6,
}

/// Public-IP reads through the tunnel (the app wires the IP monitor's wave).
pub trait EgressSource: Send + Sync {
    /// The adopted VPN exit and the real ISP address, when known.
    fn reference(&self) -> EgressRef;
    /// One family-pinned public-IP read through the tunnel; `None` when no provider answered.
    /// Must not change the monitor's own state.
    fn sample(&self, family: IpFamily) -> BoxFuture<'_, Option<IpAddr>>;
}

/// Everything a run needs besides the progress channel.
#[derive(Clone)]
pub struct SpeedEnv {
    /// `None` when the tunnel is not connected (the run is refused).
    pub connection: Option<Connection>,
    /// `None`: the egress is reported as not checked.
    pub egress: Option<Arc<dyn EgressSource>>,
    pub plan: Plan,
}

fn not_connected() -> AppError {
    AppError::conflict(Msg::new("probes.speed.notConnected"))
}

fn server_changed() -> AppError {
    AppError::conflict(Msg::new("probes.speed.serverChanged"))
}

/// Bound of one egress sample (the IP monitor's wave has a 2 s budget of its own).
const EGRESS_LIMIT: Duration = Duration::from_secs(4);

/// Sends progress frames: duplicates dropped, monotonic within a phase, none once the run is
/// cancelled (an aborted task may still be polled once after the caller saw the abort).
struct Progress<'a>(&'a watch::Sender<SpeedProgress>, &'a CancellationToken);

impl Progress<'_> {
    fn set(&self, phase: SpeedPhase, percent: u8) {
        if self.1.is_cancelled() {
            return;
        }
        self.0.send_if_modified(|current| {
            if current.phase == phase && percent <= current.percent {
                return false;
            }
            *current = SpeedProgress { percent, phase };
            true
        });
    }

    /// Reporter for one round that covers `from..to` of the phase's ratio.
    fn round(&self, phase: SpeedPhase, from: f64, to: f64) -> impl Fn(f64) + Sync + '_ {
        move |ratio| self.set(phase, percent(phase, from + (to - from) * ratio))
    }
}

/// Builds the run's HTTP client: bound to the TUN address, one TCP connection per stream
/// (HTTP/1.1, as the old test: multiplexing would measure a single connection), no content
/// decoding (a compressed answer would inflate the count).
fn client_for(connection: &Connection, plan: &Plan) -> AppResult<reqwest::Client> {
    let mut builder =
        vpnte_core::net::builder_for(&vpnte_core::net::Route::Direct, plan.run_budget)?
            .http1_only()
            .no_gzip()
            .no_brotli()
            .redirect(reqwest::redirect::Policy::limited(3));
    if let Some(v4) = connection.tun_v4 {
        builder = builder.local_address(IpAddr::V4(v4));
    }
    builder
        .build()
        .map_err(|err| AppError::internal(err.without_url()))
}

async fn sample(source: Option<&dyn EgressSource>, family: IpFamily) -> Option<IpAddr> {
    tokio::time::timeout(EGRESS_LIMIT, source?.sample(family))
        .await
        .ok()
        .flatten()
}

/// Download: per server in order, a probe round and, on a fast link, a sustained round; the
/// first server with a valid probe wins. Returns (Mbps, server).
async fn download<'p>(
    client: &reqwest::Client,
    plan: &'p Plan,
    progress: &Progress<'_>,
) -> AppResult<(f64, &'p DownloadTarget)> {
    for target in &plan.download {
        let probe = progress.round(SpeedPhase::Download, 0.0, 0.3);
        let probe = match rounds::download_round(client, target, &plan.download_probe, plan, &probe)
            .await
        {
            Ok(mbps) => mbps,
            Err(err) => {
                tracing::warn!(server = %target.name, ?err, "download endpoint failed, trying next");
                continue;
            }
        };
        if probe < plan.download_fast_mbps {
            return Ok((probe, target));
        }
        let sustained = progress.round(SpeedPhase::Download, 0.3, 1.0);
        let mbps = match rounds::download_round(
            client,
            target,
            &plan.download_sustained,
            plan,
            &sustained,
        )
        .await
        {
            Ok(sustained) => probe.max(sustained),
            // The probe was valid: keep it rather than discard the server.
            Err(err) => {
                tracing::warn!(server = %target.name, ?err, "sustained download round failed, keeping the probe");
                probe
            }
        };
        return Ok((mbps, target));
    }
    Err(AppError::msg(
        ErrorKind::Network,
        Msg::new("probes.speed.downloadFailed"),
    ))
}

/// Upload: a probe round and, on a fast link, a sustained one; `None` when it failed.
async fn upload(client: &reqwest::Client, plan: &Plan, progress: &Progress<'_>) -> Option<f64> {
    let size = plan
        .upload_probe
        .bytes_per_stream
        .max(plan.upload_sustained.bytes_per_stream);
    let payload = rounds::payload(size);
    let probe = progress.round(SpeedPhase::Upload, 0.0, 0.3);
    let probe = match rounds::upload_round(
        client,
        &plan.upload_url,
        &plan.upload_probe,
        plan,
        &payload,
        &probe,
    )
    .await
    {
        Ok(mbps) => mbps,
        Err(err) => {
            tracing::warn!(?err, "upload could not be measured");
            return None;
        }
    };
    if probe < plan.upload_fast_mbps {
        return Some(probe);
    }
    let sustained = progress.round(SpeedPhase::Upload, 0.3, 1.0);
    match rounds::upload_round(
        client,
        &plan.upload_url,
        &plan.upload_sustained,
        plan,
        &payload,
        &sustained,
    )
    .await
    {
        Ok(sustained) => Some(probe.max(sustained)),
        Err(err) => {
            tracing::warn!(?err, "sustained upload round failed, keeping the probe");
            Some(probe)
        }
    }
}

/// Runs one test over `connection` and returns the result (nothing is stored). Progress:
/// latency 0, download 5..=50, upload 50..=100, then `Complete` 100; no frame after a
/// cancellation. Errors: `Cancelled`, `Timeout` (past `plan.run_budget`), `Network`
/// `probes.speed.{latencyFailed,downloadFailed}`.
pub async fn measure(
    connection: &Connection,
    egress: Option<&dyn EgressSource>,
    plan: &Plan,
    progress: &watch::Sender<SpeedProgress>,
    cancel: &CancellationToken,
) -> AppResult<SpeedResult> {
    let client = client_for(connection, plan)?;
    let work = async {
        let progress = Progress(progress, cancel);
        progress.set(SpeedPhase::Latency, 0);
        let latency_ms = rounds::latency(&client, plan).await.ok_or_else(|| {
            AppError::msg(ErrorKind::Network, Msg::new("probes.speed.latencyFailed"))
        })?;
        let reference = egress.map(|e| e.reference()).unwrap_or_default();
        let family = match reference.baseline.or(reference.real_ip) {
            Some(IpAddr::V6(_)) => IpFamily::V6,
            _ => IpFamily::V4,
        };
        let before = sample(egress, family).await;
        progress.set(SpeedPhase::Download, percent(SpeedPhase::Download, 0.0));
        let (download_mbps, target) = download(&client, plan, &progress).await?;
        progress.set(SpeedPhase::Upload, percent(SpeedPhase::Upload, 0.0));
        let upload_mbps = upload(&client, plan, &progress).await;
        let after = sample(egress, family).await;
        let egress = egress_verdict(&[before, after], reference);
        if matches!(egress, Egress::Changed { .. } | Egress::Direct { .. }) {
            tracing::warn!(
                direct = matches!(egress, Egress::Direct { .. }),
                "speed test egress differs from the VPN exit"
            );
        }
        let transport_warning = target.plain_http.then_some(TransportWarning::PlainHttp);
        if transport_warning.is_some() {
            tracing::warn!(server = %target.name, "speed test fell back to plain HTTP");
        }
        progress.set(SpeedPhase::Complete, 100);
        Ok(SpeedResult {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: now_ms(),
            download_mbps,
            upload_mbps,
            latency_ms,
            server_name: target.name.clone(),
            profile_used: connection.profile.clone(),
            egress,
            transport_warning,
        })
    };
    tokio::select! {
        biased;
        () = cancel.cancelled() => Err(AppError::cancelled()),
        done = tokio::time::timeout(plan.run_budget, work) => done.unwrap_or_else(|_| Err(AppError::timeout())),
    }
}

/// Runs a test as the `speed-test` feature operation (one at a time) and records it at the
/// front of the history. Refused with `Conflict` `probes.speed.notConnected` before any request
/// when there is no connection; `switched` resolving (the lifecycle connection changed, B-ST-5)
/// aborts the run with `Conflict` `probes.speed.serverChanged`. A failure that is not a
/// cancellation sends an `Error` frame.
pub async fn run(
    ops: &OperationRegistry,
    history: Arc<Store<SpeedTests>>,
    env: SpeedEnv,
    switched: impl Future<Output = ()> + Send + 'static,
    progress: watch::Sender<SpeedProgress>,
    opts: RunOpts,
) -> AppResult<SpeedResult> {
    let Some(connection) = env.connection.clone() else {
        return Err(not_connected());
    };
    let frames = progress.clone();
    let started = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let admitted = started.clone();
    let outcome = ops
        .run(FeatureKind::SpeedTest, opts, move |lease| async move {
            admitted.store(true, std::sync::atomic::Ordering::Relaxed);
            let token = lease.token().clone();
            let work = async move {
                tokio::select! {
                    done = measure(&connection, env.egress.as_deref(), &env.plan, &progress, &token) => done,
                    () = switched => Err(server_changed()),
                }
            };
            let result = lease.wait(work).await??;
            lease.commit(|| {
                history.update(|doc| doc.push(result.clone()))?;
                Ok(result)
            })
        })
        .await;
    match &outcome {
        Ok(r) => tracing::info!(
            download_mbps = r.download_mbps,
            upload_mbps = ?r.upload_mbps,
            latency_ms = r.latency_ms,
            server = %r.server_name,
            "speed test completed"
        ),
        Err(err) if err.kind == ErrorKind::Cancelled => {}
        Err(err) if started.load(std::sync::atomic::Ordering::Relaxed) => {
            tracing::error!(error = %err, "speed test failed");
            frames.send_replace(SpeedProgress {
                percent: 0,
                phase: SpeedPhase::Error,
            });
        }
        Err(_) => {}
    }
    outcome
}
