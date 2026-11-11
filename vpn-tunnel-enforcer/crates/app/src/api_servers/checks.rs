//! Measurements of the Servers page: resolved addresses, pings, key health, the entry-country
//! check, the passive probe and the location of the server's address. Each runs as the user:
//! probe engines listen on loopback, pings use plain sockets / ICMP helpers, geo lookups are
//! ordinary HTTPS requests.
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use futures_util::stream;
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{ClientDevice, now_ms};
use vpnte_base::{AppError, AppResult, ErrorKind};
use vpnte_core::net::Route;
use vpnte_core::ops::{FeatureKind, RunOpts, Source};
use vpnte_core::resolve::{How, resolve_host};
use vpnte_probes::geo::{VerifyReject, geo_routes};
use vpnte_probes::key_health::{self, HealthError};
use vpnte_probes::ping::RESOLVE_TIMEOUT;
use vpnte_servers::model::{
    ArchiveReason, CountrySource, GroupId, HealthRecord, ProfileId, ServerRow, VerifiedCountry,
};
use vpnte_servers::store::HealthUpdate;
use vpnte_ui::servers::{CountryCheck, KeyHealth};

use super::project::{reason_code, same_wire};
use super::{Shared, group_not_found, server_not_found};

/// Positive answers of the IP column are reused this long, failures for [`MISS_TTL`].
const HIT_TTL: Duration = Duration::from_secs(5 * 60);
const MISS_TTL: Duration = Duration::from_secs(30);
/// Parallel lookups of the IP column (servers §3.8).
const RESOLVE_WIDTH: usize = 24;
/// Parallel pings of a ping-all (the page's contract: five at a time).
const PING_WIDTH: usize = 5;

/// Latest address per lower-case host for the IP column (memory only).
#[derive(Default)]
pub(super) struct IpBook {
    entries: Mutex<HashMap<String, (Option<IpAddr>, Instant)>>,
    running: AtomicBool,
}

impl IpBook {
    /// Hosts with a known address.
    pub(super) fn known(&self) -> HashMap<String, IpAddr> {
        let entries = self.entries.lock();
        entries
            .iter()
            .filter_map(|(host, (ip, _))| ip.map(|ip| (host.clone(), ip)))
            .collect()
    }

    fn stale(&self, host: &str, now: Instant) -> bool {
        match self.entries.lock().get(host) {
            Some((Some(_), at)) => now.duration_since(*at) >= HIT_TTL,
            Some((None, at)) => now.duration_since(*at) >= MISS_TTL,
            None => true,
        }
    }

    fn record(&self, host: String, ip: Option<IpAddr>) {
        self.entries.lock().insert(host, (ip, Instant::now()));
    }
}

/// Clears the single-flight flag however the lookup ends.
struct Flight<'a>(&'a AtomicBool);

impl Drop for Flight<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// Resolves every host name of the list for the IP column; a second call while one runs returns
/// at once (its answers arrive through the snapshot too).
pub(super) async fn resolve_ips(shared: Arc<Shared>) -> AppResult<()> {
    let book = &shared.ips;
    if book.running.swap(true, Ordering::SeqCst) {
        return Ok(());
    }
    let _flight = Flight(&book.running);
    let now = Instant::now();
    let hosts: Vec<String> = shared
        .backend
        .servers
        .all_hosts()
        .into_iter()
        .filter(|host| host.parse::<IpAddr>().is_err() && book.stale(host, now))
        .collect();
    stream::iter(hosts)
        .map(|host| async move {
            let ip = first_address(&host, |_| true).await;
            (host, ip)
        })
        .buffer_unordered(RESOLVE_WIDTH)
        .for_each(|(host, ip)| {
            book.record(host, ip);
            std::future::ready(())
        })
        .await;
    shared.publish();
    Ok(())
}

/// The first address of `host` that `keep` accepts (IPv4 first), within the resolve budget.
async fn first_address(host: &str, keep: impl Fn(IpAddr) -> bool) -> Option<IpAddr> {
    let answer = tokio::time::timeout(RESOLVE_TIMEOUT, resolve_host(host, How::System, keep));
    answer.await.ok()?.ok()?.first().copied()
}

/// Pings one server around the tunnel (never through it); `None` = no answer.
pub(super) async fn ping_one(
    shared: Arc<Shared>,
    id: ProfileId,
    cancel: CancellationToken,
) -> AppResult<Option<u32>> {
    if shared.backend.servers.get(&id).is_none() {
        return Err(server_not_found());
    }
    let tunnel = shared.backend.tunnel()?.clone();
    let answers = tunnel.ping(vec![id], cancel).await?;
    shared.publish();
    Ok(answers
        .into_iter()
        .next()
        .and_then(|(_, s)| s)
        .map(|s| s.ms))
}

/// Pings `ids` five at a time and sends every answer as it lands. A ping that could not be
/// measured (as opposed to "no answer") sends nothing, so its row gets its previous value back.
pub(super) async fn ping_many(
    shared: Arc<Shared>,
    ids: Vec<String>,
    results: mpsc::UnboundedSender<(String, Option<u32>)>,
    cancel: CancellationToken,
) -> AppResult<()> {
    let tunnel = shared.backend.tunnel()?.clone();
    stream::iter(ids)
        .map(|id| {
            let (tunnel, cancel) = (tunnel.clone(), cancel.clone());
            async move {
                let answer = tunnel
                    .ping(vec![ProfileId::from(id.as_str())], cancel)
                    .await;
                (id, answer)
            }
        })
        .buffer_unordered(PING_WIDTH)
        .for_each(|(id, answer)| {
            match answer {
                Ok(answers) => {
                    let ms = answers
                        .into_iter()
                        .next()
                        .and_then(|(_, s)| s)
                        .map(|s| s.ms);
                    let _ = results.send((id, ms));
                }
                Err(err) if err.kind == ErrorKind::Cancelled => {}
                Err(err) => tracing::debug!(error = %err, "servers: ping not measured"),
            }
            std::future::ready(())
        })
        .await;
    if cancel.is_cancelled() {
        return Err(AppError::cancelled());
    }
    Ok(())
}

/// Routes of geo lookups right now: direct only while our TUN captures traffic (`geo_routes`).
pub(super) fn lookup_routes(shared: &Shared, device: ClientDevice) -> AppResult<Vec<Route>> {
    let tunnel = shared.backend.tunnel()?;
    let tun = tunnel.probe_ctx(device).net.tunnel_running();
    Ok(shared.backend.settings.read(|s| geo_routes(s, tun)))
}

/// Country of the server's own address (the manual check, servers §3.9). Stored as `entry-ip`
/// evidence, which never replaces younger exit evidence; the answer is the country the row shows
/// afterwards, like the old app.
pub(super) async fn verify_country(
    shared: Arc<Shared>,
    id: ProfileId,
    cancel: CancellationToken,
) -> AppResult<CountryCheck> {
    let backend = shared.backend.clone();
    let row = backend.servers.get(&id).ok_or_else(server_not_found)?;
    if !backend.geo.enabled() {
        return Ok(CountryCheck::GeoDisabled);
    }
    let routes = lookup_routes(&shared, row.device)?;
    let opts = RunOpts {
        source: Source::Ui,
        resource: Some(format!("country:{id}").into()),
        cancel: Some(cancel),
        ..RunOpts::default()
    };
    let (servers, geo) = (backend.servers.clone(), backend.geo.clone());
    let result = backend
        .ops
        .run(FeatureKind::ServerProbe, opts, move |lease| async move {
            let generation = servers.geo_generation();
            match geo.verify_entry(&row.server, routes, lease.token()).await {
                Ok((iso2, ip)) => lease.commit(|| {
                    let found = VerifiedCountry {
                        iso2,
                        at: now_ms(),
                        ip: Some(ip),
                        source: CountrySource::EntryIp,
                    };
                    servers.record_country(&id, found, generation)?;
                    let shown = servers.get(&id).and_then(|r| r.display_country());
                    Ok(CountryCheck::Verified(
                        shown.unwrap_or(iso2).as_str().to_owned(),
                    ))
                }),
                Err(VerifyReject::GeoDisabled) => Ok(CountryCheck::GeoDisabled),
                Err(VerifyReject::Superseded) => Err(AppError::cancelled()),
                Err(_) => Ok(CountryCheck::Failed),
            }
        })
        .await;
    shared.publish();
    match result {
        // The 9 s budget passed: the lookup did not answer.
        Err(err) if err.kind == ErrorKind::Timeout => Ok(CountryCheck::Failed),
        other => other,
    }
}

/// A probed row: its id and its key identity when the probe started (`None`: sealed for
/// another account, which the probe reports as `no-outbound` and the list cannot match).
pub(super) type Key = (ProfileId, Option<[u8; 16]>);

/// A row to probe with its profile (`None` when sealed).
type Item = (Key, Option<vpnte_profiles::model::Profile>);

/// Checks the keys of group `id` that the user has not removed (provider-archived keys are
/// probed: that is the post-trial use) as one `HealthCheck` operation, five probes at a time;
/// the verdicts land in the list, except for rows deleted or re-keyed meanwhile.
pub(super) async fn group_health(
    shared: Arc<Shared>,
    id: GroupId,
    cancel: CancellationToken,
) -> AppResult<Vec<(String, KeyHealth)>> {
    let backend = shared.backend.clone();
    let rows = backend.servers.read(|doc| {
        doc.group(&id).ok_or_else(group_not_found)?;
        Ok::<_, AppError>(
            doc.profiles
                .iter()
                .filter(|r| r.group_id == id && !r.archived_for(ArchiveReason::User))
                .cloned()
                .collect::<Vec<_>>(),
        )
    })?;
    if rows.is_empty() {
        return Err(HealthError::GroupNotFoundOrEmpty.into());
    }
    let tunnel = backend.tunnel()?.clone();
    let servers = backend.servers.clone();
    let opts = RunOpts {
        source: Source::Ui,
        resource: Some(format!("health:{id}").into()),
        cancel: Some(cancel),
        ..RunOpts::default()
    };
    let checked = backend
        .ops
        .run(FeatureKind::HealthCheck, opts, move |lease| async move {
            let mut checked = Vec::new();
            let mut setup = None;
            for (device, items) in by_device(rows) {
                let ctx = tunnel.probe_ctx(device);
                match key_health::check_many(items, &ctx, lease.token()).await {
                    Ok(found) => checked.extend(found),
                    Err(HealthError::Setup(err)) => setup = Some(err),
                    Err(err) => return Err(err.into()),
                }
            }
            if let Some(err) = setup.filter(|_| checked.is_empty()) {
                return Err(err);
            }
            lease.commit(|| {
                servers.record_health(updates(&checked))?;
                Ok(checked)
            })
        })
        .await?;
    shared.publish();
    Ok(checked
        .iter()
        .map(|((id, _), h)| (id.to_string(), key_health_view(h)))
        .collect())
}

/// Rows grouped by client device: a probe context (uTLS default, Xray translation) per device;
/// hand-added keys of one group may differ.
fn by_device(rows: Vec<ServerRow>) -> Vec<(ClientDevice, Vec<Item>)> {
    let mut out: Vec<(ClientDevice, Vec<Item>)> = Vec::new();
    for row in rows {
        let profile = row.profile().ok();
        let item = (
            (row.id.clone(), profile.as_ref().map(|p| p.identity())),
            profile,
        );
        match out.iter_mut().find(|(d, _)| *d == row.device) {
            Some((_, items)) => items.push(item),
            None => out.push((row.device, vec![item])),
        }
    }
    out
}

/// What the list stores of the verdicts (with the trace's exit country).
pub(super) fn updates(checked: &[(Key, key_health::KeyHealth)]) -> Vec<HealthUpdate> {
    checked
        .iter()
        .filter_map(|((id, identity), h)| {
            Some(HealthUpdate {
                id: id.clone(),
                identity: (*identity)?,
                record: HealthRecord {
                    online: h.online,
                    at: h.at,
                    rtt_ms: h.rtt_ms,
                    reason: h.reason.and_then(same_wire),
                    egress_ip: h.egress_ip,
                },
                country: h.country.map(|iso2| VerifiedCountry {
                    iso2,
                    at: h.at,
                    ip: h.egress_ip,
                    source: CountrySource::HealthTrace,
                }),
            })
        })
        .collect()
}

/// A fresh verdict as the page shows it.
pub(super) fn key_health_view(h: &key_health::KeyHealth) -> KeyHealth {
    KeyHealth {
        online: h.online,
        latency_ms: h.rtt_ms,
        reason: h
            .reason
            .and_then(reason_code)
            .map(|code| vpnte_ui::servers::KeyHealthReason::from_code(&code)),
        checked_at: h.at,
    }
}
