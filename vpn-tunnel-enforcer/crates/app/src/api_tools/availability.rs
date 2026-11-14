//! «Проверить ссылку» and «Очистить историю»: one link through the protected path and directly,
//! run as an operation of the registry (one per call, so two checks may overlap, B-UA-8) and
//! committed to the history before the answer.
use std::net::IpAddr;
use std::sync::Arc;

use futures_util::future::BoxFuture;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::Loopback;
use vpnte_base::{AppError, AppResult};
use vpnte_core::net::Route;
use vpnte_core::ops::{FeatureKind, RunOpts, Source};
use vpnte_probes::availability::{
    self as probe, AvailabilityResult, CheckEnv, GeoInfo, GeoLookup, Paths, ProbeTarget, UrlChecks,
    derive_verdict,
};
use vpnte_probes::geo::{Geo, geo_routes};
use vpnte_ui::availability::UrlCheck;
use vpnte_winnet::adapters::TUN_V4;

use super::{Session, Shared, project};

/// Checks `input` for the session that runs now and saves the result at the front of the
/// history. An unusable link is `Validation` before anything is admitted.
pub(super) async fn check(
    shared: &Arc<Shared>,
    input: &str,
    cancel: CancellationToken,
) -> AppResult<UrlCheck> {
    let target = ProbeTarget::parse(input)?;
    let session = shared.session()?;
    let env = env(shared, &session);
    let soft = matches!(session, Session::Proxy { .. });
    let history = shared.url_checks.clone();
    let resource = format!(
        "{}:{}",
        FeatureKind::AvailabilityCheck.as_str(),
        uuid::Uuid::new_v4()
    );
    let opts = RunOpts {
        source: Source::Ui,
        resource: Some(resource.into()),
        cancel: Some(cancel),
        ..RunOpts::default()
    };
    let result = shared
        .backend
        .ops
        .run(
            FeatureKind::AvailabilityCheck,
            opts,
            move |lease| async move {
                let token = lease.token().clone();
                let measured = lease
                    .wait(async move { probe::check_url(&env, &target, &token).await })
                    .await??;
                let result = if soft { soft_sides(measured) } else { measured };
                lease.commit(|| {
                    history.update(|doc| doc.push(result.clone()))?;
                    Ok(result)
                })
            },
        )
        .await?;
    shared.publish();
    Ok(project::url_check(&result))
}

/// Forgets the saved checks. The write runs on the blocking pool and finishes even when the page
/// stops waiting (the projection task then publishes the empty list).
pub(super) async fn clear(shared: Arc<Shared>) -> AppResult<()> {
    let store = shared.url_checks.clone();
    tokio::task::spawn_blocking(move || store.update(UrlChecks::clear))
        .await
        .map_err(|err| AppError::internal(anyhow::anyhow!("history clear task failed: {err}")))??;
    shared.publish();
    Ok(())
}

/// Where the two sides leave for `session`.
fn env(shared: &Shared, session: &Session) -> CheckEnv {
    let paths = match session {
        Session::Off => Paths::Direct,
        // IPv4 binding only: the TUN's IPv6 address may be absent; unbound sockets still ride
        // the TUN routes.
        Session::Tun { direct, .. } => Paths::Tunnel {
            tun_v4: Some(TUN_V4.addr()),
            tun_v6: None,
            direct_inbound: direct.clone(),
        },
        // Without a TUN the OS route IS the direct path, and the mixed inbound the system proxy
        // points at is the protected one: the probes measure "native" + "through an inbound",
        // so the sides come back in each other's slots (`soft_sides`).
        Session::Proxy { proxy, .. } => Paths::Tunnel {
            tun_v4: None,
            tun_v6: None,
            direct_inbound: proxy.map(|port| Loopback { port, creds: None }),
        },
    };
    CheckEnv {
        paths,
        geo: geo_lookup(shared, matches!(session, Session::Tun { .. })),
    }
}

/// A Soft check: the native measurement of the OS route is the direct path, the HTTP request
/// through the system proxy's inbound the protected one. Put them where they belong and judge
/// them again; a dead inbound leaves the protected side "not measured", never "blocked".
pub(super) fn soft_sides(mut r: AvailabilityResult) -> AvailabilityResult {
    std::mem::swap(&mut r.protected, &mut r.direct);
    (r.verdict, r.recommendation) = derive_verdict(r.protected.as_ref(), r.direct.as_ref());
    r
}

/// The country / network lookup of the first resolved address over the app's `Geo` (its cache
/// and 429 back-off); `None` while geo lookups are off.
fn geo_lookup(shared: &Shared, tun: bool) -> Option<Arc<dyn GeoLookup>> {
    let geo = shared.backend.geo.clone();
    if !geo.enabled() {
        return None;
    }
    let routes = shared.backend.settings.read(|s| geo_routes(s, tun));
    Some(Arc::new(GeoOverApp { geo, routes }))
}

struct GeoOverApp {
    geo: Geo,
    routes: Vec<Route>,
}

impl GeoLookup for GeoOverApp {
    fn lookup(&self, ip: IpAddr) -> BoxFuture<'_, Option<GeoInfo>> {
        Box::pin(async move {
            // The check bounds the lookup and drops it with itself; nothing else cancels it.
            let info = self
                .geo
                .asn(ip, &self.routes, &CancellationToken::new())
                .await?;
            Some(GeoInfo {
                country: info.country,
                org: info.org,
            })
        })
    }
}
