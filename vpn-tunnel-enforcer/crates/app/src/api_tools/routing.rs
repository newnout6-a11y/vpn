//! «Проверка маршрутизации»: the exit seen through the protected path versus the real one, plus
//! the Smart RU echo, as a `routing-check` operation (one at a time). A TUN session takes the
//! probes' own echo clients (bound to the TUN address, and `mixed-direct-in`); a Soft session
//! asks the same echo services through the mixed inbound the system proxy points at, since its
//! OS route is not the tunnel. Without a session the probes answer "protection is off".
use std::net::IpAddr;
use std::sync::Arc;

use tokio_util::sync::CancellationToken;
use vpnte_base::AppResult;
use vpnte_base::types::ProxyKind;
use vpnte_core::net::{self, HostPort, Route};
use vpnte_core::ops::{FeatureKind, RunOpts, Source};
use vpnte_probes::diagnostics::RoutingInputs;
use vpnte_probes::diagnostics::routing::{
    ECHO_TIMEOUT, EchoFn, EchoPath, HttpEcho, routing_test_with,
};
use vpnte_ui::availability::RoutingReport;
use vpnte_winnet::adapters::TUN_V4;

use super::{Session, Shared, project};

/// Runs the self-test for the session that runs now.
pub(super) async fn run(shared: &Shared, cancel: CancellationToken) -> AppResult<RoutingReport> {
    let session = shared.session()?;
    let settings = shared.backend.settings.snapshot();
    let (direct, tun_source, soft_proxy) = match &session {
        Session::Off => (None, None, None),
        Session::Tun { direct, .. } => (direct.clone(), Some(IpAddr::V4(TUN_V4.addr())), None),
        Session::Proxy { proxy, direct } => (direct.clone(), None, Some(*proxy)),
    };
    let inputs = RoutingInputs {
        tunnel_active: session.running(),
        direct,
        tun_source,
        smart_ru: settings.smart_ru_split,
        disable_geo_lookup: settings.disable_geo_lookup,
    };
    let echo = echo_for(&inputs, soft_proxy);
    let opts = RunOpts {
        source: Source::Ui,
        cancel: Some(cancel),
        ..RunOpts::default()
    };
    let result = shared
        .backend
        .ops
        .run(FeatureKind::RoutingCheck, opts, move |lease| async move {
            let token = lease.token().clone();
            let result = lease
                .wait(async move { routing_test_with(&inputs, &echo, token).await })
                .await??;
            lease.commit(|| Ok(result))
        })
        .await?;
    Ok(project::routing_report(&result))
}

/// The echo requests of one run. `soft_proxy`: `Some` for a Soft session, whose "VPN" reads go
/// through its mixed inbound (`None` inside: the session has no inbound, so the read fails and
/// the result is inconclusive); the direct reads stay the probes' own.
fn echo_for(inputs: &RoutingInputs, soft_proxy: Option<Option<u16>>) -> EchoFn {
    let own = HttpEcho::new(inputs).into_fn();
    let Some(port) = soft_proxy else {
        return own;
    };
    let through_proxy = port.and_then(|port| proxy_client(port).ok());
    Arc::new(move |path, url| match path {
        EchoPath::Tunnel => {
            let client = through_proxy.clone();
            Box::pin(async move { fetch(client?, url).await })
        }
        EchoPath::Direct => own(path, url),
    })
}

/// A client through the unauthenticated loopback mixed inbound (SOCKS5 with remote names, so
/// the engine resolves and routes them as it does for the user's programs).
fn proxy_client(port: u16) -> AppResult<reqwest::Client> {
    let addr = HostPort::new("127.0.0.1", port)?;
    net::builder_for(&Route::proxy(ProxyKind::Socks5, &addr, None), ECHO_TIMEOUT)?
        .pool_max_idle_per_host(0)
        .build()
        .map_err(|err| vpnte_base::AppError::internal(err.without_url()))
}

/// The body of a successful answer; `None` on any failure (as the probes' own echo).
async fn fetch(client: reqwest::Client, url: &str) -> Option<String> {
    let response = client.get(url).send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }
    response.text().await.ok()
}
