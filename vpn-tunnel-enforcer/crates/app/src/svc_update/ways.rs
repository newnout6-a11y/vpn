//! The ways out of this machine for update requests, from the tunnel's runtime status (research
//! §4.6): the session's authenticated `live-check-in` (it leads to `proxy-out`, so through the VPN
//! server and past Smart RU), then direct — through the engine's `mixed-direct-in` while a session
//! runs (in TUN mode a plain direct request would be captured by the tunnel), plain otherwise.
use vpnte_base::types::{Creds, ProxyKind};
use vpnte_core::net::{HostPort, Route};
use vpnte_tunnel::api::{ProxyEndpoint, TunStatus};
use vpnte_update::net::{Via, Way};

/// Session first, then direct.
pub(crate) fn ways(status: &TunStatus) -> Vec<Way> {
    let session = status.session.as_ref().filter(|_| status.running);
    let Some(session) = session else {
        return vec![Way::direct()];
    };
    let mut out = Vec::with_capacity(2);
    if let Some(probe) = session.probe.as_ref().and_then(route) {
        out.push(Way {
            route: probe,
            via: Via::Session,
        });
    }
    out.push(Way {
        route: route(&session.direct).unwrap_or(Route::Direct),
        via: Via::Direct,
    });
    out
}

fn route(e: &ProxyEndpoint) -> Option<Route> {
    let addr = HostPort::new("127.0.0.1", e.port).ok()?;
    let creds = Creds {
        user: e.user.clone(),
        pass: e.pass.clone(),
    };
    Some(Route::proxy(ProxyKind::Socks5, &addr, Some(&creds)))
}
