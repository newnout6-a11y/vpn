//! [`ServerHost`]: the server list as the rotation, the adaptive bypass and the check-verdict
//! reactions see it (one host for the three traits: they read the same rows).
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use serde_json::Value;
use tokio::sync::watch;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use vpnte_automation::adaptive::reaction::Transport;
use vpnte_automation::adaptive::{AdaptiveHost, ProfileView, Sibling};
use vpnte_automation::rotation::{ProfileFacts, ProfileStatus, RotationProfiles};
use vpnte_base::AppResult;
use vpnte_base::types::{EnginePref, Owner};
use vpnte_core::ops::Source;
use vpnte_core::settings::Settings;
use vpnte_core::store::Store;
use vpnte_engine::xray_config::{select_engine, server_pref};
use vpnte_probes::ping::{NetPath, PingTarget, ping};
use vpnte_probes::public_ip::{Family, IpReader};
use vpnte_profiles::emit_singbox::{EmitPolicy, SingBoxFragment, emit_singbox};
use vpnte_profiles::model::{Profile, Transport as Wire};
use vpnte_servers::model::{ProfileId, ServerRow};
use vpnte_servers::store::{SelectBy, Servers};
use vpnte_tunnel::api::TunStatus;
use vpnte_tunnel::lifecycle::{DisconnectReq, SessionView, StopCause};
use vpnte_tunnel::runtime::HandshakeGate;

use super::lane::Lane;
use crate::svc_tunnel::{BudgetGate, exit_route};

/// uTLS fingerprints the check-verdict reactions set for this app run (never stored): the
/// tunnel's profile source applies them to the server's next engine start.
pub type Fingerprints = Arc<Mutex<HashMap<String, &'static str>>>;

/// How long one adaptive probe may take (a provider at a time through the tunnel).
const PROBE_BUDGET: Duration = Duration::from_secs(8);

pub struct ServerHost {
    pub(super) servers: Arc<Servers>,
    settings: Arc<Store<Settings>>,
    /// The runtime: capture kind and mixed port of the running session (the probe's route).
    status: watch::Receiver<TunStatus>,
    session: watch::Receiver<Option<SessionView>>,
    reader: Arc<IpReader>,
    pub(super) fingerprints: Fingerprints,
    lane: Arc<dyn Lane>,
}

impl ServerHost {
    pub fn new(
        servers: Arc<Servers>,
        settings: Arc<Store<Settings>>,
        status: watch::Receiver<TunStatus>,
        reader: Arc<IpReader>,
        fingerprints: Fingerprints,
        lane: Arc<dyn Lane>,
    ) -> Self {
        let session = lane.session();
        Self {
            servers,
            settings,
            status,
            session,
            reader,
            fingerprints,
            lane,
        }
    }

    /// The adaptive bypass's view of server `id`; `None` when it cannot be read or emitted.
    pub fn view(&self, id: &str) -> Option<ProfileView> {
        let row = self.servers.get(&ProfileId::from(id))?;
        view_of(&row, self.settings.read(|s| s.proxy_engine))
    }

    /// Rows automation may use: not archived, readable on this PC, in store order.
    pub(super) fn usable_rows(&self) -> Vec<ServerRow> {
        self.servers.read(|doc| {
            (doc.profiles.iter())
                .filter(|r| r.archived.is_none() && !r.is_locked())
                .cloned()
                .collect()
        })
    }

    /// The profile of the server the running session uses.
    fn running_profile(&self) -> Option<Profile> {
        let id = self.session.borrow().as_ref()?.server_id()?.to_owned();
        self.servers.get(&ProfileId::from(id))?.profile().ok()
    }
}

/// The view of one row: the outbound as `emit_singbox` with the default policy, the engine the
/// settings and the server's own choice pick.
pub fn view_of(row: &ServerRow, setting: EnginePref) -> Option<ProfileView> {
    let profile = row.profile().ok()?;
    let outbound = match emit_singbox(&profile, "proxy", &EmitPolicy::default()).ok()? {
        SingBoxFragment::Outbound(v) | SingBoxFragment::Endpoint(v) => v,
        SingBoxFragment::Chain(chain) => Value::Array(chain),
    };
    let engine = select_engine(&profile, server_pref(setting, row.engine))
        .engine()
        .ok()?;
    Some(ProfileView {
        id: row.id.0.clone(),
        outbound,
        client_device: Some(row.device),
        client_fingerprint: profile.tls.as_ref().and_then(|t| t.fingerprint.clone()),
        engine,
    })
}

/// How a profile's traffic travels (the reactions' "same transport on the same site").
pub fn transport_of(p: &Profile) -> Transport {
    if p.kind.is_udp_transport() {
        return Transport::Udp;
    }
    match &p.transport {
        None | Some(Wire::TcpHttpHeader { .. }) => Transport::Tcp,
        Some(Wire::Ws { .. }) => Transport::Ws,
        Some(Wire::Grpc { .. }) => Transport::Grpc,
        Some(Wire::Http { .. }) => Transport::Http,
        Some(Wire::HttpUpgrade { .. }) => Transport::HttpUpgrade,
        Some(Wire::Quic) => Transport::Udp,
        Some(Wire::Xhttp { .. }) => Transport::Xhttp,
    }
}

/// Round trip of the last check that reached the server.
pub fn latency(row: &ServerRow) -> Option<u32> {
    row.health
        .as_ref()
        .filter(|h| h.online)
        .and_then(|h| h.rtt_ms)
}

fn facts_of(row: &ServerRow) -> ProfileFacts {
    let profile = row.profile().ok();
    ProfileFacts {
        id: row.id.0.clone(),
        name: row.name.clone(),
        // The list has no off switch: a row is usable unless archived or locked.
        enabled: true,
        archived: row.archived.is_some(),
        has_outbound: profile.is_some(),
        status: match &row.health {
            Some(h) if h.online => ProfileStatus::Online,
            Some(_) => ProfileStatus::Offline,
            None => ProfileStatus::Unknown,
        },
        checked_at: row.health.as_ref().map(|h| h.at),
        udp: profile.as_ref().is_some_and(|p| transport_of(p).udp()),
    }
}

impl RotationProfiles for ServerHost {
    fn facts(&self, id: &str) -> Option<ProfileFacts> {
        self.servers
            .get(&ProfileId::from(id))
            .map(|row| facts_of(&row))
    }

    fn all(&self) -> Vec<ProfileFacts> {
        self.servers
            .read(|doc| doc.profiles.iter().map(facts_of).collect())
    }

    async fn reachable(&self, id: &str) -> bool {
        // Only asked without a session: the physical path, a TCP / ICMP ping (no handshake).
        let Some(profile) = self
            .servers
            .get(&ProfileId::from(id))
            .and_then(|r| r.profile().ok())
        else {
            return false;
        };
        let target = PingTarget::of(&profile);
        let cancel = CancellationToken::new();
        ping(&target, &NetPath::default(), &cancel).await.is_some()
    }

    fn select(&self, id: &str) -> AppResult<()> {
        self.servers
            .select(&ProfileId::from(id), SelectBy::Automation)
            .map(drop)
    }
}

impl AdaptiveHost for ServerHost {
    fn profile(&self, id: &str) -> Option<ProfileView> {
        self.view(id)
    }

    fn siblings(&self, id: &str) -> Vec<Sibling> {
        let Some(group) = self.servers.get(&ProfileId::from(id)).map(|r| r.group_id) else {
            return Vec::new();
        };
        let setting = self.settings.read(|s| s.proxy_engine);
        (self.usable_rows().iter())
            .filter(|r| r.group_id == group && r.id.as_str() != id)
            .filter_map(|r| {
                let profile = view_of(r, setting)?;
                Some(Sibling {
                    profile,
                    latency_ms: latency(r),
                })
            })
            .collect()
    }

    /// One HTTPS request through the running session's own exit (the TUN, or the mixed inbound
    /// of a proxy capture), behind the handshake budget: every request through the tunnel is a
    /// new handshake with the server (RU discipline).
    async fn probe(&self, cancel: CancellationToken) -> Option<Duration> {
        let route = exit_route(&self.status.borrow())?;
        if let Some(profile) = self.running_profile() {
            BudgetGate.admit(&profile, &cancel).await.ok()?;
        }
        let started = Instant::now();
        let sample = self
            .reader
            .wave(&route, Family::V4, PROBE_BUDGET, &cancel)
            .await;
        sample.map(|_| started.elapsed())
    }

    fn select(&self, id: &str) -> AppResult<()> {
        RotationProfiles::select(self, id)
    }

    async fn abandon(&self) {
        // A provisional sibling failed its window: the engine goes; with it the session ends
        // as a fault (the lane's full stop, as after an exhausted restart budget).
        let req = DisconnectReq::new(StopCause::Failed, Owner::AdaptiveRetry, Source::Lifecycle);
        if let Err(e) = self.lane.disconnect(req).await {
            tracing::warn!(error = %e, "adaptive: abandoning the sibling failed");
        }
    }
}
