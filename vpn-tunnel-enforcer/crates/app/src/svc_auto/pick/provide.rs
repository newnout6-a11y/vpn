//! [`PickHost`] for [`AutoHost`]: reading the list and the provider's word, connecting by the
//! user's settings, checking candidates, the session's counters.
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use vpnte_automation::adaptive::reaction::Report;
use vpnte_automation::autopick::{
    Allowed, Candidate, Checked, Confirmation, Counters, Exposure, NoRequest, PickHost,
    ProviderWord, UserActs,
};
use vpnte_automation::coordinator::ConnectRequest;
use vpnte_base::Msg;
use vpnte_base::types::{KillSwitchLevel, Owner, now_ms};
use vpnte_core::settings::{ConnectionMode, RoutingMode};
use vpnte_engine::clash_api::{ClashApi, ClashEndpoint};
use vpnte_engine::xray_config::server_pref;
use vpnte_probes::discipline::{Endpoint, budget};
use vpnte_probes::key_health;
use vpnte_servers::model::{GroupId, HealthRecord, ProfileId};
use vpnte_servers::store::{HealthUpdate, Servers, VerdictUpdate};
use vpnte_tunnel::api::CaptureKind;
use vpnte_tunnel::fsm::TunnelState;

use super::confirm;
use super::host::{AutoHost, candidate, record, same_wire, usable, word};

impl PickHost for AutoHost {
    fn servers(&self) -> Vec<Candidate> {
        let servers = &self.backend.servers;
        servers.read(|doc| {
            (doc.profiles.iter())
                .filter(|r| usable(r))
                .map(candidate)
                .collect()
        })
    }

    fn last_used(&self) -> Option<String> {
        let active = self.backend.servers.active()?;
        usable(&active.row).then_some(active.row.id.0)
    }

    fn provider_word(&self, id: &str) -> Option<ProviderWord> {
        let row = self.backend.servers.get(&ProfileId::from(id))?;
        self.backend.servers.read(|doc| {
            let controls = &doc.group(&row.group_id)?.controls;
            word(controls.autoconnect, controls.autoconnect_pick)
        })
    }

    fn request(&self, id: &str) -> Result<ConnectRequest, NoRequest> {
        let settings = &self.backend.settings;
        let (mode, routing) = settings.read(|s| (s.connection_mode, s.routing_mode));
        let profile_id = id.to_owned();
        match (mode, routing) {
            (ConnectionMode::LocalProxy, _) => Err(NoRequest::LocalProxy),
            // What the coordinator would refuse (never Soft silently, NOADMIN §2): known before
            // anything is measured or dialled.
            (ConnectionMode::DirectVpn, RoutingMode::Hard) if !self.coord.tun_capture() => Err(
                NoRequest::Refused(Msg::new("tunnel.runtime.tunUnavailable")),
            ),
            (ConnectionMode::DirectVpn, RoutingMode::Hard) => {
                Ok(ConnectRequest::Direct { profile_id })
            }
            (ConnectionMode::DirectVpn, RoutingMode::Soft) => {
                Ok(ConnectRequest::SoftDirect { profile_id })
            }
        }
    }

    fn allowed(&self) -> Allowed {
        self.backend.settings.read(|s| Allowed {
            reconnect: s.auto_restart_on_crash,
            // The reactions' own gate for a change of server.
            switch: s.adaptive_bypass && s.adaptive_bypass_server_fallback,
        })
    }

    async fn check(&self, id: &str, cancel: CancellationToken) -> Option<Checked> {
        let row = self.row(id)?;
        let identity = row.identity()?;
        let profile = row.profile().ok()?;
        let mut ctx = self.tunnel()?.probe_ctx(row.device);
        // The row's own engine choice applies to its probe exactly as to its connect.
        ctx.engine_pref = server_pref(ctx.engine_pref, row.engine);
        let check = key_health::check_profile_verdict(&profile, &ctx, &cancel)
            .await
            .ok()?;
        let h = check.health;
        let checked = Checked {
            alive: h.online,
            latency_ms: h.rtt_ms,
        };
        let health = HealthUpdate {
            id: row.id.clone(),
            identity,
            record: HealthRecord {
                online: h.online,
                at: h.at,
                rtt_ms: h.rtt_ms,
                reason: h.reason.and_then(same_wire),
                egress_ip: h.egress_ip,
            },
            country: None,
        };
        let verdict = VerdictUpdate {
            id: row.id,
            identity,
            record: record(check.verdict.verdict, check.verdict.reaction, h.at),
        };
        let servers = self.backend.servers.clone();
        // The list's writes go to the blocking pool; the feed then tells the reactions.
        let stored = tokio::task::spawn_blocking(move || {
            servers.record_health(vec![health])?;
            servers.record_verdicts(vec![verdict])
        });
        if let Ok(Err(e)) = stored.await {
            tracing::warn!(error = %e, "candidate check not stored");
        }
        Some(checked)
    }

    async fn counters(&self) -> Option<Counters> {
        let tunnel = self.tunnel()?;
        let (endpoint, proxy_down) = {
            let status = tunnel.runtime_status();
            let status = status.borrow();
            let session = status.session.as_ref()?;
            let endpoint = ClashEndpoint {
                port: session.clash_port,
                secret: session.clash_secret.clone(),
            };
            (endpoint, !status.proxy_reachable)
        };
        let api = self.clash_api(&endpoint)?;
        let open = api.connections().await.ok()?;
        let (up, down) = self.meter.lock().add(&endpoint, &open.connections);
        Some(Counters {
            up,
            down,
            proxy_down,
        })
    }

    async fn confirm(&self, id: &str, cancel: CancellationToken) -> Confirmation {
        let Some(tunnel) = self.tunnel() else {
            return Confirmation::Deferred;
        };
        let route = crate::svc_tunnel::exit_route(&tunnel.runtime_status().borrow());
        let profile = self.row(id).and_then(|r| r.profile().ok());
        let (Some(route), Some(profile)) = (route, profile) else {
            return Confirmation::Deferred;
        };
        confirm::through_session(&profile, &route, &cancel).await
    }

    async fn refresh(&self, id: &str, cancel: CancellationToken) -> Option<Vec<String>> {
        let servers = &self.backend.servers;
        let group = servers.get(&ProfileId::from(id))?.group_id;
        if servers.read(|doc| doc.group(&group).is_none_or(|g| g.is_manual())) {
            return None;
        }
        let before = group_keys(servers, &group);
        // The sweep's claim: a refresh the user started is never pre-empted.
        let refreshed = (servers.clone())
            .refresh_group(&self.backend.refresh, &group, Owner::Schedule, cancel)
            .await;
        if let Err(e) = refreshed {
            tracing::warn!(error = %e, "subscription refresh after failures did not run");
            return None;
        }
        let fresh = (group_keys(servers, &group).into_iter())
            .filter(|(id, key)| before.get(id) != Some(key))
            .filter(|(id, _)| servers.get(id).is_some_and(|r| usable(&r)))
            .map(|(id, _)| id.0);
        Some(fresh.collect())
    }

    async fn slot(&self, id: &str, max_wait: Duration, cancel: CancellationToken) -> bool {
        let Some(profile) = self.row(id).and_then(|r| r.profile().ok()) else {
            return false;
        };
        // A loopback server has no network in between that could freeze it.
        let Some(endpoint) = Endpoint::of(&profile) else {
            return true;
        };
        budget().acquire(&endpoint, max_wait, &cancel).await.is_ok()
    }

    fn exposure(&self) -> Exposure {
        let Some(tunnel) = self.tunnel() else {
            return Exposure::Unknown;
        };
        let state = tunnel.snapshot().borrow().state;
        let capture = tunnel.runtime_status().borrow().capture;
        let (soft, level) =
            (self.backend.settings).read(|s| (s.routing_mode == RoutingMode::Soft, s.kill_switch));
        traffic_exposure(
            state,
            capture.map_or(soft, |c| c == CaptureKind::Proxy),
            level,
        )
    }

    fn user_acts(&self) -> watch::Receiver<UserActs> {
        self.coord.user_acts()
    }

    fn report(&self, report: Report) {
        // Stored like a check's verdict: the list shows it, the failover avoids the server, and
        // the verdict feed hands it to the reactions (one path for every verdict). Not stored
        // (the row changed, the list is read-only): straight to the reactions.
        let (servers, reactions) = (self.backend.servers.clone(), self.reactions.clone());
        tokio::task::spawn_blocking(move || {
            let id = ProfileId::from(report.profile_id.as_str());
            let update = servers.get(&id).and_then(|row| {
                Some(VerdictUpdate {
                    identity: row.identity()?,
                    id,
                    record: record(report.verdict, report.reaction, now_ms()),
                })
            });
            let stored = update.map(|u| servers.record_verdicts(vec![u]));
            if !matches!(stored, Some(Ok(n)) if n > 0) {
                reactions.report(report);
            }
        });
    }
}

/// The identity of every key of `group`, by row.
fn group_keys(servers: &Servers, group: &GroupId) -> HashMap<ProfileId, Option<[u8; 16]>> {
    servers.read(|doc| {
        (doc.profiles.iter())
            .filter(|r| r.group_id == *group)
            .map(|r| (r.id.clone(), r.identity()))
            .collect()
    })
}

impl AutoHost {
    /// The Clash API client of the run at `endpoint` (a new run gets a new one).
    fn clash_api(&self, endpoint: &ClashEndpoint) -> Option<Arc<ClashApi>> {
        let mut clash = self.clash.lock();
        if let Some((known, api)) = clash.as_ref()
            && known == endpoint
        {
            return Some(api.clone());
        }
        let api = Arc::new(ClashApi::new(endpoint).ok()?);
        *clash = Some((endpoint.clone(), api.clone()));
        Some(api)
    }
}

/// What the user's traffic does now, from the lane's state, the capture and the kill-switch
/// level: a running session keeps it inside (only the system proxy's programs under proxy
/// capture); a kept block holds it; nothing running and nothing kept = direct. After an engine
/// fault or a failed connect the state is unknown or error: with the kill switch off nothing can
/// hold traffic then (the lane rolled the system proxy back, released the TUN).
pub fn traffic_exposure(state: TunnelState, proxy: bool, kill_switch: KillSwitchLevel) -> Exposure {
    match state {
        TunnelState::Connected if proxy => Exposure::ProxyTunnel,
        TunnelState::Connected => Exposure::Tunnel,
        TunnelState::Blocked if proxy => Exposure::ProxyBlocked,
        TunnelState::Blocked => Exposure::Blocked,
        TunnelState::Disconnected => Exposure::Direct,
        TunnelState::Error | TunnelState::Unknown if kill_switch == KillSwitchLevel::Off => {
            Exposure::Direct
        }
        TunnelState::Error | TunnelState::Unknown => Exposure::Unknown,
    }
}
