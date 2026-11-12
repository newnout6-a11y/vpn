//! The production [`ProfileSource`]: the server list in list order (keys the user removed and
//! keys locked to another Windows account left out), the engine setting, and the group key check
//! behind the control API's `POST /profiles/healthcheck`.
use std::collections::HashMap;
use std::sync::Arc;

use vpnte_base::AppResult;
use vpnte_base::types::ClientDevice;
use vpnte_core::ops::OperationRegistry;
use vpnte_core::settings::Settings;
use vpnte_core::store::Store;
use vpnte_probes::key_health::ProbeCtx;
use vpnte_proxies::manager::{EngineChoice, ProfileSource, ProxyProfile};
use vpnte_proxies::model::{GroupHealth, ServerStatus};
use vpnte_servers::model::{ArchiveReason, Ping, ProfileId, ServerRow};
use vpnte_servers::store::Servers;

/// What a key probe needs right now (while our TUN runs: its direct-out, so probes bypass it).
pub(crate) type ProbeCtxFn = Arc<dyn Fn(ClientDevice) -> ProbeCtx + Send + Sync>;

/// [`ProfileSource`] over the backend's server list and settings.
pub(crate) struct ServerProfiles {
    pub servers: Arc<Servers>,
    pub settings: Arc<Store<Settings>>,
    pub ops: OperationRegistry,
    pub probe_ctx: ProbeCtxFn,
}

#[async_trait::async_trait]
impl ProfileSource for ServerProfiles {
    fn profiles(&self) -> Vec<ProxyProfile> {
        // Pings live in memory beside the document: the view carries them.
        let pings: HashMap<ProfileId, Ping> = self
            .servers
            .view()
            .servers
            .into_iter()
            .filter_map(|s| Some((s.id, s.ping?)))
            .collect();
        let rows = self.servers.read(|doc| {
            doc.profiles
                .iter()
                .filter(|r| !r.archived_for(ArchiveReason::User))
                .cloned()
                .collect::<Vec<_>>()
        });
        rows.into_iter()
            .filter_map(|row| {
                let ping = pings.get(&row.id).copied();
                proxy_profile(row, ping)
            })
            .collect()
    }

    /// The list's selection is the server the VPN connection uses (old `getActiveProfileId`).
    fn active_vpn_profile_id(&self) -> Option<String> {
        self.servers.active().map(|a| a.row.id.0)
    }

    /// The app's engine setting; the default device is the main VPN server's (usually the same
    /// provider). Every slot's own row wins: `ProxyProfile::{engine, device}` (D5 of
    /// wire-proxies-live, closed by engine-choice-visible).
    fn engine_choice(&self) -> EngineChoice {
        EngineChoice {
            pref: self.settings.read(|s| s.proxy_engine),
            device: self
                .servers
                .active()
                .map(|a| a.row.device)
                .unwrap_or_default(),
        }
    }

    async fn check_group_health(&self, group_id: &str) -> AppResult<GroupHealth> {
        super::health::check_group(self, group_id).await
    }
}

/// One row as a slot candidate; `None` when its key cannot be opened under this account.
fn proxy_profile(row: ServerRow, ping: Option<Ping>) -> Option<ProxyProfile> {
    let profile = match row.profile() {
        Ok(profile) => profile,
        Err(e) => {
            tracing::debug!(error = %e, "server not offered for proxies");
            return None;
        }
    };
    let health = row.health.as_ref();
    // Key health first, else the ping (old `healthStatus ?? status`).
    let status = match (health.map(|h| h.online), ping.map(|p| p.rtt_ms.is_some())) {
        (Some(true), _) | (None, Some(true)) => ServerStatus::Online,
        (Some(false), _) | (None, Some(false)) => ServerStatus::Offline,
        (None, None) => ServerStatus::Unknown,
    };
    Some(ProxyProfile {
        country: row.display_country().map(|c| c.as_str().to_owned()),
        group_id: Some(row.group_id.0.clone()),
        device: Some(row.device),
        engine: row.engine,
        status,
        ping_ms: ping.and_then(|p| p.rtt_ms),
        health_latency_ms: health.and_then(|h| h.rtt_ms),
        health_reason: health.and_then(|h| h.reason).and_then(reason_code),
        last_checked_at: health.map(|h| h.at).or(ping.map(|p| p.at)),
        enabled: true,
        removed: row.archived_for(ArchiveReason::Provider),
        id: row.id.0,
        name: row.name,
        profile,
    })
}

/// The wire tag of a failure (`auth-failed`, `tls-failed`, ...): the enum's serde name (the
/// probes' and the server list's reasons share them).
pub(super) fn reason_code<R: serde::Serialize>(reason: R) -> Option<String> {
    match serde_json::to_value(reason) {
        Ok(serde_json::Value::String(code)) => Some(code),
        _ => None,
    }
}
