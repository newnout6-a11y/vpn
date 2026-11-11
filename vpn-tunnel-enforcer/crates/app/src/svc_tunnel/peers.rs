//! The lifecycle's view of the server list, and the external proxies this build does not run.
use std::sync::Arc;

use async_trait::async_trait;
use vpnte_servers::model::{ArchiveReason, ProfileId, ServerRow};
use vpnte_servers::store::Servers;
use vpnte_tunnel::api::VpnProfile;
use vpnte_tunnel::lifecycle::{ExternalProxies, ProfileSource, ServerChoice};

/// [`ProfileSource`] over the server list (single source of truth for server sessions).
pub(super) struct ServerSource(pub Arc<Servers>);

impl ProfileSource for ServerSource {
    fn resolve(&self, id: Option<&str>) -> Option<ServerChoice> {
        let row = match id {
            // A row the user removed is gone for connects; a provider-archived one may still be
            // picked by the user (servers `SelectBy::User`).
            Some(id) => self
                .0
                .get(&ProfileId::from(id))
                .filter(|r| !r.archived_for(ArchiveReason::User))?,
            None => self.0.active()?.row,
        };
        choice(row)
    }
}

fn choice(row: ServerRow) -> Option<ServerChoice> {
    let profile = match row.profile() {
        Ok(profile) => profile,
        Err(e) => {
            // Locked (another PC / account) or unreadable: the lifecycle reports "no server".
            tracing::warn!(error = %e, "server profile not usable");
            return None;
        }
    };
    Some(ServerChoice {
        country: row.display_country().map(|c| c.as_str().to_owned()),
        server: VpnProfile {
            id: row.id.0,
            profile: Arc::new(profile),
            device: Some(row.device),
        },
    })
}

/// External loopback proxy slots are not part of this build: nothing to stop.
pub(super) struct NoProxies;

#[async_trait]
impl ExternalProxies for NoProxies {
    async fn stop_all(&self, _reason: &str) {}
}
