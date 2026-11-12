//! The server list as the check-verdict reactions see it ([`ReactionHost`]), and the stored
//! verdicts in the reactions' terms (same wire names on both sides).
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use vpnte_automation::adaptive::reaction::{
    CheckReaction, CheckVerdict, ReactionHost, ServerFacts,
};
use vpnte_probes::discipline::{Endpoint, budget};
use vpnte_profiles::emit_singbox::{EmitPolicy, effective_fingerprint};
use vpnte_servers::model::{ProfileId, ServerReaction, ServerRow, ServerVerdict};

use super::host::{ServerHost, latency, transport_of};

impl ServerHost {
    fn server_facts(&self, row: &ServerRow) -> Option<ServerFacts> {
        let profile = row.profile().ok()?;
        let policy = EmitPolicy {
            device: Some(row.device),
            ..EmitPolicy::default()
        };
        let fingerprint = (self.fingerprints.lock().get(row.id.as_str()).copied())
            .or_else(|| effective_fingerprint(&profile, &policy));
        Some(ServerFacts {
            id: row.id.0.clone(),
            name: row.name.clone(),
            host: row.server.to_ascii_lowercase(),
            transport: transport_of(&profile),
            reality: profile.tls.as_ref().is_some_and(|t| t.reality.is_some()),
            fingerprint: fingerprint.map(str::to_owned),
            verdict: row.verdict.as_ref().and_then(|v| check_verdict(v.verdict)),
            latency_ms: latency(row),
        })
    }
}

impl ReactionHost for ServerHost {
    fn server(&self, id: &str) -> Option<ServerFacts> {
        let row = self.servers.get(&ProfileId::from(id))?;
        self.server_facts(&row)
    }

    fn servers(&self) -> Vec<ServerFacts> {
        (self.usable_rows().iter())
            .filter_map(|row| self.server_facts(row))
            .collect()
    }

    async fn handshake_slot(
        &self,
        id: &str,
        max_wait: Duration,
        cancel: CancellationToken,
    ) -> bool {
        let row = self.servers.get(&ProfileId::from(id));
        let Some(profile) = row.and_then(|r| r.profile().ok()) else {
            return false;
        };
        // A loopback server has no network in between that could freeze it.
        let Some(endpoint) = Endpoint::of(&profile) else {
            return true;
        };
        budget().acquire(&endpoint, max_wait, &cancel).await.is_ok()
    }

    fn override_fingerprint(&self, id: &str, fingerprint: Option<&'static str>) {
        let mut map = self.fingerprints.lock();
        match fingerprint {
            Some(fp) => map.insert(id.to_owned(), fp),
            None => map.remove(id),
        };
    }
}

/// A stored verdict as the reactions read it; a name this version does not know is none.
pub fn check_verdict(v: ServerVerdict) -> Option<CheckVerdict> {
    Some(match v {
        ServerVerdict::Healthy => CheckVerdict::Healthy,
        ServerVerdict::Frozen => CheckVerdict::Frozen,
        ServerVerdict::Stalled => CheckVerdict::Stalled,
        ServerVerdict::HandshakeFailed => CheckVerdict::HandshakeFailed,
        ServerVerdict::KeyRejected => CheckVerdict::KeyRejected,
        ServerVerdict::IpBanned => CheckVerdict::IpBanned,
        ServerVerdict::UdpBlocked => CheckVerdict::UdpBlocked,
        ServerVerdict::Offline => CheckVerdict::Offline,
        ServerVerdict::Deferred => CheckVerdict::Deferred,
        ServerVerdict::NotVerified => CheckVerdict::NotVerified,
        // A closed port gets the reactions of a dead server: switch away (RU audit item 6).
        ServerVerdict::Refused => CheckVerdict::Offline,
        ServerVerdict::Unknown => return None,
    })
}

/// A stored reaction as the reactions read it.
pub fn check_reaction(r: ServerReaction) -> Option<CheckReaction> {
    Some(match r {
        ServerReaction::None => CheckReaction::None,
        ServerReaction::SwitchServer => CheckReaction::SwitchServer,
        ServerReaction::TryAnotherFingerprint => CheckReaction::TryAnotherFingerprint,
        ServerReaction::PreferTcpTransport => CheckReaction::PreferTcpTransport,
        ServerReaction::RetryLater => CheckReaction::RetryLater,
        ServerReaction::Unknown => return None,
    })
}
