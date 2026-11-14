//! The tunnel's slot egress probe behind the shared handshake budget (probe discipline, RU
//! networks Nov 2026). The probe is a new handshake to the server like any check's, so a connect
//! right after a health check waits for its slot instead of being the burst that freezes the
//! server for two minutes.
use std::time::Duration;

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;
use vpnte_base::AppResult;
use vpnte_probes::discipline::{Endpoint, WINDOW, budget};
use vpnte_profiles::model::Profile;
use vpnte_tunnel::runtime::HandshakeGate;

/// How long a connect waits for its slot: one window and a little, so only a hold after a freeze
/// verdict defers it (then connecting would fail anyway and extend the freeze). The user can
/// cancel the connect meanwhile.
const EGRESS_WAIT: Duration = WINDOW.saturating_add(Duration::from_secs(5));

/// [`HandshakeGate`] over the process-wide budget every check shares.
pub(crate) struct BudgetGate;

#[async_trait]
impl HandshakeGate for BudgetGate {
    async fn admit(&self, server: &Profile, cancel: &CancellationToken) -> AppResult<()> {
        // A loopback server (a local proxy) has no network in between that could freeze it.
        let Some(endpoint) = Endpoint::of(server) else {
            return Ok(());
        };
        budget().acquire(&endpoint, EGRESS_WAIT, cancel).await?;
        Ok(())
    }

    fn ready_now(&self, server: &Profile) -> bool {
        Endpoint::of(server).is_none_or(|endpoint| budget().wait_for(&endpoint).is_zero())
    }
}

#[cfg(test)]
mod tests {
    use vpnte_base::ErrorKind;

    use super::*;

    /// A fake key whose server name no other test uses (the budget is process-wide).
    fn server(sni: &str) -> Profile {
        key("203.0.113.20", sni)
    }

    fn key(host: &str, sni: &str) -> Profile {
        let uri = format!(
            "vless://00000000-0000-4000-8000-000000000009@{host}:443?security=tls&sni={sni}&type=tcp#Gate"
        );
        vpnte_profiles::uri::parse_uri(&uri).expect("fake key parses")
    }

    /// A free endpoint is admitted at once; a held one (a freeze verdict) defers the probe with
    /// the budget's "retry in N s" instead of dialling into the freeze.
    #[tokio::test]
    async fn a_freeze_hold_defers_the_egress_probe() {
        let token = CancellationToken::new();
        let free = server("gate-free.test");
        BudgetGate.admit(&free, &token).await.expect("free slot");
        let held = server("gate-held.test");
        let endpoint = Endpoint::of(&held).expect("network endpoint");
        budget().hold(&endpoint, Duration::from_secs(600));
        let err = BudgetGate.admit(&held, &token).await.expect_err("held");
        assert_eq!(
            (err.kind, err.user_msg().key.as_ref()),
            (ErrorKind::Conflict, "probes.discipline.deferred")
        );
    }

    /// A cancelled connect stops waiting for its slot.
    #[tokio::test]
    async fn a_cancelled_wait_ends_at_once() {
        let waiting = server("gate-cancel.test");
        let endpoint = Endpoint::of(&waiting).expect("network endpoint");
        budget().hold(&endpoint, Duration::from_secs(30));
        let token = CancellationToken::new();
        token.cancel();
        let err = BudgetGate
            .admit(&waiting, &token)
            .await
            .expect_err("cancelled");
        assert_eq!(err.kind, ErrorKind::Cancelled);
    }

    /// A server on this machine (a local relay) never touches the budget.
    #[tokio::test]
    async fn a_loopback_server_needs_no_slot() {
        let local = key("127.0.0.1", "gate-local.test");
        assert!(Endpoint::of(&local).is_none());
        let token = CancellationToken::new();
        token.cancel();
        BudgetGate.admit(&local, &token).await.expect("no budget");
    }
}
