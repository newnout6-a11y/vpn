//! The network check inside our TUN session (owner logs O-8, 15.11.2026): the UDP probes leave
//! from the uplink's own address, which the running session holds (its TUN and kill switch take
//! the PC's UDP), so their silence said «UDP blocked» about a network that was not, and taught
//! the server ranking so. Inside a session they are not run: the step reads «not checked».
use std::net::SocketAddr;

use vpnte_core::resolve::DohByName;
use vpnte_probes::discipline::{Reach, Transfer};
use vpnte_probes::netmode::{HostFacts, LiveProbe, NetProbe, Outcome};

/// [`LiveProbe`], with UDP only outside a session.
pub(super) struct CheckProbe(pub(super) LiveProbe);

impl CheckProbe {
    fn udp(&self) -> bool {
        !self.0.via_session()
    }
}

impl NetProbe for CheckProbe {
    async fn system_dns(&self, name: &str) -> Outcome {
        self.0.system_dns(name).await
    }

    async fn doh(&self, resolver: DohByName, name: &str) -> Outcome {
        self.0.doh(resolver, name).await
    }

    async fn https(&self, host: &str) -> HostFacts {
        self.0.https(host).await
    }

    async fn transfer(&self) -> Option<Transfer> {
        self.0.transfer().await
    }

    async fn quic(&self, host: &str) -> Outcome {
        match self.udp() {
            true => self.0.quic(host).await,
            false => Outcome::NotRun,
        }
    }

    async fn stun(&self, host: &str, port: u16) -> Outcome {
        match self.udp() {
            true => self.0.stun(host, port).await,
            false => Outcome::NotRun,
        }
    }

    async fn reach(&self, dst: SocketAddr) -> Reach {
        self.0.reach(dst).await
    }
}

#[cfg(test)]
mod tests {
    use vpnte_base::types::Loopback;
    use vpnte_probes::netmode::{Facts, NetProbe, Outcome, UdpEvidence, udp_evidence};

    use super::{CheckProbe, LiveProbe};

    /// O-8: inside a session the UDP probes are not run (no packet leaves; nothing to time out),
    /// so the report says «not checked» and feeds no «UDP dropped» to the server ranking.
    #[tokio::test]
    async fn inside_a_session_udp_is_not_checked() {
        let session = Loopback {
            port: 1,
            creds: None,
        };
        let probe = CheckProbe(LiveProbe::new(Some(session), None).await.expect("probe"));
        assert_eq!(probe.quic("quic.example").await, Outcome::NotRun);
        assert_eq!(probe.stun("stun.example", 3478).await, Outcome::NotRun);
        let facts = Facts {
            quic: vec![Outcome::NotRun],
            stun: vec![Outcome::NotRun],
            ..Facts::default()
        };
        assert_ne!(udp_evidence(&facts), UdpEvidence::Dropped);
    }
}
