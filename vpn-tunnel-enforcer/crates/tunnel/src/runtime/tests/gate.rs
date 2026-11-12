//! The slot egress probe of the real engines behind the app's handshake gate: every echo request
//! waits for its own slot, and a refused slot ends the probe before anything is dialled.
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::Creds;
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use vpnte_profiles::model::Profile;

use super::XRAY_KEY;
use crate::runtime::{Engines, HandshakeGate, RealEngines};

/// Counts admissions and refuses once `allow` is used up.
struct Gate {
    allow: usize,
    seen: AtomicUsize,
}

#[async_trait]
impl HandshakeGate for Gate {
    async fn admit(&self, server: &Profile, _cancel: &CancellationToken) -> AppResult<()> {
        assert_eq!(
            server.server.to_string(),
            "203.0.113.10",
            "the slot's upstream"
        );
        if self.seen.fetch_add(1, Ordering::SeqCst) < self.allow {
            return Ok(());
        }
        Err(AppError::msg(
            ErrorKind::Conflict,
            Msg::new("probes.discipline.deferred").arg("seconds", 42),
        ))
    }
}

/// A loopback port nobody listens on: every SOCKS connect is refused at once, no network.
fn closed_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("loopback bind");
    listener.local_addr().expect("bound").port()
}

async fn probe(allow: usize) -> (AppResult<std::net::IpAddr>, usize) {
    let gate = Arc::new(Gate {
        allow,
        seen: AtomicUsize::new(0),
    });
    let engines =
        RealEngines::new("sing-box.exe".into(), "xray.exe".into(), None).with_gate(gate.clone());
    let server = vpnte_profiles::uri::parse_uri(XRAY_KEY).expect("fake key parses");
    let creds = Creds {
        user: "u".into(),
        pass: "p".into(),
    };
    let token = CancellationToken::new();
    let answer = engines
        .egress_via(&server, closed_port(), &creds, &token)
        .await;
    (answer, gate.seen.load(Ordering::SeqCst))
}

/// A refused slot is the probe's answer: the budget's "retry in N s", nothing dialled.
#[tokio::test]
async fn a_refused_slot_ends_the_probe_before_any_dial() {
    let (answer, seen) = probe(0).await;
    let err = answer.expect_err("deferred");
    assert_eq!(
        (err.kind, err.user_msg().key.as_ref()),
        (ErrorKind::Conflict, "probes.discipline.deferred")
    );
    assert_eq!(seen, 1);
}

/// The fallback echo service is a new connection, so it takes a slot of its own; a refused
/// second slot stops the retry instead of bursting.
#[tokio::test]
async fn each_echo_request_takes_its_own_slot() {
    let (answer, seen) = probe(1).await;
    let err = answer.expect_err("second slot refused");
    assert_eq!(err.user_msg().key, "probes.discipline.deferred");
    assert_eq!(seen, 2);
    let (answer, seen) = probe(2).await;
    let err = answer.expect_err("nobody listens");
    assert_eq!(err.user_msg().key, "tunnel.runtime.egressUnknown");
    assert_eq!(seen, 2, "one slot per echo request");
}
