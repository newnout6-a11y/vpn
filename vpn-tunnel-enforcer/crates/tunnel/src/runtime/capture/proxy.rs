//! Proxy capture (NOADMIN.md §2, Soft mode): the engine listens on a loopback `mixed` inbound
//! (HTTP + SOCKS5, no authentication) and the app points the per-user system proxy at it. No
//! adapter and no WFP: nothing here needs privileges, and there is no protection to engage, keep
//! or release. The port belongs to the session: chosen by the first start, kept across crash
//! restarts, preserved stops and protected restarts (the system proxy keeps pointing at it),
//! forgotten by `release` (full stop, failed start).
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::Value;
use tokio::net::TcpStream;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::KillSwitchLevel;
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use vpnte_engine::ports;
use vpnte_engine::singbox_config::{self, ConfigError, ConfigInputs, TunStack};

use super::{Capture, CaptureCheck, CapturePlan, CaptureProof, EngineParts, TunForm};
use crate::api::StartRequest;

/// Poll period of the readiness and release waits.
const POLL: Duration = Duration::from_millis(50);
/// Budget of one accept probe.
const PROBE: Duration = Duration::from_millis(500);
/// Failed probes in a row before a running capture counts as lost (one refused connect can be
/// a full backlog under a burst; three in a row are not).
const LOST_AFTER: u32 = 3;

const STRICT_UNAVAILABLE: &str = "tunnel.runtime.proxy.strictUnavailable";
const NOT_ACCEPTING: &str = "tunnel.runtime.proxy.notAccepting";

/// The engine behind a loopback mixed inbound (see the module doc).
#[derive(Default)]
pub struct ProxyCapture {
    /// The mixed port of the current session, from its first `prepare` to `release`.
    port: parking_lot::Mutex<Option<u16>>,
}

impl ProxyCapture {
    /// A capture with no session yet.
    pub fn new() -> Self {
        Self::default()
    }
}

fn loopback(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

/// Something accepts TCP connections on `127.0.0.1:port` within `within`.
async fn accepts(port: u16, within: Duration) -> bool {
    let connect = TcpStream::connect(loopback(port));
    matches!(tokio::time::timeout(within, connect).await, Ok(Ok(_)))
}

/// The plan's port (its capture identity).
fn plan_port(plan: &CapturePlan) -> Option<u16> {
    plan.alias.as_deref().and_then(|a| a.parse().ok())
}

#[async_trait]
impl Capture for ProxyCapture {
    async fn prepare(&self, req: &StartRequest, avoid: &[String]) -> AppResult<CapturePlan> {
        if req.kill_switch == KillSwitchLevel::Strict {
            // Strict blocks everything outside the tunnel with persistent WFP filters: there is
            // no user-level equivalent, and a silent downgrade would promise what is not done.
            let msg = Msg::new(STRICT_UNAVAILABLE);
            return Err(AppError::msg(ErrorKind::Validation, msg));
        }
        let held = *self.port.lock();
        let port = match held.filter(|p| !avoid.contains(&p.to_string())) {
            Some(port) => port,
            None => {
                // A fresh identity never reuses the port it replaces.
                let taken: Vec<u16> = held.into_iter().collect();
                let port = ports::alloc_port(false, &taken)?;
                *self.port.lock() = Some(port);
                port
            }
        };
        Ok(CapturePlan {
            alias: Some(port.to_string()),
            form: TunForm {
                dual_stack: false,
                dns_hijack: false,
            },
            stack: TunStack::Mixed,
            mtu: singbox_config::select_mtu(req.stealth, req.adaptive, req.public_wifi),
            guard: req.kill_switch,
            warnings: Vec::new(),
        })
    }

    fn config(
        &self,
        plan: &CapturePlan,
        parts: &EngineParts,
    ) -> Result<(Value, [u8; 32]), ConfigError> {
        proxy_config(plan, parts)
    }

    async fn begin(&self, _plan: &CapturePlan, _session_programs: &[PathBuf]) -> AppResult<()> {
        Ok(())
    }

    async fn ready(
        &self,
        plan: &CapturePlan,
        timeout: Duration,
        cancel: &CancellationToken,
    ) -> AppResult<CaptureProof> {
        let port = plan_port(plan).ok_or_else(|| AppError::new(ErrorKind::Internal))?;
        let deadline = Instant::now() + timeout;
        loop {
            if accepts(port, PROBE).await {
                return Ok(CaptureProof {
                    luid: None,
                    alias: None,
                    port: Some(port),
                });
            }
            if Instant::now() >= deadline {
                tracing::warn!(port, "the mixed inbound does not accept connections");
                let msg = Msg::new(NOT_ACCEPTING).arg("port", port);
                return Err(AppError::msg(ErrorKind::Network, msg));
            }
            tokio::select! {
                () = cancel.cancelled() => return Err(AppError::cancelled()),
                () = tokio::time::sleep(POLL) => {}
            }
        }
    }

    async fn routes_ok(&self, proof: &CaptureProof) -> bool {
        match proof.port {
            Some(port) => accepts(port, PROBE).await,
            None => false,
        }
    }

    async fn lost(&self) -> AppResult<()> {
        Ok(())
    }

    async fn release(&self) -> AppResult<()> {
        self.port.lock().take();
        Ok(())
    }

    async fn wait_gone(
        &self,
        plan: &CapturePlan,
        timeout: Duration,
        cancel: &CancellationToken,
    ) -> bool {
        let Some(port) = plan_port(plan) else {
            return true;
        };
        let deadline = Instant::now() + timeout;
        loop {
            // Free = it binds again (the test listener closes at once).
            if TcpListener::bind(loopback(port)).is_ok() {
                return true;
            }
            if Instant::now() >= deadline || cancel.is_cancelled() {
                return false;
            }
            tokio::select! {
                () = cancel.cancelled() => return false,
                () = tokio::time::sleep(POLL) => {}
            }
        }
    }

    async fn check(&self, proof: &CaptureProof) -> CaptureCheck {
        let Some(port) = proof.port else {
            return CaptureCheck::Unknown;
        };
        for _ in 0..LOST_AFTER {
            if accepts(port, PROBE).await {
                return CaptureCheck::Clear;
            }
            tokio::time::sleep(POLL).await;
        }
        tracing::warn!(port, "the mixed inbound stopped accepting connections");
        CaptureCheck::Lost
    }
}

/// The sing-box config of a proxy-capture session and its compatibility key.
pub(crate) fn proxy_config(
    plan: &CapturePlan,
    parts: &EngineParts,
) -> Result<(Value, [u8; 32]), ConfigError> {
    // An unparsable identity yields port 0, which the builder refuses (`InvalidListeners`).
    let port = plan_port(plan).unwrap_or_default();
    let inputs = ConfigInputs {
        upstream: parts.upstream.clone(),
        capture: singbox_config::Capture::Proxy { port },
        listeners: parts.listeners.clone(),
        routing: parts.routing.clone(),
        phys_dns: parts.phys_dns.clone(),
    };
    Ok((
        singbox_config::build(&inputs)?,
        singbox_config::compat_key(&inputs),
    ))
}
