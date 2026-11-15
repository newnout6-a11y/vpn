//! What the AutoPilot launch run reads from this PC: the listening sockets (local proxies such as
//! Happ's) and the local-proxy detection a manual connect uses.
use std::collections::HashMap;
use std::net::IpAddr;

use vpnte_automation::autopilot::{AutoPilotEnv, Listener};
use vpnte_automation::coordinator::ProxyEndpoint;
use vpnte_winnet::process::{SocketRow, TcpState, Transport, image_path, socket_table};

use super::coord::Detect;

pub struct PilotEnv {
    pub detect: Detect,
}

/// TCP listeners on loopback or every address of other processes than `own` (this app): where a
/// local proxy can be reached from here. The app's own sockets (the window's edits websocket, the
/// control API) are never probed (lab F-7: three ERROR lines from a probe of the websocket).
pub fn local_listeners(
    rows: &[SocketRow],
    own: u32,
    process: impl Fn(u32) -> String,
) -> Vec<Listener> {
    let mut names: HashMap<u32, String> = HashMap::new();
    rows.iter()
        .filter(|r| r.transport == Transport::Tcp && r.state == Some(TcpState::Listen))
        .filter(|r| r.pid != own && reachable_here(r.local.ip()))
        .map(|r| Listener {
            host: r.local.ip().to_string(),
            port: r.local.port(),
            process: names.entry(r.pid).or_insert_with(|| process(r.pid)).clone(),
        })
        .collect()
}

fn reachable_here(ip: IpAddr) -> bool {
    ip.is_loopback() || ip.is_unspecified()
}

/// The executable's file name, `""` when the process cannot be read (another account, gone).
fn process_name(pid: u32) -> String {
    image_path(pid)
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_default()
}

impl AutoPilotEnv for PilotEnv {
    fn listeners(&self) -> Vec<Listener> {
        match socket_table() {
            Ok(rows) => local_listeners(&rows, std::process::id(), process_name),
            Err(e) => {
                tracing::warn!(error = %e, "autopilot: socket table not readable");
                Vec::new()
            }
        }
    }

    async fn detect(&self) -> Option<ProxyEndpoint> {
        (self.detect)().await
    }
}
