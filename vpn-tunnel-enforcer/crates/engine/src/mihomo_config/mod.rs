//! An AmneziaWG profile as one mihomo run (WP-12 lab engine): the proxy entry is
//! `vpnte_profiles::export::export_mihomo` of the profile (renamed, endpoint pinned to the
//! address the app resolved, MTU and tunnel DNS defaulted), behind two TCP-only listeners on
//! 127.0.0.1 and `MATCH` to it: the keyed hop sing-box dials ([`HopEndpoint`]) and an
//! authenticated SOCKS5 listener for the app's own readiness and traffic proof. Everything else
//! that could listen, download or write is off: no LAN, no geodata, no stored selections, the
//! controller on 127.0.0.1 with a secret.
//! The text goes to mihomo on stdin (`-f -`); it holds the keys and is never written or logged.
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use serde_json::{Value, json};
use vpnte_base::AppError;
use vpnte_base::msg::Msg;
use vpnte_profiles::export::export_mihomo;
use vpnte_profiles::model::{Host, Kind, Profile};

use crate::clash_api::ClashEndpoint;
use crate::slot::SlotEndpoint;

mod hop;
mod preflight;
#[cfg(test)]
mod tests;

pub use hop::{HOP_INBOUND, HOP_METHOD, HopEndpoint};
pub use preflight::{Gap, PreflightError, preflight};

/// Name of the one proxy (a profile name could break the `MATCH,<name>` rule syntax).
pub const PROXY: &str = "awg";
/// Name of the app's SOCKS5 listener (readiness and the egress proof; sing-box dials the hop).
pub const INBOUND: &str = "vpnte-in";
/// MTU when the key sets none: AmneziaVPN's AWG default. mihomo's own 1408 leaves no room for
/// the S4 padding AWG 1.5+ adds to every data packet (1408 + 80 bytes of WireGuard over IPv6 +
/// S4 > 1500).
pub const DEFAULT_MTU: u16 = 1376;
/// Resolvers asked through the tunnel when the key names none: mihomo resolves every name a
/// client sends inside the tunnel (`remote-dns-resolve`), never with a local resolver.
pub const DEFAULT_DNS: [IpAddr; 2] = [
    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
    IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
];

/// The loopback endpoints of one run (all on 127.0.0.1, none answers without its secret).
pub struct Listen<'a> {
    /// SOCKS5 with credentials, TCP only: the app's readiness check and egress proof.
    pub socks: &'a SlotEndpoint,
    /// What sing-box dials.
    pub hop: &'a HopEndpoint,
    pub controller: &'a ClashEndpoint,
}

/// What the config sets that the profile did not say (the explicit diff of AT-12-004).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Applied {
    /// [`DEFAULT_MTU`].
    Mtu(u16),
    /// [`DEFAULT_DNS`] as the tunnel resolvers.
    Dns,
    /// This many peer names replaced by the address the app resolved.
    Pinned(usize),
}

/// One run's config text (holds the keys: `Debug` shows only its size).
pub struct Compiled {
    pub text: String,
    pub applied: Vec<Applied>,
    /// Every secret of the text, masked in each engine line before it is kept or shown.
    pub(crate) secrets: Vec<String>,
    /// Port of the hop listener (readiness waits for it).
    pub(crate) hop: u16,
}

impl Compiled {
    /// Port of the hop this config listens on (the one sing-box dials).
    pub fn hop_port(&self) -> u16 {
        self.hop
    }
}

impl std::fmt::Debug for Compiled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Compiled({} bytes, {:?})", self.text.len(), self.applied)
    }
}

/// Why no config was produced.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TranslateError {
    #[error(transparent)]
    Preflight(#[from] PreflightError),
    /// A peer name without a resolved address: mihomo must never resolve it itself.
    #[error("peer name not resolved")]
    Unresolved,
}

impl From<TranslateError> for AppError {
    fn from(err: TranslateError) -> Self {
        match err {
            TranslateError::Preflight(p) => p.into(),
            TranslateError::Unresolved => AppError::msg(
                vpnte_base::ErrorKind::Internal,
                Msg::new("engine.lab.config.unresolved"),
            )
            .with_source(err),
        }
    }
}

/// The peer names to resolve before [`translate`] (IP literals need nothing).
pub fn hosts(p: &Profile) -> Vec<String> {
    let mut names: Vec<String> = p
        .kind
        .wireguard()
        .into_iter()
        .flat_map(|wg| &wg.peers)
        .filter_map(|peer| match &peer.host {
            Host::Domain(name) => Some(name.clone()),
            Host::Ip(_) => None,
        })
        .collect();
    names.dedup();
    names
}

/// The config of one run of `p` behind `listen`; `resolved` maps each of [`hosts`] to its address.
pub fn translate(
    p: &Profile,
    resolved: &HashMap<String, IpAddr>,
    listen: &Listen<'_>,
) -> Result<Compiled, TranslateError> {
    preflight(p)?;
    let mut run = p.clone();
    run.name = PROXY.to_owned();
    let mut applied = Vec::new();
    if let Kind::Amneziawg { wg, .. } = &mut run.kind {
        let mut pinned = 0;
        for peer in &mut wg.peers {
            if let Host::Domain(name) = &peer.host {
                let ip = resolved.get(name).ok_or(TranslateError::Unresolved)?;
                peer.host = Host::Ip(*ip);
                pinned += 1;
            }
        }
        if pinned > 0 {
            applied.push(Applied::Pinned(pinned));
        }
        if wg.mtu.is_none() {
            wg.mtu = Some(DEFAULT_MTU);
            applied.push(Applied::Mtu(DEFAULT_MTU));
        }
        if wg.dns.is_empty() {
            wg.dns = DEFAULT_DNS.to_vec();
            applied.push(Applied::Dns);
        }
    }
    // The preflight passed, so the exporter takes the profile; `None` would be a contract bug.
    let proxies = export_mihomo(&run).ok_or(PreflightError::Unsupported(vec![]))?;
    let mut text = String::new();
    for (key, value) in header(listen) {
        text.push_str(&format!("{key}: {value}\n"));
    }
    text.push_str(&proxies);
    Ok(Compiled {
        text,
        applied,
        secrets: secrets(&run, listen),
        hop: listen.hop.port(),
    })
}

/// The keys of the profile and our listener secrets.
fn secrets(p: &Profile, listen: &Listen<'_>) -> Vec<String> {
    let mut out = vec![
        listen.controller.secret.clone(),
        listen.socks.creds().user.clone(),
        listen.socks.creds().pass.clone(),
        listen.hop.key().to_owned(),
    ];
    if let Kind::Amneziawg { wg, awg } = &p.kind {
        out.push(wg.private_key.clone());
        out.extend(wg.peers.iter().filter_map(|x| x.pre_shared_key.clone()));
        out.extend(awg.header_protection_key.clone());
    }
    out
}

/// Our top-level keys, each as a JSON value (valid YAML flow).
fn header(listen: &Listen<'_>) -> Vec<(&'static str, Value)> {
    let creds = listen.socks.creds();
    vec![
        ("mode", json!("rule")),
        // Warnings and errors only: info lines name every visited host, trace would print the
        // WireGuard IPC config with the private key.
        ("log-level", json!("warning")),
        ("allow-lan", json!(false)),
        ("bind-address", json!("127.0.0.1")),
        ("find-process-mode", json!("off")),
        ("geo-auto-update", json!(false)),
        ("geodata-mode", json!(false)),
        ("unified-delay", json!(false)),
        ("skip-auth-prefixes", json!([])),
        (
            "profile",
            json!({ "store-selected": false, "store-fake-ip": false }),
        ),
        (
            "external-controller",
            json!(format!("127.0.0.1:{}", listen.controller.port)),
        ),
        (
            "external-controller-cors",
            json!({ "allow-origins": [], "allow-private-network": false }),
        ),
        ("secret", json!(listen.controller.secret)),
        ("dns", json!({ "enable": false })),
        (
            "listeners",
            json!([
                {
                    "name": INBOUND,
                    "type": "socks",
                    "listen": "127.0.0.1",
                    "port": listen.socks.port(),
                    // Its UDP relay would take datagrams from anyone (no credential check).
                    "udp": false,
                    "users": [{ "username": creds.user, "password": creds.pass }],
                },
                listen.hop.listener(),
            ]),
        ),
        ("rules", json!([format!("MATCH,{PROXY}")])),
    ]
}
