//! The one foreign / competing TUN detector, shared by the start preflight, the routing planner and
//! the runtime watch so they can never disagree. A tunnel that captures default routes fights our
//! TUN for the traffic (Conflict: start refuses); one without default routes is a split tunnel
//! (Warning only).
use std::net::IpAddr;

use vpnte_base::{AppError, AppResult, Msg};

use super::tun::same_alias;
use super::{Adapter, Family, Route, TUN_V4, inventory, routes};

/// Tunnel-like words in an alias or description (old `TUNNEL_RX`), plus the word `tun` and
/// `wg<digits>` matched on word boundaries below.
const TUNNEL_WORDS: [&str; 11] = [
    "wintun",
    "wireguard",
    "openvpn",
    "tap-windows",
    "happ",
    "hiddify",
    "singbox",
    "sing-tun",
    "v2ray",
    "xray",
    "vpn",
];

/// How a foreign tunnel affects us.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Severity {
    /// A split tunnel next to ours: shown, never refused.
    Warning,
    /// Owns a default-capturing route (`0.0.0.0/0`, `0.0.0.0/1`, `128.0.0.0/1`, `::/0`, `::/1`,
    /// `8000::/1`): two TUNs would fight for the default route and break DNS.
    Conflict,
}

/// A tunnel adapter that is not ours.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Foreign {
    pub name: String,
    pub description: String,
    pub luid: u64,
    /// First IPv4 address, else first IPv6 address (an adapter without any is not reported).
    pub address: IpAddr,
    pub severity: Severity,
}

impl Foreign {
    /// `name (address)`, the wording logs and notifications have always used.
    pub fn label(&self) -> String {
        format!("{} ({})", self.name, self.address)
    }
}

/// Foreign tunnels that are up, most severe first. Ours is excluded by `own_luid` once known;
/// before that (a restart while the old adapter is still going away) by one of `own_aliases`
/// carrying our exact IPv4. A shared private subnet alone never proves ownership.
pub fn detect(own_luid: Option<u64>, own_aliases: &[&str]) -> windows::core::Result<Vec<Foreign>> {
    let mut table = routes(Family::V4)?;
    table.extend(routes(Family::V6)?);
    Ok(classify(&inventory()?, &table, own_luid, own_aliases))
}

/// `Err(conflict)` when any foreign tunnel captures default routes.
pub fn refuse_on_conflict(found: &[Foreign]) -> AppResult<()> {
    if found.iter().any(|f| f.severity == Severity::Conflict) {
        return Err(AppError::conflict(Msg::new(
            "winnet.adapters.foreignTunConflict",
        )));
    }
    Ok(())
}

fn classify(
    adapters: &[Adapter],
    routes: &[Route],
    own_luid: Option<u64>,
    own_aliases: &[&str],
) -> Vec<Foreign> {
    let mut found: Vec<Foreign> = adapters
        .iter()
        .filter(|a| {
            // A hardware-backed NIC is never a software tunnel, whatever the user named it ("VPN
            // router"): flagging the uplink, which owns the default route, would refuse every start.
            a.is_up()
                && a.is_visible()
                && !a.hardware
                && looks_like_tunnel(a)
                && !is_ours(a, own_luid, own_aliases)
        })
        .filter_map(|a| {
            let addresses = || {
                a.addresses
                    .iter()
                    .map(|u| u.ip)
                    .filter(|ip| !ip.is_loopback())
            };
            // An adapter without addresses cannot carry traffic.
            let address = addresses()
                .find(IpAddr::is_ipv4)
                .or_else(|| addresses().next())?;
            let captures = routes
                .iter()
                .any(|r| r.luid == a.luid && r.destination.prefix_len() <= 1);
            Some(Foreign {
                name: a.alias.clone(),
                description: a.description.clone(),
                luid: a.luid,
                address,
                severity: if captures {
                    Severity::Conflict
                } else {
                    Severity::Warning
                },
            })
        })
        .collect();
    found.sort_by_key(|f| std::cmp::Reverse(f.severity));
    found
}

fn is_ours(a: &Adapter, own_luid: Option<u64>, own_aliases: &[&str]) -> bool {
    own_luid == Some(a.luid)
        || (own_aliases.iter().any(|own| same_alias(own, &a.alias))
            && a.addresses
                .iter()
                .any(|u| u.ip == IpAddr::V4(TUN_V4.addr())))
}

/// Alias or description says tunnel, or the driver is Wintun, WireGuard or TAP-Windows (an
/// OpenVPN TAP renamed "Ethernet 3" or a WireGuard tunnel named "Home" still counts).
fn looks_like_tunnel(a: &Adapter) -> bool {
    let driver = a.driver.as_deref().unwrap_or("");
    [&a.alias, &a.description]
        .into_iter()
        .any(|text| tunnel_text(text))
        || driver == "wintun"
        || driver == "wireguard"
        || driver.starts_with("tap0")
}

fn tunnel_text(text: &str) -> bool {
    let lower = text.to_lowercase();
    TUNNEL_WORDS.iter().any(|w| lower.contains(w))
        || has_word(&lower, "tun", false)
        || has_word(&lower, "wg", true)
}

/// `word` (optionally followed by digits) bounded by non-word characters, like JS `\b` (ASCII).
fn has_word(text: &str, word: &str, digits: bool) -> bool {
    let is_word = |c: char| c.is_ascii_alphanumeric() || c == '_';
    text.match_indices(word).any(|(start, _)| {
        let before = text[..start].chars().next_back();
        let mut rest = text[start + word.len()..].chars().peekable();
        if digits {
            while rest.next_if(char::is_ascii_digit).is_some() {}
        }
        !before.is_some_and(is_word) && !rest.peek().copied().is_some_and(is_word)
    })
}

#[cfg(test)]
mod tests;
