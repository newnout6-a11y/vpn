//! AmneziaVPN server descriptions (amnezia-client `ServerConfig::toJson`):
//! `{"containers": [{"container": "amnezia-awg2", "awg": {<server params>, "last_config":
//! "<JSON text>"}}], "defaultContainer", "description", "hostName", "dns1", "dns2"}`. The
//! `last_config` of `awg` / `wireguard` holds the client `.conf` in `config` (plus `mtu`); that of
//! `xray` / `ssxray` is the Xray client config. SSH credentials of an administrator export
//! (`userName`, `password`) are never read.
use serde_json::{Map, Value};

use super::skipped;
use crate::common::fields::clean_name;
use crate::model::{ParseReport, Profile, SkipReason};
use crate::{json, wg_ini};

/// How a container's client config is written.
enum Config {
    /// A wg-quick / AmneziaWG `.conf` text.
    Conf,
    /// An Xray client config.
    Xray,
}

/// Containers whose client config this app imports: the key of their protocol object.
fn importable(container: &str) -> Option<(&'static str, Config)> {
    Some(match container {
        "amnezia-awg" | "amnezia-awg2" => ("awg", Config::Conf),
        "amnezia-wireguard" => ("wireguard", Config::Conf),
        "amnezia-xray" => ("xray", Config::Xray),
        "amnezia-ssxray" => ("ssxray", Config::Xray),
        _ => return None,
    })
}

/// The name AmneziaVPN shows for a container no engine of this app runs.
fn unsupported_name(container: &str) -> String {
    match container {
        "amnezia-openvpn" => "OpenVPN",
        "amnezia-openvpn-cloak" => "OpenVPN over Cloak",
        "amnezia-shadowsocks" => "OpenVPN over Shadowsocks",
        "amnezia-ipsec" => "IKEv2 / IPsec",
        "amnezia-torwebsite" => "Tor website",
        "amnezia-dns" => "AmneziaDNS",
        "amnezia-sftp" => "SFTP",
        "amnezia-socks5proxy" => "AmneziaVPN SOCKS5 service",
        "amnezia-mtproxy" => "MTProxy",
        "amnezia-telemt" => "Telemt",
        "amnezia-tproxy" => "TProxy",
        other => other,
    }
    .to_owned()
}

/// The profiles of an AmneziaVPN server description, one per importable container; every other
/// container is reported by name. `None` when `doc` is not such a description.
pub fn parse_document(doc: &Value) -> Option<ParseReport> {
    let doc = doc.as_object()?;
    let mut report = ParseReport::default();
    // Amnezia Premium / Free keys name an account the AmneziaVPN client trades for a config at
    // Amnezia's gateway.
    if ["api_key", "auth_data", "apiConfig"]
        .iter()
        .any(|k| doc.contains_key(*k))
    {
        let name = "AmneziaVPN subscription (Amnezia Premium / Free)".to_owned();
        report
            .skipped
            .push(skipped(SkipReason::UnsupportedProtocol(name)));
        return Some(report);
    }
    let containers = doc.get("containers")?.as_array()?;
    let names: Vec<&str> = containers
        .iter()
        .map(|c| c.get("container").and_then(Value::as_str))
        .collect::<Option<_>>()?;
    if names.is_empty() || !names.iter().all(|n| n.starts_with("amnezia-")) {
        return None;
    }
    let server = Server::of(doc);
    for (container, name) in containers.iter().zip(names) {
        let Some((key, config)) = importable(name) else {
            let reason = SkipReason::UnsupportedProtocol(unsupported_name(name));
            report.skipped.push(skipped(reason));
            continue;
        };
        let last = container
            .get(key)
            .and_then(|p| p.get("last_config"))
            .and_then(Value::as_str)
            .and_then(|text| serde_json::from_str::<Value>(text).ok());
        let Some(last) = last else {
            let detail = format!("{name} carries no client config (an administrator key?)");
            report.skipped.push(skipped(invalid(detail)));
            continue;
        };
        match config {
            Config::Conf => match server.conf(&last) {
                Ok(profile) => report.profiles.push(profile),
                Err(reason) => report.skipped.push(skipped(reason)),
            },
            Config::Xray => {
                let mut inner = json::parse_json(&last);
                for profile in &mut inner.profiles {
                    server.rename(profile);
                }
                report.profiles.append(&mut inner.profiles);
                report.skipped.append(&mut inner.skipped);
            }
        }
    }
    Some(report)
}

/// What the description says about the server for every container.
struct Server {
    /// The name AmneziaVPN shows (`description`), if any.
    name: Option<String>,
    /// `dns1` / `dns2`: what the `$PRIMARY_DNS` / `$SECONDARY_DNS` placeholders of older exports
    /// stand for (AmneziaVPN fills them in at connect).
    dns: [(&'static str, Option<String>); 2],
}

impl Server {
    fn of(doc: &Map<String, Value>) -> Self {
        let text = |key: &str| {
            doc.get(key)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
        };
        Self {
            name: text("description")
                .map(|n| clean_name(&n))
                .filter(|n| !n.is_empty()),
            dns: [
                ("$PRIMARY_DNS", text("dns1")),
                ("$SECONDARY_DNS", text("dns2")),
            ],
        }
    }

    fn rename(&self, profile: &mut Profile) {
        if let Some(name) = &self.name {
            profile.name.clone_from(name);
        }
    }

    /// A WireGuard / AmneziaWG container: its `.conf`, with the MTU AmneziaVPN keeps beside it.
    fn conf(&self, last: &Value) -> Result<Profile, SkipReason> {
        let mut text = last
            .get("config")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("a WireGuard container without its .conf".to_owned()))?
            .to_owned();
        for (placeholder, value) in &self.dns {
            if let Some(value) = value {
                text = text.replace(placeholder, value);
            }
        }
        let mut profile = wg_ini::parse_wg_ini(&text)
            .ok_or_else(|| invalid("the client config is not a WireGuard .conf".to_owned()))??;
        let mtu = match last.get("mtu") {
            Some(Value::String(s)) => s.trim().parse::<u16>().ok(),
            Some(Value::Number(n)) => n.as_u64().and_then(|n| u16::try_from(n).ok()),
            _ => None,
        };
        if let Some(wg) = profile.kind.wireguard_mut()
            && wg.mtu.is_none()
        {
            wg.mtu = mtu.filter(|&m| m > 0);
        }
        self.rename(&mut profile);
        Ok(profile)
    }
}

fn invalid(detail: String) -> SkipReason {
    SkipReason::Invalid {
        scheme: super::SCHEME.to_owned(),
        detail,
    }
}
