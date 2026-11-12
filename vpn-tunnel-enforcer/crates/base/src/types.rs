//! Small value types shared by several crates. Anything used by one crate only lives there.
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::msg::Msg;

/// Milliseconds since the Unix epoch (the timestamp format of every persisted document).
pub type UnixMs = i64;

/// Current wall-clock time in [`UnixMs`].
pub fn now_ms() -> UnixMs {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as UnixMs)
}

/// Protocol of a local upstream proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyKind {
    #[default]
    Socks5,
    Http,
}

/// Which client a subscription server should believe we are (User-Agent and device headers).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum ClientDevice {
    #[default]
    Pc,
    Android,
    Ios,
    Mac,
}

/// Kill-switch level. `Standard` lives as long as the app process; `Strict` survives exit and reboot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KillSwitchLevel {
    #[default]
    Off,
    Standard,
    Strict,
}

/// Proxy engine selection (setting) and the engine actually used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnginePref {
    SingBox,
    Xray,
    /// WP-12 lab engine (feature `lab`, never in a production build).
    #[cfg(feature = "lab")]
    Mihomo,
    /// Also what an unknown stored value reads as: a lab build's `"mihomo"` must not cost a
    /// production build the server row it sits on (last: serde wants its `other` variant there).
    #[default]
    #[serde(other)]
    Auto,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Engine {
    SingBox,
    Xray,
    /// WP-12 lab engine for AmneziaWG (feature `lab`, never in a production build).
    #[cfg(feature = "lab")]
    Mihomo,
}

/// Who asked for a connection operation. Order is priority: a higher owner pre-empts a lower one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Owner {
    AdaptiveRetry = 1,
    Autopilot = 2,
    Rotation = 3,
    Schedule = 4,
    Manual = 5,
    Recovery = 6,
}

/// Why an engine could not reach or authenticate with its upstream (classified from engine logs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OutboundFault {
    RealityKeyMismatch,
    TlsHandshakeFailed,
    UpstreamUnreachable,
}

/// Compatibility mode chosen by adaptive bypass for a (network, profile) pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AdaptiveMode {
    #[default]
    Baseline,
    TlsCompatibility,
    MtuCompatibility,
}

/// Username/password of an app-owned loopback listener.
#[derive(Clone, PartialEq, Eq)]
pub struct Creds {
    pub user: String,
    pub pass: String,
}

impl std::fmt::Debug for Creds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Creds(..)")
    }
}

/// An app-owned proxy listener on 127.0.0.1 (engine inbound, Xray slot, external proxy).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Loopback {
    pub port: u16,
    pub creds: Option<Creds>,
}

/// Result of a check that may not have run: "not checked" must never read as "fine".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    Ok,
    Warn,
    Fail,
    #[default]
    NotChecked,
}

/// Severity of a [`Notice`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Info,
    Success,
    Warn,
    Error,
}

/// Something the user should see (toast / in-app notification), produced by backend code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Notice {
    pub level: Level,
    pub title: Msg,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<Msg>,
}

impl Notice {
    pub fn new(level: Level, title: impl Into<Msg>) -> Self {
        Self {
            level,
            title: title.into(),
            body: None,
        }
    }
    #[must_use]
    pub fn body(mut self, body: impl Into<Msg>) -> Self {
        self.body = Some(body.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_order_is_priority() {
        assert!(Owner::Recovery > Owner::Manual);
        assert!(Owner::Manual > Owner::Schedule);
        assert!(Owner::Schedule > Owner::Rotation);
        assert!(Owner::Rotation > Owner::Autopilot);
        assert!(Owner::Autopilot > Owner::AdaptiveRetry);
    }

    /// AT-12-002: a lab build's stored per-server choice loads as `Auto` without the lab feature.
    #[test]
    fn unknown_engine_choice_reads_as_auto() {
        let pref: EnginePref = serde_json::from_str("\"xray\"").unwrap();
        assert_eq!(pref, EnginePref::Xray);
        let stored: EnginePref = serde_json::from_str("\"mihomo\"").unwrap();
        #[cfg(not(feature = "lab"))]
        assert_eq!(stored, EnginePref::Auto);
        #[cfg(feature = "lab")]
        assert_eq!(stored, EnginePref::Mihomo);
        let unknown: EnginePref = serde_json::from_str("\"future-engine\"").unwrap();
        assert_eq!(unknown, EnginePref::Auto);
    }

    #[test]
    fn wire_names() {
        assert_eq!(
            serde_json::to_string(&EnginePref::SingBox).unwrap(),
            "\"sing-box\""
        );
        assert_eq!(
            serde_json::to_string(&Owner::AdaptiveRetry).unwrap(),
            "\"adaptive-retry\""
        );
        assert_eq!(
            serde_json::to_string(&Verdict::NotChecked).unwrap(),
            "\"not-checked\""
        );
        assert_eq!(
            format!(
                "{:?}",
                Creds {
                    user: "u".into(),
                    pass: "p".into()
                }
            ),
            "Creds(..)"
        );
    }
}
