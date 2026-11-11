//! Settings, exceptions, connection state, status and errors of the protection.
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use vpnte_base::types::{KillSwitchLevel, UnixMs};
use vpnte_base::{AppError, ErrorKind, Msg};

use super::engine::WfpError;
use super::fwpolicy::FwProfileBlock;
use super::validate::{self, ValidationError};

/// Protection settings as the user chose them (one `level` field, no legacy boolean).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ProtectionSettings {
    pub level: KillSwitchLevel,
    /// Blocks non-TUN IPv6 and DNS during a TUN session even with the kill switch off.
    pub leak_protection: bool,
    /// Strict while no session exists: DNS to LAN resolvers stays possible (captive portals,
    /// router DNS). During a session non-TUN DNS is always blocked (review D1 / D5).
    pub public_wifi_compat: bool,
    /// LAN, link-local and multicast stay reachable while blocking (printers, NAS, mDNS).
    pub allow_lan: bool,
    pub exceptions: Vec<KillSwitchException>,
}

impl Default for ProtectionSettings {
    fn default() -> Self {
        Self {
            level: KillSwitchLevel::Off,
            leak_protection: true,
            public_wifi_compat: true,
            allow_lan: true,
            exceptions: Vec::new(),
        }
    }
}

impl ProtectionSettings {
    /// The plain switches of these settings.
    pub fn toggles(&self) -> Toggles {
        Toggles {
            leak_protection: self.leak_protection,
            public_wifi_compat: self.public_wifi_compat,
            allow_lan: self.allow_lan,
        }
    }
}

/// The switches `Protection::update_settings` changes; level and exceptions have their own
/// operations because their persistence order matters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Toggles {
    pub leak_protection: bool,
    pub public_wifi_compat: bool,
    pub allow_lan: bool,
}

/// Kind of a user exception (wire names of the old store: `app`, `ip`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExceptionKind {
    App,
    Ip,
}

/// What a user exception lets through while blocking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExceptionTarget {
    /// Canonical local `.exe` path.
    App(PathBuf),
    /// Remote network, kept as entered (host bits too); installed with host bits masked.
    Ip(IpNet),
}

impl ExceptionTarget {
    /// The kind of this target.
    pub fn kind(&self) -> ExceptionKind {
        match self {
            ExceptionTarget::App(_) => ExceptionKind::App,
            ExceptionTarget::Ip(_) => ExceptionKind::Ip,
        }
    }

    /// Canonical text: the path, or the address with its prefix (a full-length prefix is left out).
    pub fn value(&self) -> String {
        match self {
            ExceptionTarget::App(path) => path.display().to_string(),
            ExceptionTarget::Ip(net) if net.prefix_len() == net.max_prefix_len() => {
                net.addr().to_string()
            }
            ExceptionTarget::Ip(net) => net.to_string(),
        }
    }

    /// Two exceptions are equivalent when they install the same filter: same kind and the same
    /// case-folded path or masked network.
    pub(crate) fn identity(&self) -> (ExceptionKind, String) {
        match self {
            ExceptionTarget::App(path) => (
                ExceptionKind::App,
                path.display().to_string().to_lowercase(),
            ),
            ExceptionTarget::Ip(net) => (ExceptionKind::Ip, net.trunc().to_string()),
        }
    }
}

/// One user exception, stored as `{id, type, value, label}` (the old store shape).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawException", into = "RawException")]
pub struct KillSwitchException {
    /// Stable reference for the UI (the old app used UUID strings).
    pub id: String,
    pub target: ExceptionTarget,
    /// Trimmed user label, 1..=200 characters.
    pub label: String,
}

#[derive(Serialize, Deserialize)]
struct RawException {
    id: String,
    #[serde(rename = "type")]
    kind: ExceptionKind,
    value: String,
    label: String,
}

impl TryFrom<RawException> for KillSwitchException {
    type Error = ValidationError;
    fn try_from(raw: RawException) -> Result<Self, ValidationError> {
        let target = match raw.kind {
            ExceptionKind::Ip => ExceptionTarget::Ip(validate::parse_ip_or_cidr(&raw.value)?),
            ExceptionKind::App => ExceptionTarget::App(PathBuf::from(raw.value)),
        };
        Ok(Self {
            id: raw.id,
            target,
            label: raw.label,
        })
    }
}

impl From<KillSwitchException> for RawException {
    fn from(e: KillSwitchException) -> Self {
        Self {
            id: e.id,
            kind: e.target.kind(),
            value: e.target.value(),
            label: e.label,
        }
    }
}

/// Engine executables permitted in every TUN session (and persistently in `strict`). Use the
/// canonical image paths the engines are launched from: app IDs are path based.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EnginePaths {
    pub singbox: PathBuf,
    pub xray: Option<PathBuf>,
    pub external_proxy: Option<PathBuf>,
}

impl EnginePaths {
    pub(crate) fn all(&self) -> impl Iterator<Item = &Path> {
        std::iter::once(self.singbox.as_path())
            .chain(self.xray.as_deref())
            .chain(self.external_proxy.as_deref())
    }
}

/// Where the TUN session is, as reported by the tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Conn {
    #[default]
    Disconnected,
    /// `connect_begin` ran; engines may be starting, no TUN yet.
    Connecting,
    /// The TUN is up.
    Up,
    /// The TUN went away unexpectedly; blocks stay until the user disconnects.
    Dropped,
}

impl Conn {
    pub(crate) fn in_session(self) -> bool {
        self != Conn::Disconnected
    }
}

/// What the kill switch is doing right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KillSwitchState {
    Off,
    /// `standard`, no session: filters go up at the next connect.
    Armed,
    /// Filters and a tunnel.
    Engaged,
    /// Filters without a tunnel: traffic outside the VPN is blocked.
    Blocking,
    /// The last change could not be applied (see `ProtectionStatus::last_error`).
    Failed,
}

/// Status for the UI, built from a fresh enumeration of our filters.
#[derive(Debug, Clone)]
pub struct ProtectionStatus {
    pub level: KillSwitchLevel,
    pub conn: Conn,
    pub kill_switch: KillSwitchState,
    /// Why the last apply failed (the previous filters stayed in place).
    pub last_error: Option<ProtectionError>,
    pub leak_protection_active: bool,
    /// Our dynamic filters counted right now; `None` = could not be read.
    pub dynamic_filters: Option<u32>,
    /// Our persistent filters counted right now; `None` = could not be read.
    pub persistent_filters: Option<u32>,
    /// Weight BFE actually gave our sublayer (it may be below the requested `0xFFFF`).
    pub sublayer_weight: Option<u16>,
    /// `None` until an engine call was attempted.
    pub bfe_running: Option<bool>,
    /// Last time a fresh enumeration matched what we installed.
    pub last_verified: Option<UnixMs>,
    /// Ids of app exceptions skipped by the last apply because their file is missing.
    pub skipped_exceptions: Vec<String>,
    /// Enabled Windows Firewall profiles whose outbound default is Block (they beat our soft
    /// permits, so engines cannot connect); `None` = could not be read.
    pub windows_firewall_outbound_block: Option<Vec<FwProfileBlock>>,
    /// A Hyper-V virtual switch exists: its guests (WSL 2, Sandbox, Docker, VMs) bypass our
    /// filters; `None` = could not be read.
    pub hyperv_switch_present: Option<bool>,
}

impl ProtectionStatus {
    /// The warning to show when an active Windows Firewall profile blocks outbound by default.
    pub fn firewall_warning(&self) -> Option<Msg> {
        let blocking = self
            .windows_firewall_outbound_block
            .iter()
            .flatten()
            .any(|b| b.active);
        blocking.then(|| Msg::new("winnet.wfp.status.firewallOutboundBlock"))
    }

    /// The warning to show while the kill switch is on and Hyper-V guests could leak past it.
    pub fn hyperv_warning(&self) -> Option<Msg> {
        let exposed =
            self.level != KillSwitchLevel::Off && self.hyperv_switch_present == Some(true);
        exposed.then(|| Msg::new("winnet.wfp.status.hypervUnfiltered"))
    }
}

/// Which change could neither be saved nor rolled back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unconfirmed {
    Level,
    Exceptions,
}

/// Why a protection operation failed.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ProtectionError {
    /// The base filtering engine cannot be reached (RPC failure, e.g. 1753 after a BFE restart).
    #[error("base filtering engine unavailable ({code:#x})")]
    BfeUnavailable { code: u32 },
    /// Not elevated, or BFE refused the change.
    #[error("access denied by the base filtering engine")]
    AccessDenied,
    /// A program that must be permitted does not exist.
    #[error("program not found: {}", .0.display())]
    EngineMissing(PathBuf),
    #[error("WFP {op} failed with {code:#010x}")]
    Wfp { op: &'static str, code: u32 },
    #[error(transparent)]
    Validation(#[from] ValidationError),
    #[error("protection settings not saved: {0}")]
    Persist(Arc<AppError>),
    /// Maintenance actions are refused while a TUN session exists.
    #[error("not possible while a VPN session is active")]
    SessionActive,
    /// Saving failed and restoring the previous filters failed too.
    #[error("{0:?} change not confirmed: not saved and the previous filters could not be restored")]
    Unconfirmed(Unconfirmed),
}

impl ProtectionError {
    /// Error category for callers and the UI.
    pub fn kind(&self) -> ErrorKind {
        match self {
            ProtectionError::AccessDenied => ErrorKind::Permission,
            ProtectionError::Validation(_) => ErrorKind::Validation,
            ProtectionError::SessionActive => ErrorKind::Conflict,
            ProtectionError::Persist(e) => e.kind,
            _ => ErrorKind::Internal,
        }
    }

    /// The user-facing message.
    pub fn msg(&self) -> Msg {
        match self {
            ProtectionError::BfeUnavailable { .. } => Msg::new("winnet.wfp.error.bfeUnavailable"),
            ProtectionError::AccessDenied => Msg::new("winnet.wfp.error.accessDenied"),
            ProtectionError::EngineMissing(path) => Msg::new("winnet.wfp.error.programMissing")
                .arg(
                    "name",
                    path.file_name().map_or_else(
                        || path.display().to_string(),
                        |n| n.to_string_lossy().into_owned(),
                    ),
                ),
            ProtectionError::Wfp { code, .. } => {
                Msg::new("winnet.wfp.error.wfp").arg("code", format!("{code:#010x}"))
            }
            ProtectionError::Validation(v) => v.msg(),
            ProtectionError::Persist(_) => Msg::new("winnet.wfp.error.persist"),
            ProtectionError::SessionActive => Msg::new("winnet.wfp.error.sessionActive"),
            ProtectionError::Unconfirmed(Unconfirmed::Level) => {
                Msg::new("winnet.wfp.error.levelUnconfirmed")
            }
            ProtectionError::Unconfirmed(Unconfirmed::Exceptions) => {
                Msg::new("winnet.wfp.error.exceptionsUnconfirmed")
            }
        }
    }
}

impl From<ProtectionError> for AppError {
    fn from(e: ProtectionError) -> Self {
        AppError::msg(e.kind(), e.msg()).with_source(e)
    }
}

/// A rejected exception as the UI's action error: `Validation` with the field message.
impl From<ValidationError> for AppError {
    fn from(e: ValidationError) -> Self {
        ProtectionError::Validation(e).into()
    }
}

impl From<WfpError> for ProtectionError {
    fn from(e: WfpError) -> Self {
        if e.is_access_denied() {
            ProtectionError::AccessDenied
        } else if e.is_rpc_failure() {
            ProtectionError::BfeUnavailable { code: e.code }
        } else {
            ProtectionError::Wfp {
                op: e.op,
                code: e.code,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Review D3: the Hyper-V warning shows only with the kill switch on and a switch present.
    #[test]
    fn hyperv_warning_needs_the_kill_switch_and_a_switch() {
        let status = |level, hyperv_switch_present| ProtectionStatus {
            level,
            conn: Conn::Disconnected,
            kill_switch: KillSwitchState::Off,
            last_error: None,
            leak_protection_active: false,
            dynamic_filters: None,
            persistent_filters: None,
            sublayer_weight: None,
            bfe_running: None,
            last_verified: None,
            skipped_exceptions: Vec::new(),
            windows_firewall_outbound_block: None,
            hyperv_switch_present,
        };
        let warn = status(KillSwitchLevel::Standard, Some(true)).hyperv_warning();
        assert_eq!(
            warn.map(|m| m.key.into_owned()).as_deref(),
            Some("winnet.wfp.status.hypervUnfiltered")
        );
        assert!(
            status(KillSwitchLevel::Off, Some(true))
                .hyperv_warning()
                .is_none()
        );
        assert!(
            status(KillSwitchLevel::Strict, None)
                .hyperv_warning()
                .is_none()
        );
    }

    /// A validation error reaches the UI as `Validation` with the field message.
    #[test]
    fn validation_errors_convert_to_app_errors() {
        let e = AppError::from(ValidationError::InvalidIp);
        assert_eq!(e.kind, ErrorKind::Validation);
        assert_eq!(e.user_msg().key, "winnet.wfp.exception.invalidIp");
    }

    /// The stored shape is the old store's: `{id, type, value, label}`; IP values are validated
    /// on load, defaults are Off / leak protection on / public Wi-Fi compatible / LAN allowed.
    #[test]
    fn settings_wire_shape() {
        let s: ProtectionSettings = serde_json::from_str(
            r#"{"level":"strict","exceptions":[{"id":"7","type":"ip","value":"2001:DB8::/32","label":"Lab"},
                {"id":"8","type":"app","value":"C:\\Tools\\a.exe","label":"Tool"}]}"#,
        )
        .unwrap();
        assert_eq!(s.level, KillSwitchLevel::Strict);
        assert!(s.leak_protection && s.public_wifi_compat && s.allow_lan);
        assert_eq!(s.exceptions[0].target.value(), "2001:db8::/32");
        assert_eq!(
            s.exceptions[1].target,
            ExceptionTarget::App(PathBuf::from(r"C:\Tools\a.exe"))
        );
        let json = serde_json::to_value(&s).unwrap();
        assert_eq!(json["exceptions"][0]["type"], "ip");
        assert_eq!(json["exceptions"][0]["value"], "2001:db8::/32");
        assert_eq!(json["leakProtection"], true);
        let bad = r#"{"exceptions":[{"id":"1","type":"ip","value":"0.0.0.0/0","label":"x"}]}"#;
        assert!(serde_json::from_str::<ProtectionSettings>(bad).is_err());
        assert_eq!(ProtectionSettings::default().level, KillSwitchLevel::Off);
    }

    /// Error categories and user messages: elevation is `Permission`, BFE RPC loss is its own
    /// message, the user never sees the technical text.
    #[test]
    fn errors_map_to_kinds_and_keys() {
        let denied = ProtectionError::from(WfpError {
            op: "FwpmEngineOpen0",
            code: 5,
        });
        assert_eq!(
            (denied.kind(), denied.msg().key.as_ref()),
            (ErrorKind::Permission, "winnet.wfp.error.accessDenied")
        );
        let lost = ProtectionError::from(WfpError {
            op: "FwpmFilterAdd0",
            code: 1753,
        });
        assert!(matches!(
            lost,
            ProtectionError::BfeUnavailable { code: 1753 }
        ));
        let other = ProtectionError::from(WfpError {
            op: "FwpmFilterAdd0",
            code: 0x8032_0004,
        });
        assert_eq!(other.msg().args[0].1, "0x80320004");
        let app: AppError = other.into();
        assert_eq!(
            (app.kind, app.user_msg().key.as_ref()),
            (ErrorKind::Internal, "winnet.wfp.error.wfp")
        );
    }
}
