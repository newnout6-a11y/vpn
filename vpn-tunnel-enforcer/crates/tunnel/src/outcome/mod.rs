//! Why a connection session ended: a fine-grained kind, a headline for the user and the evidence
//! behind it (lifecycle-app §3.5, §3.22).
//!
//! The headline is a [`Msg`] chosen from the kind and the evidence when the row is written, so it
//! renders in the language the user has when reading the history. Electron-era rows carry Russian
//! text instead; it is kept as a [verbatim](verbatim) message.
use std::borrow::Cow;
use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use vpnte_base::Msg;
use vpnte_base::i18n::Lang;
use vpnte_base::types::{AdaptiveMode, Engine, OutboundFault};

/// Key of a message that is shown as written (old records, free text from the runtime).
pub const VERBATIM: &str = "tunnel.outcome.verbatim";

/// Free text as a message (rendered unchanged in every language).
pub fn verbatim(text: impl Into<String>) -> Msg {
    Msg::new(VERBATIM).arg("text", text.into())
}

/// The text of a verbatim message, `None` for a translated one.
pub fn verbatim_text(msg: &Msg) -> Option<&str> {
    (msg.key == VERBATIM).then(|| {
        msg.args
            .iter()
            .find(|(name, _)| name == "text")
            .map_or("", |(_, text)| text.as_str())
    })
}

/// Renders a history message in `lang`; verbatim text never depends on the loaded catalogs.
pub fn render(msg: &Msg, lang: Lang) -> String {
    match verbatim_text(msg) {
        Some(text) => text.to_owned(),
        None => msg.render(lang),
    }
}

/// Why a session ended (15 kinds; wire names are the Electron ones).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OutcomeKind {
    UserStop,
    AppQuit,
    ServerSwitch,
    Rotation,
    Schedule,
    ProxyUnreachable,
    ServerRejectedKey,
    ServerDown,
    SingboxCrash,
    Killswitch,
    TunSetupFailed,
    NetworkLost,
    SystemSleep,
    StartFailed,
    Unknown,
}

impl OutcomeKind {
    /// Every kind, in the Electron order (intentional, node / connectivity, never came up).
    pub const ALL: [OutcomeKind; 15] = [
        OutcomeKind::UserStop,
        OutcomeKind::AppQuit,
        OutcomeKind::ServerSwitch,
        OutcomeKind::Rotation,
        OutcomeKind::Schedule,
        OutcomeKind::ProxyUnreachable,
        OutcomeKind::ServerRejectedKey,
        OutcomeKind::ServerDown,
        OutcomeKind::SingboxCrash,
        OutcomeKind::Killswitch,
        OutcomeKind::TunSetupFailed,
        OutcomeKind::NetworkLost,
        OutcomeKind::SystemSleep,
        OutcomeKind::StartFailed,
        OutcomeKind::Unknown,
    ];

    /// Wire name (`user-stop`, `singbox-crash`, …), as in the CSV export.
    pub fn as_str(self) -> &'static str {
        match self {
            OutcomeKind::UserStop => "user-stop",
            OutcomeKind::AppQuit => "app-quit",
            OutcomeKind::ServerSwitch => "server-switch",
            OutcomeKind::Rotation => "rotation",
            OutcomeKind::Schedule => "schedule",
            OutcomeKind::ProxyUnreachable => "proxy-unreachable",
            OutcomeKind::ServerRejectedKey => "server-rejected-key",
            OutcomeKind::ServerDown => "server-down",
            OutcomeKind::SingboxCrash => "singbox-crash",
            OutcomeKind::Killswitch => "killswitch",
            OutcomeKind::TunSetupFailed => "tun-setup-failed",
            OutcomeKind::NetworkLost => "network-lost",
            OutcomeKind::SystemSleep => "system-sleep",
            OutcomeKind::StartFailed => "start-failed",
            OutcomeKind::Unknown => "unknown",
        }
    }

    /// The coarse bucket the filter chips and the CSV `disconnectReason` column use.
    pub fn bucket(self) -> DisconnectReason {
        match self {
            OutcomeKind::UserStop | OutcomeKind::AppQuit | OutcomeKind::ServerSwitch => {
                DisconnectReason::User
            }
            OutcomeKind::Rotation => DisconnectReason::Rotation,
            OutcomeKind::Schedule => DisconnectReason::Schedule,
            OutcomeKind::Killswitch => DisconnectReason::Crash,
            OutcomeKind::ProxyUnreachable
            | OutcomeKind::ServerRejectedKey
            | OutcomeKind::ServerDown
            | OutcomeKind::SingboxCrash
            | OutcomeKind::TunSetupFailed
            | OutcomeKind::NetworkLost
            | OutcomeKind::SystemSleep
            | OutcomeKind::StartFailed
            | OutcomeKind::Unknown => DisconnectReason::Error,
        }
    }

    /// Confidence in the cause; never an attestation that the user was protected.
    pub fn confidence(self) -> Confidence {
        match self {
            OutcomeKind::Unknown => Confidence::Indeterminate,
            OutcomeKind::UserStop
            | OutcomeKind::AppQuit
            | OutcomeKind::ServerSwitch
            | OutcomeKind::Rotation
            | OutcomeKind::Schedule
            | OutcomeKind::StartFailed => Confidence::Observed,
            _ => Confidence::Inferred,
        }
    }

    /// The tunnel never came up: such rows are not connections and stay out of the statistics.
    pub fn never_connected(self) -> bool {
        matches!(self, OutcomeKind::StartFailed | OutcomeKind::TunSetupFailed)
    }
}

/// Coarse five-bucket reason of the Electron history (filter chips, CSV).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DisconnectReason {
    User,
    Error,
    Rotation,
    Schedule,
    Crash,
}

impl DisconnectReason {
    /// Wire name, as in the CSV export.
    pub fn as_str(self) -> &'static str {
        match self {
            DisconnectReason::User => "user",
            DisconnectReason::Error => "error",
            DisconnectReason::Rotation => "rotation",
            DisconnectReason::Schedule => "schedule",
            DisconnectReason::Crash => "crash",
        }
    }
}

/// How sure the recorded cause is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Observed,
    Inferred,
    Indeterminate,
}

impl Confidence {
    /// Wire name, as in the CSV export.
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::Observed => "observed",
            Confidence::Inferred => "inferred",
            Confidence::Indeterminate => "indeterminate",
        }
    }
}

/// Adaptive-bypass mode during the session; `ExternalManaged` exists only in Electron-era rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AdaptiveContext {
    Baseline,
    TlsCompatibility,
    MtuCompatibility,
    ExternalManaged,
}

impl From<AdaptiveMode> for AdaptiveContext {
    fn from(mode: AdaptiveMode) -> Self {
        match mode {
            AdaptiveMode::Baseline => AdaptiveContext::Baseline,
            AdaptiveMode::TlsCompatibility => AdaptiveContext::TlsCompatibility,
            AdaptiveMode::MtuCompatibility => AdaptiveContext::MtuCompatibility,
        }
    }
}

/// What changed in the physical network under the tunnel (from the adapter-count change).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NetworkTransition {
    AdapterRemoved,
    AdapterAdded,
    AddressChanged,
    /// Text of an Electron-era record that is not one of the three phrases it wrote.
    Text(String),
}

impl NetworkTransition {
    /// Wire form: a token, or the old free text.
    pub fn as_str(&self) -> &str {
        match self {
            NetworkTransition::AdapterRemoved => "adapter-removed",
            NetworkTransition::AdapterAdded => "adapter-added",
            NetworkTransition::AddressChanged => "address-changed",
            NetworkTransition::Text(text) => text,
        }
    }

    /// Reads a token or an old record; the three Russian phrases the old app wrote become typed.
    pub fn parse(text: &str) -> Self {
        match text {
            "adapter-removed" | "адаптер отключился" => {
                NetworkTransition::AdapterRemoved
            }
            "adapter-added" | "подключился новый адаптер" => {
                NetworkTransition::AdapterAdded
            }
            "address-changed" | "сменился IP-адрес" => {
                NetworkTransition::AddressChanged
            }
            other => NetworkTransition::Text(other.to_owned()),
        }
    }
}

impl Serialize for NetworkTransition {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for NetworkTransition {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d).map(|text| NetworkTransition::parse(&text))
    }
}

/// Facts collected when a session ended. Every field is optional; empty text never counts as a fact.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub singbox_exit_code: Option<i64>,
    /// Last engine output lines (technical, English).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub singbox_stderr_tail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbound_fault: Option<OutboundFault>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adaptive_mode: Option<AdaptiveContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adaptive_attempts: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_restart_attempts: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kill_switch_engaged: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leak_detected_during_session: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_transition: Option<NetworkTransition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress_country: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_engine: Option<Engine>,
    /// What the user can do about a failed start.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "de::opt_msg_or_text"
    )]
    pub hint: Option<Msg>,
}

impl Evidence {
    /// True when no fact survived.
    pub fn is_empty(&self) -> bool {
        *self == Evidence::default()
    }

    /// Drops blank text (old rule: `''` is not evidence, while `false` and `0` are) and masks
    /// secrets in the engine output: it can quote a share link, a UUID or a key, and the history
    /// file is plain JSON.
    #[must_use]
    pub fn normalized(mut self) -> Self {
        fn text(v: &mut Option<String>) {
            if v.as_deref().is_some_and(|s| s.trim().is_empty()) {
                *v = None;
            }
        }
        if let Some(tail) = self.singbox_stderr_tail.as_mut()
            && let Cow::Owned(masked) = vpnte_core::redact::text(tail)
        {
            *tail = masked;
        }
        text(&mut self.singbox_stderr_tail);
        text(&mut self.egress_country);
        text(&mut self.egress_ip);
        if self
            .network_transition
            .as_ref()
            .is_some_and(|t| t.as_str().trim().is_empty())
        {
            self.network_transition = None;
        }
        if self
            .hint
            .as_ref()
            .and_then(verbatim_text)
            .is_some_and(|t| t.trim().is_empty())
        {
            self.hint = None;
        }
        self
    }
}

/// One connection-history verdict: what happened, the sentence for the user, and why we think so.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionOutcome {
    pub kind: OutcomeKind,
    #[serde(deserialize_with = "de::msg_or_text")]
    pub headline: Msg,
    /// `null` is invalid here (old reader contract), absent means "no evidence".
    #[serde(default, skip_serializing_if = "Evidence::is_empty")]
    pub evidence: Evidence,
}

impl SessionOutcome {
    /// Outcome whose headline is composed from the kind and the evidence.
    pub fn new(kind: OutcomeKind, evidence: Evidence) -> Self {
        let evidence = evidence.normalized();
        Self {
            kind,
            headline: headline(kind, &evidence),
            evidence,
        }
    }

    /// Outcome with a given headline (the runtime's last warning, a lifecycle sentence). Blank
    /// verbatim text falls back to the composed headline; other text is trimmed.
    pub fn with_headline(kind: OutcomeKind, evidence: Evidence, headline: Msg) -> Self {
        let mut outcome = Self::new(kind, evidence);
        match verbatim_text(&headline).map(str::trim) {
            Some("") => {}
            Some(text) => outcome.headline = verbatim(text),
            None => outcome.headline = headline,
        }
        outcome
    }

    /// A start that never brought the tunnel up: Wintun / route / DNS bring-up failures are
    /// `TunSetupFailed`, everything else `StartFailed` (lifecycle L-14). `hint` says what to do.
    pub fn start_failure(tun_setup: bool, hint: Option<Msg>, evidence: Evidence) -> Self {
        let kind = if tun_setup {
            OutcomeKind::TunSetupFailed
        } else {
            OutcomeKind::StartFailed
        };
        Self::new(kind, Evidence { hint, ..evidence })
    }
}

macro_rules! key {
    ($name:literal) => {
        concat!("tunnel.outcome.headline.", $name)
    };
}

/// The sentence for `kind`, deterministic in the evidence (lifecycle §3.22).
///
/// A fault is named only where the classifier pairs it with the kind (a fault decides the kind
/// first): REALITY / TLS for a rejected key, no answer for a node that is down; any other pair gets
/// the plain sentence and the fault stays in the evidence. A failed start with a translated hint
/// shows the hint itself (it already says what failed and what to do; messages cannot nest), while
/// hint text is quoted as before.
pub fn headline(kind: OutcomeKind, evidence: &Evidence) -> Msg {
    use OutboundFault as F;
    let restarts = evidence.auto_restart_attempts.unwrap_or(0);
    match kind {
        OutcomeKind::UserStop => Msg::new(key!("userStop")),
        OutcomeKind::AppQuit => Msg::new(key!("appQuit")),
        OutcomeKind::ServerSwitch => Msg::new(key!("serverSwitch")),
        OutcomeKind::Rotation => Msg::new(key!("rotation")),
        OutcomeKind::Schedule => Msg::new(key!("schedule")),
        OutcomeKind::ProxyUnreachable => Msg::new(key!("proxyUnreachable")),
        OutcomeKind::ServerRejectedKey => Msg::new(match evidence.outbound_fault {
            Some(F::RealityKeyMismatch) => key!("serverRejectedKey.realityKeyMismatch"),
            Some(F::TlsHandshakeFailed) => key!("serverRejectedKey.tlsHandshakeFailed"),
            _ => key!("serverRejectedKey.plain"),
        }),
        OutcomeKind::ServerDown => Msg::new(match evidence.outbound_fault {
            Some(F::UpstreamUnreachable) => key!("serverDown.upstreamUnreachable"),
            _ => key!("serverDown.plain"),
        }),
        OutcomeKind::SingboxCrash => match (evidence.singbox_exit_code, restarts) {
            (None, 0) => Msg::new(key!("singboxCrash.plain")),
            (Some(code), 0) => Msg::new(key!("singboxCrash.code")).arg("code", code),
            (None, n) => Msg::new(key!("singboxCrash.restarts")).arg("count", n),
            (Some(code), n) => Msg::new(key!("singboxCrash.codeRestarts"))
                .arg("code", code)
                .arg("count", n),
        },
        OutcomeKind::Killswitch if restarts > 0 => {
            Msg::new(key!("killswitch.restarts")).arg("count", restarts)
        }
        OutcomeKind::Killswitch => Msg::new(key!("killswitch.plain")),
        OutcomeKind::TunSetupFailed => Msg::new(key!("tunSetupFailed")),
        OutcomeKind::NetworkLost => match &evidence.network_transition {
            None => Msg::new(key!("networkLost.plain")),
            Some(NetworkTransition::AdapterRemoved) => Msg::new(key!("networkLost.adapterRemoved")),
            Some(NetworkTransition::AdapterAdded) => Msg::new(key!("networkLost.adapterAdded")),
            Some(NetworkTransition::AddressChanged) => Msg::new(key!("networkLost.addressChanged")),
            Some(NetworkTransition::Text(text)) => {
                Msg::new(key!("networkLost.text")).arg("transition", text)
            }
        },
        OutcomeKind::SystemSleep => Msg::new(key!("systemSleep")),
        OutcomeKind::StartFailed => match &evidence.hint {
            None => Msg::new(key!("startFailed.plain")),
            Some(hint) => match verbatim_text(hint) {
                Some(text) => Msg::new(key!("startFailed.hint")).arg("hint", text),
                None => hint.clone(),
            },
        },
        OutcomeKind::Unknown => Msg::new(key!("unknown")),
    }
}

/// Serde readers shared with the history document.
pub(crate) mod de {
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer};
    use serde_json::Value;
    use vpnte_base::Msg;

    /// A message, or the plain text an Electron-era record stored in its place.
    pub fn msg_or_text<'de, D: Deserializer<'de>>(d: D) -> Result<Msg, D::Error> {
        opt_msg_or_text(d)?.ok_or_else(|| D::Error::custom("expected a message or text"))
    }

    /// Like [`msg_or_text`]; `null` reads as absent.
    pub fn opt_msg_or_text<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Msg>, D::Error> {
        match Value::deserialize(d)? {
            Value::Null => Ok(None),
            Value::String(text) => Ok(Some(super::verbatim(text))),
            value @ Value::Object(_) => Msg::deserialize(value).map(Some).map_err(D::Error::custom),
            _ => Err(D::Error::custom("expected a message or text")),
        }
    }
}

/// A resume this recent explains everything that broke after it.
const SLEEP_WINDOW: Duration = Duration::from_secs(25);
/// A network change this recent explains a dropped tunnel.
const NETWORK_WINDOW: Duration = Duration::from_secs(15);
/// An engine exit this recent (and not asked for) is the crash.
const EXIT_WINDOW: Duration = Duration::from_secs(30);

/// How the engine of this session exited.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EngineExit {
    /// Time since the exit.
    pub since: Duration,
    /// We stopped it ourselves.
    pub user_initiated: bool,
    pub code: Option<i64>,
    /// Last output lines, already redacted by the engine supervisor.
    pub stderr_tail: Option<String>,
}

/// What the lifecycle knows when a session ends without being asked to. Capture the traffic
/// counters before anything is stopped (stopping the monitor zeroes them).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct EndSignals {
    /// Time since the last resume from sleep / screen unlock.
    pub since_resume: Option<Duration>,
    /// Time since the last change of the physical network.
    pub since_network_change: Option<Duration>,
    /// Upstream fault read from the engine log (`None` also when reading failed).
    pub outbound_fault: Option<OutboundFault>,
    /// The tunnel ended with the kill switch holding traffic.
    pub kill_switch_active: bool,
    /// The runtime's last warning says the proxy stopped answering (the old app matched the
    /// warning text against `прокси .*не отвеч|proxy .*(unreachable|not answ)|не отвечает`).
    pub proxy_unreachable: bool,
    /// The runtime's last warning, if any; it becomes the headline of an otherwise unknown end.
    pub warning: Option<Msg>,
    /// Automatic restarts the runtime made before giving up.
    pub restart_attempts: u32,
    pub engine_exit: Option<EngineExit>,
}

/// The kind of an unexpected end; the first matching rule wins (lifecycle §3.5).
pub fn classify_end(s: &EndSignals) -> OutcomeKind {
    let within = |since: Option<Duration>, window: Duration| since.is_some_and(|d| d < window);
    let exit_is_crash = s
        .engine_exit
        .as_ref()
        .is_some_and(|e| !e.user_initiated && e.since < EXIT_WINDOW);
    if within(s.since_resume, SLEEP_WINDOW) {
        OutcomeKind::SystemSleep
    } else if matches!(
        s.outbound_fault,
        Some(OutboundFault::RealityKeyMismatch | OutboundFault::TlsHandshakeFailed)
    ) {
        OutcomeKind::ServerRejectedKey
    } else if s.outbound_fault == Some(OutboundFault::UpstreamUnreachable) {
        OutcomeKind::ServerDown
    } else if within(s.since_network_change, NETWORK_WINDOW) {
        OutcomeKind::NetworkLost
    } else if s.kill_switch_active {
        OutcomeKind::Killswitch
    } else if s.proxy_unreachable {
        OutcomeKind::ProxyUnreachable
    } else if exit_is_crash {
        OutcomeKind::SingboxCrash
    } else {
        OutcomeKind::Unknown
    }
}

/// The outcome of an unexpected end. `session` carries the session facts (egress IP / country,
/// engine, adaptive mode and attempts, leak seen, last network transition); the engine exit, the
/// fault, the kill-switch state and the restart count are added from `signals`.
pub fn unexpected_end(signals: &EndSignals, session: Evidence) -> SessionOutcome {
    let kind = classify_end(signals);
    let exit = signals.engine_exit.as_ref();
    let evidence = Evidence {
        singbox_exit_code: exit.and_then(|e| e.code),
        singbox_stderr_tail: exit.and_then(|e| e.stderr_tail.clone()),
        outbound_fault: signals.outbound_fault,
        kill_switch_engaged: Some(signals.kill_switch_active),
        auto_restart_attempts: (signals.restart_attempts > 0).then_some(signals.restart_attempts),
        // The old app wrote `attempts || null` and `leak || null`: zero / false is not a fact here.
        adaptive_attempts: session.adaptive_attempts.filter(|&n| n > 0),
        leak_detected_during_session: session.leak_detected_during_session.filter(|&seen| seen),
        ..session
    };
    match (kind, &signals.warning) {
        (OutcomeKind::Unknown, Some(warning)) => {
            SessionOutcome::with_headline(kind, evidence, warning.clone())
        }
        _ => SessionOutcome::new(kind, evidence),
    }
}

/// Kind of a protected restart that moved the session to another node, from the runtime's restart
/// reason (`profile rotation to <name>`, `server switch`); other restarts keep the session.
pub fn node_switch_kind(reason: &str) -> Option<OutcomeKind> {
    const ROTATION: &str = "profile rotation to ";
    let is_rotation = reason
        .get(..ROTATION.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(ROTATION));
    if is_rotation {
        Some(OutcomeKind::Rotation)
    } else if reason.eq_ignore_ascii_case("server switch") {
        Some(OutcomeKind::ServerSwitch)
    } else {
        None
    }
}

#[cfg(test)]
pub(crate) mod tests;
