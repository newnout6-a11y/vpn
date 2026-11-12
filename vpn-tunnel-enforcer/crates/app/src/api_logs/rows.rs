//! History rows: `vpnte_tunnel::history::Entry` -> the page's `SessionRow` (display data only).
use vpnte_base::Msg;
use vpnte_base::i18n::Lang;
use vpnte_tunnel::history::{Entry, SessionMode};
use vpnte_tunnel::outcome::{self, AdaptiveContext, SessionOutcome};
use vpnte_ui::logs::{DisconnectReason, Evidence, Mode, Outcome, OutcomeKind, SessionRow, Text};

/// One stored session as the page shows it. Messages stay messages (re-rendered on a language
/// switch); verbatim text of old rows and engine output stays text.
pub fn row(e: &Entry, lang: Lang) -> SessionRow {
    SessionRow {
        id: e.id.clone(),
        started_at: e.started_at,
        ended_at: e.ended_at,
        duration_ms: e.duration_ms,
        profile_name: e.profile_name.clone(),
        mode: match e.mode {
            SessionMode::Hard => Mode::Hard,
            SessionMode::Soft => Mode::Soft,
            SessionMode::Direct => Mode::Direct,
        },
        bytes_down: e.bytes_down,
        bytes_up: e.bytes_up,
        reason: reason(e.disconnect_reason),
        // The technical message is plain text on the page (also what the CSV carries).
        error_message: e.error_message.as_ref().map(|m| outcome::render(m, lang)),
        outcome: e.outcome.as_ref().map(session_outcome),
    }
}

fn reason(r: outcome::DisconnectReason) -> DisconnectReason {
    match r {
        outcome::DisconnectReason::User => DisconnectReason::User,
        outcome::DisconnectReason::Error => DisconnectReason::Error,
        outcome::DisconnectReason::Rotation => DisconnectReason::Rotation,
        outcome::DisconnectReason::Schedule => DisconnectReason::Schedule,
        outcome::DisconnectReason::Crash => DisconnectReason::Crash,
    }
}

fn session_outcome(o: &SessionOutcome) -> Outcome {
    let e = &o.evidence;
    Outcome {
        kind: kind(o.kind),
        headline: text(&o.headline),
        evidence: Evidence {
            singbox_exit_code: e.singbox_exit_code,
            singbox_stderr_tail: e.singbox_stderr_tail.clone(),
            outbound_fault: e.outbound_fault,
            adaptive_mode: e.adaptive_mode.map(|m| adaptive_name(m).to_owned()),
            adaptive_attempts: e.adaptive_attempts,
            auto_restart_attempts: e.auto_restart_attempts,
            kill_switch_engaged: e.kill_switch_engaged,
            leak_detected_during_session: e.leak_detected_during_session,
            network_transition: e.network_transition.as_ref().map(|t| t.as_str().to_owned()),
            egress_country: e.egress_country.clone(),
            egress_ip: e.egress_ip.clone(),
            proxy_engine: e.proxy_engine,
            proxy_engine_reason: e.proxy_engine_reason.as_ref().map(text),
            hint: e.hint.as_ref().map(text),
        },
    }
}

/// A stored message: verbatim text stays text, anything else is rendered by the page.
fn text(msg: &Msg) -> Text {
    match outcome::verbatim_text(msg) {
        Some(plain) => Text::Plain(plain.to_owned()),
        None => Text::Msg(msg.clone()),
    }
}

/// Wire name of the adaptive mode (the page's evidence value and copied text).
fn adaptive_name(m: AdaptiveContext) -> &'static str {
    match m {
        AdaptiveContext::Baseline => "baseline",
        AdaptiveContext::TlsCompatibility => "tls-compatibility",
        AdaptiveContext::MtuCompatibility => "mtu-compatibility",
        AdaptiveContext::ExternalManaged => "external-managed",
    }
}

fn kind(k: outcome::OutcomeKind) -> OutcomeKind {
    use outcome::OutcomeKind as K;
    match k {
        K::UserStop => OutcomeKind::UserStop,
        K::AppQuit => OutcomeKind::AppQuit,
        K::ServerSwitch => OutcomeKind::ServerSwitch,
        K::Rotation => OutcomeKind::Rotation,
        K::Schedule => OutcomeKind::Schedule,
        K::ProxyUnreachable => OutcomeKind::ProxyUnreachable,
        K::ServerRejectedKey => OutcomeKind::ServerRejectedKey,
        K::ServerDown => OutcomeKind::ServerDown,
        K::SingboxCrash => OutcomeKind::SingboxCrash,
        K::Killswitch => OutcomeKind::Killswitch,
        K::TunSetupFailed => OutcomeKind::TunSetupFailed,
        K::NetworkLost => OutcomeKind::NetworkLost,
        K::SystemSleep => OutcomeKind::SystemSleep,
        K::StartFailed => OutcomeKind::StartFailed,
        K::Unknown => OutcomeKind::Unknown,
    }
}
