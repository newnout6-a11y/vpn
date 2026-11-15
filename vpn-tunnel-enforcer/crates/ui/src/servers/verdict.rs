//! The classifier's verdict in a server row: a quiet mono caption («заморозка → другой сервер»)
//! with the full sentences and the check's age as the hover text. Only a frozen or banned server
//! takes the signal colour: it is unusable in this network now, and changing the port, the
//! transport or retrying will not help; every other verdict can wait.
use dioxus::prelude::*;
use vpnte_base::types::UnixMs;

use super::model::{CheckVerdict, VerdictAdvice, VerdictKind};
use super::present::relative_time;
use crate::lang::{LANG, tr};
use crate::t;

/// Caption key of a verdict.
pub(crate) fn verdict_key(kind: VerdictKind) -> &'static str {
    match kind {
        VerdictKind::Healthy => "ui.servers.verdict.healthy",
        VerdictKind::Frozen => "ui.servers.verdict.frozen",
        VerdictKind::Stalled => "ui.servers.verdict.stalled",
        VerdictKind::HandshakeFailed => "ui.servers.verdict.handshakeFailed",
        VerdictKind::KeyRejected => "ui.servers.verdict.keyRejected",
        VerdictKind::IpBanned => "ui.servers.verdict.ipBanned",
        VerdictKind::UdpBlocked => "ui.servers.verdict.udpBlocked",
        VerdictKind::Offline => "ui.servers.verdict.offline",
        VerdictKind::Deferred => "ui.servers.verdict.deferred",
        VerdictKind::NotVerified => "ui.servers.verdict.notVerified",
        VerdictKind::Refused => "ui.servers.verdict.refused",
    }
}

/// Caption key of an advice.
pub(crate) fn advice_key(advice: VerdictAdvice) -> &'static str {
    match advice {
        VerdictAdvice::SwitchServer => "ui.servers.verdict.advice.switchServer",
        VerdictAdvice::TryAnotherFingerprint => "ui.servers.verdict.advice.tryAnotherFingerprint",
        VerdictAdvice::PreferTcpTransport => "ui.servers.verdict.advice.preferTcpTransport",
        VerdictAdvice::RetryLater => "ui.servers.verdict.advice.retryLater",
    }
}

/// The verdicts shown in the signal colour.
pub(crate) fn alarming(kind: VerdictKind) -> bool {
    matches!(kind, VerdictKind::Frozen | VerdictKind::IpBanned)
}

/// Caption and hover text of `v` at `now`.
fn texts(v: &CheckVerdict, now: UnixMs) -> (String, String) {
    let caption = match v.advice {
        Some(advice) => format!("{} → {}", t!(verdict_key(v.kind)), t!(advice_key(advice))),
        None => t!(verdict_key(v.kind)),
    };
    let when = relative_time(v.checked_at, now, *LANG.read());
    let mut hover = tr(&v.detail);
    if let Some(advice) = &v.advice_detail {
        hover.push('\n');
        hover.push_str(&tr(advice));
    }
    hover.push('\n');
    hover.push_str(&t!("ui.servers.verdict.checked", when = when));
    (caption, hover)
}

/// The verdict caption of a row.
#[component]
pub(crate) fn VerdictCap(verdict: CheckVerdict, now: UnixMs) -> Element {
    let (caption, hover) = texts(&verdict, now);
    rsx! {
        span {
            class: "srv-row-cap swiss-mono",
            class: if alarming(verdict.kind) { "is-alert" },
            title: "{hover}",
            "{caption}"
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    const KINDS: [VerdictKind; 11] = [
        VerdictKind::Healthy,
        VerdictKind::Frozen,
        VerdictKind::Stalled,
        VerdictKind::HandshakeFailed,
        VerdictKind::KeyRejected,
        VerdictKind::IpBanned,
        VerdictKind::UdpBlocked,
        VerdictKind::Offline,
        VerdictKind::Deferred,
        VerdictKind::NotVerified,
        VerdictKind::Refused,
    ];

    /// The signal colour is kept for the two verdicts that need another server now.
    #[test]
    fn only_frozen_and_banned_take_the_signal_colour() {
        let loud: Vec<_> = KINDS.into_iter().filter(|k| alarming(*k)).collect();
        assert_eq!(loud, [VerdictKind::Frozen, VerdictKind::IpBanned]);
    }

    /// Every verdict and advice has its own caption in both languages (and the health check's
    /// "not checked" count, asked for by the group actions).
    #[test]
    fn every_caption_is_distinct_and_translated() {
        let advice = [
            VerdictAdvice::SwitchServer,
            VerdictAdvice::TryAnotherFingerprint,
            VerdictAdvice::PreferTcpTransport,
            VerdictAdvice::RetryLater,
        ];
        let keys: Vec<&str> = KINDS
            .into_iter()
            .map(verdict_key)
            .chain(advice.into_iter().map(advice_key))
            .chain(["ui.servers.verdict.notChecked"])
            .collect();
        assert_eq!(keys.iter().collect::<HashSet<_>>().len(), keys.len());
        crate::test_locales::assert_resolve(&crate::test_locales::catalogs(&[]), keys);
    }
}
