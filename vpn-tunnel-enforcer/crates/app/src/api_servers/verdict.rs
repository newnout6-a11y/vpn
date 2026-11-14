//! The probe-discipline verdicts on the Servers page (RU networks, Nov 2026): what a key check
//! concluded (frozen, IP banned, …) is stored beside the health record and shown in the row with
//! the classifier's advice. Probes and the list share the wire names, so conversions go by name.
use vpnte_base::types::UnixMs;
use vpnte_probes::discipline::{Classification, Reaction, Verdict};
use vpnte_probes::key_health::KeyCheck;
use vpnte_servers::model::{HealthRecord, ServerReaction, ServerVerdict, VerdictRecord};
use vpnte_servers::store::VerdictUpdate;
use vpnte_ui::servers as ui;

use super::checks::Key;
use super::project::same_wire;

/// What the list stores of the classifications (the check's time; rows sealed for another account
/// cannot be matched and are left out, as their health is).
pub(super) fn updates(checked: &[(Key, KeyCheck)]) -> Vec<VerdictUpdate> {
    checked
        .iter()
        .filter_map(|((id, identity), check)| {
            Some(VerdictUpdate {
                id: id.clone(),
                identity: (*identity)?,
                record: record(&check.verdict, check.health.at),
            })
        })
        .collect()
}

/// The stored form of a classification. The list's enums know every probes name (a name they
/// did not know would read back as `Unknown` and simply not be shown).
pub(super) fn record(c: &Classification, at: UnixMs) -> VerdictRecord {
    VerdictRecord {
        verdict: same_wire(c.verdict).unwrap_or(ServerVerdict::Unknown),
        reaction: same_wire(c.reaction).unwrap_or(ServerReaction::Unknown),
        at,
    }
}

/// The verdict a row shows. None when a later check without a verdict has spoken since (its
/// health record is younger: the old verdict would contradict it) or when the stored name is
/// unknown to this build (written by a newer one).
pub(super) fn view(
    record: &VerdictRecord,
    health: Option<&HealthRecord>,
) -> Option<ui::CheckVerdict> {
    if health.is_some_and(|h| h.at > record.at) {
        return None;
    }
    let verdict: Verdict = same_wire(record.verdict)?;
    let reaction: Option<Reaction> = same_wire(record.reaction);
    Some(ui::CheckVerdict {
        kind: kind(record.verdict)?,
        advice: advice(record.reaction),
        detail: verdict.msg(),
        advice_detail: reaction.and_then(Reaction::msg),
        checked_at: record.at,
    })
}

fn kind(v: ServerVerdict) -> Option<ui::VerdictKind> {
    Some(match v {
        ServerVerdict::Healthy => ui::VerdictKind::Healthy,
        ServerVerdict::Frozen => ui::VerdictKind::Frozen,
        ServerVerdict::Stalled => ui::VerdictKind::Stalled,
        ServerVerdict::HandshakeFailed => ui::VerdictKind::HandshakeFailed,
        ServerVerdict::KeyRejected => ui::VerdictKind::KeyRejected,
        ServerVerdict::IpBanned => ui::VerdictKind::IpBanned,
        ServerVerdict::UdpBlocked => ui::VerdictKind::UdpBlocked,
        ServerVerdict::Offline => ui::VerdictKind::Offline,
        ServerVerdict::Refused => ui::VerdictKind::Refused,
        ServerVerdict::Deferred => ui::VerdictKind::Deferred,
        ServerVerdict::NotVerified => ui::VerdictKind::NotVerified,
        ServerVerdict::Unknown => return None,
    })
}

fn advice(r: ServerReaction) -> Option<ui::VerdictAdvice> {
    Some(match r {
        ServerReaction::SwitchServer => ui::VerdictAdvice::SwitchServer,
        ServerReaction::TryAnotherFingerprint => ui::VerdictAdvice::TryAnotherFingerprint,
        ServerReaction::PreferTcpTransport => ui::VerdictAdvice::PreferTcpTransport,
        ServerReaction::RetryLater => ui::VerdictAdvice::RetryLater,
        ServerReaction::None | ServerReaction::Unknown => return None,
    })
}
