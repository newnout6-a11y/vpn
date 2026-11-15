//! `firewall.json`: the old kill switch's saved profile defaults, validated like the old
//! recovery path (`firewallKillSwitch.ts`), with the salvage of `savedProfiles`.
use serde_json::{Map, Value};
use vpnte_winnet::wfp::FwProfile;

use super::{bool_field, has_control, safe_int, str_field, truthy};

/// A saved Windows Firewall outbound default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outbound {
    Allow,
    Block,
    NotConfigured,
}

/// `firewall.json`, as far as the cleanup needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FirewallJournal {
    pub strict_mode: bool,
    /// Valid entries only (salvage: invalid or duplicate entries are skipped).
    pub profiles: Vec<(FwProfile, Outbound)>,
    pub skipped: Vec<String>,
}

pub(super) fn parse_firewall(obj: Map<String, Value>) -> Result<FirewallJournal, String> {
    if let Some(policy) = obj.get("ipv6Policy").filter(|p| truthy(p))
        && policy.get("schemaVersion").and_then(Value::as_u64) != Some(1)
    {
        return Err("ipv6Policy version".into());
    }
    let op_ok = str_field(&obj, "operationId")
        .is_some_and(|s| s.len() == 36 && s.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-'));
    let phase_ok = matches!(str_field(&obj, "phase"), Some("prepared" | "active"));
    let strict_mode = bool_field(&obj, "strictMode")?;
    let created_ok = safe_int(obj.get("createdAt")).is_some_and(|n| n > 0);
    let names_ok = obj
        .get("ruleNames")
        .and_then(Value::as_array)
        .is_some_and(|names| {
            names.len() <= 500
                && names
                    .iter()
                    .all(|n| n.as_str().is_some_and(is_journal_rule_name))
        });
    let exe_ok = match obj.get("singboxExePath") {
        Some(Value::Null) => true,
        Some(Value::String(p)) => drive_path(p) && !has_control(p),
        _ => false,
    };
    for (ok, field) in [
        (op_ok, "operationId"),
        (phase_ok, "phase"),
        (created_ok, "createdAt"),
        (names_ok, "ruleNames"),
        (exe_ok, "singboxExePath"),
    ] {
        if !ok {
            return Err(field.into());
        }
    }
    let (profiles, skipped) = saved_profiles(obj.get("savedProfiles"))?;
    Ok(FirewallJournal {
        strict_mode,
        profiles,
        skipped,
    })
}

fn drive_path(p: &str) -> bool {
    let b = p.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\'
}

/// `^VPNTE-killswitch-[a-zA-Z0-9_-]{1,100}$`.
fn is_journal_rule_name(name: &str) -> bool {
    name.strip_prefix("VPNTE-killswitch-").is_some_and(|rest| {
        (1..=100).contains(&rest.len())
            && rest
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    })
}

/// Valid saved profiles and the report lines of the skipped entries.
type Salvaged = (Vec<(FwProfile, Outbound)>, Vec<String>);

/// Recovery salvage of `savedProfiles` (`firewallKillSwitch.ts` `validateSavedProfiles` with a
/// rejection list): at most three entries; an invalid or duplicated entry is skipped.
fn saved_profiles(v: Option<&Value>) -> Result<Salvaged, String> {
    let list = v
        .and_then(Value::as_array)
        .filter(|l| l.len() <= 3)
        .ok_or("savedProfiles")?;
    let name_of = |item: &Value| item.get("name").and_then(Value::as_str).map(str::to_owned);
    let mut profiles = Vec::new();
    let mut skipped = Vec::new();
    for (index, item) in list.iter().enumerate() {
        let profile = match item.get("name").and_then(Value::as_str) {
            Some("Domain") => Some(FwProfile::Domain),
            Some("Private") => Some(FwProfile::Private),
            Some("Public") => Some(FwProfile::Public),
            _ => None,
        };
        let outbound = match item.get("defaultOutbound").and_then(Value::as_str) {
            Some("Allow") => Some(Outbound::Allow),
            Some("Block") => Some(Outbound::Block),
            Some("NotConfigured") => Some(Outbound::NotConfigured),
            _ => None,
        };
        let unique = list.iter().filter(|o| name_of(o) == name_of(item)).count() == 1;
        match (profile, outbound) {
            (Some(p), Some(o)) if unique => profiles.push((p, o)),
            _ => skipped.push(format!("firewall profile entry {index}")),
        }
    }
    for (profile, name) in [
        (FwProfile::Domain, "Domain"),
        (FwProfile::Private, "Private"),
        (FwProfile::Public, "Public"),
    ] {
        if !profiles.iter().any(|(p, _)| *p == profile) {
            skipped.push(format!("firewall {name}: no valid snapshot"));
        }
    }
    Ok((profiles, skipped))
}
