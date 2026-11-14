//! The old app's journals in `%ProgramData%\VPNTE\manifests` (spec §2.2), read once with the
//! minimal trust check and validated like the old recovery path: an untrusted, corrupt or
//! unsupported journal is never acted on, and inside a valid one an invalid entry is skipped
//! while its valid neighbours are still restored (ТЗ-06 §10.13). This module holds the envelope,
//! the shared field checks and `tun-owner.json`; `firewall` and `adapters` hold the two salvage
//! readers.
mod adapters;
mod firewall;

use std::net::IpAddr;
use std::path::Path;

use serde_json::{Map, Value};
use windows::core::GUID;

use super::report::{Outcome, StepId, StepRecord};
use super::trust::Untrusted;

use adapters::parse_adapters;
pub(crate) use adapters::{AdapterJournal, AdapterRecord, DnsSource, PolicyValue, Transition};
use firewall::parse_firewall;
pub(crate) use firewall::{FirewallJournal, Outbound};

pub(crate) const FIREWALL: &str = "firewall.json";
pub(crate) const ADAPTERS: &str = "latest-physical-adapter-lockdown.json";
pub(crate) const POLICY: &str = "recovery-policy.json";
pub(crate) const TUN_OWNER: &str = "tun-owner.json";
const MAX_BYTES: u64 = 1 << 20;

/// The trust check, injectable so tests can read journals from a temp folder.
pub(crate) type Trust<'a> = &'a dyn Fn(&Path, bool) -> Result<(), Untrusted>;

/// One journal file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Slot<T> {
    Absent,
    Valid(T),
    /// Present but never to be acted on: untrusted, corrupt, unsupported or invalid.
    Rejected(String),
}

impl<T> Slot<T> {
    pub(crate) fn valid(&self) -> Option<&T> {
        match self {
            Slot::Valid(v) => Some(v),
            _ => None,
        }
    }
}

/// `tun-owner.json`: the old Wintun adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TunOwner {
    pub alias: String,
    pub guid: GUID,
}

/// Everything read from the manifests folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Journals {
    /// The folder (or `%ProgramData%\VPNTE`) failed the trust check: nothing in it is used.
    pub dir_problem: Option<Untrusted>,
    pub firewall: Slot<FirewallJournal>,
    pub adapters: Slot<AdapterJournal>,
    pub policy: Slot<bool>,
    pub tun_owner: Slot<TunOwner>,
}

impl Journals {
    /// Reads every journal under `root\manifests` (`root` = `%ProgramData%\VPNTE`).
    pub(crate) fn read(root: &Path, trust: Trust) -> Self {
        let dir = root.join("manifests");
        let dir_problem = match dir.is_dir() {
            true => trust(root, true).and_then(|()| trust(&dir, true)).err(),
            false => None,
        };
        let load = |name| load(&dir, name, dir_problem, trust);
        Journals {
            firewall: load(FIREWALL).and_then(parse_firewall),
            adapters: load(ADAPTERS).and_then(parse_adapters),
            policy: load(POLICY).and_then(|o| bool_field(&o, "strictMode")),
            tun_owner: load(TUN_OWNER).and_then(parse_tun_owner),
            dir_problem,
        }
    }

    /// The old strict mode was on (spec §6.6 step 2): its boot task may have set Windows
    /// Firewall to Block without a journal, so saved profile values cannot be trusted (B31).
    pub(crate) fn strict_evidence(&self) -> bool {
        self.policy.valid() == Some(&true) || self.firewall.valid().is_some_and(|f| f.strict_mode)
    }

    /// The report line of the reading step.
    pub(crate) fn record(&self) -> StepRecord {
        if let Some(problem) = self.dir_problem {
            let detail = format!(
                "manifests folder not trusted ({}): journals ignored",
                problem.reason()
            );
            return StepRecord::new(StepId::Journals, Outcome::Skipped, detail);
        }
        let slots = [
            (FIREWALL, rejection(&self.firewall)),
            (ADAPTERS, rejection(&self.adapters)),
            (POLICY, rejection(&self.policy)),
            (TUN_OWNER, rejection(&self.tun_owner)),
        ];
        let rejected: Vec<String> = slots
            .iter()
            .filter_map(|(name, r)| r.map(|why| format!("{name}: {why}")))
            .collect();
        match rejected.is_empty() {
            true => StepRecord::new(StepId::Journals, Outcome::Done, "journals read"),
            false => StepRecord::new(StepId::Journals, Outcome::Skipped, rejected.join("; ")),
        }
    }
}

fn rejection<T>(slot: &Slot<T>) -> Option<&str> {
    match slot {
        Slot::Rejected(why) => Some(why),
        _ => None,
    }
}

impl Slot<Map<String, Value>> {
    fn and_then<T>(self, parse: impl FnOnce(Map<String, Value>) -> Result<T, String>) -> Slot<T> {
        match self {
            Slot::Absent => Slot::Absent,
            Slot::Rejected(why) => Slot::Rejected(why),
            Slot::Valid(obj) => match parse(obj) {
                Ok(v) => Slot::Valid(v),
                Err(field) => Slot::Rejected(format!("invalid {field}")),
            },
        }
    }
}

/// Reads one journal through the trust check and checks its envelope.
fn load(
    dir: &Path,
    name: &str,
    dir_problem: Option<Untrusted>,
    trust: Trust,
) -> Slot<Map<String, Value>> {
    let path = dir.join(name);
    if std::fs::symlink_metadata(&path).is_err() {
        return Slot::Absent;
    }
    if let Some(problem) = dir_problem {
        return Slot::Rejected(format!("folder not trusted ({})", problem.reason()));
    }
    if let Err(problem) = trust(&path, false) {
        return Slot::Rejected(format!("not trusted ({})", problem.reason()));
    }
    match std::fs::metadata(&path) {
        Ok(m) if m.len() > MAX_BYTES => return Slot::Rejected("larger than 1 MiB".into()),
        Ok(_) => {}
        Err(_) => return Slot::Rejected("unreadable".into()),
    }
    let Ok(bytes) = std::fs::read(&path) else {
        return Slot::Rejected("unreadable".into());
    };
    parse_envelope(&bytes)
}

/// UTF-8 JSON object (BOM tolerated) with `schemaVersion: 1` and `owner: "VPNTE"`.
pub(crate) fn parse_envelope(bytes: &[u8]) -> Slot<Map<String, Value>> {
    let text = String::from_utf8_lossy(bytes);
    let text = text.trim_start_matches('\u{feff}').trim();
    let Ok(Value::Object(obj)) = serde_json::from_str::<Value>(text) else {
        return Slot::Rejected("corrupt JSON".into());
    };
    match obj.get("schemaVersion") {
        Some(v) if v.as_u64() == Some(1) => {}
        Some(Value::Number(_)) => return Slot::Rejected("unsupported version".into()),
        _ => return Slot::Rejected("invalid envelope".into()),
    }
    if obj.get("owner").and_then(Value::as_str) != Some("VPNTE") {
        return Slot::Rejected("invalid envelope".into());
    }
    Slot::Valid(obj)
}

fn bool_field(obj: &Map<String, Value>, key: &str) -> Result<bool, String> {
    obj.get(key)
        .and_then(Value::as_bool)
        .ok_or_else(|| key.to_string())
}

fn str_field<'a>(obj: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    obj.get(key).and_then(Value::as_str)
}

/// JavaScript `Number.isSafeInteger`.
fn safe_int(v: Option<&Value>) -> Option<i64> {
    const MAX_SAFE: i64 = (1 << 53) - 1;
    v.and_then(Value::as_i64).filter(|n| n.abs() <= MAX_SAFE)
}

fn has_control(s: &str) -> bool {
    s.chars().any(|c| (c as u32) < 0x20)
}

/// `^\{?[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\}?$`, case-insensitive.
pub(crate) fn parse_guid(s: &str) -> Option<GUID> {
    let s = s.strip_prefix('{').unwrap_or(s);
    let s = s.strip_suffix('}').unwrap_or(s);
    let groups: Vec<&str> = s.split('-').collect();
    let shape = groups.iter().map(|g| g.len()).eq([8, 4, 4, 4, 12]);
    if !shape
        || !groups
            .iter()
            .all(|g| g.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return None;
    }
    u128::from_str_radix(&groups.concat(), 16)
        .ok()
        .map(GUID::from_u128)
}

fn ip_list(v: Option<&Value>) -> Option<Vec<IpAddr>> {
    v?.as_array()?
        .iter()
        .map(|ip| ip.as_str().and_then(|s| s.parse().ok()))
        .collect()
}

/// JavaScript truthiness for the optional-object checks of the old validators.
fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        _ => true,
    }
}

fn parse_tun_owner(obj: Map<String, Value>) -> Result<TunOwner, String> {
    let alias = str_field(&obj, "alias")
        .filter(|a| !a.is_empty() && !has_control(a))
        .ok_or("alias")?;
    let guid = str_field(&obj, "interfaceGuid")
        .and_then(parse_guid)
        .ok_or("interfaceGuid")?;
    Ok(TunOwner {
        alias: alias.to_string(),
        guid,
    })
}

#[cfg(test)]
mod tests;
