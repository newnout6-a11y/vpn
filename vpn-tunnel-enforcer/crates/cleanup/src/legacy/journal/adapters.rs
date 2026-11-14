//! `latest-physical-adapter-lockdown.json`: IPv6 bindings, IPv4 DNS and DNS client policy values
//! of the old adapter lockdown, validated like the old recovery path
//! (`physicalAdapterLockdown.ts`), with the per-entry salvage.
use std::net::IpAddr;

use serde_json::{Map, Value};
use windows::core::GUID;

use super::{has_control, ip_list, parse_guid, safe_int, str_field, truthy};

/// How an adapter got its IPv4 DNS before the lockdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DnsSource {
    Dhcp,
    Static,
    Unknown,
}

/// One adapter entry of `latest-physical-adapter-lockdown.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdapterRecord {
    pub guid: GUID,
    pub alias: String,
    pub ipv6_enabled: bool,
    pub dns_servers: Vec<IpAddr>,
    pub dns_source: DnsSource,
    pub forced_dns_to: Option<Vec<IpAddr>>,
    pub forced_ipv6_off: bool,
}

/// A recorded DNS client policy value (`exists:false` = the value was absent).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PolicyValue {
    pub exists: bool,
    pub data: u32,
}

/// Teredo / 6to4 / ISATAP states before the lockdown (`None` = not recorded or invalid).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Transition {
    pub teredo: Option<String>,
    pub six_to_four: Option<String>,
    pub isatap: Option<String>,
}

/// `latest-physical-adapter-lockdown.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdapterJournal {
    pub adapters: Vec<AdapterRecord>,
    pub transition: Transition,
    pub smart_name_resolution: Option<PolicyValue>,
    pub parallel_a_aaaa: Option<PolicyValue>,
    /// Entries left out by the salvage, by step and field name (never values).
    pub skipped: Vec<String>,
}

/// Recovery salvage of the adapter journal (`physicalAdapterLockdown.ts`
/// `validateLockdownManifest` with a rejection list). Reports name steps and fields, never
/// values (they hold private topology).
pub(super) fn parse_adapters(obj: Map<String, Value>) -> Result<AdapterJournal, String> {
    safe_int(obj.get("appliedAt")).ok_or("appliedAt")?;
    str_field(&obj, "tunDnsIpv4")
        .and_then(|s| s.parse::<IpAddr>().ok())
        .ok_or("tunDnsIpv4")?;
    let list = obj
        .get("adapters")
        .and_then(Value::as_array)
        .filter(|l| l.len() <= 256)
        .ok_or("adapters")?;
    let mut skipped = Vec::new();
    if list.is_empty() {
        skipped.push("physical adapters: none recorded".to_string());
    }
    let guids: Vec<Option<GUID>> = list
        .iter()
        .map(|a| {
            a.get("interfaceGuid")
                .and_then(Value::as_str)
                .and_then(parse_guid)
        })
        .collect();
    let mut adapters = Vec::new();
    for (index, item) in list.iter().enumerate() {
        match adapter_record(item) {
            Err(fields) => skipped.push(format!("adapter entry {index}: invalid {fields}")),
            Ok(r) if guids.iter().filter(|g| **g == Some(r.guid)).count() != 1 => {
                skipped.push(format!("adapter entry {index}: duplicate adapter identity"));
            }
            Ok(r) => adapters.push(r),
        }
    }
    let transition = transition(obj.get("transitionAdapters"), &mut skipped);
    let policy = obj.get("dnsRegistryPolicy").filter(|p| truthy(p));
    let mut value = |key: &str| {
        let v = policy.and_then(|p| p.get(key)).and_then(policy_value);
        if v.is_none() {
            skipped.push(format!("DNS policy/{key}: invalid or missing"));
        }
        v
    };
    let smart_name_resolution = value("smartNameResolution");
    let parallel_a_aaaa = value("parallelAandAAAA");
    Ok(AdapterJournal {
        adapters,
        transition,
        smart_name_resolution,
        parallel_a_aaaa,
        skipped,
    })
}

/// One adapter entry, or the comma-separated names of its invalid fields.
fn adapter_record(a: &Value) -> Result<AdapterRecord, String> {
    let alias = a
        .get("alias")
        .and_then(Value::as_str)
        .filter(|s| s.encode_utf16().count() <= 256 && !has_control(s));
    let dns_source = match a.get("ipv4DnsSource").and_then(Value::as_str) {
        Some("dhcp") => Some(DnsSource::Dhcp),
        Some("static") => Some(DnsSource::Static),
        Some("unknown") => Some(DnsSource::Unknown),
        _ => None,
    };
    let forced_dns_to = match a.get("forcedDnsTo") {
        Some(Value::Null) => Some(None),
        other => ip_list(other).map(Some),
    };
    let if_index_ok = a
        .get("ifIndex")
        .and_then(Value::as_u64)
        .is_some_and(|n| n > 0);
    let guid = a
        .get("interfaceGuid")
        .and_then(Value::as_str)
        .and_then(parse_guid);
    let ipv6_enabled = a.get("ipv6Enabled").and_then(Value::as_bool);
    let forced_ipv6_off = a.get("forcedIpv6Off").and_then(Value::as_bool);
    let dns_servers = ip_list(a.get("ipv4DnsServers"));
    let fields = [
        ("ifIndex", if_index_ok),
        ("alias", alias.is_some()),
        ("ipv6Enabled", ipv6_enabled.is_some()),
        ("forcedIpv6Off", forced_ipv6_off.is_some()),
        ("interfaceGuid", guid.is_some()),
        ("ipv4DnsSource", dns_source.is_some()),
        ("ipv4DnsServers", dns_servers.is_some()),
        ("forcedDnsTo", forced_dns_to.is_some()),
    ];
    let invalid: Vec<&str> = fields
        .iter()
        .filter(|(_, ok)| !ok)
        .map(|(f, _)| *f)
        .collect();
    match (
        alias,
        guid,
        ipv6_enabled,
        forced_ipv6_off,
        dns_source,
        dns_servers,
        forced_dns_to,
    ) {
        (
            Some(alias),
            Some(guid),
            Some(ipv6_enabled),
            Some(forced_ipv6_off),
            Some(dns_source),
            Some(dns_servers),
            Some(forced_dns_to),
        ) if invalid.is_empty() => Ok(AdapterRecord {
            guid,
            alias: alias.to_string(),
            ipv6_enabled,
            dns_servers,
            dns_source,
            forced_dns_to,
            forced_ipv6_off,
        }),
        _ => Err(invalid.join(", ")),
    }
}

fn transition(v: Option<&Value>, skipped: &mut Vec<String>) -> Transition {
    let Some(v) = v.filter(|v| truthy(v)) else {
        return Transition::default();
    };
    let Some(obj) = v.as_object() else {
        skipped.push("transition adapters: invalid".to_string());
        return Transition::default();
    };
    let mut state = |key: &str, allowed: &[&str]| match obj.get(key) {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if allowed.contains(&s.as_str()) => Some(s.clone()),
        Some(_) => {
            skipped.push(format!("transition/{key}: invalid"));
            None
        }
    };
    const STATES: &[&str] = &["disabled", "default", "enabled"];
    Transition {
        teredo: state(
            "teredoType",
            &[
                "disabled",
                "default",
                "client",
                "enterpriseclient",
                "natclient",
                "server",
            ],
        ),
        six_to_four: state("sixToFourState", STATES),
        isatap: state("isatapState", STATES),
    }
}

/// `{exists: bool, type?: 'REG_DWORD', data?: '0x<1..8 hex>' | '<1..10 digits>'}`, data ≤ u32::MAX.
pub(super) fn policy_value(v: &Value) -> Option<PolicyValue> {
    let exists = v.get("exists")?.as_bool()?;
    if !exists {
        return Some(PolicyValue { exists, data: 0 });
    }
    if v.get("type")?.as_str()? != "REG_DWORD" {
        return None;
    }
    let data = v.get("data")?.as_str()?;
    let parsed = match data.get(..2) {
        Some("0x" | "0X")
            if (3..=10).contains(&data.len())
                && data[2..].bytes().all(|b| b.is_ascii_hexdigit()) =>
        {
            u64::from_str_radix(&data[2..], 16).ok()
        }
        _ if (1..=10).contains(&data.len()) && data.bytes().all(|b| b.is_ascii_digit()) => {
            data.parse().ok()
        }
        _ => None,
    };
    let data = u32::try_from(parsed?).ok()?;
    Some(PolicyValue { exists, data })
}
