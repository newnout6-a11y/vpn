//! One old row -> a new row, and the settings cache of the builds before the server list.
use std::net::IpAddr;

use serde_json::Value;
use vpnte_base::types::{ClientDevice, UnixMs};
use vpnte_base::{AppError, Msg};
use vpnte_core::legacy::is_locked;
use vpnte_core::secret::Secret;

use super::country::legacy_country;
use super::{LegacyDirect, LegacyReport, LegacySkip, array, num};
use crate::common::is_http_url;
use crate::model::{
    ArchiveReason, Archived, CountrySource, GroupId, HealthReason, HealthRecord, Origin, ProfileId,
    ServerRow, ServersDoc, VerifiedCountry,
};

/// One old row -> a row of the manual group (the caller moves feed rows); `None` when skipped.
pub(super) fn import_row(
    old: &Value,
    cache: &DirectVpnCache,
    now: UnixMs,
    report: &mut LegacyReport,
) -> Option<ServerRow> {
    let name = old.get("name").and_then(Value::as_str).unwrap_or("").trim();
    let skip = |report: &mut LegacyReport, reason: Msg| {
        report.skipped.push(LegacySkip {
            name: name.to_owned(),
            reason,
        });
    };
    if !old.is_object() {
        skip(report, Msg::new("servers.legacy.rowUnreadable"));
        return None;
    }
    let outbound = match old.get("outbound") {
        Some(v) if is_locked(v) => {
            report.locked += 1;
            return None;
        }
        Some(v) if v.is_object() => v,
        // Very old builds saved rows without the outbound (`backfillMissingOutbounds`).
        _ => match cache.outbound_for(old) {
            Some(v) => v,
            None => {
                skip(report, Msg::new("servers.legacy.noOutbound"));
                return None;
            }
        },
    };
    // The feed URL that JSON / Clash rows carried is not a per-row identity (§2.1).
    let source_uri = old
        .get("sourceUri")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty() && !is_http_url(s));
    let protocol = old.get("protocol").and_then(Value::as_str).unwrap_or("");
    // The old app ran every row with `outbound.server_port` rewritten to the row's port.
    let port = row_port(old, outbound);
    let mut outbound = outbound.clone();
    if let Some(obj) = outbound.as_object_mut() {
        obj.insert("server_port".into(), port.into());
    }
    let read = |uri| vpnte_profiles::legacy::from_legacy(name, protocol, &outbound, uri);
    // A row edited after import (other port than its link) is read from the stored outbound.
    let profile = match read(source_uri) {
        Ok(p) if p.port != port && source_uri.is_some() => read(None),
        other => other,
    };
    let profile = match profile {
        Ok(profile) => profile,
        Err(err) => {
            skip(report, AppError::from(err).user_msg());
            return None;
        }
    };
    let device = device(old);
    let mut row = match ServerRow::new(&profile, GroupId::from(""), Origin::Manual, device, now) {
        Ok(row) => row,
        Err(err) => {
            skip(report, err.user_msg());
            return None;
        }
    };
    // Proves the key can be sealed and read back under this account before it replaces the old one.
    if let Err(err) = row.profile.verify() {
        tracing::warn!("servers: legacy key could not be re-sealed: {err}");
        skip(report, Msg::new("servers.legacy.sealFailed"));
        return None;
    }
    if let Some(id) = old
        .get("id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        row.id = ProfileId::from(id);
    }
    row.last_seen_at = num(old, "lastSeenInSubscriptionAt");
    // `enabled: false` without a removal date was never a user decision: the row stays active.
    row.archived = num(old, "removedFromSubscriptionAt").map(|at| Archived {
        at,
        reason: ArchiveReason::Provider,
    });
    row.country = verified_country(old);
    row.health = health(old);
    Some(row)
}

/// `normalizeServerPort(row.port ?? outbound.server_port, 443)`: a present but invalid row port
/// gives 443, not the outbound's port (storage §7.4).
fn row_port(old: &Value, outbound: &Value) -> u16 {
    let value = match old.get("port") {
        Some(Value::Null) | None => outbound.get("server_port"),
        some => some,
    };
    let port = match value {
        Some(Value::Number(n)) => n.as_u64(),
        Some(Value::String(s)) => s.trim().parse::<u64>().ok(),
        _ => None,
    };
    port.and_then(|p| u16::try_from(p).ok())
        .filter(|&p| p != 0)
        .unwrap_or(443)
}

/// `clientDevice`, `pc` when absent or unknown.
fn device(old: &Value) -> ClientDevice {
    old.get("clientDevice")
        .and_then(Value::as_str)
        .and_then(|d| serde_json::from_value(Value::String(d.trim().to_ascii_lowercase())).ok())
        .unwrap_or_default()
}

/// A country with `countryVerifiedAt` becomes a low-confidence `legacy` record; a claimed one is
/// dropped (it is derived from the name now, S-11).
fn verified_country(old: &Value) -> Option<VerifiedCountry> {
    let at = num(old, "countryVerifiedAt")?;
    let iso2 = legacy_country(old.get("country")?.as_str()?)?;
    let ip = old
        .get("countryVerifiedIp")
        .and_then(Value::as_str)
        .and_then(|s| s.trim().parse::<IpAddr>().ok());
    Some(VerifiedCountry {
        iso2,
        at,
        ip,
        source: CountrySource::Legacy,
    })
}

fn health(old: &Value) -> Option<HealthRecord> {
    let online = match old.get("healthStatus").and_then(Value::as_str)? {
        "online" => true,
        "offline" => false,
        _ => return None,
    };
    Some(HealthRecord {
        online,
        at: num(old, "healthCheckedAt")?,
        rtt_ms: num(old, "healthLatencyMs").and_then(|n| u32::try_from(n).ok()),
        reason: old
            .get("healthReason")
            .and_then(Value::as_str)
            .and_then(|r| serde_json::from_value::<HealthReason>(Value::String(r.to_owned())).ok()),
        egress_ip: old
            .get("egressIp")
            .and_then(Value::as_str)
            .and_then(|s| s.trim().parse().ok()),
    })
}

/// `settings.directVpnCachedProfiles` of builds before the server list existed.
pub(super) struct DirectVpnCache<'a> {
    entries: &'a [Value],
    /// `directVpnInput` (trimmed): the key or subscription the user accepted.
    input: &'a str,
    /// The cache belongs to the accepted input (`directVpnInput == directVpnCachedInput`, entries
    /// present); wizard previews that were never accepted are not imported (AT-09-014).
    pub(super) accepted: bool,
    selected: usize,
}

impl<'a> DirectVpnCache<'a> {
    pub(super) fn read(settings: Option<&'a Value>) -> Self {
        let s = settings.and_then(|v| v.get("settings"));
        let text = |key: &str| {
            s.and_then(|s| s.get(key))
                .and_then(Value::as_str)
                .map_or("", str::trim)
        };
        let input = text("directVpnInput");
        let entries = array(s, "directVpnCachedProfiles");
        Self {
            entries,
            input,
            accepted: !input.is_empty()
                && input == text("directVpnCachedInput")
                && !entries.is_empty(),
            selected: s
                .and_then(|s| num(s, "directVpnSelectedIndex"))
                .and_then(|n| usize::try_from(n).ok())
                .unwrap_or(0),
        }
    }

    /// Outbound for a row saved without one: same host and port, else same name.
    pub(super) fn outbound_for(&self, row: &Value) -> Option<&'a Value> {
        let outbound = |e: &'a Value| e.get("outbound").filter(|o| o.is_object());
        let host = row.get("server").and_then(Value::as_str).map(str::trim);
        let port = num(row, "port");
        self.entries
            .iter()
            .filter_map(outbound)
            .find(|o| {
                host.is_some()
                    && o.get("server").and_then(Value::as_str).map(str::trim) == host
                    && num(o, "server_port") == port
            })
            .or_else(|| {
                let name = row.get("name").and_then(Value::as_str)?;
                self.entries
                    .iter()
                    .find(|e| e.get("name").and_then(Value::as_str) == Some(name))
                    .and_then(outbound)
            })
    }

    /// `migrateLegacyDirectVpnProfiles` of an accepted cache: only for an empty server list.
    pub(super) fn migrate(&self, doc: &mut ServersDoc, now: UnixMs, report: &mut LegacyReport) {
        // (cache index, row id): the old selected index counts cache entries, not imported rows.
        let mut added = Vec::new();
        for (index, entry) in self.entries.iter().enumerate() {
            let Some(outbound) = entry.get("outbound").filter(|o| o.is_object()) else {
                continue;
            };
            let name = entry.get("name").and_then(Value::as_str).unwrap_or("");
            let protocol = entry
                .get("protocol")
                .and_then(Value::as_str)
                .unwrap_or("vless");
            let reason = match vpnte_profiles::legacy::from_legacy(name, protocol, outbound, None) {
                Ok(profile) => {
                    let group = doc.ensure_manual_group(now);
                    match ServerRow::new(&profile, group, Origin::Manual, ClientDevice::Pc, now) {
                        Ok(row) if row.profile.verify().is_ok() => {
                            added.push((index, row.id.clone()));
                            doc.profiles.push(row);
                            continue;
                        }
                        Ok(_) => Msg::new("servers.legacy.sealFailed"),
                        Err(err) => err.user_msg(),
                    }
                }
                Err(err) => AppError::from(err).user_msg(),
            };
            report.skipped.push(LegacySkip {
                name: name.trim().to_owned(),
                reason,
            });
        }
        // The selected entry; when it was not imported, the clamped index (storage §7.3).
        doc.active_profile_id = added
            .iter()
            .find(|(index, _)| *index == self.selected)
            .or_else(|| added.get(self.selected.min(added.len().saturating_sub(1))))
            .map(|(_, id)| id.clone());
    }

    /// The input to resolve online when the cache is not the accepted one (storage §7.3).
    pub(super) fn direct(&self) -> Option<LegacyDirect> {
        (!self.input.is_empty()).then(|| LegacyDirect {
            input: Secret::new(self.input),
            selected: self.selected,
        })
    }
}
