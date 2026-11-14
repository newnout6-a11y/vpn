//! `POST /profiles/healthcheck` of the control API: the key check of one server group, run like
//! the Servers page's «Check keys» (one `HealthCheck` operation per group, one probe context per
//! client device, verdicts recorded in the list).
use vpnte_base::AppResult;
use vpnte_base::types::{ClientDevice, EnginePref};
use vpnte_core::ops::{FeatureKind, RunOpts, Source};
use vpnte_engine::xray_config::server_pref;
use vpnte_probes::key_health::{self, HealthError};
use vpnte_profiles::model::Profile;
use vpnte_proxies::model::{GroupHealth, KeyHealth};
use vpnte_servers::model::{
    ArchiveReason, CountrySource, GroupId, HealthRecord, ProfileId, ServerRow, VerifiedCountry,
};
use vpnte_servers::store::HealthUpdate;

use super::source::{ServerProfiles, reason_code};

/// A probed key: its id and the key identity taken before the probe.
type Key = (ProfileId, Option<[u8; 16]>);
/// The keys of one client device and engine choice with their profiles (`None`: unreadable,
/// checked as such).
type DeviceItems = ((ClientDevice, EnginePref), Vec<(Key, Option<Profile>)>);

/// Checks the keys of group `group_id` the user has not removed. An unknown or empty group is
/// `HealthError::GroupNotFoundOrEmpty` (the control API answers 404).
pub(super) async fn check_group(src: &ServerProfiles, group_id: &str) -> AppResult<GroupHealth> {
    let id = GroupId::from(group_id);
    let rows: Vec<ServerRow> = src.servers.read(|doc| {
        doc.profiles
            .iter()
            .filter(|r| r.group_id == id && !r.archived_for(ArchiveReason::User))
            .cloned()
            .collect()
    });
    if rows.is_empty() {
        return Err(HealthError::GroupNotFoundOrEmpty.into());
    }
    let servers = src.servers.clone();
    let probe_ctx = src.probe_ctx.clone();
    let opts = RunOpts {
        source: Source::Unknown,
        resource: Some(format!("health:{id}").into()),
        ..RunOpts::default()
    };
    let checked = src
        .ops
        .run(FeatureKind::HealthCheck, opts, move |lease| async move {
            let mut checked = Vec::new();
            let mut setup = None;
            for ((device, engine), items) in by_device(rows) {
                let mut ctx = probe_ctx(device);
                ctx.engine_pref = server_pref(ctx.engine_pref, engine);
                match key_health::check_many(items, &ctx, lease.token()).await {
                    Ok(found) => checked.extend(found),
                    Err(HealthError::Setup(err)) => setup = Some(err),
                    Err(err) => return Err(err.into()),
                }
            }
            if let Some(err) = setup.filter(|_| checked.is_empty()) {
                return Err(err);
            }
            lease.commit(|| {
                servers.record_health(updates(&checked))?;
                Ok(checked)
            })
        })
        .await?;
    Ok(GroupHealth {
        ok: true,
        results: checked
            .into_iter()
            .map(|((id, _), h)| KeyHealth {
                profile_id: id.0,
                online: h.online,
                latency_ms: h.rtt_ms,
                reason: h.reason.and_then(reason_code),
                egress_ip: h.egress_ip,
                country: h.country.map(|c| c.as_str().to_owned()),
            })
            .collect(),
    })
}

/// Rows grouped by client device (uTLS default, Xray translation differ per device) and their
/// own engine choice (applied to the probe exactly as to a connect). Each key is probed as it
/// runs, the user's TLS tricks included (twire-a4, as the Servers page's checks).
fn by_device(rows: Vec<ServerRow>) -> Vec<DeviceItems> {
    let mut out: Vec<DeviceItems> = Vec::new();
    for row in rows {
        let profile = row.run_profile().ok();
        let choice = (row.device, row.engine);
        let item = ((row.id, profile.as_ref().map(Profile::identity)), profile);
        match out.iter_mut().find(|(c, _)| *c == choice) {
            Some((_, items)) => items.push(item),
            None => out.push((choice, vec![item])),
        }
    }
    out
}

/// What the list stores of the verdicts; a key without an identity (unreadable) is not stored.
fn updates(checked: &[(Key, key_health::KeyHealth)]) -> Vec<HealthUpdate> {
    checked
        .iter()
        .filter_map(|((id, identity), h)| {
            Some(HealthUpdate {
                id: id.clone(),
                identity: (*identity)?,
                record: HealthRecord {
                    online: h.online,
                    at: h.at,
                    rtt_ms: h.rtt_ms,
                    // Same wire names on both sides (key_health API).
                    reason: h
                        .reason
                        .and_then(reason_code)
                        .and_then(|code| serde_json::from_value(code.into()).ok()),
                    egress_ip: h.egress_ip,
                },
                country: h.country.map(|iso2| VerifiedCountry {
                    iso2,
                    at: h.at,
                    ip: h.egress_ip,
                    source: CountrySource::HealthTrace,
                }),
            })
        })
        .collect()
}
