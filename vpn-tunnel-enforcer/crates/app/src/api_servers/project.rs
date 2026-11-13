//! The page snapshot: a pure projection of the server list, the tunnel state and local marks
//! (switch target, resolved addresses), plus the read that gathers its inputs.
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::num::NonZeroU32;

use serde::Serialize;
use serde::de::DeserializeOwned;
use vpnte_base::Msg;
use vpnte_base::i18n::Lang;
use vpnte_base::types::{Engine, EnginePref, UnixMs};
use vpnte_engine::xray_config::{self, Decision, select_engine, server_pref};
use vpnte_profiles::caps;
use vpnte_profiles::model::{Profile, Source as ProfileSource};
use vpnte_servers::model::{
    self as sm, ARCHIVE_TTL_MS, CountrySource, FetchOutcome, GroupSummary, HealthRecord, NetFail,
    ProfileId, ServerRow, ServerSummary,
};
use vpnte_servers::subscription::Hwids;
use vpnte_tunnel::fsm::{TunnelSnapshot, TunnelState};
use vpnte_ui::servers as ui;

use super::{Shared, verdict};

/// Display facts of a row that need its decrypted profile or its stored evidence.
#[derive(Debug, Clone, Default, PartialEq)]
pub(super) struct RowExtras {
    pub exit_ip: Option<IpAddr>,
    pub last_seen_at: Option<UnixMs>,
    pub stealth: Option<ui::Stealth>,
    pub fingerprint: Option<String>,
    /// The engine's warning about that fingerprint (see [`fingerprint_warning`]).
    pub fingerprint_warning: Option<Msg>,
    pub has_outbound: bool,
    /// What a connect would run under the current setting and the row's own choice.
    pub engine_plan: Option<ui::EnginePlan>,
    /// The classifier's verdict, when no younger health record contradicts it.
    pub verdict: Option<ui::CheckVerdict>,
    /// The key carried its provider's hide-settings out of the provider's group
    /// (`ServerRow::hidden`); a hiding group hides its own rows on top.
    pub config_hidden: bool,
    /// The whitelist badge (the user's mark, or the last proof at the current endpoint).
    pub whitelist: Option<ui::WhitelistReady>,
}

impl RowExtras {
    /// The extras of `row` under the engine `setting`; a key sealed for another account shows
    /// none of the profile facts.
    pub(super) fn of(row: &ServerRow, setting: EnginePref) -> Self {
        let profile = row.profile().ok();
        let plan = profile
            .as_ref()
            .map(|p| engine_plan(p, server_pref(setting, row.engine)));
        Self {
            exit_ip: exit_ip(row),
            last_seen_at: row.last_seen_at,
            stealth: profile
                .as_ref()
                .map(|p| stealth(caps::capabilities(p).stealth)),
            fingerprint: profile
                .as_ref()
                .and_then(|p| p.tls.as_ref()?.fingerprint.clone()),
            fingerprint_warning: profile
                .as_ref()
                .and_then(|p| fingerprint_warning(p, plan.as_ref())),
            has_outbound: profile.as_ref().is_some_and(has_outbound),
            engine_plan: plan,
            verdict: row
                .verdict
                .as_ref()
                .and_then(|v| verdict::view(v, row.health.as_ref())),
            config_hidden: row.hidden,
            whitelist: whitelist(row),
        }
    }
}

/// The row's whitelist badge: the user's mark, or when it last carried data on a whitelisted
/// network at its current endpoint.
fn whitelist(row: &ServerRow) -> Option<ui::WhitelistReady> {
    let marked = row.whitelist.as_ref().is_some_and(|w| w.marked);
    let worked_at = row.worked_under_whitelist().map(|w| w.at).max();
    (marked || worked_at.is_some()).then_some(ui::WhitelistReady { marked, worked_at })
}

/// The engine's warning about the provider-pinned uTLS fingerprint. A fingerprint current
/// REALITY servers refuse, or one that fails everywhere, matters on both engines (sing-box
/// sends a known provider fingerprint as is); "unknown to Xray, replaced" only when Xray runs.
pub(super) fn fingerprint_warning(p: &Profile, plan: Option<&ui::EnginePlan>) -> Option<Msg> {
    let xray = matches!(
        plan,
        Some(ui::EnginePlan::Runs {
            engine: Engine::Xray,
            ..
        })
    );
    xray_config::warnings(p, false).into_iter().find(|m| {
        m.key.starts_with("engine.xray.warn.fingerprint")
            && (xray || m.key != "engine.xray.warn.fingerprintUnknown")
    })
}

/// The tunnel's own selection rule for `p` (the same function the start runs).
pub(super) fn engine_plan(p: &Profile, pref: EnginePref) -> ui::EnginePlan {
    match select_engine(p, pref) {
        Decision::Selected { engine, reason } => ui::EnginePlan::Runs {
            engine,
            reason: reason.msg(),
        },
        Decision::Rejected(reject) => ui::EnginePlan::Refused(reject.msg()),
    }
}

/// Everything one projection reads.
pub(super) struct Inputs<'a> {
    pub list: &'a sm::ServersView,
    pub extras: &'a HashMap<ProfileId, RowExtras>,
    /// Lower-case host -> its latest address.
    pub ips: &'a HashMap<String, IpAddr>,
    pub tunnel: Option<&'a TunnelSnapshot>,
    /// Profile id of the running session (`"local-proxy"` for a local-proxy upstream).
    pub session: Option<&'a str>,
    pub switching: Option<&'a str>,
    pub geo_disabled: bool,
    pub lang: Lang,
    /// This PC's device IDs (a subscription without its own ID sends these).
    pub hwids: &'a Hwids,
}

/// Reads the backend and projects it.
pub(super) fn current(shared: &Shared) -> ui::ServersView {
    let backend = &shared.backend;
    let list = backend.servers.view();
    let setting = backend.settings.read(|s| s.proxy_engine);
    let extras = backend.servers.read(|doc| {
        doc.profiles
            .iter()
            .map(|row| (row.id.clone(), RowExtras::of(row, setting)))
            .collect::<HashMap<_, _>>()
    });
    let tunnel = backend.tunnel().ok();
    let snapshot = tunnel.map(|t| t.snapshot().borrow().clone());
    let session = tunnel.and_then(|t| t.session().borrow().as_ref().map(|s| s.profile_id.clone()));
    let switching = shared.switching.lock().clone();
    project(&Inputs {
        list: &list,
        extras: &extras,
        ips: &shared.ips.known(),
        tunnel: snapshot.as_ref(),
        session: session.as_deref(),
        switching: switching.as_deref(),
        geo_disabled: backend.settings.read(|s| s.disable_geo_lookup),
        lang: shared.backend.lang(),
        hwids: backend.refresh.fetcher.hwids(),
    })
}

/// The snapshot of `i`. While our tunnel runs on a list server, that server is the marker: a
/// switch moves it only once the session moved (the selection may change first).
pub(super) fn project(i: &Inputs) -> ui::ServersView {
    let connected = i.tunnel.is_some_and(|t| t.state == TunnelState::Connected);
    let on_server = i
        .session
        .filter(|id| connected && i.list.servers.iter().any(|s| s.id.as_str() == *id));
    let empty = RowExtras::default();
    // Provider `hide-settings`: the rows of these groups offer no key view, copy or export.
    let hidden: HashSet<&str> = i
        .list
        .groups
        .iter()
        .filter(|g| !g.manual && g.controls.hides_settings())
        .map(|g| g.id.as_str())
        .collect();
    ui::ServersView {
        loaded: true,
        servers: i
            .list
            .servers
            .iter()
            .map(|s| {
                let extras = i.extras.get(&s.id).unwrap_or(&empty);
                let config_hidden = extras.config_hidden || hidden.contains(s.group_id.as_str());
                server(s, extras, i.ips, config_hidden)
            })
            .collect(),
        groups: i
            .list
            .groups
            .iter()
            .map(|g| group(g, i.lang, i.hwids))
            .collect(),
        active_id: on_server
            .map(str::to_owned)
            .or_else(|| i.list.active.as_ref().map(|id| id.to_string())),
        switching_to: i.switching.map(str::to_owned),
        tunnel_running: on_server.is_some(),
        tunnel_busy: i.tunnel.is_some_and(|t| t.transition.is_some()),
        foreign_vpn: i.tunnel.is_some_and(|t| t.competing_tun.is_some()),
        geo_lookup_disabled: i.geo_disabled,
    }
}

fn server(
    s: &ServerSummary,
    x: &RowExtras,
    ips: &HashMap<String, IpAddr>,
    config_hidden: bool,
) -> ui::ServerView {
    ui::ServerView {
        id: s.id.to_string(),
        name: s.name.clone(),
        protocol: s.protocol.clone(),
        host: s.server.clone(),
        port: s.port,
        resolved_ip: s
            .server
            .parse()
            .ok()
            .or_else(|| ips.get(&s.server.to_ascii_lowercase()).copied()),
        country: s.country.map(|c| c.as_str().to_owned()),
        exit_ip: x.exit_ip,
        device: s.device,
        engine: s.engine,
        engine_plan: x.engine_plan.clone(),
        fingerprint: x.fingerprint.clone(),
        fingerprint_warning: x.fingerprint_warning.clone(),
        has_outbound: x.has_outbound,
        stealth: x.stealth,
        ping_ms: s.ping.and_then(|p| p.rtt_ms),
        status: match s.ping {
            Some(p) if p.rtt_ms.is_some() => ui::OnlineStatus::Online,
            Some(_) => ui::OnlineStatus::Offline,
            None => ui::OnlineStatus::Unknown,
        },
        health: s.health.as_ref().map(health),
        verdict: x.verdict.clone(),
        group_id: Some(s.group_id.to_string()),
        last_seen_in_subscription_at: x.last_seen_at,
        archived: s.archived.map(|a| ui::Archive {
            reason: match a.reason {
                sm::ArchiveReason::Provider => ui::ArchiveReason::Provider,
                sm::ArchiveReason::User => ui::ArchiveReason::User,
            },
            at: a.at,
            purge_at: s.purge_at.unwrap_or(a.at.saturating_add(ARCHIVE_TTL_MS)),
        }),
        // The list has no on / off switch; a key sealed for another Windows account cannot be
        // used until it is imported again, so it shows as switched off.
        enabled: !s.locked,
        config_hidden,
        whitelist: x.whitelist,
        // A provider notice an older build stored: the page shows it as such (p-live-fix).
        placeholder: s.origin == sm::Origin::Feed && sm::is_placeholder(&s.name, &s.server, s.port),
    }
}

fn group(g: &GroupSummary, lang: Lang, hwids: &Hwids) -> ui::GroupView {
    let info = &g.info;
    // The ID the subscription sends: its own after a reset, else this PC's for its device.
    let device_id = g
        .own_hwid
        .clone()
        .or_else(|| g.device.map(|d| hwids.get(d).to_owned()));
    ui::GroupView {
        id: g.id.to_string(),
        name: g.title.render(lang),
        source: if g.manual {
            ui::GroupSource::Manual
        } else {
            ui::GroupSource::Subscription
        },
        status: match g.status {
            sm::GroupStatus::Active => ui::GroupStatus::Active,
            sm::GroupStatus::Expired => ui::GroupStatus::Expired,
            sm::GroupStatus::Unreachable => ui::GroupStatus::Unreachable,
            // The panel answered with something unusable: the status line shows the typed
            // `last_fetch_error`, never "offline".
            sm::GroupStatus::Failed | sm::GroupStatus::Unknown => ui::GroupStatus::Unknown,
        },
        imported_at: g.imported_at,
        last_fetched_at: g.fetch.last_success_at,
        last_fetch_attempt_at: g.fetch.last_attempt_at,
        last_fetch_error: g.fetch.last_outcome.and_then(fetch_error),
        traffic_used: match (info.upload, info.download) {
            (None, None) => None,
            (up, down) => Some(up.unwrap_or(0).saturating_add(down.unwrap_or(0))),
        },
        traffic_total: info.total,
        expires_at: info.expires_at.filter(|&at| at > 0),
        web_page_url: info.web_page_url.clone(),
        refresh_minutes: g
            .refresh_override_min
            .and_then(|m| NonZeroU32::new(u32::from(m))),
        support_url: info.support_url.clone(),
        announce: info.announce.clone(),
        provider_refresh_hours: info.refresh_hours,
        send_hwid: g.send_hwid,
        device_id: device_id.filter(|_| !g.manual),
        own_device_id: g.own_hwid.is_some(),
        header_names: g.header_names.clone(),
        moved_at: g.moved_at,
        host: g.host.clone(),
        settings_hidden: !g.manual && g.controls.hides_settings(),
        provider_said: g.said.clone(),
    }
}

/// The typed failure of a fetch outcome (`None` for a success).
pub(super) fn fetch_error(outcome: FetchOutcome) -> Option<ui::FetchError> {
    Some(match outcome {
        FetchOutcome::Ok { .. } => return None,
        FetchOutcome::EmptyList => ui::FetchError::Empty,
        FetchOutcome::HwidRequired => ui::FetchError::HwidRequired,
        FetchOutcome::DeviceLimit => ui::FetchError::DeviceLimit,
        FetchOutcome::Placeholder => ui::FetchError::Placeholder,
        FetchOutcome::Unparseable(sm::BodyKind::Encrypted) => ui::FetchError::Encrypted,
        FetchOutcome::Unparseable(_) => ui::FetchError::Invalid,
        FetchOutcome::Http(code) => ui::FetchError::Http(code),
        FetchOutcome::Network(NetFail::Tls) => ui::FetchError::Tls,
        FetchOutcome::Network(_) => ui::FetchError::Network,
        FetchOutcome::Timeout => ui::FetchError::Timeout,
    })
}

/// A stored key-health verdict as the page shows it.
pub(super) fn health(record: &HealthRecord) -> ui::KeyHealth {
    ui::KeyHealth {
        online: record.online,
        latency_ms: record.rtt_ms,
        reason: record
            .reason
            .and_then(reason_code)
            .map(|c| ui::KeyHealthReason::from_code(&c)),
        checked_at: record.at,
    }
}

/// The wire code of a health reason (`auth-failed`, …): the page's `KeyHealthReason` key.
pub(super) fn reason_code<R: Serialize>(reason: R) -> Option<String> {
    match serde_json::to_value(reason).ok()? {
        serde_json::Value::String(code) => Some(code),
        _ => None,
    }
}

/// Converts between two enums that share their serde wire names (the probes' and the server
/// list's health reasons).
pub(super) fn same_wire<A: Serialize, B: DeserializeOwned>(value: A) -> Option<B> {
    serde_json::from_value(serde_json::to_value(value).ok()?).ok()
}

/// The page's camouflage badge of a key (a display hint).
fn stealth(kind: caps::Stealth) -> ui::Stealth {
    match kind {
        caps::Stealth::Reality => ui::Stealth::Reality,
        caps::Stealth::Ech => ui::Stealth::Ech,
        caps::Stealth::Naive => ui::Stealth::Naive,
        caps::Stealth::Obfs => ui::Stealth::Obfs,
        caps::Stealth::Utls => ui::Stealth::Utls,
        caps::Stealth::Tls => ui::Stealth::Tls,
        caps::Stealth::Plain => ui::Stealth::Plain,
    }
}

/// The exit address a check observed through the server (country check or key-health trace).
fn exit_ip(row: &ServerRow) -> Option<IpAddr> {
    row.country
        .filter(|c| matches!(c.source, CountrySource::ExitIp | CountrySource::HealthTrace))
        .and_then(|c| c.ip)
        .or_else(|| row.health.and_then(|h| h.egress_ip))
}

/// The key came as a full engine outbound (JSON document, the old app's stored outbound or a
/// provider Xray graph), not as a share link: Happ's «| JSON» caption.
fn has_outbound(p: &Profile) -> bool {
    p.native_xray.is_some() || matches!(p.source, ProfileSource::Json | ProfileSource::Legacy)
}
