//! Tests of the Servers page wiring: the pure projection and report builders here, the API over
//! a real backend (throw-away data dir, fake tunnel) in `backend`.
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::LazyLock;

use vpnte_base::Msg;
use vpnte_base::i18n::Lang;
use vpnte_base::types::ClientDevice;
use vpnte_profiles::countries::Iso2;
use vpnte_profiles::device::MachineIdentity;
use vpnte_profiles::model::SubscriptionMeta;
use vpnte_servers::model::{
    self as sm, ARCHIVE_TTL_MS, ArchiveReason, Archived, FetchOutcome, FetchState, GroupId,
    GroupStatus, GroupSummary, HealthReason, HealthRecord, NetFail, Origin, Ping, ProfileId,
    ServerSummary,
};
use vpnte_servers::subscription::Hwids;
use vpnte_tunnel::fsm::{Transition, TunnelSnapshot, TunnelState};
use vpnte_ui::servers as ui;

use super::project::{Inputs, RowExtras, fetch_error, project};

mod backend;
mod flows;
mod phones;
mod relays;
mod reports;
mod tricks;
mod verdicts;

/// Registers every locale layer of the app once (the first registration of the process wins).
pub(super) fn locales() {
    vpnte_base::i18n::init(&crate::svc_core::locale_layers());
}

fn row(id: &str, group: &str) -> ServerSummary {
    ServerSummary {
        id: ProfileId::from(id),
        group_id: GroupId::from(group),
        origin: Origin::Feed,
        name: format!("server {id}"),
        protocol: "vless".into(),
        server: format!("{id}.example.net"),
        port: 443,
        device: ClientDevice::Pc,
        engine: Default::default(),
        country: Iso2::new("DE"),
        country_verified: false,
        missing_since: None,
        archived: None,
        purge_at: None,
        health: None,
        ping: None,
        locked: false,
        selected: false,
    }
}

fn group(id: &str, manual: bool) -> GroupSummary {
    let title = if manual {
        "servers.group.manualDefault"
    } else {
        "servers.group.subscriptionDefault"
    };
    GroupSummary {
        id: GroupId::from(id),
        name: String::new(),
        title: Msg::new(title),
        manual,
        device: (!manual).then_some(ClientDevice::Pc),
        host: None,
        url_locked: false,
        status: GroupStatus::Unknown,
        imported_at: 1,
        fetch: FetchState::default(),
        info: SubscriptionMeta::default(),
        refresh_override_min: None,
        servers: 0,
        archived: 0,
        send_hwid: false,
        header_names: Vec::new(),
        moved_at: None,
        controls: Default::default(),
        own_hwid: None,
        said: None,
    }
}

/// Three rows: `a` (manual, resolved through the book), `b` (feed, IP literal, pinged, dead key,
/// dropped by the provider), `c` (sealed for another account).
fn list() -> sm::ServersView {
    let mut b = row("b", "sub");
    b.server = "203.0.113.7".into();
    b.ping = Some(Ping {
        rtt_ms: Some(42),
        at: 5,
    });
    b.health = Some(HealthRecord {
        online: false,
        at: 7,
        rtt_ms: None,
        reason: Some(HealthReason::AuthFailed),
        egress_ip: None,
    });
    b.archived = Some(Archived {
        at: 1_000,
        reason: ArchiveReason::Provider,
    });
    let mut c = row("c", "keys");
    c.locked = true;
    c.ping = Some(Ping {
        rtt_ms: None,
        at: 6,
    });
    let mut sub = group("sub", false);
    sub.status = GroupStatus::Failed;
    sub.fetch.last_outcome = Some(FetchOutcome::Http(500));
    sub.info.upload = Some(10);
    sub.info.download = Some(5);
    sub.info.total = Some(100);
    sub.info.expires_at = Some(0);
    sub.refresh_override_min = Some(15);
    sm::ServersView {
        groups: vec![group("keys", true), sub],
        servers: vec![row("a", "keys"), b, c],
        active: Some(ProfileId::from("a")),
        fallback: false,
        notice: None,
    }
}

/// This PC's device IDs in the projections (one fixed value for every device).
static HWIDS: LazyLock<Hwids> =
    LazyLock::new(|| Hwids::of(&MachineIdentity::default(), Some("test-pc-id-0001".into())));

fn inputs<'a>(
    list: &'a sm::ServersView,
    extras: &'a HashMap<ProfileId, RowExtras>,
    ips: &'a HashMap<String, IpAddr>,
) -> Inputs<'a> {
    Inputs {
        list,
        extras,
        ips,
        tunnel: None,
        session: None,
        switching: None,
        geo_disabled: true,
        lang: Lang::En,
        hwids: &HWIDS,
    }
}

/// p-subs: a subscription shows the device ID it sends (this PC's, or its own after a reset);
/// the manual group has none.
#[test]
fn groups_show_the_device_id_they_send() {
    let mut list = list();
    let (empty, ips) = (HashMap::new(), HashMap::new());
    let view = project(&inputs(&list, &empty, &ips));
    let ids: Vec<_> = view
        .groups
        .iter()
        .map(|g| (g.id.as_str(), g.device_id.as_deref(), g.own_device_id))
        .collect();
    assert_eq!(
        ids,
        [
            ("keys", None, false),
            ("sub", Some("test-pc-id-0001"), false)
        ]
    );
    list.groups[1].own_hwid = Some("0123456789abcdef".into());
    let view = project(&inputs(&list, &empty, &ips));
    let sub = &view.groups[1];
    assert_eq!(
        (sub.device_id.as_deref(), sub.own_device_id),
        (Some("0123456789abcdef"), true)
    );
}

/// p-live-fix: a provider notice an older build stored as a feed row is shown as such (never a
/// server); the user's own 127.0.0.1 key is a key; the provider's words reach the group.
#[test]
fn placeholders_and_the_providers_words_are_shown() {
    let mut list = list();
    let mut stub = row("stub", "sub");
    stub.name = "Приложение не поддерживается".into();
    stub.server = "0.0.0.0".into();
    stub.port = 1;
    let mut local = row("local", "keys");
    local.origin = Origin::Manual;
    local.server = "127.0.0.1".into();
    local.port = 10808;
    list.servers.extend([stub, local]);
    list.groups[1].fetch.last_outcome = Some(FetchOutcome::Placeholder);
    list.groups[1].said = Some("Приложение не поддерживается".into());
    let (empty, ips) = (HashMap::new(), HashMap::new());
    let view = project(&inputs(&list, &empty, &ips));
    let marks: Vec<(&str, bool)> = view
        .servers
        .iter()
        .map(|s| (s.id.as_str(), s.placeholder))
        .collect();
    assert_eq!(
        marks,
        [
            ("a", false),
            ("b", false),
            ("c", false),
            ("stub", true),
            ("local", false)
        ]
    );
    let sub = &view.groups[1];
    assert_eq!(sub.last_fetch_error, Some(ui::FetchError::Placeholder));
    assert_eq!(
        sub.provider_said.as_deref(),
        Some("Приложение не поддерживается")
    );
    assert_eq!(view.groups[0].provider_said, None);
}

#[test]
fn projection_maps_rows_and_groups() {
    locales();
    let list = list();
    let exit = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9));
    let extras = HashMap::from([(
        ProfileId::from("a"),
        RowExtras {
            exit_ip: Some(exit),
            last_seen_at: Some(3),
            stealth: Some(ui::Stealth::Reality),
            fingerprint: Some("chrome".into()),
            fingerprint_warning: Some(Msg::new("engine.xray.warn.fingerprintBroken")),
            has_outbound: true,
            engine_plan: None,
            verdict: None,
            config_hidden: false,
            whitelist: None,
        },
    )]);
    let resolved = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
    let ips = HashMap::from([("a.example.net".to_owned(), resolved)]);
    let view = project(&inputs(&list, &extras, &ips));
    assert!(view.loaded && view.geo_lookup_disabled);
    assert_eq!(view.active_id.as_deref(), Some("a"));
    assert!(!view.tunnel_running && !view.tunnel_busy && !view.foreign_vpn);
    let [a, b, c] = &view.servers[..] else {
        panic!("three rows: {:?}", view.servers);
    };
    assert_eq!(a.resolved_ip, Some(resolved));
    assert_eq!(
        (a.exit_ip, a.last_seen_in_subscription_at),
        (Some(exit), Some(3))
    );
    assert_eq!(a.stealth, Some(ui::Stealth::Reality));
    assert_eq!(a.fingerprint.as_deref(), Some("chrome"));
    assert_eq!(
        a.fingerprint_warning.as_ref().map(|m| m.key.as_ref()),
        Some("engine.xray.warn.fingerprintBroken"),
        "the warning reaches the server view"
    );
    assert!(a.has_outbound && a.enabled && a.archived.is_none());
    assert_eq!(a.country.as_deref(), Some("DE"));
    assert_eq!(a.group_id.as_deref(), Some("keys"));
    assert_eq!((a.ping_ms, a.status), (None, ui::OnlineStatus::Unknown));
    // An IP literal needs no lookup; a ping and a dead key show side by side.
    assert_eq!(b.resolved_ip, "203.0.113.7".parse().ok());
    assert_eq!((b.ping_ms, b.status), (Some(42), ui::OnlineStatus::Online));
    let health = b.health.as_ref().expect("health");
    assert!(!health.online && health.checked_at == 7);
    assert_eq!(health.reason, Some(ui::KeyHealthReason::AuthFailed));
    let archive = b.archived.expect("archived");
    assert_eq!(archive.reason, ui::ArchiveReason::Provider);
    assert_eq!(archive.purge_at, 1_000 + ARCHIVE_TTL_MS);
    // A key sealed for another account cannot be used: shown switched off.
    assert!(!c.enabled);
    assert_eq!((c.ping_ms, c.status), (None, ui::OnlineStatus::Offline));
    let [keys, sub] = &view.groups[..] else {
        panic!("two groups: {:?}", view.groups);
    };
    assert_eq!(keys.name, "Manual keys");
    assert_eq!(keys.source, ui::GroupSource::Manual);
    assert_eq!(sub.name, "Subscription");
    assert_eq!(sub.source, ui::GroupSource::Subscription);
    // "Failed" is not "offline": the typed error tells what happened.
    assert_eq!(sub.status, ui::GroupStatus::Unknown);
    assert_eq!(sub.last_fetch_error, Some(ui::FetchError::Http(500)));
    assert_eq!((sub.traffic_used, sub.traffic_total), (Some(15), Some(100)));
    assert_eq!(sub.expires_at, None, "0 = no expiry");
    assert_eq!(sub.refresh_minutes.map(|m| m.get()), Some(15));
}

#[test]
fn the_marker_follows_the_session_on_a_list_server() {
    let list = list();
    let (extras, ips) = (HashMap::new(), HashMap::new());
    let connected = TunnelSnapshot {
        state: TunnelState::Connected,
        ..TunnelSnapshot::default()
    };
    let mut i = inputs(&list, &extras, &ips);
    i.tunnel = Some(&connected);
    i.session = Some("b");
    i.switching = Some("c");
    let view = project(&i);
    assert!(view.tunnel_running);
    assert_eq!(
        view.active_id.as_deref(),
        Some("b"),
        "the session, not the selection"
    );
    assert_eq!(view.switching_to.as_deref(), Some("c"));
    // A local-proxy upstream is not a list server: the selection stays the marker.
    i.session = Some("local-proxy");
    let view = project(&i);
    assert!(!view.tunnel_running);
    assert_eq!(view.active_id.as_deref(), Some("a"));
    // A session left over in a disconnected snapshot does not count.
    let busy = TunnelSnapshot {
        state: TunnelState::Disconnected,
        transition: Some(Transition::Connecting),
        competing_tun: Some("Other VPN".into()),
        ..TunnelSnapshot::default()
    };
    i.tunnel = Some(&busy);
    i.session = Some("b");
    let view = project(&i);
    assert!(!view.tunnel_running && view.tunnel_busy && view.foreign_vpn);
    assert_eq!(view.active_id.as_deref(), Some("a"));
}

#[test]
fn fetch_outcomes_map_to_the_page_errors() {
    let cases = [
        (FetchOutcome::Ok { partial: true }, None),
        (FetchOutcome::EmptyList, Some(ui::FetchError::Empty)),
        (
            FetchOutcome::HwidRequired,
            Some(ui::FetchError::HwidRequired),
        ),
        (FetchOutcome::DeviceLimit, Some(ui::FetchError::DeviceLimit)),
        (FetchOutcome::Placeholder, Some(ui::FetchError::Placeholder)),
        (
            FetchOutcome::Unparseable(sm::BodyKind::Encrypted),
            Some(ui::FetchError::Encrypted),
        ),
        (
            FetchOutcome::Unparseable(sm::BodyKind::Html),
            Some(ui::FetchError::Invalid),
        ),
        (FetchOutcome::Http(404), Some(ui::FetchError::Http(404))),
        (
            FetchOutcome::Network(NetFail::Tls),
            Some(ui::FetchError::Tls),
        ),
        (
            FetchOutcome::Network(NetFail::Dns),
            Some(ui::FetchError::Network),
        ),
        (FetchOutcome::Timeout, Some(ui::FetchError::Timeout)),
    ];
    for (outcome, expected) in cases {
        assert_eq!(fetch_error(outcome), expected, "{outcome:?}");
    }
}

/// The fragments: valid JSON, the same keys in ru and en, every key used by this package's
/// code and every `app.servers.*` key of the code present.
#[test]
fn locale_fragments_pair_up_and_match_the_code() {
    fn keys(prefix: &str, value: &serde_json::Value, out: &mut Vec<String>) {
        match value {
            serde_json::Value::Object(map) => {
                for (k, v) in map {
                    keys(&format!("{prefix}{k}."), v, out);
                }
            }
            _ => out.push(prefix.trim_end_matches('.').to_owned()),
        }
    }
    let flat = |json: &str| {
        let value: serde_json::Value = serde_json::from_str(json).expect("valid JSON");
        let mut out = Vec::new();
        keys("", &value, &mut out);
        out.sort();
        out
    };
    let ru = flat(include_str!("../../locales/app-servers.ru.json"));
    let en = flat(include_str!("../../locales/app-servers.en.json"));
    assert_eq!(ru, en);
    let code = [
        include_str!("mod.rs"),
        include_str!("checks.rs"),
        include_str!("detail.rs"),
        include_str!("export.rs"),
        include_str!("import.rs"),
        include_str!("project.rs"),
    ]
    .concat();
    let mut used: Vec<String> = code
        .split('"')
        .filter(|part| part.starts_with("app.servers."))
        .map(str::to_owned)
        .collect();
    used.sort();
    used.dedup();
    assert_eq!(used, ru, "keys of the code = keys of the fragments");
}

/// A provider-pinned fingerprint current REALITY servers refuse is flagged on either engine
/// (both send it); one only Xray does not know is flagged only when Xray would run the server.
#[test]
fn pinned_fingerprints_are_flagged_where_they_matter() {
    use vpnte_base::types::Engine;

    use super::project::fingerprint_warning;

    let reality = |fp: &str| {
        vpnte_profiles::uri::parse_uri(&format!(
            "vless://00000000-0000-4000-8000-00000000000a@203.0.113.20:443?security=reality\
             &sni=example.com&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=ab&fp={fp}\
             &type=tcp#Fake"
        ))
        .expect("fake REALITY key")
    };
    let runs = |engine| ui::EnginePlan::Runs {
        engine,
        reason: Msg::new("x"),
    };
    let (singbox, xray) = (runs(Engine::SingBox), runs(Engine::Xray));
    for plan in [Some(&singbox), Some(&xray), None] {
        let refused = fingerprint_warning(&reality("edge"), plan).expect("edge is refused");
        assert_eq!(refused.key, "engine.xray.warn.fingerprintRejected");
    }
    assert_eq!(fingerprint_warning(&reality("chrome"), Some(&xray)), None);
    let unknown = reality("netscape");
    assert_eq!(fingerprint_warning(&unknown, Some(&singbox)), None);
    assert_eq!(
        fingerprint_warning(&unknown, Some(&xray)).map(|m| m.key),
        Some("engine.xray.warn.fingerprintUnknown".into())
    );
}
