use super::*;
use crate::panels::model::ServerRowView;

/// The instance template of `ExternalProxyCard.test.ts:50-70`.
fn running(slot: u16) -> ProxyRowView {
    ProxyRowView {
        slot,
        process_running: true,
        ready: true,
        health: ProxyHealth::Healthy,
        port: Some(17_990),
        proxy_url: Some("socks5://127.0.0.1:17990".into()),
        country: Some("DE".into()),
        ..ProxyRowView::default()
    }
}

fn view(rows: Vec<ProxyRowView>) -> ProxiesView {
    ProxiesView {
        rows,
        choices: Vec::new(),
    }
}

/// Spec ui-dashboard §7.4 (`ExternalProxyCard.test.ts:50-70`), all four cases.
#[test]
fn refresh_interval_follows_route_health() {
    // backs off while no proxy instance is running
    assert_eq!(refresh_interval(&view(vec![])), IDLE_REFRESH);
    assert_eq!(IDLE_REFRESH, Duration::from_millis(10_000));
    // keeps healthy running routes visibly fresh without polling every five seconds
    assert_eq!(refresh_interval(&view(vec![running(1)])), HEALTHY_REFRESH);
    assert_eq!(HEALTHY_REFRESH, Duration::from_millis(10_000));
    // refreshes a starting or unhealthy route more quickly
    let starting = ProxyRowView {
        ready: false,
        health: ProxyHealth::Starting,
        ..running(1)
    };
    assert_eq!(refresh_interval(&view(vec![starting])), UNSTABLE_REFRESH);
    assert_eq!(UNSTABLE_REFRESH, Duration::from_millis(3_000));
    let degraded = ProxyRowView {
        health: ProxyHealth::Degraded,
        ..running(2)
    };
    assert_eq!(
        refresh_interval(&view(vec![running(1), degraded])),
        UNSTABLE_REFRESH
    );
    // keeps disabled routes on the slower health refresh cadence
    let disabled = ProxyRowView {
        process_running: false,
        health: ProxyHealth::Failed,
        ..running(1)
    };
    assert_eq!(refresh_interval(&view(vec![disabled])), HEALTHY_REFRESH);
}

/// `firstAvailableSlot` (`ExternalProxyCard.tsx:99-104`): failed / disabled slots are reused.
#[test]
fn first_free_slot_skips_running_slots_only() {
    assert_eq!(first_free_slot(&[]), 1);
    assert_eq!(first_free_slot(&[running(1), running(2)]), 3);
    assert_eq!(first_free_slot(&[running(2)]), 1);
    let failed = ProxyRowView {
        process_running: false,
        ..running(1)
    };
    assert_eq!(first_free_slot(&[failed, running(2)]), 1);
    assert_eq!(running_count(&[running(1), running(3)]), 2);
}

/// Country summary (`ExternalProxyCard.tsx:123-131`): distinct, running only, six + « +N».
#[test]
fn country_summary_names_six_then_counts() {
    assert_eq!(country_summary(&[]), None);
    let with = |slot: u16, cc: &str| ProxyRowView {
        country: Some(cc.into()),
        ..running(slot)
    };
    let s = country_summary(&[with(1, "DE"), with(2, "FI"), with(3, "DE")]).unwrap();
    assert_eq!((s.text.as_str(), s.title.as_str()), ("DE, FI", "DE, FI"));
    let stopped = ProxyRowView {
        process_running: false,
        ..with(4, "NL")
    };
    assert_eq!(country_summary(&[stopped]), None);
    let many: Vec<ProxyRowView> = ["DE", "FI", "NL", "PL", "SE", "US", "GB", "FR"]
        .iter()
        .zip(1..)
        .map(|(cc, slot)| with(slot, cc))
        .collect();
    let s = country_summary(&many).unwrap();
    assert_eq!(s.text, "DE, FI, NL, PL, SE, US +2");
    assert_eq!(s.title, "DE, FI, NL, PL, SE, US, GB, FR");
}

fn choice(id: &str, in_proxy: bool, vpn_server: bool) -> ProxyChoice {
    ProxyChoice {
        id: id.into(),
        name: format!("Server {id}"),
        country: Some("PL".into()),
        protocol: Some("hysteria2".into()),
        health: ServerHealth::Online,
        in_proxy,
        vpn_server,
    }
}

/// Picker options (`ExternalProxyCard.tsx:302-325`): label parts, assignment, indicator.
#[test]
fn choice_labels_join_the_known_parts() {
    let key = |m: &Msg| m.key.to_string();
    assert_eq!(
        choice_label(&choice("a", false, false), key),
        "Server a · PL · HYSTERIA2"
    );
    assert_eq!(
        choice_label(&choice("a", true, true), key),
        "Server a · PL · HYSTERIA2 · ui.panels.proxy.inProxy"
    );
    let bare = ProxyChoice {
        country: None,
        protocol: Some(String::new()),
        ..choice("b", false, true)
    };
    assert_eq!(
        choice_label(&bare, key),
        "Server b · ui.panels.proxy.vpnServer"
    );
    assert_eq!(Indicator::of(ServerHealth::Online), Indicator::Success);
    assert_eq!(Indicator::of(ServerHealth::Offline), Indicator::Danger);
    assert_eq!(Indicator::of(ServerHealth::Unknown), Indicator::Muted);
    assert_eq!(
        Indicator::Muted.label().key,
        "ui.panels.proxy.serverUnchecked"
    );
}

/// Selection after a refresh (`ExternalProxyCard.tsx:151-155`, verifier note 3).
#[test]
fn selection_survives_only_while_usable() {
    let list = [
        choice("nl", false, true),
        choice("de", true, false),
        choice("pl", false, false),
        choice("se", false, false),
    ];
    assert_eq!(keep_selection(Some("se"), &list).as_deref(), Some("se"));
    assert_eq!(keep_selection(Some("de"), &list).as_deref(), Some("pl"));
    assert_eq!(keep_selection(Some("gone"), &list).as_deref(), Some("pl"));
    assert_eq!(keep_selection(None, &list).as_deref(), Some("pl"));
    assert_eq!(keep_selection(Some("nl"), &list[..2]), None);
}

/// Row read-outs (`ExternalProxyCard.tsx:375-418`) and the two-text-node meta line
/// (`connected-*.textnodes.json`: runs `[6, 8]` = ":18001" + " · 46 мс").
#[test]
fn proxy_rows_read_out_address_and_state() {
    let render = |m: &Msg| match m.key.as_ref() {
        "ui.panels.proxy.metaLatency" => format!("{} мс", m.args[0].1),
        other => other.to_owned(),
    };
    let row = ProxyRowView {
        port: Some(18_001),
        latency_ms: Some(46),
        ..running(1)
    };
    let (head, tail) = proxy_meta(&row, render);
    assert_eq!(
        (head.as_str(), tail.as_deref()),
        (":18001", Some(" · 46 мс"))
    );
    assert_eq!(
        (head.chars().count(), tail.unwrap().chars().count()),
        (6, 8)
    );
    assert_eq!(proxy_dot_class(&row), "swiss-health-dot shrink-0");
    assert_eq!(proxy_dot_title(&row).key, "ui.panels.proxy.health.healthy");
    let rotating = ProxyRowView {
        health: ProxyHealth::Rotating,
        ..row.clone()
    };
    assert_eq!(
        proxy_meta(&rotating, render).1.as_deref(),
        Some(" · ui.panels.proxy.metaStarting")
    );
    assert_eq!(
        proxy_dot_class(&rotating),
        "swiss-health-dot shrink-0 is-unknown is-wait"
    );
    let failed = ProxyRowView {
        process_running: false,
        health: ProxyHealth::Failed,
        port: None,
        proxy_url: None,
        latency_ms: None,
        last_error: Some(Msg::new("proxies.portBusy")),
        ..row
    };
    assert_eq!(proxy_meta(&failed, render), (DASH.to_owned(), None));
    assert_eq!(
        proxy_dot_class(&failed),
        "swiss-health-dot shrink-0 is-offline"
    );
    assert_eq!(proxy_dot_title(&failed).key, "proxies.portBusy");
    let url_only = ProxyRowView {
        proxy_url: Some("http://127.0.0.1:8080".into()),
        ..failed
    };
    assert_eq!(proxy_meta(&url_only, render).0, "http://127.0.0.1:8080");
}

const MIN: UnixMs = 60_000;
const NOW: UnixMs = 1_794_396_896_000;

fn server(id: &str, ping: Option<u32>, health: ServerHealth, ago: Option<i64>) -> ServerRowView {
    ServerRowView {
        id: id.into(),
        name: id.into(),
        country: Some(id[4..6].to_uppercase()),
        protocol: Some("vless".into()),
        ping,
        health_latency: ping,
        health,
        checked_at: ago.map(|m| NOW - m * MIN),
    }
}

/// The reference servers (`fixtures.md` "Servers"): Germany has the best ping among the
/// servers that are not offline, Netherlands is the ink row, USA is muted.
fn reference() -> ServersView {
    use ServerHealth::*;
    ServersView {
        rows: vec![
            server("srv-nl-ams", Some(38), Online, Some(3)),
            server("srv-de-fra", Some(31), Online, Some(3)),
            server("srv-fi-hel", Some(54), Online, Some(7)),
            server("srv-pl-waw", Some(47), Online, Some(12)),
            server("srv-se-sto", None, Unknown, None),
            server("srv-us-nyc", Some(12), Offline, Some(5)),
        ],
        active_id: Some("srv-nl-ams".into()),
        tun_running: false,
        locked: false,
    }
}

/// Servers panel rows (`SwissPanels.tsx:151-276`): best chip, selection, muted offline
/// row, health ages; an offline server never gets the chip even with the lowest ping.
#[test]
fn server_lines_match_the_reference_panel() {
    let lines = server_lines(&reference(), &LocalPings::default(), NOW);
    let best: Vec<&str> = lines
        .iter()
        .filter(|l| l.best)
        .map(|l| l.id.as_str())
        .collect();
    assert_eq!(best, ["srv-de-fra"]);
    assert!(lines[0].selected && !lines[0].muted);
    assert!(lines[5].muted && !lines[5].selected);
    assert_eq!(
        lines[0].health_text,
        Msg::new("swiss.minAgo").arg("n", 3_u64)
    );
    assert_eq!(
        lines[3].health_text,
        Msg::new("swiss.minAgo").arg("n", 12_u64)
    );
    assert_eq!(lines[4].health_text, Msg::new("swiss.unchecked"));
    assert_eq!(lines[5].health_text, Msg::new("swiss.offline"));
    assert_eq!(lines[4].ping, None);
    assert_eq!(lines[1].country.as_deref(), Some("DE"));
    let mut just = reference();
    just.rows[0].checked_at = Some(NOW - 10_000);
    just.rows[0].health = ServerHealth::Online;
    let line = &server_lines(&just, &LocalPings::default(), NOW)[0];
    assert_eq!(line.health_text, Msg::new("swiss.justNow"));
}

/// Local pings (`SwissPanels.tsx:143-194`): an in-flight ping hides the number, a result
/// wins over the stored ping and may move the chip; a route change discards late results.
#[test]
fn local_pings_follow_the_route() {
    let view = reference();
    let mut local = LocalPings::default();
    let route = local.begin("srv-pl-waw");
    let lines = server_lines(&view, &local, NOW);
    assert!(lines[3].pinging && lines[3].ping.is_none());
    local.finish("srv-pl-waw", route, Some(20));
    let lines = server_lines(&view, &local, NOW);
    assert!(!lines[3].pinging && lines[3].best && !lines[1].best);
    assert_eq!(lines[3].ping, Some(20));
    // a measurement that started before the route changed is dropped
    let route = local.begin("srv-fi-hel");
    local.new_route();
    local.finish("srv-fi-hel", route, Some(5));
    assert_eq!(
        local,
        LocalPings {
            route: 1,
            pings: HashMap::new()
        }
    );
    assert_eq!(server_lines(&view, &local, NOW)[2].ping, Some(54));
    // an unanswered ping shows the dash, not the stored value
    let route = local.begin("srv-nl-ams");
    local.finish("srv-nl-ams", route, None);
    assert_eq!(server_lines(&view, &local, NOW)[0].ping, None);
    local.clear();
    assert_eq!(local.get("srv-nl-ams"), None);
}
