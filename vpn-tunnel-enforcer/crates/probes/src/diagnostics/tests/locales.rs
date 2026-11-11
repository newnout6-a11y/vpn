//! Locale fragments: valid JSON, the same keys and placeholders in ru and en, and every key the
//! code emits present.
use vpnte_base::Msg;

use crate::diagnostics::checks::{self, ProfileFacts, ProxyState};
use crate::diagnostics::endpoints::{ENDPOINTS, endpoint_item, parse_write_out};
use crate::diagnostics::plan::{PlanInputs, TunnelInfo, routing_plan};
use crate::diagnostics::routing::derive_routing_verdict;
use crate::diagnostics::sysinfo::OsInfo;
use crate::diagnostics::{Category, CheckItem};
use crate::local_proxy::{LocalProxy, Source, SystemProxy};
use crate::test_support::{flatten, placeholders};

const RU: &str = include_str!("../../../locales/probes-diag.ru.json");
const EN: &str = include_str!("../../../locales/probes-diag.en.json");

#[test]
fn ru_and_en_match() {
    let (ru, en) = (flatten(RU), flatten(EN));
    assert_eq!(ru.keys().collect::<Vec<_>>(), en.keys().collect::<Vec<_>>());
    for (k, v) in &ru {
        assert_eq!(placeholders(v), placeholders(&en[k]), "placeholders of {k}");
        assert!(k.starts_with("probes."), "{k}");
    }
}

fn plan_msgs() -> Vec<Msg> {
    let proxy = |verified| {
        Some(LocalProxy {
            addr: "127.0.0.1:1080".parse().unwrap(),
            kind: Default::default(),
            source: Source::TypicalPort,
            verified,
            public_ip: None,
        })
    };
    let tun = |conflict| TunnelInfo {
        name: "wg".into(),
        description: "WireGuard".into(),
        address: "10.0.0.2".parse().unwrap(),
        conflict,
    };
    let base = PlanInputs {
        tunnels: Some(Vec::new()),
        ..PlanInputs::default()
    };
    let cases = [
        PlanInputs {
            tun_running: true,
            tunnels: Some(vec![tun(true)]),
            ..base.clone()
        },
        PlanInputs {
            tunnels: Some(vec![tun(true)]),
            proxy: proxy(true),
            ..base.clone()
        },
        PlanInputs {
            direct_vpn: true,
            ..base.clone()
        },
        PlanInputs {
            direct_vpn: true,
            active_profile: Some("p".into()),
            tunnels: None,
            ..base.clone()
        },
        base.clone(),
        PlanInputs {
            proxy: proxy(false),
            ..base.clone()
        },
        PlanInputs {
            proxy: proxy(true),
            ..base
        },
    ];
    let mut out = Vec::new();
    for inputs in cases {
        let plan = routing_plan(&inputs);
        if let Err(e) = plan.gate() {
            out.push(e.user_msg());
        }
        out.extend([plan.title, plan.explanation, plan.before, plan.after]);
        out.extend(plan.note);
        out.extend(plan.blockers);
        out.extend(
            plan.steps
                .into_iter()
                .flat_map(|s| [s.label, s.before, s.after]),
        );
    }
    out
}

fn report_items() -> Vec<CheckItem> {
    let ip = "1.2.3.4".parse().unwrap();
    let mut items = vec![
        checks::app_item(&OsInfo::default(), "2.0.0", false, &[]),
        crate::diagnostics::report::settings_item(&vpnte_core::settings::Settings::default()),
        checks::tun_item(true, None),
        checks::tun_item(false, None),
        checks::binaries_item(&[("a", None)], &[]),
        checks::binaries_item(&[("a", Some(1))], &[]),
        checks::dns_item(&Ok(vec![ip])),
        checks::dns_item(&Ok(Vec::new())),
        checks::dns_item(&Err("x".into())),
        checks::tun_log_item(&[], true),
        checks::tun_log_item(&["ERROR failed".into()], true),
        checks::tun_log_item(&[], false),
        checks::app_log_item(&[], 0),
        checks::profile_item(None),
        checks::profile_item(Some(&ProfileFacts::default())),
        checks::routes_item(&Err("x".into()), |_| String::new(), None, None),
        checks::routes_item(&Ok(Vec::new()), |_| String::new(), Some(1), Some(true)),
        checks::routes_item(&Ok(Vec::new()), |_| String::new(), Some(1), None),
        checks::routes_item(&Ok(Vec::new()), |_| String::new(), None, None),
    ];
    items.push(checks::app_log_item(
        &[vpnte_core::logging::Problem {
            at: 0,
            level: tracing::Level::WARN,
            target: "t".into(),
            msg: "m".into(),
        }],
        0,
    ));
    let states = [
        ProxyState::DirectVpn(true),
        ProxyState::DirectVpn(false),
        ProxyState::Missing {
            external_tunnel: true,
            listeners: 0,
        },
        ProxyState::Missing {
            external_tunnel: false,
            listeners: 1,
        },
        ProxyState::Missing {
            external_tunnel: false,
            listeners: 0,
        },
        ProxyState::Probed {
            addr: "a".into(),
            open: true,
        },
        ProxyState::Probed {
            addr: "a".into(),
            open: false,
        },
    ];
    items.extend(
        states
            .iter()
            .map(|s| checks::proxy_item(s, checks::system_proxy_rows(&SystemProxy::default()))),
    );
    items.extend(checks::adapter_items(&Ok(Vec::new())));
    items.extend(checks::adapter_items(&Err("x".into())));
    items.extend(checks::client_items(&[], &[], false));
    items.extend(checks::service_items(&[], &[]));
    for (id, label, url) in ENDPOINTS {
        items.push(endpoint_item(
            id,
            label,
            url,
            Ok(parse_write_out(Some(0), "200|1.2.3.4|0.1|")),
        ));
        items.push(endpoint_item(
            id,
            label,
            url,
            Ok(parse_write_out(Some(7), "000||0|x")),
        ));
        items.push(endpoint_item(id, label, url, Err("x".into())));
    }
    items
}

#[test]
fn every_emitted_key_exists() {
    let (ru, en) = (flatten(RU), flatten(EN));
    let mut msgs = plan_msgs();
    for (t, vpn, direct, smart, ru_ip) in [
        (false, None, None, false, None),
        (true, None, None, false, None),
        (true, Some("1.1.1.1"), Some("1.1.1.1"), false, None),
        (true, Some("1.1.1.1"), Some("2.2.2.2"), true, None),
        (
            true,
            Some("1.1.1.1"),
            Some("2.2.2.2"),
            true,
            Some("2.2.2.2"),
        ),
        (
            true,
            Some("1.1.1.1"),
            Some("2.2.2.2"),
            true,
            Some("1.1.1.1"),
        ),
        (true, Some("1.1.1.1"), Some("2.2.2.2"), false, None),
    ] {
        let p = |s: Option<&str>| s.map(|s| s.parse().unwrap());
        msgs.push(derive_routing_verdict(t, p(vpn), p(direct), smart, p(ru_ip)).1);
    }
    use Category::*;
    msgs.extend(
        [
            App, Tun, Proxy, Network, Internet, Windows, Logs, Routing, Profile,
        ]
        .map(Category::msg),
    );
    for item in report_items() {
        msgs.extend([item.label, item.value]);
    }
    for m in msgs {
        assert!(
            ru.contains_key(m.key.as_ref()) && en.contains_key(m.key.as_ref()),
            "missing key {}",
            m.key
        );
        // Every placeholder of the text is supplied (a missing one renders as `{{name}}`).
        for name in placeholders(&ru[m.key.as_ref()]) {
            assert!(
                m.args.iter().any(|(k, _)| *k == name),
                "{} lacks the argument {name}",
                m.key
            );
        }
    }
}
