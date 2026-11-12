//! Pure projections of the sections, the wizard routing rule and the locale fragments.
use vpnte_base::ErrorKind;
use vpnte_base::types::KillSwitchLevel;
use vpnte_core::settings::Settings;
use vpnte_engine::routing::RulesDoc;
use vpnte_engine::routing::domain::{DomainAction as RuleAction, DomainPattern};
use vpnte_tunnel::fsm::{TunnelSnapshot, TunnelState};
use vpnte_ui::settings as ui;
use vpnte_ui::wizard::{Connection, KeyText, Routing, WizardChoices};
use vpnte_winnet::toast::NotifySetting;
use vpnte_winnet::wfp::{ExceptionTarget, KillSwitchException, ProtectionSettings};

use super::super::actions::os_state;
use super::super::project::{self, kill_switch_view};
use super::super::wizard::routing_for;
use crate::services::KillSwitchStatus;
use crate::svc_core::docs::{CustomTheme, ThemesDoc};

fn status(level: KillSwitchLevel) -> KillSwitchStatus {
    KillSwitchStatus {
        settings: ProtectionSettings {
            level,
            ..ProtectionSettings::default()
        },
        wfp: None,
    }
}

/// Without a WFP read-back only what the level means in proxy mode is shown: "If the VPN
/// drops" waits for a lost engine (`Blocked`); a stored "Always" works as "If the VPN drops"
/// without the helper service (ks-a); never "engaged".
#[test]
fn kill_switch_view_without_wfp_is_honest() {
    let idle = TunnelSnapshot::default();
    let blocked = TunnelSnapshot {
        state: TunnelState::Blocked,
        ..TunnelSnapshot::default()
    };
    let view = |level, snap: &TunnelSnapshot| kill_switch_view(&status(level), snap, false).status;
    assert_eq!(view(KillSwitchLevel::Off, &idle), ui::ProtectionStatus::Off);
    assert_eq!(
        view(KillSwitchLevel::Standard, &idle),
        ui::ProtectionStatus::Armed
    );
    assert_eq!(
        view(KillSwitchLevel::Standard, &blocked),
        ui::ProtectionStatus::Blocking
    );
    assert_eq!(
        view(KillSwitchLevel::Strict, &idle),
        ui::ProtectionStatus::Armed
    );
    let strict = kill_switch_view(&status(KillSwitchLevel::Strict), &idle, false);
    assert!(!strict.firewall_blocks_outbound && !strict.hyperv_unfiltered);
    assert!(!strict.always_available);
    assert_eq!(
        strict.level,
        KillSwitchLevel::Strict,
        "the stored value stays"
    );
    assert!(kill_switch_view(&status(KillSwitchLevel::Strict), &idle, true).always_available);
}

/// Exceptions show their canonical value and the wide-network warning.
#[test]
fn kill_switch_exceptions_are_listed() {
    let exception = |id: &str, net: &str| KillSwitchException {
        id: id.into(),
        target: ExceptionTarget::Ip(net.parse().expect("net")),
        label: id.into(),
    };
    let mut st = status(KillSwitchLevel::Standard);
    st.settings.exceptions = vec![
        exception("e1", "16.0.0.0/4"),
        exception("e2", "192.0.2.0/24"),
    ];
    let view = kill_switch_view(&st, &TunnelSnapshot::default(), false);
    assert_eq!(view.exceptions.len(), 2);
    assert_eq!(view.exceptions[0].kind, ui::ExceptionKind::Ip);
    assert!(view.exceptions[0].broad);
    assert!(!view.exceptions[1].broad);
    assert_eq!(view.exceptions[1].value, "192.0.2.0/24");
}

/// DNS: built-ins listed, the transport derived from the address, the choice shown. Domain
/// rules keep their order and hit counts.
#[test]
fn dns_and_domain_views() {
    let mut doc = RulesDoc::default();
    let view = project::dns_view(&doc);
    assert!(view.profiles.iter().any(|p| p.builtin));
    assert_eq!(view.active, None);
    let addr = "https://dns.example/dns-query".parse().expect("doh");
    let id = doc.add_dns_profile("Mine", addr, None).expect("added");
    doc.select_dns(Some(&id)).expect("selected");
    let view = project::dns_view(&doc);
    let mine = view.profiles.iter().find(|p| p.id == id).expect("listed");
    assert_eq!(mine.kind, ui::DnsKind::Doh);
    assert!(!mine.builtin);
    assert_eq!(view.active.as_deref(), Some(id.as_str()));

    let pattern = |raw: &str| DomainPattern::parse(raw).expect("pattern");
    let first = doc
        .add_domain_rule(pattern("*.example.com"), RuleAction::Direct)
        .expect("rule");
    doc.add_domain_rule(pattern("example.org"), RuleAction::Block)
        .expect("rule");
    doc.add_hits(&[(first, 3)].into_iter().collect());
    let domains = project::domains_view(&doc, true);
    assert!(domains.smart_ru);
    assert_eq!(domains.rules.len(), 2);
    assert_eq!(domains.rules[0].pattern, "*.example.com");
    assert_eq!(domains.rules[0].action, ui::DomainAction::Direct);
    assert_eq!(domains.rules[0].hits, 3);
    assert_eq!(domains.rules[1].action, ui::DomainAction::Block);
}

/// Notification switches in `NotifyEvent::ALL` order, and Windows' own setting.
#[test]
fn notifications_view_and_windows_state() {
    let mut s = Settings::default();
    s.notifications.leak_detected = false;
    s.desktop_notifications = false;
    let view = project::notifications_view(&s, ui::OsNotifications::Blocked);
    assert!(!view.enabled);
    assert!(!view.event(ui::NotifyEvent::LeakDetected));
    assert!(view.event(ui::NotifyEvent::VpnConnect));
    assert_eq!(view.os, ui::OsNotifications::Blocked);
    assert_eq!(
        os_state(NotifySetting::Enabled),
        ui::OsNotifications::Allowed
    );
    assert_eq!(
        os_state(NotifySetting::Unregistered),
        ui::OsNotifications::Unknown
    );
    assert_eq!(
        os_state(NotifySetting::DisabledByGroupPolicy),
        ui::OsNotifications::Blocked
    );
}

/// Built-ins first, then the user's themes; only existing ids can be activated.
#[test]
fn themes_list_and_existence() {
    let doc = ThemesDoc {
        custom_themes: vec![CustomTheme {
            id: "custom-1".into(),
            name: "Ocean".into(),
            mode: "dark".into(),
            colors: Default::default(),
        }],
        ..ThemesDoc::default()
    };
    let list = project::themes(&doc);
    assert_eq!(list.len(), 4);
    assert!(list[..3].iter().all(|t| t.builtin));
    assert_eq!(list[3].mode, ui::ThemeMode::Dark);
    assert!(project::theme_exists(&doc, "custom-1"));
    assert!(project::theme_exists(&doc, "builtin-dark"));
    assert!(!project::theme_exists(&doc, "deleted"));
}

/// Wizard routing without TUN capture: Soft as chosen; a key (the page offers no Soft with a
/// key) is stored as Soft and the user is told; Hard over Soft with a local proxy is refused.
#[test]
fn wizard_routing_without_tun() {
    use vpnte_core::settings::RoutingMode as R;
    let choices = |connection, routing| WizardChoices {
        lang: vpnte_base::i18n::Lang::Ru,
        connection,
        routing,
        key: (connection == Connection::Key).then(|| KeyText("vless://fake".into())),
        kill_switch: KillSwitchLevel::Off,
        autostart: false,
    };
    let key_hard = choices(Connection::Key, Routing::Hard);
    assert_eq!(
        routing_for(&key_hard, false).expect("soft"),
        (R::Soft, true)
    );
    assert_eq!(
        routing_for(&key_hard, true).expect("hard"),
        (R::Hard, false)
    );
    let proxy_soft = choices(Connection::LocalProxy, Routing::Soft);
    assert_eq!(
        routing_for(&proxy_soft, false).expect("soft"),
        (R::Soft, false)
    );
    let proxy_hard = choices(Connection::LocalProxy, Routing::Hard);
    let err = routing_for(&proxy_hard, false).expect_err("needs admin");
    assert_eq!(err.kind, ErrorKind::Permission);
}
