//! Pure projections: backend documents -> the page's view models, and the enum mappings both
//! ways (the UI keeps its own copies of the settings enums, without serde).
use vpnte_automation::tweaks::DevTargets;
use vpnte_base::Msg;
use vpnte_base::i18n::Lang;
use vpnte_base::types::KillSwitchLevel;
use vpnte_core::settings::{self as core, RuleSetMode, Settings};
use vpnte_engine::routing::RulesDoc;
use vpnte_engine::routing::dns::DnsAddr;
use vpnte_engine::routing::domain::DomainAction as RuleAction;
use vpnte_engine::routing::smart_ru::{SmartRoute, SmartRu};
use vpnte_tunnel::fsm::{TunnelSnapshot, TunnelState};
use vpnte_ui::settings as ui;
use vpnte_winnet::wfp::{self, KillSwitchState};

use crate::services::KillSwitchStatus;
use crate::svc_core::docs::{BUILTIN_DARK, BUILTIN_LIGHT, BUILTIN_SYSTEM, ThemesDoc};

/// Capture quota shown while packet capture is not part of the build (the UI's default).
pub const CAPTURE_QUOTA_MB: u32 = 8192;

/// The draft fields as stored. Packet capture is not part of this build, so it shows off
/// whatever an old import stored.
pub fn settings_view(s: &Settings, soft: &DevTargets, leak_protection: bool) -> ui::SettingsView {
    ui::SettingsView {
        connection_mode: connection_mode(s.connection_mode),
        routing_mode: routing_mode(s.routing_mode),
        soft_git: soft.git,
        soft_gradle: soft.gradle,
        soft_studio: soft.android_studio,
        proxy_bypass: s.proxy_bypass.join("\n"),
        proxy_bypass_auto: s.proxy_bypass_auto,
        proxy_engine: s.proxy_engine,
        leak_protection,
        public_wifi_compatibility: s.public_wifi_compatibility,
        auto_restart_on_crash: s.auto_restart_on_crash,
        stealth_mode: s.stealth_mode,
        adaptive_bypass: s.adaptive_bypass,
        disable_geo_lookup: s.disable_geo_lookup,
        smart_ru_split: s.smart_ru_split,
        smart_ru_maps_direct: s.smart_ru_maps_direct,
        smart_ru_auto_update: s.smart_ru_rule_set_mode == RuleSetMode::Managed
            && s.smart_ru_rule_set_auto_update,
        minimize_to_tray: s.minimize_to_tray,
        autopilot: s.autopilot,
        domain_enrichment: s.domain_enrichment,
        advanced_mode: s.advanced_mode,
        proxy_override: s
            .proxy_override
            .as_ref()
            .map(|p| p.addr.to_string())
            .unwrap_or_default(),
        proxy_type: s.proxy_type,
        bootstrap_route_mode: bootstrap_mode(s.bootstrap_route_mode),
        check_interval_ms: s.check_interval_ms,
        adaptive_bypass_server_fallback: s.adaptive_bypass_server_fallback,
        deep_inspection: false,
        deep_inspection_max_mb: s.deep_inspection_max_mb,
        capture_quota_mb: CAPTURE_QUOTA_MB,
    }
}

pub fn connection_mode(m: core::ConnectionMode) -> ui::ConnectionMode {
    match m {
        core::ConnectionMode::LocalProxy => ui::ConnectionMode::LocalProxy,
        core::ConnectionMode::DirectVpn => ui::ConnectionMode::DirectVpn,
    }
}

pub fn core_connection_mode(m: ui::ConnectionMode) -> core::ConnectionMode {
    match m {
        ui::ConnectionMode::LocalProxy => core::ConnectionMode::LocalProxy,
        ui::ConnectionMode::DirectVpn => core::ConnectionMode::DirectVpn,
    }
}

pub fn routing_mode(m: core::RoutingMode) -> ui::RoutingMode {
    match m {
        core::RoutingMode::Hard => ui::RoutingMode::Hard,
        core::RoutingMode::Soft => ui::RoutingMode::Soft,
    }
}

pub fn core_routing_mode(m: ui::RoutingMode) -> core::RoutingMode {
    match m {
        ui::RoutingMode::Hard => core::RoutingMode::Hard,
        ui::RoutingMode::Soft => core::RoutingMode::Soft,
    }
}

pub fn bootstrap_mode(m: core::BootstrapRouteMode) -> ui::BootstrapRouteMode {
    match m {
        core::BootstrapRouteMode::Auto => ui::BootstrapRouteMode::Auto,
        core::BootstrapRouteMode::Direct => ui::BootstrapRouteMode::Direct,
        core::BootstrapRouteMode::LocalProxy => ui::BootstrapRouteMode::LocalProxy,
    }
}

pub fn core_bootstrap_mode(m: ui::BootstrapRouteMode) -> core::BootstrapRouteMode {
    match m {
        ui::BootstrapRouteMode::Auto => core::BootstrapRouteMode::Auto,
        ui::BootstrapRouteMode::Direct => core::BootstrapRouteMode::Direct,
        ui::BootstrapRouteMode::LocalProxy => core::BootstrapRouteMode::LocalProxy,
    }
}

pub fn notify_method(m: core::NotifyMethod) -> ui::NotifyMethod {
    match m {
        core::NotifyMethod::System => ui::NotifyMethod::System,
        core::NotifyMethod::InApp => ui::NotifyMethod::InApp,
        core::NotifyMethod::Both => ui::NotifyMethod::Both,
    }
}

pub fn core_notify_method(m: ui::NotifyMethod) -> core::NotifyMethod {
    match m {
        ui::NotifyMethod::System => core::NotifyMethod::System,
        ui::NotifyMethod::InApp => core::NotifyMethod::InApp,
        ui::NotifyMethod::Both => core::NotifyMethod::Both,
    }
}

pub fn rule_action(a: RuleAction) -> ui::DomainAction {
    match a {
        RuleAction::Vpn => ui::DomainAction::Vpn,
        RuleAction::Direct => ui::DomainAction::Direct,
        RuleAction::Block => ui::DomainAction::Block,
    }
}

pub fn core_rule_action(a: ui::DomainAction) -> RuleAction {
    match a {
        ui::DomainAction::Vpn => RuleAction::Vpn,
        ui::DomainAction::Direct => RuleAction::Direct,
        ui::DomainAction::Block => RuleAction::Block,
    }
}

pub fn exception_kind(k: wfp::ExceptionKind) -> ui::ExceptionKind {
    match k {
        wfp::ExceptionKind::App => ui::ExceptionKind::App,
        wfp::ExceptionKind::Ip => ui::ExceptionKind::Ip,
    }
}

pub fn wfp_exception_kind(k: ui::ExceptionKind) -> wfp::ExceptionKind {
    match k {
        ui::ExceptionKind::App => wfp::ExceptionKind::App,
        ui::ExceptionKind::Ip => wfp::ExceptionKind::Ip,
    }
}

/// The kill switch section. With a WFP read-back (elevated) the filters' own state; without
/// one only what the level means in proxy mode (NOADMIN §2): "If the VPN drops" holds programs
/// that honour the system proxy once the engine is lost (`Blocked`). A stored "Always" works as
/// "If the VPN drops" until `always` (the helper service keeps it safe).
pub fn kill_switch_view(
    ks: &KillSwitchStatus,
    tunnel: &TunnelSnapshot,
    always: bool,
) -> ui::KillSwitchView {
    let level = ks.settings.level;
    let status = match &ks.wfp {
        Some(wfp) => match wfp.kill_switch {
            KillSwitchState::Off => ui::ProtectionStatus::Off,
            KillSwitchState::Armed => ui::ProtectionStatus::Armed,
            KillSwitchState::Engaged => ui::ProtectionStatus::Engaged,
            KillSwitchState::Blocking => ui::ProtectionStatus::Blocking,
            KillSwitchState::Failed => {
                ui::ProtectionStatus::Unconfirmed(wfp.last_error.as_ref().map_or_else(
                    || Msg::new("app.settings.killSwitch.unconfirmed"),
                    |e| e.msg(),
                ))
            }
        },
        None => match level.effective(always) {
            KillSwitchLevel::Off => ui::ProtectionStatus::Off,
            _ if tunnel.state == TunnelState::Blocked => ui::ProtectionStatus::Blocking,
            _ => ui::ProtectionStatus::Armed,
        },
    };
    let exceptions = ks
        .settings
        .exceptions
        .iter()
        .map(|e| ui::ExceptionView {
            id: e.id.clone(),
            kind: exception_kind(e.target.kind()),
            value: e.target.value(),
            label: e.label.clone(),
            broad: wfp::broad_warning(&e.target).is_some(),
        })
        .collect();
    ui::KillSwitchView {
        level,
        status,
        exceptions,
        firewall_blocks_outbound: ks
            .wfp
            .as_ref()
            .is_some_and(|w| w.firewall_warning().is_some()),
        hyperv_unfiltered: ks
            .wfp
            .as_ref()
            .is_some_and(|w| w.hyperv_warning().is_some()),
        always_available: always,
    }
}

/// Transport of a resolver address.
pub fn dns_kind(addr: &DnsAddr) -> ui::DnsKind {
    match addr {
        DnsAddr::Plain(_) => ui::DnsKind::Plain,
        DnsAddr::Doh { .. } => ui::DnsKind::Doh,
        DnsAddr::Dot { .. } => ui::DnsKind::Dot,
    }
}

/// Built-in and custom profiles; a choice pointing at a deleted profile shows as automatic.
pub fn dns_view(doc: &RulesDoc) -> ui::DnsView {
    let profiles = doc
        .dns_profiles()
        .into_iter()
        .map(|p| ui::DnsProfileView {
            builtin: p.is_builtin(),
            kind: dns_kind(&p.primary),
            address: match &p.secondary {
                Some(second) => format!("{}, {second}", p.primary),
                None => p.primary.to_string(),
            },
            name: p.name,
            id: p.id,
        })
        .collect();
    ui::DnsView {
        profiles,
        active: doc.active_dns().map(|p| p.id),
    }
}

pub fn domains_view(doc: &RulesDoc, smart: SmartRu) -> ui::DomainsView {
    let rules = doc
        .domain_rules
        .iter()
        .map(|r| ui::DomainRuleView {
            id: r.id.to_string(),
            pattern: r.pattern.to_string(),
            action: rule_action(r.action),
            hits: doc.hit_count(r.id),
            overrides: smart.overridden_by(r).map(|route| match route {
                SmartRoute::Direct => ui::SmartRoute::Direct,
                SmartRoute::Vpn => ui::SmartRoute::Vpn,
            }),
        })
        .collect();
    ui::DomainsView {
        rules,
        smart_ru: smart.enabled,
    }
}

pub fn notifications_view(s: &Settings, os: ui::OsNotifications) -> ui::NotificationsView {
    let n = &s.notifications;
    ui::NotificationsView {
        enabled: s.desktop_notifications,
        events: [
            n.vpn_connect,
            n.vpn_disconnect,
            n.leak_detected,
            n.profile_rotation,
            n.schedule_triggered,
            n.connection_error,
        ],
        method: notify_method(n.method),
        sound: n.sound,
        os,
    }
}

/// Built-in themes first (their names in `lang`), then the user's.
pub fn themes(doc: &ThemesDoc, lang: Lang) -> Vec<ui::ThemeChoice> {
    let builtin = |id: &str, key: &'static str, mode| ui::ThemeChoice {
        id: id.to_owned(),
        name: Msg::new(key).render(lang),
        mode,
        builtin: true,
    };
    let mut list = vec![
        builtin(
            BUILTIN_LIGHT,
            "app.settings.theme.light",
            ui::ThemeMode::Light,
        ),
        builtin(BUILTIN_DARK, "app.settings.theme.dark", ui::ThemeMode::Dark),
        builtin(
            BUILTIN_SYSTEM,
            "app.settings.theme.system",
            ui::ThemeMode::System,
        ),
    ];
    list.extend(doc.custom_themes.iter().map(|t| ui::ThemeChoice {
        id: t.id.clone(),
        name: t.name.clone(),
        mode: t.mode(),
        builtin: false,
    }));
    list
}

/// Whether `id` names a theme that exists (a built-in or one of the user's).
pub fn theme_exists(doc: &ThemesDoc, id: &str) -> bool {
    [BUILTIN_LIGHT, BUILTIN_DARK, BUILTIN_SYSTEM].contains(&id)
        || doc.custom_themes.iter().any(|t| t.id == id)
}
