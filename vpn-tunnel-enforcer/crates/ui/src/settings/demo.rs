//! [`DemoSettingsApi`]: an in-memory fake of the backend with realistic data and short delays,
//! for `demo_settings` and the CDP checks. Scenes: `default` (connected Direct VPN), `fresh`
//! (defaults, no session), `blocked` (Windows blocks notifications), `failures` (save, strict
//! level, DNS switch, rotation and config apply fail; rule lists stale).
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::Duration;

use tokio::sync::watch;
use vpnte_base::types::now_ms;
use vpnte_base::{AppError, ErrorKind, Msg};

use super::model::*;

mod backend;

/// The fake backend (cheap to clone through `Rc`).
pub struct DemoSettingsApi {
    state: watch::Sender<SettingsState>,
    kill: watch::Sender<KillSwitchView>,
    rotation: watch::Sender<RotationView>,
    dns: watch::Sender<DnsView>,
    domains: watch::Sender<DomainsView>,
    notifications: watch::Sender<NotificationsView>,
    failures: bool,
    picked_domains: Cell<bool>,
    picked_config: RefCell<Option<ImportPreview>>,
    next_id: Cell<u64>,
}

async fn pause(ms: u64) {
    tokio::time::sleep(Duration::from_millis(ms)).await;
}

fn demo_err(kind: ErrorKind, key: &'static str) -> AppError {
    AppError::msg(kind, Msg::new(key))
}

fn server(
    id: &str,
    name: &str,
    protocol: &str,
    country: &str,
    status: ServerStatus,
) -> RotationServer {
    RotationServer {
        id: id.into(),
        name: name.into(),
        protocol: protocol.into(),
        country: Some(country.into()),
        status,
    }
}

fn dns_profile(
    id: &str,
    name: &str,
    address: &str,
    kind: DnsKind,
    builtin: bool,
) -> DnsProfileView {
    DnsProfileView {
        id: id.into(),
        name: name.into(),
        address: address.into(),
        kind,
        builtin,
    }
}

fn rule(id: &str, pattern: &str, action: DomainAction, hits: u64) -> DomainRuleView {
    DomainRuleView {
        id: id.into(),
        pattern: pattern.into(),
        action,
        hits,
        overrides: None,
    }
}

fn themes() -> Vec<ThemeChoice> {
    let builtin = |id: &str, name: &str, mode| ThemeChoice {
        id: id.into(),
        name: name.into(),
        mode,
        builtin: true,
    };
    vec![
        builtin("builtin-light", "Light", ThemeMode::Light),
        builtin("builtin-dark", "Dark", ThemeMode::Dark),
        builtin("builtin-system", "System", ThemeMode::System),
        ThemeChoice {
            id: "custom-1730000000000".into(),
            name: "Графит".into(),
            mode: ThemeMode::Dark,
            builtin: false,
        },
    ]
}

fn browsers(status: impl Fn(&str) -> BrowserStatus) -> Vec<BrowserState> {
    ["Google Chrome", "Microsoft Edge", "Mozilla Firefox"]
        .into_iter()
        .map(|name| BrowserState {
            name: name.into(),
            status: status(name),
        })
        .collect()
}

impl DemoSettingsApi {
    /// The fake for a scene (unknown scenes behave like `default`), starting on the built-in
    /// theme of `theme` (the window's launch theme).
    pub fn new(scene: &str, theme: ThemeMode) -> Rc<Self> {
        let fresh = scene == "fresh";
        let failures = scene == "failures";
        let now = now_ms();
        let mut settings = SettingsView::default();
        if !fresh {
            settings.connection_mode = ConnectionMode::DirectVpn;
            settings.smart_ru_split = true;
            settings.stealth_mode = true;
            settings.advanced_mode = scene == "advanced";
        }
        let state = SettingsState {
            settings,
            locale: None,
            active_theme_id: format!("builtin-{}", theme.name()),
            themes: themes(),
            autostart: !fresh,
            location_privacy: false,
            proxy_credentials_saved: scene == "advanced",
            capture_consent_given: false,
            capture_used_bytes: Some(if fresh { 0 } else { 734_003_200 }),
            connected: !fresh,
            direct_session: !fresh,
            launch: LaunchView {
                effective: if fresh {
                    LaunchChoice::Off
                } else {
                    LaunchChoice::LastUsed
                },
                source: if fresh {
                    LaunchSource::Default
                } else {
                    LaunchSource::Provider
                },
                server_mode: !fresh,
            },
            adaptive: AdaptiveView {
                phase: if failures {
                    AdaptivePhase::Failed
                } else {
                    AdaptivePhase::Connected
                },
                mode: AdaptiveMode::Baseline,
                message: (!fresh).then(|| {
                    Msg::new(if failures {
                        "ui.settings.demo.adaptiveFailed"
                    } else {
                        "ui.settings.demo.adaptiveConnected"
                    })
                }),
            },
            rule_sets: RuleSetView {
                active_source: RuleSource::Bundled,
                managed_at: None,
                refreshing: false,
                last_error: failures.then(|| Msg::new("errors.network")),
            },
            browser: BrowserView {
                browsers: browsers(|name| {
                    if name.contains("Firefox") {
                        BrowserStatus::NotInstalled
                    } else {
                        BrowserStatus::NotChecked
                    }
                }),
                restart_required: false,
            },
            diagnostics_export_running: false,
            // The demo plays an elevated process: every choice is on offer.
            tun_available: true,
            capture_available: true,
        };
        let kill = KillSwitchView {
            level: if fresh {
                KillSwitchLevel::Off
            } else {
                KillSwitchLevel::Standard
            },
            status: if fresh {
                ProtectionStatus::Off
            } else {
                ProtectionStatus::Engaged
            },
            exceptions: if fresh {
                Vec::new()
            } else {
                vec![
                    ExceptionView {
                        id: "ex-1".into(),
                        kind: ExceptionKind::Ip,
                        value: "192.168.1.0/24".into(),
                        label: "Домашняя сеть".into(),
                        broad: false,
                    },
                    ExceptionView {
                        id: "ex-2".into(),
                        kind: ExceptionKind::App,
                        value: r"C:\Program Files\Demo\Printer.exe".into(),
                        label: "Принтер".into(),
                        broad: false,
                    },
                ]
            },
            firewall_blocks_outbound: failures,
            hyperv_unfiltered: failures,
            // The demo has no helper service: "Always" shows as unavailable.
            always_available: false,
        };
        let servers = vec![
            server(
                "prof-1",
                "Netherlands · Amsterdam",
                "vless",
                "NL",
                ServerStatus::Online,
            ),
            server(
                "prof-2",
                "Germany · Frankfurt",
                "trojan",
                "DE",
                ServerStatus::Online,
            ),
            server(
                "prof-3",
                "Finland · Helsinki",
                "hysteria2",
                "FI",
                ServerStatus::Offline,
            ),
            server(
                "prof-4",
                "Latvia · Riga",
                "vless",
                "LV",
                ServerStatus::Unknown,
            ),
        ];
        let rotation = RotationView {
            enabled: !fresh,
            interval_minutes: 15,
            order: RotationOrder::Sequential,
            profile_ids: if fresh {
                Vec::new()
            } else {
                vec!["prof-1".into(), "prof-2".into()]
            },
            current_profile_id: (!fresh).then(|| "prof-1".into()),
            next_rotation_at: (!fresh).then_some(now + 10 * 60_000 + 25_000),
            servers,
        };
        let mut profiles = vec![
            dns_profile(
                "builtin-cloudflare",
                "Cloudflare",
                "1.1.1.1",
                DnsKind::Plain,
                true,
            ),
            dns_profile("builtin-google", "Google", "8.8.8.8", DnsKind::Plain, true),
            dns_profile("builtin-quad9", "Quad9", "9.9.9.9", DnsKind::Plain, true),
            dns_profile(
                "builtin-adguard",
                "AdGuard",
                "94.140.14.14",
                DnsKind::Plain,
                true,
            ),
        ];
        if !fresh {
            profiles.push(dns_profile(
                "dns-1",
                "Мой DoH",
                "https://dns.example.net/dns-query",
                DnsKind::Doh,
                false,
            ));
        }
        let dns = DnsView {
            profiles,
            active: (!fresh).then(|| "builtin-cloudflare".into()),
        };
        let domains = DomainsView {
            rules: if fresh {
                Vec::new()
            } else {
                vec![
                    rule("r-1", "*.example.ru", DomainAction::Direct, 214),
                    rule("r-2", "video.example.com", DomainAction::Vpn, 98),
                    DomainRuleView {
                        overrides: Some(SmartRoute::Direct),
                        ..rule("r-5", "music.yandex.ru", DomainAction::Vpn, 37)
                    },
                    rule("r-3", "ads.example.net", DomainAction::Block, 2320),
                    rule("r-4", "~tracker", DomainAction::Block, 0),
                ]
            },
            smart_ru: !fresh,
        };
        let mut events = [true; 6];
        events[NotifyEvent::ProfileRotation as usize] = false;
        let notifications = NotificationsView {
            enabled: true,
            events,
            method: NotifyMethod::System,
            sound: true,
            os: match scene {
                "blocked" => OsNotifications::Blocked,
                "failures" => OsNotifications::CheckFailed(Msg::new("errors.permission")),
                _ => OsNotifications::Allowed,
            },
        };
        Rc::new(Self {
            state: watch::Sender::new(state),
            kill: watch::Sender::new(kill),
            rotation: watch::Sender::new(rotation),
            dns: watch::Sender::new(dns),
            domains: watch::Sender::new(domains),
            notifications: watch::Sender::new(notifications),
            failures,
            picked_domains: Cell::new(false),
            picked_config: RefCell::new(None),
            next_id: Cell::new(100),
        })
    }

    fn id(&self, prefix: &str) -> String {
        let n = self.next_id.get() + 1;
        self.next_id.set(n);
        format!("{prefix}-{n}")
    }

    /// The live settings (for tests of the fake itself).
    pub fn live(&self) -> SettingsView {
        self.state.borrow().settings.clone()
    }
}
