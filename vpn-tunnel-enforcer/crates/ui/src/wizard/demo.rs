//! [`DemoWizardApi`]: the fake backend of `demo_wizard`. Detection, key checks and «Завершить»
//! take realistic time; scenes inject the failures the spec's tests describe. It follows the apply
//! order the app must implement (ui-servers §6.7) and keeps a log of what it was asked to do (keys
//! are never written to it).
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use vpnte_base::i18n::Lang;
use vpnte_base::types::{KillSwitchLevel, ProxyKind};
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};

use super::{
    Connection, KeyCheck, LocalProxy, Routing, WizardApi, WizardChoices, WizardDefaults,
    WizardState,
};

/// Situations the demo can start in (`--scene <name>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DemoScene {
    /// First start: defaults, a local proxy is found.
    #[default]
    FirstRun,
    /// First start, no local proxy on this computer.
    NoProxy,
    /// Second run from Settings: key connection, 12 servers, standard kill switch, autostart on.
    Rerun,
    /// Saving the settings fails; autostart and kill switch are put back.
    FinishFails,
    /// Saving the settings fails and putting autostart back fails too.
    RestoreFails,
    /// «Пропустить» cannot save.
    SkipFails,
}

impl DemoScene {
    /// `first-run`, `no-proxy`, `rerun`, `finish-fails`, `restore-fails`, `skip-fails`.
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "first-run" => Self::FirstRun,
            "no-proxy" => Self::NoProxy,
            "rerun" => Self::Rerun,
            "finish-fails" => Self::FinishFails,
            "restore-fails" => Self::RestoreFails,
            "skip-fails" => Self::SkipFails,
            _ => return None,
        })
    }
}

/// Fake [`WizardApi`] with a call log for the demo page and CDP checks.
pub struct DemoWizardApi {
    scene: DemoScene,
    state: watch::Sender<WizardState>,
    log: watch::Sender<Vec<String>>,
}

const SCHEMES: [&str; 9] = [
    "vless://",
    "vmess://",
    "trojan://",
    "ss://",
    "hysteria2://",
    "hy2://",
    "tuic://",
    "wireguard://",
    "happ://",
];

impl DemoWizardApi {
    pub fn new(scene: DemoScene) -> Self {
        let current = match scene {
            DemoScene::Rerun => WizardDefaults {
                connection: Connection::Key,
                routing: Routing::Hard,
                kill_switch: KillSwitchLevel::Standard,
                autostart: true,
                servers: 12,
            },
            _ => WizardDefaults::default(),
        };
        let (state, _) = watch::channel(WizardState {
            open: true,
            current,
        });
        let (log, _) = watch::channel(Vec::new());
        Self { scene, state, log }
    }

    /// Opens the wizard again, as Settings «Пройти мастер заново» does.
    pub fn reopen(&self) {
        self.note("open".into());
        self.state.send_modify(|s| s.open = true);
    }

    /// What the fake backend was asked to do, oldest first.
    pub fn log(&self) -> watch::Receiver<Vec<String>> {
        self.log.subscribe()
    }

    fn note(&self, line: String) {
        tracing::info!(target: "ui", "demo wizard: {line}");
        self.log.send_modify(|log| log.push(line));
    }

    fn disk_full() -> AppError {
        AppError::msg(ErrorKind::Internal, Msg::new("ui.wizard.demo.diskFull"))
    }
}

/// Waits `ms`, or fails as cancelled when `cancel` fires first.
async fn wait(ms: u64, cancel: Option<&CancellationToken>) -> AppResult<()> {
    let sleep = tokio::time::sleep(Duration::from_millis(ms));
    match cancel {
        Some(token) => tokio::select! {
            () = sleep => Ok(()),
            () = token.cancelled() => Err(AppError::cancelled()),
        },
        None => {
            sleep.await;
            Ok(())
        }
    }
}

/// Servers in a pasted text: one per line with a known scheme, a subscription link counts as 7.
fn count_keys(text: &str) -> KeyCheck {
    if text.starts_with("https://") || text.starts_with("http://") {
        return KeyCheck {
            servers: 7,
            subscription: true,
        };
    }
    let servers = text
        .lines()
        .map(str::trim)
        .filter(|line| SCHEMES.iter().any(|s| line.starts_with(s)) && line.len() > 12)
        .count();
    KeyCheck {
        servers,
        subscription: false,
    }
}

fn connection_name(c: Connection) -> &'static str {
    match c {
        Connection::Key => "key",
        Connection::LocalProxy => "local-proxy",
    }
}

fn level_name(level: KillSwitchLevel) -> &'static str {
    match level {
        KillSwitchLevel::Off => "off",
        KillSwitchLevel::Standard => "standard",
        KillSwitchLevel::Strict => "strict",
    }
}

#[async_trait(?Send)]
impl WizardApi for DemoWizardApi {
    fn state(&self) -> watch::Receiver<WizardState> {
        self.state.subscribe()
    }

    async fn detect_proxy(&self) -> AppResult<Option<LocalProxy>> {
        self.note("detect".into());
        wait(1200, None).await?;
        Ok((self.scene != DemoScene::NoProxy).then(|| LocalProxy {
            host: "127.0.0.1".into(),
            port: 2080,
            kind: ProxyKind::Socks5,
        }))
    }

    async fn check_key(&self, text: String, cancel: CancellationToken) -> AppResult<KeyCheck> {
        self.note("check".into());
        wait(900, Some(&cancel)).await?;
        if text.contains("offline") {
            return Err(AppError::msg(
                ErrorKind::Network,
                Msg::new("ui.wizard.demo.subscriptionDown"),
            ));
        }
        Ok(count_keys(&text))
    }

    async fn finish(&self, c: WizardChoices) -> AppResult<()> {
        let current = self.state.borrow().current.clone();
        wait(400, None).await?;
        // ui-servers §6.7: key import first (it stays even if a later step fails), then the OS
        // side effects with their previous values remembered, the settings write last.
        let imported = c.key.as_ref().map_or(0, |k| count_keys(&k.0).servers);
        if c.key.is_some() {
            self.note(format!("import: {imported} servers"));
        }
        let autostart_changed = c.autostart != current.autostart;
        if autostart_changed {
            self.note(format!("autostart: {}", c.autostart));
        }
        let level_changed = c.kill_switch != current.kill_switch;
        if level_changed {
            self.note(format!("kill switch: {}", level_name(c.kill_switch)));
        }
        wait(500, None).await?;
        if matches!(self.scene, DemoScene::FinishFails | DemoScene::RestoreFails) {
            self.note("settings: write failed".into());
            if level_changed {
                self.note(format!(
                    "undo kill switch: {}",
                    level_name(current.kill_switch)
                ));
            }
            if autostart_changed && self.scene == DemoScene::RestoreFails {
                self.note("undo autostart: failed".into());
                return Err(AppError::msg(
                    ErrorKind::Internal,
                    Msg::new("ui.wizard.demo.autostartNotRestored"),
                ));
            }
            if autostart_changed {
                self.note(format!("undo autostart: {}", current.autostart));
            }
            return Err(Self::disk_full());
        }
        self.note(format!(
            "settings: lang={} connection={} routing={} kill={} first_run_complete",
            c.lang.code(),
            connection_name(c.connection),
            match c.routing {
                Routing::Hard => "hard",
                Routing::Soft => "soft",
            },
            level_name(c.kill_switch),
        ));
        self.state.send_modify(|s| {
            s.open = false;
            s.current = WizardDefaults {
                connection: c.connection,
                routing: c.routing,
                kill_switch: c.kill_switch,
                autostart: c.autostart,
                servers: s.current.servers + imported,
            };
        });
        Ok(())
    }

    async fn skip(&self, lang: Lang) -> AppResult<()> {
        wait(300, None).await?;
        if self.scene == DemoScene::SkipFails {
            self.note("skip: write failed".into());
            return Err(Self::disk_full());
        }
        self.note(format!("skip: lang={} first_run_complete", lang.code()));
        self.state.send_modify(|s| s.open = false);
        Ok(())
    }
}
