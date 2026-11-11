//! Demo backend of the tray: fake snapshots for every status, slow fake actions, a random-walk
//! traffic feed and a scene whose quit cleanup is refused.
use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};

use super::host::{QuitMode, TrayApi};
use super::model::{ProxyStatus, Transition, TrayState, TrayStatus, TunnelState};

/// [`TrayApi`] over fake data.
pub struct DemoTray {
    tx: Arc<watch::Sender<TrayState>>,
    refuse_restore: bool,
}

impl DemoTray {
    /// Starts in `scene`: a [`TrayStatus::key`] (`protected`, `proxyDown`, …) or `quit-fails`
    /// (protected; every quit that restores the system proxy is refused). Unknown: `off`.
    pub fn new(scene: Option<&str>) -> DemoTray {
        let refuse_restore = scene == Some("quit-fails");
        let status = TrayStatus::ALL
            .into_iter()
            .find(|s| Some(s.key()) == scene)
            .unwrap_or(if refuse_restore {
                TrayStatus::Protected
            } else {
                TrayStatus::Off
            });
        let (tx, _) = watch::channel(DemoTray::scene(status));
        DemoTray {
            tx: Arc::new(tx),
            refuse_restore,
        }
    }

    /// A believable snapshot that maps to `status`.
    pub fn scene(status: TrayStatus) -> TrayState {
        let protected = TrayState {
            tunnel: TunnelState::Connected,
            proxy: ProxyStatus::Running,
            engine_running: true,
            kill_switch: true,
            public_ip: Some("198.51.100.7".into()),
            proxy_addr: Some("127.0.0.1:2080".into()),
            down_bps: 2_450_000,
            up_bps: 61_000,
            minimize_to_tray: true,
            ..TrayState::default()
        };
        let off = TrayState {
            minimize_to_tray: true,
            ..TrayState::default()
        };
        match status {
            TrayStatus::Protected => protected,
            TrayStatus::Leak => TrayState {
                leak: true,
                ..protected
            },
            TrayStatus::Off => off,
            TrayStatus::Starting => TrayState {
                transition: Some(Transition::Connecting),
                ..off
            },
            TrayStatus::ProxyDown => TrayState {
                proxy: ProxyStatus::ProxyDown,
                down_bps: 0,
                up_bps: 0,
                ..protected
            },
            TrayStatus::KillSwitch => TrayState {
                tunnel: TunnelState::Blocked,
                kill_switch: true,
                ..off
            },
            TrayStatus::Restarting => TrayState {
                transition: Some(Transition::Reconnecting),
                restart: Some((2, 5)),
                ..protected
            },
            TrayStatus::Stopping => TrayState {
                transition: Some(Transition::Disconnecting),
                ..protected
            },
            TrayStatus::Error => TrayState {
                tunnel: TunnelState::Error,
                ..off
            },
            TrayStatus::Unknown => TrayState {
                degraded: true,
                ..protected
            },
        }
    }

    /// Changes the pushed state (the demo page's controls).
    pub fn update(&self, change: impl FnOnce(&mut TrayState)) {
        self.tx.send_modify(change);
    }

    /// Feeds random-walk traffic while an engine runs (call inside the tokio runtime).
    pub fn spawn_traffic(&self) {
        let tx = self.tx.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_millis(400));
            loop {
                tick.tick().await;
                tx.send_if_modified(|state| {
                    if !state.engine_running || state.proxy == ProxyStatus::ProxyDown {
                        return false;
                    }
                    let walk = |v: u64, scale: u64| {
                        let step = fastrand::u64(0..=scale * 2);
                        (v + step)
                            .saturating_sub(scale)
                            .clamp(scale / 4, scale * 40)
                    };
                    state.down_bps = walk(state.down_bps, 90_000);
                    state.up_bps = walk(state.up_bps, 6_000);
                    true
                });
            }
        });
    }

    async fn after(&self, ms: u64, change: impl FnOnce(&mut TrayState)) {
        tokio::time::sleep(Duration::from_millis(ms)).await;
        self.update(change);
    }
}

#[async_trait::async_trait(?Send)]
impl TrayApi for DemoTray {
    fn state(&self) -> watch::Receiver<TrayState> {
        self.tx.subscribe()
    }

    async fn start(&self) -> AppResult<()> {
        let keep = self.tx.borrow().minimize_to_tray;
        self.update(|s| s.transition = Some(Transition::Connecting));
        self.after(1_500, |s| {
            *s = TrayState {
                minimize_to_tray: keep,
                ..DemoTray::scene(TrayStatus::Protected)
            }
        })
        .await;
        Ok(())
    }

    async fn stop(&self) -> AppResult<()> {
        self.update(|s| s.transition = Some(Transition::Disconnecting));
        self.after(1_000, |s| {
            *s = TrayState {
                minimize_to_tray: s.minimize_to_tray,
                ..TrayState::default()
            }
        })
        .await;
        Ok(())
    }

    async fn check_route(&self) -> AppResult<()> {
        tokio::time::sleep(Duration::from_millis(1_200)).await;
        tracing::info!("demo: route check passed");
        Ok(())
    }

    async fn open_logs(&self) -> AppResult<()> {
        tracing::info!("demo: the log folder would open now");
        Ok(())
    }

    async fn quit(&self, mode: QuitMode) -> AppResult<()> {
        if self.tx.borrow().engine_running {
            self.update(|s| s.transition = Some(Transition::Disconnecting));
            self.after(800, |s| {
                *s = TrayState {
                    minimize_to_tray: s.minimize_to_tray,
                    ..TrayState::default()
                }
            })
            .await;
        }
        if self.refuse_restore && mode == QuitMode::Restore {
            return Err(AppError::msg(
                ErrorKind::Internal,
                Msg::new("ui.tray.demo.restoreFailed"),
            ));
        }
        Ok(())
    }
}

/// `data:` URI of `bytes` in percent-encoding (RFC 2397), for images on the demo page.
pub fn data_uri(mime: &str, bytes: &[u8]) -> String {
    let mut out = format!("data:{mime},");
    for &b in bytes {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}
