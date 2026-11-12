//! A fake backend for the start page: the reference fixtures (`.tmp/rewrite/ref/ui/fixtures.md`)
//! as scenes, played after the first paint like the reference timelines (boot disconnected, then
//! the scene's frames), and actions that move the fake state like the app would (connect,
//! disconnect, cancel, Smart RU, leak check, kill-switch banner).
//!
//! Addresses are RFC 5737 documentation addresses; nothing touches the network or the clipboard.
use std::cell::Cell;
use std::net::{IpAddr, Ipv4Addr};
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{Notify, watch};
use vpnte_base::types::{Verdict, now_ms};
use vpnte_base::{AppError, AppResult, Msg};
use vpnte_view::identity::{ExitIp, Geo};
use vpnte_view::labels::{FirewallStatus, FwState};
use vpnte_view::swiss::{ConnView, Mode, OpWindow, Transition, TunnelState};

use super::{DashboardApi, DashboardView};
use crate::panels::PanelsApi;
use crate::panels::demo::{DemoFeed, DemoPanels, DemoScene};

/// The user's real address in every scene.
pub const HOME_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 47));
/// The VPN exit address in every scene.
pub const VPN_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 23));

/// A start-page scene (reference ids such as `connected-dark-860x600` name one too).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DashScene {
    Disconnected,
    Connecting,
    Connected,
    Verify,
    Closing,
    Cancelling,
    Switching,
    Reconnecting,
    /// Auto-restart after an engine crash (`restart-legacy` in the reference).
    Restart,
    Leak,
    ErrorKillSwitch,
    UnknownKillSwitch,
    TunnelBlocked,
    ProxyDown,
    CompetingTun,
    ForeignVpn,
    ServersEmpty,
    ConfirmDisconnect,
    ConnectedSoft,
    MascotAlert,
    /// Disconnected; every action works with realistic delays.
    Live,
}

impl DashScene {
    /// Every scene with its name.
    pub const ALL: [(&'static str, DashScene); 21] = [
        ("disconnected", DashScene::Disconnected),
        ("connecting", DashScene::Connecting),
        ("connected-soft", DashScene::ConnectedSoft),
        ("connected", DashScene::Connected),
        ("verify", DashScene::Verify),
        ("closing", DashScene::Closing),
        ("cancelling", DashScene::Cancelling),
        ("switching", DashScene::Switching),
        ("reconnecting", DashScene::Reconnecting),
        ("restart", DashScene::Restart),
        ("leak", DashScene::Leak),
        ("error-killswitch", DashScene::ErrorKillSwitch),
        ("unknown-killswitch", DashScene::UnknownKillSwitch),
        ("tunnel-blocked", DashScene::TunnelBlocked),
        ("proxy-down", DashScene::ProxyDown),
        ("competing-tun", DashScene::CompetingTun),
        ("foreign-vpn", DashScene::ForeignVpn),
        ("servers-empty", DashScene::ServersEmpty),
        ("confirm-disconnect", DashScene::ConfirmDisconnect),
        ("mascot-alert", DashScene::MascotAlert),
        ("live", DashScene::Live),
    ];

    /// The scene a name or reference id starts with (`mascot-bubble` / `mascot-sleep` are the
    /// disconnected page at the right moment).
    pub fn from_name(name: &str) -> Option<DashScene> {
        let name = name.to_ascii_lowercase();
        if name.starts_with("mascot-bubble") || name.starts_with("mascot-sleep") {
            return Some(DashScene::Disconnected);
        }
        DashScene::ALL
            .iter()
            .find(|(prefix, _)| name.starts_with(prefix))
            .map(|&(_, scene)| scene)
    }

    /// The panel row's data for this scene.
    fn panels(self) -> DemoScene {
        use DashScene::*;
        match self {
            Connected | ConfirmDisconnect | Verify | Leak | CompetingTun | Switching
            | Reconnecting => DemoScene::Connected,
            ServersEmpty => DemoScene::ServersEmpty,
            Live => DemoScene::Live,
            _ => DemoScene::Disconnected,
        }
    }

    /// The JS the demo binary runs once the scene's frames are in (`confirm-disconnect` presses
    /// the power button like the reference timeline).
    pub fn after_frames_js(self) -> Option<&'static str> {
        (self == DashScene::ConfirmDisconnect)
            .then_some("document.querySelector('.swiss-skin .swiss-power')?.click()")
    }
}

/// `Instant::now() - ago` (or now, right after boot).
fn before(ago: Duration) -> Instant {
    let now = Instant::now();
    now.checked_sub(ago).unwrap_or(now)
}

/// An operation that started `ago` with the lifecycle's 120 s deadline.
fn operation(ago: Duration) -> Option<OpWindow> {
    let started = before(ago);
    Some(OpWindow {
        started,
        deadline: Some(started + Duration::from_secs(120)),
    })
}

/// Booted, not connected: the home address seen, nothing of ours installed.
fn base() -> DashboardView {
    DashboardView {
        exit: ExitIp {
            ip: Some(HOME_IP),
            ..ExitIp::default()
        },
        firewall: FirewallStatus {
            state: FwState::Inactive,
            checking: false,
        },
        smart_ru: true,
        ..DashboardView::default()
    }
}

/// A transition makes the kill-switch read-back unknown until it settles.
const CHECKING: FirewallStatus = FirewallStatus {
    state: FwState::Unknown,
    checking: true,
};

fn connecting(ago: Duration) -> DashboardView {
    DashboardView {
        conn: ConnView {
            transition: Some(Transition::Connecting),
            cleanup_required: true,
            operation: operation(ago),
            ..ConnView::default()
        },
        firewall: CHECKING,
        ..base()
    }
}

/// Connected through the TUN for `session`, exit verified in Amsterdam, kill-switch holding.
fn connected(session: Duration) -> DashboardView {
    DashboardView {
        conn: ConnView {
            state: TunnelState::Connected,
            mode: Some(Mode::Tun),
            cleanup_required: true,
            started_at: Some(now_ms() - session.as_millis() as i64),
            ..ConnView::default()
        },
        exit: ExitIp {
            ip: Some(VPN_IP),
            vpn_ip: Some(VPN_IP),
            verdict: Verdict::Ok,
            leak: false,
            geo: Some((
                VPN_IP,
                Geo {
                    country: Some("Netherlands".into()),
                    city: Some("Amsterdam".into()),
                },
            )),
        },
        exit_country: Some("NL".into()),
        firewall: FirewallStatus {
            state: FwState::Verified,
            checking: false,
        },
        // Auto chose Xray for the reference REALITY node.
        engine: Some(super::EngineLine {
            engine: vpnte_base::types::Engine::Xray,
            reason: Some(Msg::new("engine.xray.reason.reality")),
        }),
        ..base()
    }
}

/// `frame` with the connection replaced by `edit` of it.
fn with_conn(mut frame: DashboardView, edit: impl FnOnce(&mut ConnView)) -> DashboardView {
    edit(&mut frame.conn);
    frame
}

/// The scene's frames after the first paint: (delay since the previous frame, frame).
fn timeline(scene: DashScene) -> Vec<(u64, DashboardView)> {
    use DashScene::*;
    let secs = Duration::from_secs_f64;
    let fault = |state: TunnelState, fw: FwState| DashboardView {
        conn: ConnView {
            state,
            cleanup_required: true,
            ..ConnView::default()
        },
        // a faulted lifecycle drops the address it can no longer vouch for
        exit: ExitIp::default(),
        firewall: FirewallStatus {
            state: fw,
            checking: false,
        },
        ..base()
    };
    let leak = || DashboardView {
        exit: ExitIp {
            ip: Some(HOME_IP),
            vpn_ip: Some(VPN_IP),
            verdict: Verdict::Fail,
            leak: true,
            geo: None,
        },
        exit_country: None,
        ..connected(secs(5.5))
    };
    match scene {
        Disconnected | ServersEmpty | Live => vec![],
        Connecting => vec![(300, connecting(secs(18.0)))],
        Connected | ConfirmDisconnect => vec![(300, connected(secs(9.0)))],
        Verify => vec![(
            300,
            DashboardView {
                exit: base().exit,
                exit_country: None,
                ..connected(secs(4.5))
            },
        )],
        Closing => vec![
            (300, connected(secs(4.0))),
            (
                300,
                with_conn(
                    DashboardView {
                        firewall: CHECKING,
                        ..connected(secs(7.0))
                    },
                    |c| {
                        c.transition = Some(Transition::Disconnecting);
                        c.operation = operation(secs(3.0));
                    },
                ),
            ),
        ],
        Cancelling => vec![(
            300,
            with_conn(connecting(secs(4.5)), |c| c.cancelling = true),
        )],
        Switching => vec![
            (300, connected(secs(6.0))),
            (
                300,
                with_conn(
                    DashboardView {
                        firewall: CHECKING,
                        ..connected(secs(7.6))
                    },
                    |c| {
                        c.transition = Some(Transition::Reconnecting);
                        c.switching = Some("Germany · Frankfurt".into());
                        c.operation = operation(secs(1.6));
                    },
                ),
            ),
        ],
        Reconnecting => vec![
            (300, connected(secs(4.0))),
            (
                300,
                with_conn(
                    DashboardView {
                        firewall: CHECKING,
                        ..connected(secs(7.0))
                    },
                    |c| {
                        c.transition = Some(Transition::Reconnecting);
                        c.operation = operation(secs(3.0));
                    },
                ),
            ),
        ],
        Restart => vec![(
            300,
            // the engine crashed: no operation window yet (the ruler shows stripes)
            with_conn(base(), |c| {
                c.restarting = Some((1, 3));
                c.cleanup_required = true;
            }),
        )],
        Leak => vec![(300, connected(secs(1.5))), (300, leak())],
        MascotAlert => vec![(300, connected(secs(4.0))), (4_000, leak())],
        ErrorKillSwitch => vec![
            (300, connected(secs(2.0))),
            (300, fault(TunnelState::Error, FwState::Verified)),
        ],
        UnknownKillSwitch => vec![(300, fault(TunnelState::Unknown, FwState::Unknown))],
        TunnelBlocked => vec![(300, fault(TunnelState::Blocked, FwState::Verified))],
        ProxyDown => vec![
            (300, connected(secs(1.5))),
            (
                300,
                with_conn(connected(secs(1.8)), |c| {
                    c.proxy_down = true;
                    c.degraded = true;
                }),
            ),
        ],
        CompetingTun => vec![
            (300, connected(secs(1.0))),
            (
                300,
                with_conn(connected(secs(1.3)), |c| {
                    c.competing_tun = Some("happ-tun (172.19.0.1)".into());
                    c.degraded = true;
                }),
            ),
        ],
        ForeignVpn => vec![(
            300,
            DashboardView {
                foreign_vpn: Some("happ-tun (172.19.0.1)".into()),
                ..base()
            },
        )],
        ConnectedSoft => vec![(
            300,
            // Soft mode has no TUN, so no geo lookup: the sub-line says «через VPN»
            DashboardView {
                soft_mode: true,
                firewall: base().firewall,
                exit: ExitIp {
                    geo: None,
                    ..connected(secs(6.3)).exit
                },
                exit_country: None,
                ..with_conn(connected(secs(6.3)), |c| {
                    c.mode = Some(Mode::Soft);
                    c.started_at = None;
                })
            },
        )],
    }
}

/// The fake start-page backend.
pub struct DemoDashboard {
    tx: Arc<watch::Sender<DashboardView>>,
    /// Bumped by every connect and cancel: a cancelled connect must not land.
    attempt: Cell<u64>,
}

/// Plays the scene after the first paint: call [`DemoStart::start`] once the page is drawn.
#[derive(Clone)]
pub struct DemoStart {
    go: Arc<Notify>,
    panels: DemoFeed,
}

impl DemoStart {
    /// Lets the scene's frames and the panels' traffic feed run.
    pub fn start(&self) {
        self.go.notify_one();
        self.panels.start();
    }
}

impl DemoDashboard {
    /// Both fake APIs of the page for `scene` (call inside the tokio runtime).
    pub fn handle(scene: DashScene) -> (Rc<dyn DashboardApi>, Rc<dyn PanelsApi>, DemoStart) {
        let tx = Arc::new(watch::Sender::new(base()));
        let go = Arc::new(Notify::new());
        let (frames, sender, gate) = (timeline(scene), Arc::clone(&tx), Arc::clone(&go));
        tokio::spawn(async move {
            gate.notified().await;
            for (delay, frame) in frames {
                tokio::time::sleep(Duration::from_millis(delay)).await;
                sender.send_replace(frame);
            }
        });
        let (panels, feed) = DemoPanels::handle(scene.panels());
        let demo = DemoDashboard {
            tx,
            attempt: Cell::new(0),
        };
        (Rc::new(demo), panels, DemoStart { go, panels: feed })
    }

    fn view(&self) -> DashboardView {
        self.tx.borrow().clone()
    }

    /// Publishes `frame`, keeping the settings the user changed.
    fn publish(&self, mut frame: DashboardView) {
        let now = self.view();
        frame.smart_ru = now.smart_ru;
        frame.soft_mode = now.soft_mode;
        self.tx.send_replace(frame);
    }

    fn next_attempt(&self) -> u64 {
        self.attempt.set(self.attempt.get() + 1);
        self.attempt.get()
    }
}

async fn pause(ms: u64) {
    tokio::time::sleep(Duration::from_millis(ms)).await;
}

#[async_trait::async_trait(?Send)]
impl DashboardApi for DemoDashboard {
    fn state(&self) -> watch::Receiver<DashboardView> {
        self.tx.subscribe()
    }

    async fn connect(&self) -> AppResult<()> {
        let attempt = self.next_attempt();
        let mut frame = connecting(Duration::ZERO);
        if let Some(op) = frame.conn.operation.as_mut() {
            op.deadline = Some(op.started + Duration::from_secs(8));
        }
        self.publish(frame);
        pause(4_000).await;
        if self.attempt.get() != attempt {
            return Err(AppError::cancelled());
        }
        self.publish(connected(Duration::ZERO));
        Ok(())
    }

    async fn disconnect(&self) -> AppResult<Option<Msg>> {
        let frame = with_conn(self.view(), |c| {
            c.transition = Some(Transition::Disconnecting);
            c.operation = operation(Duration::ZERO);
        });
        self.publish(DashboardView {
            firewall: CHECKING,
            ..frame
        });
        pause(1_500).await;
        self.publish(base());
        Ok(None)
    }

    async fn cancel(&self) -> AppResult<Option<Msg>> {
        let switching = self.view().conn.switching.is_some();
        self.next_attempt();
        self.publish(with_conn(self.view(), |c| c.cancelling = true));
        pause(1_200).await;
        if switching {
            // back on the previous server
            self.publish(connected(Duration::from_secs(9)));
        } else {
            self.publish(base());
        }
        Ok(None)
    }

    async fn set_smart_ru(&self, on: bool) -> AppResult<()> {
        pause(300).await;
        self.tx.send_modify(|view| view.smart_ru = on);
        Ok(())
    }

    async fn run_leak_check(&self) -> AppResult<Verdict> {
        pause(2_000).await;
        self.tx.send_modify(|view| view.leak = Verdict::Ok);
        Ok(Verdict::Ok)
    }

    async fn copy_ip(&self, _ip: IpAddr) -> AppResult<()> {
        // the demo has no clipboard access; the app writes it through winnet
        Ok(())
    }

    async fn recheck_firewall(&self) -> AppResult<()> {
        let before = self.view().firewall;
        self.tx.send_modify(|view| view.firewall = CHECKING);
        pause(1_000).await;
        // an unconfirmed read-back that is re-run finds nothing of ours (spec §7.8 #8)
        let state = match before.state {
            FwState::Unknown => FwState::Inactive,
            other => other,
        };
        self.tx.send_modify(|view| {
            view.firewall = FirewallStatus {
                state,
                checking: false,
            };
        });
        Ok(())
    }

    async fn release_kill_switch(&self) -> AppResult<()> {
        pause(800).await;
        let now = self.view();
        if now.conn.connected() {
            self.tx.send_modify(|view| view.firewall = base().firewall);
        } else {
            self.publish(base());
        }
        Ok(())
    }

    /// The demo's paused session comes back at once.
    async fn retry_now(&self) -> AppResult<()> {
        pause(600).await;
        self.tx.send_modify(|view| view.pause = None);
        Ok(())
    }
}
