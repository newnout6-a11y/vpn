//! [`DemoServersApi`]: the Servers page over the fake store of `demo_data` — realistic delays,
//! progress streams and failures, no network, no files, no clipboard.
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::time::Duration;

use tokio::sync::{Notify, watch};
use tokio::time::sleep;
use vpnte_base::types::now_ms;
use vpnte_base::{AppError, AppResult, Msg};

use super::demo_data::{demo_check, demo_view};
use super::live_model::*;
use super::model::*;

mod backend;
mod live;

/// Starting state of the demo store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DemoScene {
    #[default]
    Normal,
    /// No servers and no groups (the empty state).
    Empty,
    /// The first store read never finishes.
    Loading,
    /// The tunnel is down and a competing VPN adapter is up.
    Foreign,
}

impl DemoScene {
    /// Parses a `--scene` value; unknown names give `Normal`.
    pub fn from_name(name: &str) -> Self {
        match name {
            "empty" => DemoScene::Empty,
            "loading" => DemoScene::Loading,
            "foreign" => DemoScene::Foreign,
            _ => DemoScene::Normal,
        }
    }
}

/// Fake backend of the Servers page.
pub struct DemoServersApi {
    state: watch::Sender<ServersView>,
    expanded: RefCell<Vec<String>>,
    history: RefCell<HashMap<String, Vec<LiveCheck>>>,
    runs: Cell<u64>,
    history_failed: Cell<bool>,
    cancel_switch: Notify,
}

impl DemoServersApi {
    pub fn new(scene: DemoScene) -> Self {
        let now = now_ms();
        let mut view = demo_view(now);
        match scene {
            DemoScene::Normal => {}
            DemoScene::Empty => {
                view.servers.clear();
                view.groups.clear();
                view.active_id = None;
            }
            DemoScene::Loading => view = ServersView::default(),
            DemoScene::Foreign => {
                view.tunnel_running = false;
                view.foreign_vpn = true;
            }
        }
        let api = Self {
            state: watch::Sender::new(view),
            expanded: RefCell::new(vec!["sub".into(), "keys".into()]),
            history: RefCell::default(),
            runs: Cell::new(0),
            history_failed: Cell::new(false),
            cancel_switch: Notify::new(),
        };
        // Two stored receipts for the connected server, so the history drawer has content.
        if scene == DemoScene::Normal
            && let Some(server) = api.server("nl-ams")
        {
            let older = demo_check(&server, LiveMode::Basic, 3, now - 26 * 3_600_000);
            let newer = demo_check(&server, LiveMode::Extended, 2, now - 3_600_000);
            api.history
                .borrow_mut()
                .insert(server.id, vec![newer, older]);
            api.runs.set(4);
        }
        api
    }

    fn view(&self) -> ServersView {
        self.state.borrow().clone()
    }

    fn server(&self, id: &str) -> Option<ServerView> {
        self.state
            .borrow()
            .servers
            .iter()
            .find(|s| s.id == id)
            .cloned()
    }

    fn known(&self, id: &str) -> AppResult<ServerView> {
        self.server(id)
            .ok_or_else(|| AppError::conflict(Msg::new("ui.servers.demo.unknownServer")))
    }

    fn edit(&self, f: impl FnOnce(&mut ServersView)) {
        self.state.send_modify(f);
    }

    fn edit_server(&self, id: &str, f: impl FnOnce(&mut ServerView)) {
        self.edit(|v| {
            if let Some(s) = v.servers.iter_mut().find(|s| s.id == id) {
                f(s);
            }
        });
    }

    fn next_run(&self) -> u64 {
        let n = self.runs.get() + 1;
        self.runs.set(n);
        n
    }

    /// A deterministic fake ping: the seed latency plus a little jitter; dead keys never answer.
    fn measure(&self, id: &str) -> Option<u32> {
        let server = self.server(id)?;
        let base = server.ping_ms.or(if server.id == "se-sto" {
            Some(61)
        } else {
            None
        })?;
        Some(base + fastrand::u32(0..9))
    }

    /// Stores a ping only while the tunnel is down (in-tunnel numbers would poison the list).
    fn record_ping(&self, id: &str, ms: Option<u32>) {
        if self.state.borrow().tunnel_running {
            return;
        }
        self.edit_server(id, |s| {
            s.ping_ms = ms;
            s.status = if ms.is_some() {
                OnlineStatus::Online
            } else {
                OnlineStatus::Offline
            };
        });
    }
}

fn delay(ms: u64) -> tokio::time::Sleep {
    sleep(Duration::from_millis(ms))
}

/// Archived servers are purged this long after they were archived (servers spec: 30 days).
const ARCHIVE_TTL_MS: i64 = 30 * 24 * 3_600_000;

/// The key schemes the demo importer accepts.
const SCHEMES: [&str; 8] = [
    "vless://",
    "vmess://",
    "trojan://",
    "ss://",
    "hysteria2://",
    "hy2://",
    "tuic://",
    "wireguard://",
];

/// Clears the in-flight switch marker however `select` ends (also when its future is dropped).
struct SwitchMarker<'a>(&'a DemoServersApi);

impl Drop for SwitchMarker<'_> {
    fn drop(&mut self) {
        self.0.edit(|v| v.switching_to = None);
    }
}
