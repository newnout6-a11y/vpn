//! A fake [`PanelsApi`] with the reference fixtures (`.tmp/rewrite/ref/ui/fixtures.md`): six
//! servers (one offline, one unchecked, Germany the best ping), the 48-sample traffic curve and
//! two healthy external proxies. Actions answer after short delays; `Live` keeps traffic going.
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Notify, watch};
use vpnte_base::types::{UnixMs, now_ms};
use vpnte_base::{AppError, AppResult, Msg};
use vpnte_view::identity::ServerHealth;
use vpnte_view::traffic::{HISTORY, TrafficSample};

use super::PanelsApi;
use super::model::{
    ProxiesView, ProxyChoice, ProxyHealth, ProxyRowView, Selected, ServerRowView, ServersView,
};

/// Download curve of the connected reference scenes, Mbit/s, oldest first.
const CURVE: [f64; HISTORY] = [
    24.7, 28.1, 28.9, 27.6, 34.1, 22.8, 21.3, 35.2, 21.9, 22.7, 22.6, 20.6, 16.8, 11.7, 6.4, 6.0,
    6.0, 12.4, 22.6, 15.7, 23.2, 29.4, 33.0, 33.4, 30.9, 26.7, 22.1, 18.2, 16.0, 29.5, 24.9, 16.4,
    16.1, 14.4, 11.5, 8.2, 6.0, 6.0, 7.7, 12.7, 33.5, 26.7, 32.5, 44.6, 35.2, 31.6, 25.8, 19.4,
];

/// (id, name, country, protocol, ping, health, checked minutes ago) of a reference server.
type Fixture = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    Option<u32>,
    ServerHealth,
    Option<i64>,
);

/// The reference servers.
const SERVERS: [Fixture; 6] = [
    (
        "srv-nl-ams",
        "Netherlands · Amsterdam",
        "NL",
        "vless",
        Some(38),
        ServerHealth::Online,
        Some(3),
    ),
    (
        "srv-de-fra",
        "Germany · Frankfurt",
        "DE",
        "vless",
        Some(31),
        ServerHealth::Online,
        Some(3),
    ),
    (
        "srv-fi-hel",
        "Finland · Helsinki",
        "FI",
        "trojan",
        Some(54),
        ServerHealth::Online,
        Some(7),
    ),
    (
        "srv-pl-waw",
        "Poland · Warsaw",
        "PL",
        "hysteria2",
        Some(47),
        ServerHealth::Online,
        Some(12),
    ),
    (
        "srv-se-sto",
        "Sweden · Stockholm",
        "SE",
        "vless",
        None,
        ServerHealth::Unknown,
        None,
    ),
    (
        "srv-us-nyc",
        "USA · New York",
        "US",
        "shadowsocks",
        None,
        ServerHealth::Offline,
        Some(5),
    ),
];

/// The server the demo VPN uses.
const VPN_SERVER: &str = "srv-nl-ams";

/// Which reference state the demo shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DemoScene {
    /// Connected: 48 traffic samples, two healthy proxies (`connected-*`, `proxy-picker-open`).
    Connected,
    /// Not connected: idle traffic, no proxies (`disconnected-*`).
    Disconnected,
    /// Fresh install: no servers, nothing to start (`servers-empty`).
    ServersEmpty,
    /// Connected with a new traffic sample every second and drifting latencies.
    Live,
}

impl DemoScene {
    /// Scene by name; reference scene ids (`connected-light-1100x720`) map by their prefix.
    pub fn from_name(name: &str) -> Option<DemoScene> {
        let name = name.to_ascii_lowercase();
        let scene = if name.starts_with("disconnected") {
            DemoScene::Disconnected
        } else if name.starts_with("servers-empty") {
            DemoScene::ServersEmpty
        } else if name.starts_with("live") {
            DemoScene::Live
        } else if name.starts_with("connected") || name.starts_with("proxy-picker-open") {
            DemoScene::Connected
        } else {
            return None;
        };
        Some(scene)
    }

    fn connected(self) -> bool {
        matches!(self, DemoScene::Connected | DemoScene::Live)
    }
}

/// One traffic sample of the reference curve (`trafficSample` in the capture tool).
fn sample(i: usize, started_at: UnixMs, ts: UnixMs) -> TrafficSample {
    let bps = CURVE[i % HISTORY] * 1e6 / 8.0;
    let up = (2.1 + (i % 5) as f64 * 0.35) * 1e6 / 8.0;
    TrafficSample {
        ts,
        running: true,
        download_bps: bps,
        upload_bps: up,
        smoothed_download_bps: bps,
        smoothed_upload_bps: up,
        session_download_bytes: 386_000_000 + i as u64 * 2_600_000,
        started_at: Some(started_at),
    }
}

fn servers(scene: DemoScene, now: UnixMs) -> ServersView {
    if scene == DemoScene::ServersEmpty {
        return ServersView::default();
    }
    let rows = SERVERS
        .iter()
        .map(
            |&(id, name, cc, protocol, ping, health, ago)| ServerRowView {
                id: id.into(),
                name: name.into(),
                country: Some(cc.into()),
                protocol: Some(protocol.into()),
                ping,
                health_latency: ping,
                health,
                checked_at: ago.map(|m| now - m * 60_000),
            },
        )
        .collect();
    ServersView {
        rows,
        active_id: Some(VPN_SERVER.into()),
        tun_running: scene.connected(),
        locked: false,
    }
}

fn proxy_row(
    slot: u16,
    server: &ServerRowView,
    latency: Option<u32>,
    health: ProxyHealth,
) -> ProxyRowView {
    let port = 18_000 + slot;
    ProxyRowView {
        slot,
        process_running: true,
        ready: health == ProxyHealth::Healthy,
        health,
        profile_name: Some(server.name.clone()),
        country: server.country.clone(),
        port: Some(port),
        proxy_url: Some(format!("socks5://127.0.0.1:{port}")),
        latency_ms: latency,
        last_error: None,
    }
}

/// The picker's servers for `rows`: running proxies and the VPN's server are taken.
fn choices(servers: &ServersView, rows: &[ProxyRowView]) -> Vec<ProxyChoice> {
    servers
        .rows
        .iter()
        .map(|s| ProxyChoice {
            id: s.id.clone(),
            name: s.name.clone(),
            country: s.country.clone(),
            protocol: s.protocol.clone(),
            health: s.health,
            in_proxy: rows
                .iter()
                .any(|r| r.process_running && r.profile_name.as_deref() == Some(s.name.as_str())),
            vpn_server: servers.active_id.as_deref() == Some(s.id.as_str()),
        })
        .collect()
}

fn proxies(scene: DemoScene, servers: &ServersView) -> ProxiesView {
    let rows = if scene.connected() {
        vec![
            proxy_row(1, &servers.rows[1], Some(46), ProxyHealth::Healthy),
            proxy_row(2, &servers.rows[2], Some(63), ProxyHealth::Healthy),
        ]
    } else {
        Vec::new()
    };
    ProxiesView {
        choices: choices(servers, &rows),
        rows,
    }
}

/// The demo backend of the panel row.
pub struct DemoPanels {
    scene: DemoScene,
    traffic: Arc<watch::Sender<TrafficSample>>,
    servers: Arc<watch::Sender<ServersView>>,
    proxies: Arc<watch::Sender<ProxiesView>>,
}

impl DemoPanels {
    /// The demo for `scene` as the context value the panels read, and the switch that starts its
    /// traffic. Call inside the tokio runtime (`launch`'s contexts closure). After
    /// [`DemoFeed::start`] connected scenes feed the reference curve, one sample every 40 ms (the
    /// bars need every sample), and `Live` then one a second.
    pub fn handle(scene: DemoScene) -> (Rc<dyn PanelsApi>, DemoFeed) {
        let now = now_ms();
        let servers = servers(scene, now);
        let proxies = proxies(scene, &servers);
        let demo = DemoPanels {
            scene,
            traffic: Arc::new(watch::Sender::new(TrafficSample {
                ts: now,
                ..TrafficSample::default()
            })),
            servers: Arc::new(watch::Sender::new(servers)),
            proxies: Arc::new(watch::Sender::new(proxies)),
        };
        let start = DemoFeed(Arc::new(Notify::new()));
        if scene.connected() {
            let (tx, go) = (Arc::clone(&demo.traffic), Arc::clone(&start.0));
            tokio::spawn(async move {
                go.notified().await;
                feed(tx, scene == DemoScene::Live).await;
            });
        }
        (Rc::new(demo), start)
    }

    fn server(&self, id: &str) -> Option<ServerRowView> {
        self.servers
            .borrow()
            .rows
            .iter()
            .find(|r| r.id == id)
            .cloned()
    }

    /// Pushes `rows` with the picker's flags recomputed; returns the new state.
    fn set_rows(&self, rows: Vec<ProxyRowView>) -> ProxiesView {
        let view = ProxiesView {
            choices: choices(&self.servers.borrow(), &rows),
            rows,
        };
        self.proxies.send_replace(view.clone());
        view
    }

    /// Turns `slot` healthy after a start-up delay, as a real engine would.
    fn settle(&self, slot: u16) {
        let proxies = Arc::clone(&self.proxies);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(1_500)).await;
            proxies.send_modify(|v| {
                if let Some(r) = v.rows.iter_mut().find(|r| r.slot == slot) {
                    r.health = ProxyHealth::Healthy;
                    r.ready = true;
                    r.latency_ms = Some(40 + fastrand::u32(0..40));
                }
            });
        });
    }
}

/// Starts the demo traffic. Call once the window has painted: a burst sent while WebView2 is
/// still starting would be coalesced by the watch channel and leave holes in the bars.
#[derive(Clone)]
pub struct DemoFeed(Arc<Notify>);

impl DemoFeed {
    /// Lets the traffic feed run (later calls do nothing).
    pub fn start(&self) {
        self.0.notify_one();
    }
}

/// Feeds the reference curve, then (live) one sample a second around it.
async fn feed(tx: Arc<watch::Sender<TrafficSample>>, live: bool) {
    let started_at = now_ms() - 13_000;
    for i in 0..HISTORY {
        tx.send_replace(sample(i, started_at, now_ms() + i as i64));
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    if !live {
        return;
    }
    let mut i = HISTORY;
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let mut s = sample(i, started_at, now_ms());
        let jitter = 0.7 + fastrand::f64() * 0.6;
        s.download_bps *= jitter;
        s.smoothed_download_bps = s.download_bps;
        tx.send_replace(s);
        i += 1;
    }
}

#[async_trait::async_trait(?Send)]
impl PanelsApi for DemoPanels {
    fn traffic(&self) -> watch::Receiver<TrafficSample> {
        self.traffic.subscribe()
    }

    fn servers(&self) -> watch::Receiver<ServersView> {
        self.servers.subscribe()
    }

    fn proxies(&self) -> watch::Receiver<ProxiesView> {
        self.proxies.subscribe()
    }

    async fn ping_one(&self, id: &str) -> AppResult<Option<u32>> {
        tokio::time::sleep(Duration::from_millis(700)).await;
        let server = self
            .server(id)
            .ok_or_else(|| AppError::validation(Msg::new("errors.validation")))?;
        Ok(match server.health {
            ServerHealth::Offline => None,
            _ => Some(server.ping.unwrap_or(60) + fastrand::u32(0..9)),
        })
    }

    async fn ping_all(&self) -> AppResult<()> {
        tokio::time::sleep(Duration::from_millis(1_200)).await;
        let now = now_ms();
        self.servers.send_modify(|v| {
            for r in &mut v.rows {
                if r.health != ServerHealth::Offline {
                    let ms = r.ping.unwrap_or(70) + fastrand::u32(0..9);
                    (r.ping, r.health_latency) = (Some(ms), Some(ms));
                    (r.health, r.checked_at) = (ServerHealth::Online, Some(now));
                }
            }
        });
        Ok(())
    }

    async fn select_server(&self, id: &str) -> AppResult<Selected> {
        tokio::time::sleep(Duration::from_millis(300)).await;
        self.servers
            .send_modify(|v| v.active_id = Some(id.to_owned()));
        let rows = self.proxies.borrow().rows.clone();
        self.set_rows(rows);
        Ok(Selected::Done)
    }

    async fn proxy_start(&self, slot: u16, profile_id: &str) -> AppResult<ProxiesView> {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let server = self
            .server(profile_id)
            .ok_or_else(|| AppError::validation(Msg::new("ui.panels.proxy.pickFirst")))?;
        let mut rows = self.proxies.borrow().rows.clone();
        rows.retain(|r| r.slot != slot);
        rows.push(proxy_row(slot, &server, None, ProxyHealth::Starting));
        rows.sort_by_key(|r| r.slot);
        let view = self.set_rows(rows);
        self.settle(slot);
        Ok(view)
    }

    async fn proxy_stop(&self, slot: u16) -> AppResult<ProxiesView> {
        tokio::time::sleep(Duration::from_millis(400)).await;
        let mut rows = self.proxies.borrow().rows.clone();
        rows.retain(|r| r.slot != slot);
        Ok(self.set_rows(rows))
    }

    async fn proxy_rotate(&self, slot: u16) -> AppResult<ProxiesView> {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let current = self.proxies.borrow().clone();
        let at = current.rows.iter().position(|r| r.slot == slot);
        let name = at.and_then(|i| current.rows[i].profile_name.clone());
        let usable: Vec<&ProxyChoice> = current.choices.iter().filter(|c| c.usable()).collect();
        let next = usable
            .iter()
            .find(|c| Some(&c.name) > name.as_ref())
            .or(usable.first())
            .and_then(|c| self.server(&c.id));
        let (Some(at), Some(server)) = (at, next) else {
            return Err(AppError::conflict(Msg::new("errors.conflict")));
        };
        let mut rows = current.rows;
        rows[at] = proxy_row(slot, &server, None, ProxyHealth::Rotating);
        let view = self.set_rows(rows);
        self.settle(slot);
        Ok(view)
    }

    async fn proxy_stop_all(&self) -> AppResult<ProxiesView> {
        tokio::time::sleep(Duration::from_millis(600)).await;
        Ok(self.set_rows(Vec::new()))
    }

    async fn proxy_refresh(&self) -> AppResult<()> {
        if self.scene == DemoScene::Live {
            self.proxies.send_modify(|v| {
                for r in v
                    .rows
                    .iter_mut()
                    .filter(|r| r.health == ProxyHealth::Healthy)
                {
                    r.latency_ms = r
                        .latency_ms
                        .map(|ms| (ms + fastrand::u32(0..7)).saturating_sub(3).max(20));
                }
            });
        }
        Ok(())
    }
}
