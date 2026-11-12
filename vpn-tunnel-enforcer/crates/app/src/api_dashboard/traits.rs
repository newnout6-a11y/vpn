//! `vpnte_ui`'s start-page and tray traits over the [`Hub`].
use std::net::IpAddr;
use std::sync::Arc;

use tokio::sync::watch;
use vpnte_base::types::Verdict;
use vpnte_base::{AppResult, Msg};
use vpnte_core::ops::Source;
use vpnte_servers::model::ProfileId;
use vpnte_ui::dashboard::{DashboardApi, DashboardView};
use vpnte_ui::panels::{PanelsApi, ProxiesView, Selected, ServersView};
use vpnte_ui::tray::{QuitMode, TrayApi, TrayState};
use vpnte_view::traffic::TrafficSample;

use super::actions::Shows;
use super::proxies::ProxyAction;
use super::{Hub, project};

/// [`DashboardApi`] over the hub.
pub(super) struct Dashboard(pub Arc<Hub>);

/// [`PanelsApi`] over the hub.
pub(super) struct Panels(pub Arc<Hub>);

/// [`TrayApi`] over the hub.
pub(super) struct Tray(pub Arc<Hub>);

#[async_trait::async_trait(?Send)]
impl DashboardApi for Dashboard {
    fn state(&self) -> watch::Receiver<DashboardView> {
        self.0.dash.subscribe()
    }

    async fn connect(&self) -> AppResult<()> {
        let call =
            |t: Arc<dyn crate::services::TunnelOps>| async move { t.connect(Source::Ui).await };
        self.0.lane(Shows::Notices, call).await.map(|_| ())
    }

    async fn disconnect(&self) -> AppResult<Option<Msg>> {
        let call =
            |t: Arc<dyn crate::services::TunnelOps>| async move { t.disconnect(Source::Ui).await };
        let done = self.0.lane(Shows::Answer, call).await?;
        Ok(done.warnings.into_iter().next())
    }

    async fn cancel(&self) -> AppResult<Option<Msg>> {
        self.0.cancel().await
    }

    async fn set_smart_ru(&self, on: bool) -> AppResult<()> {
        self.0.set_smart_ru(on).await
    }

    async fn run_leak_check(&self) -> AppResult<Verdict> {
        let report = self.0.leak_check(Source::Ui).await?;
        Ok(project::leak_verdict(&report))
    }

    async fn copy_ip(&self, ip: IpAddr) -> AppResult<()> {
        self.0.copy_ip(ip).await
    }

    async fn recheck_firewall(&self) -> AppResult<()> {
        self.0.recheck_firewall().await
    }

    async fn release_kill_switch(&self) -> AppResult<()> {
        self.0.release_kill_switch().await
    }

    async fn retry_now(&self) -> AppResult<()> {
        if self.0.retry_now().await? {
            return Ok(());
        }
        // Nothing paused any more: «Подключить» is a plain connect.
        self.connect().await
    }
}

#[async_trait::async_trait(?Send)]
impl PanelsApi for Panels {
    fn traffic(&self) -> watch::Receiver<TrafficSample> {
        self.0.traffic.subscribe()
    }

    fn servers(&self) -> watch::Receiver<ServersView> {
        self.0.servers.subscribe()
    }

    fn proxies(&self) -> watch::Receiver<ProxiesView> {
        self.0.proxies.subscribe()
    }

    async fn ping_one(&self, id: &str) -> AppResult<Option<u32>> {
        let id = ProfileId::from(id);
        let results = self.0.ping(vec![id.clone()]).await?;
        Ok(results
            .into_iter()
            .find(|(k, _)| *k == id)
            .and_then(|(_, sample)| sample)
            .map(|s| s.ms))
    }

    async fn ping_all(&self) -> AppResult<()> {
        let ids = self
            .0
            .servers
            .borrow()
            .rows
            .iter()
            .map(|row| ProfileId::from(row.id.as_str()))
            .collect();
        self.0.ping(ids).await.map(|_| ())
    }

    async fn select_server(&self, id: &str) -> AppResult<Selected> {
        self.0.select(id.to_owned()).await
    }

    async fn proxy_start(&self, slot: u16, profile_id: &str) -> AppResult<ProxiesView> {
        let profile_id = profile_id.to_owned();
        self.0.proxy(ProxyAction::Start { slot, profile_id }).await
    }

    async fn proxy_stop(&self, slot: u16) -> AppResult<ProxiesView> {
        self.0.proxy(ProxyAction::Stop(slot)).await
    }

    async fn proxy_rotate(&self, slot: u16) -> AppResult<ProxiesView> {
        self.0.proxy(ProxyAction::Rotate(slot)).await
    }

    async fn proxy_stop_all(&self) -> AppResult<ProxiesView> {
        self.0.proxy(ProxyAction::StopAll).await
    }

    /// The manager pushes every visible change; readiness alone expires with the clock, so the
    /// page's cadence re-projects it.
    async fn proxy_refresh(&self) -> AppResult<()> {
        self.0.publish_proxies();
        Ok(())
    }
}

#[async_trait::async_trait(?Send)]
impl TrayApi for Tray {
    fn state(&self) -> watch::Receiver<TrayState> {
        self.0.tray.subscribe()
    }

    async fn start(&self) -> AppResult<()> {
        // In the paused state the menu's «Подключить» retries the paused session now.
        if self.0.tray.borrow().paused && self.0.retry_now().await? {
            return Ok(());
        }
        let call =
            |t: Arc<dyn crate::services::TunnelOps>| async move { t.connect(Source::Tray).await };
        self.0.lane(Shows::Notices, call).await.map(|_| ())
    }

    async fn stop(&self) -> AppResult<()> {
        let call = |t: Arc<dyn crate::services::TunnelOps>| async move {
            t.disconnect(Source::Tray).await
        };
        self.0.lane(Shows::Notices, call).await.map(|_| ())
    }

    async fn check_route(&self) -> AppResult<()> {
        self.0.check_route().await
    }

    async fn open_logs(&self) -> AppResult<()> {
        vpnte_winnet::shell::open_folder(&self.0.backend.dirs.logs).await
    }

    async fn quit(&self, mode: QuitMode) -> AppResult<()> {
        self.0.quit(mode).await
    }
}
