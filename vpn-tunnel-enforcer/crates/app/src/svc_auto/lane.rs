//! The lifecycle as the coordinator drives it: one seam, so the owner rules on top of the lane
//! are tested against a fake lane (production: [`Lifecycle`] itself).
use async_trait::async_trait;
use tokio::sync::{broadcast, watch};
use vpnte_base::types::{AdaptiveMode, Owner};
use vpnte_tunnel::lifecycle::{
    ConnError, ConnectReq, DisconnectReq, Done, Lifecycle, SessionEvent, SessionView, SwitchReq,
};

#[async_trait]
pub trait Lane: Send + Sync + 'static {
    async fn connect(&self, req: ConnectReq) -> Result<Done, ConnError>;
    async fn disconnect(&self, req: DisconnectReq) -> Result<Done, ConnError>;
    /// A switch as a rotation (`rotation = true`, history `rotation`) or a server switch.
    async fn switch(&self, req: SwitchReq, rotation: bool) -> Result<Done, ConnError>;
    async fn restart_adaptive(
        &self,
        mode: AdaptiveMode,
        sibling: Option<String>,
        owner: Owner,
    ) -> Result<Done, ConnError>;
    fn session(&self) -> watch::Receiver<Option<SessionView>>;
    fn events(&self) -> broadcast::Receiver<SessionEvent>;
    fn busy(&self) -> bool;
    fn adopt(&self, owner: Owner);
}

#[async_trait]
impl Lane for Lifecycle {
    async fn connect(&self, req: ConnectReq) -> Result<Done, ConnError> {
        Lifecycle::connect(self, req).await
    }

    async fn disconnect(&self, req: DisconnectReq) -> Result<Done, ConnError> {
        Lifecycle::disconnect(self, req).await
    }

    async fn switch(&self, req: SwitchReq, rotation: bool) -> Result<Done, ConnError> {
        if rotation {
            self.rotate(req).await
        } else {
            self.switch_upstream(req).await
        }
    }

    async fn restart_adaptive(
        &self,
        mode: AdaptiveMode,
        sibling: Option<String>,
        owner: Owner,
    ) -> Result<Done, ConnError> {
        Lifecycle::restart_adaptive(self, mode, sibling, owner).await
    }

    fn session(&self) -> watch::Receiver<Option<SessionView>> {
        Lifecycle::session(self)
    }

    fn events(&self) -> broadcast::Receiver<SessionEvent> {
        Lifecycle::events(self)
    }

    fn busy(&self) -> bool {
        Lifecycle::busy(self)
    }

    fn adopt(&self, owner: Owner) {
        Lifecycle::adopt(self, owner);
    }
}
