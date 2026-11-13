//! What needs the helper service, said up front (p-noadmin-ui; NOADMIN §0, owner decision
//! 12.11.2026). The app runs without administrator rights; Tunnel mode and the WFP kill switch run
//! in the helper service. Pages read one [`Capability`] view and show a privileged control as
//! available after the install: one calm line where it lives and «Установить службу-помощник»
//! where installing helps — never a modal, a warning colour or an error after a click.
//!
//! The app implements [`HelperApi`] and hands it down as `Rc<dyn HelperApi>` in context;
//! [`demo::DemoHelper`] is the fake for the demos and the tests.
use std::rc::Rc;

use dioxus::prelude::*;
use tokio::sync::watch;
use vpnte_base::AppResult;

use crate::hooks::use_watch;

pub mod demo;
mod model;
mod strip;
#[cfg(test)]
mod tests;
mod view;

pub use model::{Ability, Capability, Feature, Lack, Service};
pub use strip::TunnelStrip;
pub use view::{HelperLine, InstallService};

/// The helper service as the pages need it (implemented by the app's `api_helper`).
#[async_trait::async_trait(?Send)]
pub trait HelperApi: 'static {
    /// The capability view: pushed at start, after an install and when the service's version
    /// becomes known.
    fn capability(&self) -> watch::Receiver<Capability>;
    /// «Установить службу-помощник»: Windows shows its one prompt for the service's own install
    /// verb (the app itself never elevates). `Ok(true)` installed (the view says so before this
    /// returns), `Ok(false)` nobody approved the prompt: nothing changes, proxy mode goes on.
    async fn install_service(&self) -> AppResult<bool>;
}

/// The capability view of the app in context, followed live; `None` without a helper backend
/// (the demos and tests of other pages), where a page shows nothing of it.
pub fn use_capability() -> Option<Capability> {
    let api = try_use_context::<Rc<dyn HelperApi>>();
    let present = api.is_some();
    let view = use_watch(move || match api {
        Some(api) => api.capability(),
        None => watch::channel(Capability::default()).1,
    });
    present.then(|| view.read().clone())
}
