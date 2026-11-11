//! The Apps page («Приложения», split tunnel): a rule per program — through the VPN, around it
//! or none — plus bypass by bare process name; search, rescan, add a program (ui-pages §3.14).
//!
//! Data and actions come from a [`SplitTunnelApi`] in context (`Rc<dyn SplitTunnelApi>`); the
//! app implements it over the routing service, [`demo::DemoSplitTunnel`] fakes it. Register the
//! page with `registry.register(Page::Apps, SplitTunnelPage)`. The page stays mounted when
//! hidden, so the search and a running rescan survive navigation, as before.
pub mod demo;
mod model;
mod page;
#[cfg(test)]
mod tests;

use std::rc::Rc;

use crate::hooks::use_watch;
use crate::lang::tr_now;
use dioxus::prelude::*;

pub use model::{
    AppKind, AppRule, SplitApp, SplitSnapshot, SplitTunnelApi, display_path, icon_src, initial,
    matches,
};
pub use page::SplitTunnelPage;

/// The API from context.
fn use_api() -> Rc<dyn SplitTunnelApi> {
    use_context::<Rc<dyn SplitTunnelApi>>()
}
