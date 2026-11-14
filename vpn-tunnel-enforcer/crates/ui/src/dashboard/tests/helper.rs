//! The start page's strip of a saved Tunnel mode that waits for the helper service
//! (p-noadmin-ui): said before «Подключить» is pressed, with its install, only while the
//! service is missing and the saved mode is Tunnel; the «Пломба» page is otherwise unchanged.
use std::rc::Rc;

use dioxus::prelude::*;

use super::super::Dashboard;
use super::super::demo::{DashScene, DemoDashboard};
use crate::helper::HelperApi;
use crate::helper::demo::{DemoHelper, HelperScene};
use crate::test_support::{Shown, shown};
use crate::widgets::Toasts;

#[derive(Clone, Copy)]
struct Scenes(DashScene, HelperScene);

fn root() -> Element {
    let Scenes(dash, helper) = use_context::<Scenes>();
    let (api, panels, start) = use_hook(|| DemoDashboard::handle(dash));
    use_context_provider(|| api);
    use_context_provider(|| panels);
    use_context_provider(|| Rc::new(DemoHelper::new(helper)) as Rc<dyn HelperApi>);
    use_hook(|| start.start());
    Toasts::use_provider();
    rsx! {
        Dashboard {}
    }
}

/// Whether the page showed the strip's body (and, with it, the install).
async fn strip(dash: DashScene, helper: HelperScene) -> (bool, bool) {
    crate::test_locales::init_locales();
    let mut dom = VirtualDom::new(root).with_root_context(Scenes(dash, helper));
    let seen: Shown = shown(&mut dom).await;
    let text = |key: &str| dom.in_runtime(|| crate::lang::translate_now(key, &[]));
    (
        seen.shows(&text("ui.helper.strip.body")),
        seen.shows(&text("ui.helper.install")),
    )
}

#[tokio::test]
async fn a_saved_tunnel_mode_without_the_service_is_said_before_connecting() {
    let shown = strip(DashScene::Disconnected, HelperScene::Missing).await;
    assert_eq!(shown, (true, true));
}

/// (Proxy mode saved: `helper::tests`, the strip on its own; the demo's timelines start from a
/// Tunnel frame.)
#[tokio::test]
async fn nothing_is_said_where_tunnel_mode_runs() {
    for helper in [
        HelperScene::Installed,
        HelperScene::Older,
        HelperScene::Elevated,
    ] {
        let shown = strip(DashScene::Disconnected, helper).await;
        assert_eq!(shown, (false, false), "{helper:?}");
    }
}
