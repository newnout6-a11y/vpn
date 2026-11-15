//! The Maintenance page in each helper service state (p-noadmin-ui), unelevated unless the
//! scene says otherwise: the protection read-back and the repair steps say up front what needs
//! the service (or is not in this version) instead of failing after «Починить».
use std::rc::Rc;

use dioxus::prelude::*;

use super::demo::{DemoMaintenanceApi, Scene};
use super::{MaintenanceApi, MaintenancePage};
use crate::helper::HelperApi;
use crate::helper::demo::{DemoHelper, HelperScene};
use crate::test_support::{Shown, shown};
use crate::widgets::Toasts;

#[component]
fn Root() -> Element {
    Toasts::use_provider();
    rsx! {
        MaintenancePage {}
    }
}

async fn page(scene: HelperScene) -> (VirtualDom, Shown) {
    crate::test_locales::init_locales();
    let demo = DemoMaintenanceApi::new(Scene::Off);
    if scene == HelperScene::Missing {
        demo.without_service();
    }
    let api: Rc<dyn MaintenanceApi> = demo;
    let helper: Rc<dyn HelperApi> = Rc::new(DemoHelper::new(scene));
    let mut dom = VirtualDom::new(Root)
        .with_root_context(api)
        .with_root_context(helper);
    let seen = shown(&mut dom).await;
    (dom, seen)
}

fn text(dom: &VirtualDom, key: &str) -> String {
    dom.in_runtime(|| crate::lang::translate_now(key, &[]))
}

/// No service: no filters to read back is said calmly (not a failure), the kill switch's line
/// offers the install once, the filters step says it runs through the service and the old
/// version's step that it is not in this version — before any click.
#[tokio::test]
async fn without_the_service_the_page_says_so_before_a_click() {
    let (dom, seen) = page(HelperScene::Missing).await;
    assert!(seen.shows(&text(&dom, "ui.maintenance.protection.state.proxyOnly")));
    assert!(seen.has("data-helper", "kill-switch"), "{:?}", seen.texts);
    assert!(seen.shows(&text(&dom, "ui.helper.killSwitch")));
    assert_eq!(
        seen.texts
            .iter()
            .filter(|t| **t == text(&dom, "ui.helper.install"))
            .count(),
        1
    );
    assert!(seen.shows(&text(&dom, "ui.helper.viaService")));
    assert!(seen.shows(&text(&dom, "ui.helper.notInVersion")));
}

/// Installed (and older, which carries the filters all the same): the filters step and the
/// kill switch say nothing; only the old version's step, which no part of this version runs
/// for an unelevated app, is marked.
#[tokio::test]
async fn with_the_service_only_the_old_versions_step_is_marked() {
    for scene in [HelperScene::Installed, HelperScene::Older] {
        let (dom, seen) = page(scene).await;
        assert!(!seen.has("data-helper", "kill-switch"), "{scene:?}");
        assert!(
            !seen.shows(&text(&dom, "ui.helper.viaService")),
            "{scene:?}"
        );
        assert!(!seen.shows(&text(&dom, "ui.helper.install")), "{scene:?}");
        assert!(
            seen.shows(&text(&dom, "ui.helper.notInVersion")),
            "{scene:?}"
        );
        assert!(!seen.shows(&text(&dom, "ui.maintenance.protection.state.proxyOnly")));
    }
}

/// Elevated without the service: every step runs in-process; nothing is marked.
#[tokio::test]
async fn an_elevated_app_marks_nothing() {
    let (dom, seen) = page(HelperScene::Elevated).await;
    assert!(!seen.has("data-helper", "kill-switch"));
    for key in [
        "ui.helper.viaService",
        "ui.helper.notInVersion",
        "ui.helper.install",
    ] {
        assert!(!seen.shows(&text(&dom, key)), "{key}");
    }
}
