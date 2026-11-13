//! The Settings page in each helper service state (p-noadmin-ui), unelevated unless the scene
//! says otherwise: what needs the service says so where it lives, with its install where that
//! helps; nothing extra while it works; nothing offered that cannot run.
use std::rc::Rc;

use dioxus::prelude::*;

use super::demo::DemoSettingsApi;
use super::{SettingsApi, SettingsPage};
use crate::helper::HelperApi;
use crate::helper::demo::{DemoHelper, HelperScene};
use crate::pages::{Page, use_nav_provider};
use crate::test_support::{Shown, shown};
use crate::theme::ThemeMode;
use crate::widgets::Toasts;

#[component]
fn Root() -> Element {
    let advanced = use_signal(|| true);
    use_nav_provider(Page::Settings, advanced.into());
    Toasts::use_provider();
    rsx! {
        SettingsPage {}
    }
}

async fn page(scene: HelperScene) -> (VirtualDom, Shown) {
    crate::test_locales::init_locales();
    let demo = DemoSettingsApi::new("default", ThemeMode::default());
    demo.set_always_available(matches!(scene, HelperScene::Installed | HelperScene::Older));
    let api: Rc<dyn SettingsApi> = demo;
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

fn count(seen: &Shown, text: &str) -> usize {
    seen.texts.iter().filter(|t| *t == text).count()
}

/// No service: Tunnel mode and the kill switch say they work through it, each with the
/// install; browser policies are not in this version (no buttons); the exceptions stay
/// read-only; «Всегда» needs no note of its own.
#[tokio::test]
async fn without_the_service_each_privileged_control_says_so_up_front() {
    let (dom, seen) = page(HelperScene::Missing).await;
    assert!(seen.has("data-helper", "tunnel"), "{:?}", seen.texts);
    assert!(seen.has("data-helper", "kill-switch"));
    assert!(seen.has("data-helper", "policies"));
    assert!(seen.shows(&text(&dom, "ui.helper.tunnel")));
    assert!(seen.shows(&text(&dom, "ui.helper.killSwitch")));
    assert!(seen.shows(&text(&dom, "ui.helper.notInVersion")));
    assert_eq!(count(&seen, &text(&dom, "ui.helper.install")), 2);
    assert!(!seen.shows(&text(&dom, "ui.settings.browser.apply")));
    assert!(!seen.shows(&text(&dom, "killSwitch.addException")));
    assert!(!seen.shows(&text(&dom, "ui.settings.killSwitch.needsService")));
}

/// Installed: Tunnel mode and the kill switch say nothing; the exceptions can be added; the
/// browser policies are still not in this version (the service carries no registry writes).
#[tokio::test]
async fn an_installed_service_leaves_only_what_this_version_lacks() {
    let (dom, seen) = page(HelperScene::Installed).await;
    assert!(!seen.has("data-helper", "tunnel"));
    assert!(!seen.has("data-helper", "kill-switch"));
    assert!(seen.has("data-helper", "policies"));
    assert!(!seen.shows(&text(&dom, "ui.helper.install")));
    assert!(seen.shows(&text(&dom, "killSwitch.addException")));
    assert!(!seen.shows(&text(&dom, "ui.settings.browser.apply")));
}

/// An older service: one line under Tunnel mode says what it does not do yet; no install.
#[tokio::test]
async fn an_older_service_says_what_it_does_not_do_yet() {
    let (dom, seen) = page(HelperScene::Older).await;
    assert!(seen.has("data-lack", "app-scope"));
    assert!(seen.shows(&text(&dom, "ui.helper.older.appScope")));
    assert!(!seen.shows(&text(&dom, "ui.helper.install")));
    assert!(!seen.has("data-helper", "kill-switch"));
}

/// An elevated app without the service: everything it hosts works in-process, as before; no
/// line, no install, the browser buttons are there.
#[tokio::test]
async fn an_elevated_app_works_in_process_without_a_line() {
    let (dom, seen) = page(HelperScene::Elevated).await;
    for id in ["tunnel", "kill-switch", "policies"] {
        assert!(!seen.has("data-helper", id), "{id}");
    }
    assert!(!seen.shows(&text(&dom, "ui.helper.install")));
    assert!(seen.shows(&text(&dom, "ui.settings.browser.apply")));
    assert!(seen.shows(&text(&dom, "killSwitch.addException")));
}
