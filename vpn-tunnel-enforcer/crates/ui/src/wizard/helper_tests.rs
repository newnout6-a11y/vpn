//! The wizard's Tunnel mode in each helper service state (p-noadmin-ui), unelevated unless the
//! scene says otherwise: the routing step and the summary say up front where Tunnel mode waits
//! for the service, with its install, and the summary shows what «Завершить» saves.
use std::rc::Rc;

use dioxus::prelude::*;
use vpnte_base::i18n::Lang;

use super::model::{Model, Step};
use super::steps::StepBody;
use super::view::Ctx;
use super::{DemoScene, DemoWizardApi, Routing, WizardApi, WizardDefaults};
use crate::helper::HelperApi;
use crate::helper::demo::{DemoHelper, HelperScene};
use crate::test_support::{Shown, shown};
use crate::widgets::use_job;

#[derive(Clone, Copy)]
struct At(Step, HelperScene);

/// One step of a wizard where Tunnel mode was chosen.
fn root() -> Element {
    let At(step, helper) = use_context::<At>();
    use_context_provider(|| Rc::new(DemoHelper::new(helper)) as Rc<dyn HelperApi>);
    use_context_provider(|| Rc::new(DemoWizardApi::new(DemoScene::default())) as Rc<dyn WizardApi>);
    let model = use_signal(|| {
        let mut model = Model::new(Lang::Ru, &WizardDefaults::default());
        model.routing = Routing::Hard;
        model.step = step;
        model
    });
    let ctx = Ctx {
        model,
        check: use_job(),
        detect: use_job(),
    };
    rsx! {
        StepBody { ctx, title_id: "wz-title".to_string() }
    }
}

async fn step(step: Step, helper: HelperScene) -> (VirtualDom, Shown) {
    crate::test_locales::init_locales();
    let mut dom = VirtualDom::new(root).with_root_context(At(step, helper));
    let seen = shown(&mut dom).await;
    (dom, seen)
}

fn text(dom: &VirtualDom, key: &str) -> String {
    dom.in_runtime(|| crate::lang::translate_now(key, &[]))
}

/// No service: the routing step says Tunnel mode works through it and offers the install; the
/// summary shows Proxy (what is saved) with the same line, so «Завершить» never fails for it.
#[tokio::test]
async fn without_the_service_tunnel_mode_is_said_up_front() {
    let (dom, seen) = step(Step::Routing, HelperScene::Missing).await;
    assert!(seen.has("data-helper", "tunnel"), "{:?}", seen.texts);
    assert!(seen.shows(&text(&dom, "ui.helper.install")));

    let (dom, seen) = step(Step::Done, HelperScene::Missing).await;
    assert!(seen.shows(&text(&dom, "ui.wizard.routing.soft")));
    assert!(!seen.shows(&text(&dom, "ui.wizard.routing.hard")));
    assert!(seen.has("data-helper", "tunnel"));
}

/// Installed, or an elevated app hosting it in-process: Tunnel mode is saved as chosen and
/// nothing is said; an older service says what it does not do yet, without an install.
#[tokio::test]
async fn where_tunnel_mode_runs_it_is_saved_as_chosen() {
    for helper in [HelperScene::Installed, HelperScene::Elevated] {
        for at in [Step::Routing, Step::Done] {
            let (dom, seen) = step(at, helper).await;
            assert!(!seen.has("data-helper", "tunnel"), "{helper:?} {at:?}");
            assert!(!seen.shows(&text(&dom, "ui.helper.install")), "{helper:?}");
        }
        let (dom, seen) = step(Step::Done, helper).await;
        assert!(
            seen.shows(&text(&dom, "ui.wizard.routing.hard")),
            "{helper:?}"
        );
    }
    for at in [Step::Routing, Step::Done] {
        let (dom, seen) = step(at, HelperScene::Older).await;
        assert!(seen.has("data-lack", "app-scope"), "{at:?}");
        assert!(!seen.shows(&text(&dom, "ui.helper.install")), "{at:?}");
    }
}
