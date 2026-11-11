//! The overlay: pumps [`WizardState`], owns the [`Model`] and the backend runs (proxy search, key
//! check, finish / skip), and renders the frame: kicker and counter, step ruler, the current
//! screen, the error of a failed finish, the footer.
use std::rc::Rc;

use dioxus::prelude::*;

use super::model::{Model, Step};
use super::steps::StepBody;
use super::{WizardApi, WizardState};
use crate::lang::{LANG, tr};
use crate::t;
use crate::widgets::{Button, ButtonKind, IconButton, IconGlyph, JobSlot, use_dom_id, use_job};

/// What the screens share with the frame.
#[derive(Clone, Copy, PartialEq)]
pub(super) struct Ctx {
    pub model: Signal<Model>,
    pub check: JobSlot<()>,
    pub detect: JobSlot<()>,
}

/// Which of the two applying actions is running (both share one slot: never both at once).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Apply {
    Finish,
    Skip,
}

/// Searches for a local proxy (once per session on the Connect screen, again on «Искать снова»).
pub(super) fn start_detection(api: Rc<dyn WizardApi>, ctx: Ctx) {
    let mut model = ctx.model;
    if !model.write().begin_detect() {
        return;
    }
    ctx.detect.start(move |_| async move {
        let result = api.detect_proxy().await;
        model.write().end_detect(result.map_err(|e| e.user_msg()));
        Ok(())
    });
}

/// Checks the key text; an edit cancels the run and the model drops a late answer anyway.
pub(super) fn start_check(api: Rc<dyn WizardApi>, ctx: Ctx) {
    let mut model = ctx.model;
    if ctx.check.running() {
        return;
    }
    let Some((seq, text)) = model.write().begin_check() else {
        return;
    };
    ctx.check.start(move |cancel| async move {
        let result = api.check_key(text, cancel).await;
        model
            .write()
            .end_check(seq, result.map_err(|e| e.user_msg()));
        Ok(())
    });
}

/// After a successful finish or skip the wizard closes at once; the app confirms with
/// `open: false`, and a later `open: true` is a new opening.
fn close(mut state: Signal<WizardState>) {
    state.write().open = false;
}

/// The first-run wizard. Renders nothing while [`super::WizardState::open`] is `false`; put it into
/// the shell's `overlays`. Needs `Rc<dyn WizardApi>` in context.
#[component]
pub fn Wizard() -> Element {
    let api = use_context::<Rc<dyn WizardApi>>();
    let rx = use_hook({
        let api = api.clone();
        move || api.state()
    });
    let mut state = use_signal({
        let rx = rx.clone();
        move || rx.borrow().clone()
    });
    let mut model = use_signal(|| Model::new(*LANG.peek(), &state.peek().current));
    let check = use_job::<()>();
    let detect = use_job::<()>();
    let apply = use_job::<()>();
    let mut applying = use_signal(|| Apply::Finish);
    let ctx = Ctx {
        model,
        check,
        detect,
    };
    use_future(move || {
        let mut rx = rx.clone();
        async move {
            while rx.changed().await.is_ok() {
                let next = rx.borrow_and_update().clone();
                if next.open && !state.peek().open {
                    // a fresh wizard each time it opens, from the settings as they are now
                    check.cancel();
                    detect.cancel();
                    apply.clear();
                    model.set(Model::new(*LANG.peek(), &next.current));
                }
                state.set(next);
            }
        }
    });
    let finish = {
        let api = api.clone();
        move |_| {
            let choices = model.peek().choices();
            let api = api.clone();
            applying.set(Apply::Finish);
            apply.start(move |_| async move {
                api.finish(choices).await?;
                close(state);
                Ok(())
            });
        }
    };
    let skip = {
        let api = api.clone();
        move |_| {
            let lang = model.peek().lang;
            let api = api.clone();
            applying.set(Apply::Skip);
            apply.start(move |_| async move {
                api.skip(lang).await?;
                close(state);
                Ok(())
            });
        }
    };
    let next = {
        let api = api.clone();
        move |_| {
            model.write().forward();
            if model.peek().wants_detection() {
                start_detection(api.clone(), ctx);
            }
        }
    };

    let title_id = use_dom_id("wz-title");
    if !state.read().open {
        return rsx! {};
    }
    let step = model.read().step;
    let busy = apply.running();
    let finishing = busy && applying() == Apply::Finish;
    let skipping = busy && applying() == Apply::Skip;
    let error = match apply.last() {
        Some(Err(e)) => Some(tr(&e.msg)),
        _ => None,
    };
    rsx! {
        div {
            class: "c-swiss wz-root",
            role: "dialog",
            aria_modal: "true",
            aria_labelledby: "{title_id}",
            tabindex: "-1",
            div { class: "wz-frame",
                div { class: "wz-head",
                    p { class: "swiss-label wz-kicker", {t!("ui.wizard.kicker")} }
                    p { class: "swiss-label wz-count",
                        {t!("onboarding.step", current = step.index() + 1, total = Step::ALL.len())}
                    }
                }
                Ruler { step }
                section { class: "wz-panel",
                    StepBody { ctx, title_id: title_id.clone() }
                }
                if let Some(text) = error {
                    div { class: "wz-error", role: "alert",
                        span { class: "wz-error-mark" }
                        p { class: "wz-error-text", "{text}" }
                        IconButton {
                            glyph: IconGlyph::Close,
                            label: t!("common.close"),
                            onclick: move |_| apply.clear(),
                        }
                    }
                }
                div { class: "wz-foot",
                    if step != Step::Done {
                        Button { kind: ButtonKind::Link, busy: skipping, disabled: busy, onclick: skip,
                            {t!("onboarding.skip")}
                        }
                    }
                    div { class: "wz-foot-main",
                        if step != Step::Welcome {
                            Button {
                                kind: ButtonKind::Ghost,
                                disabled: busy,
                                onclick: move |_| {
                                    model.write().backward();
                                },
                                {t!("onboarding.back")}
                            }
                        }
                        if step == Step::Done {
                            Button {
                                kind: ButtonKind::Primary,
                                busy: finishing,
                                disabled: check.running() || skipping,
                                disabled_reason: check.running().then(|| t!("ui.wizard.done.waitCheck")),
                                onclick: finish,
                                {t!("onboarding.finish")}
                            }
                        } else {
                            Button { kind: ButtonKind::Primary, disabled: busy, onclick: next,
                                {t!("onboarding.next")}
                                span { class: "wz-arrow", aria_hidden: "true", "→" }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// The five steps as a numbered hairline ruler; the current one is marked for assistive
/// technology with `aria-current="step"`.
#[component]
fn Ruler(step: Step) -> Element {
    rsx! {
        ol { class: "wz-ruler", aria_label: t!("ui.wizard.progress"),
            for s in Step::ALL {
                li {
                    key: "{s.index()}",
                    class: "wz-ruler-item",
                    class: if s.index() < step.index() { "is-done" },
                    class: if s == step { "is-current" },
                    aria_current: (s == step).then_some("step"),
                    span { class: "wz-ruler-num swiss-mono", "{s.index() + 1:02}" }
                    span { class: "wz-ruler-name", {t!(s.label_key())} }
                }
            }
        }
    }
}
