//! «Пломбик» on screen: the overlay that draws the mascot on his current perch, hops between
//! perches, talks in a speech bubble and reacts to the rest of the UI.
//!
//! - [`MascotBus`]: the channel other components use to tell him things (tunnel phase, speed band,
//!   session start, page visibility, power-button hover, leak results, Smart RU, proxy actions,
//!   notices). Provide one with [`use_mascot_bus_provider`] above every sender and the host.
//! - [`MascotHost`]: the overlay. One task owns the behaviour machine
//!   ([`vpnte_view::mascot::MascotBrain`]) and its RNG; geometry and frame-rate motion run in the
//!   page (`assets/js/mascot.js`, protocol in `mascot/stage.rs`).
//!
//! Spots are marked in the page with `data-perch="<name>"` (+ optional `data-perch-x` 0..1,
//! `data-perch-y` `top|bottom`, `data-perch-scale`, `data-perch-fit="gap"`); the brain names the
//! spot ([`Perch::as_str`]), the stage finds it.
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, Instant};

use dioxus::document::{self, EvalError};
use dioxus::prelude::*;
use tokio::sync::broadcast::{self, error::RecvError};
use vpnte_view::mascot::{LABEL_KEY, MascotBrain, MascotView};

use crate::lang::translate;
use crate::theme;

mod bus;
mod face;
mod markup;
mod stage;

pub use bus::{MascotBus, use_mascot_bus, use_mascot_bus_provider};
use face::Surface;
pub use vpnte_view::mascot::{MascotEvent, MascotPhase, Perch};

use stage::{Cmd, Geo, JsEvent};

/// The greeting is once per app session, not once per dashboard mount.
static GREETED: AtomicBool = AtomicBool::new(false);

/// Distinguishes the overlay roots of hosts (a remount or a stray second host).
static NEXT_STAGE: AtomicU32 = AtomicU32::new(1);

/// The mascot overlay (`position: fixed` over the whole window, `z-index: 40`). Render it once:
/// at the shell root, or inside the dashboard. Nothing is drawn until the bus knows the tunnel
/// phase and the stage has placed him; he is hidden while the bus says the dashboard is not the
/// active page.
///
/// `greet_time`: local time of day used by the once-per-session greeting; `None` reads the clock
/// (the app). Demos pin it to reproduce the reference scenes.
#[component]
pub fn MascotHost(#[props(default)] greet_time: Option<Duration>) -> Element {
    let bus = use_mascot_bus();
    let stage_id = use_hook(|| NEXT_STAGE.fetch_add(1, Ordering::Relaxed));
    // Subscribe at mount so nothing sent between the first render and the task's start is lost.
    let inbox = use_hook(|| Rc::new(RefCell::new(Some(bus.subscribe()))));
    let out = Out {
        view: use_signal(|| None),
        geo: use_signal(Geo::default),
        phase: use_signal(|| bus.facts().phase.unwrap_or(MascotPhase::Off)),
        active: use_signal(|| bus.facts().page_active),
    };

    let poke_bus = bus.clone();
    // A hook, not `EventHandler::new` in the body: that would add a box to this scope per render.
    let on_poke = use_callback(move |()| poke_bus.send(MascotEvent::Poke));
    let theme_bus = bus.clone();
    use_effect(move || theme_bus.send(MascotEvent::ThemeDark(theme::scheme().is_dark())));

    use_future(move || {
        let bus = bus.clone();
        let inbox = inbox.borrow_mut().take();
        async move {
            if let Some(inbox) = inbox {
                run(bus, inbox, stage_id, greet_time, out).await;
            }
        }
    });

    let label = translate(LABEL_KEY, &[], None);
    let geo = (out.geo)();
    let shown = geo.placed && (out.active)();
    let drawn = (out.view)().filter(|_| shown).map(|view| {
        let on = (out.phase)() == MascotPhase::On;
        // In the air he is excited and drawn as on paper, whatever is below.
        let (view, surface) = if geo.airborne {
            let mood = vpnte_view::mascot::Mood::Excited;
            (MascotView { mood, ..view }, Surface::Paper)
        } else {
            (view, geo.surface)
        };
        markup::Look {
            colors: face::colors(on, surface),
            view,
            land: geo.land,
            label,
        }
    });
    rsx! {
        div { class: "c-swiss pointer-events-none fixed inset-0 z-40", "data-mascot-stage": "{stage_id}",
            if let Some(look) = drawn {
                div { class: "pointer-events-auto absolute", style: stage::BOX_STYLE,
                    {markup::mascot(&look, on_poke)}
                }
                if let Some(speech) = &look.view.speech {
                    {markup::bubble(speech.id, &crate::lang::tr(&speech.msg), geo.below)}
                }
                // Replies the user asked for (pokes, petting) are read out; ambient chatter is not.
                span { class: "sr-only", aria_live: "polite",
                    if let Some(speech) = look.view.speech.as_ref().filter(|s| s.announce) {
                        {crate::lang::tr(&speech.msg)}
                    }
                }
            }
        }
    }
}

/// Signals the host task writes and the overlay renders.
#[derive(Clone, Copy)]
struct Out {
    /// `None` until the brain exists (the phase is known).
    view: Signal<Option<MascotView>>,
    geo: Signal<Geo>,
    phase: Signal<MascotPhase>,
    active: Signal<bool>,
}

/// The host task: starts the stage, waits until the tunnel phase is known, then feeds the brain
/// with bus events, stage reports and its own deadlines, and publishes view and perch.
async fn run(
    bus: MascotBus,
    mut inbox: broadcast::Receiver<MascotEvent>,
    stage_id: u32,
    greet_time: Option<Duration>,
    mut out: Out,
) {
    let mut js = document::eval(&stage::script(stage_id));
    let mut js_alive = true;
    let send = move |cmd: Cmd| {
        if let Err(e) = js.send(cmd) {
            tracing::debug!(%e, ?cmd, "mascot stage did not take a command");
        }
    };
    send(Cmd::Active {
        value: bus.facts().page_active,
    });
    send(Cmd::Perch {
        name: Perch::Home.as_str(),
    });

    let Some(phase) = known_phase(&bus, &mut inbox).await else {
        return;
    };
    let mut rng = fastrand::Rng::new();
    let now = Instant::now();
    let greeting =
        (!GREETED.load(Ordering::Relaxed)).then(|| greet_time.unwrap_or_else(local_time_of_day));
    let mut brain = MascotBrain::new(now, phase, greeting, &mut rng);
    let facts = bus.facts();
    for ev in [
        MascotEvent::ThemeDark(theme::scheme().is_dark()),
        MascotEvent::SpeedBand(facts.band),
        MascotEvent::SessionAge(bus::session_age(facts.session_started)),
        MascotEvent::PageActive(facts.page_active),
    ] {
        brain.handle(ev, now, &mut rng);
    }
    out.phase.set(phase);
    out.active.set(facts.page_active);
    send(Cmd::Active {
        value: facts.page_active,
    });
    let mut perch = Perch::Home;
    loop {
        publish(&brain, &mut out);
        if brain.perch() != perch {
            perch = brain.perch();
            send(Cmd::Perch {
                name: perch.as_str(),
            });
        }
        let deadline = brain.next_deadline();
        tokio::select! {
            ev = inbox.recv() => match ev {
                Ok(ev) => {
                    match ev {
                        MascotEvent::Phase(p) if p != *out.phase.peek() => {
                            out.phase.set(p);
                            send(Cmd::Glue);
                        }
                        MascotEvent::PageActive(a) if a != *out.active.peek() => {
                            out.active.set(a);
                            send(Cmd::Active { value: a });
                        }
                        _ => {}
                    }
                    brain.handle(ev, Instant::now(), &mut rng);
                }
                Err(RecvError::Lagged(n)) => tracing::debug!(n, "mascot inbox overflowed"),
                Err(RecvError::Closed) => return,
            },
            msg = js.recv::<JsEvent>(), if js_alive => match msg {
                Ok(JsEvent::Geo(geo)) => {
                    if *out.geo.peek() != geo {
                        out.geo.set(geo);
                    }
                }
                Ok(JsEvent::Home) => brain.handle(MascotEvent::GoHome, Instant::now(), &mut rng),
                Ok(JsEvent::Pet) => brain.handle(MascotEvent::Pet, Instant::now(), &mut rng),
                Ok(JsEvent::Activity { mascot }) => {
                    let ev = MascotEvent::Activity { on_mascot: mascot };
                    brain.handle(ev, Instant::now(), &mut rng);
                }
                Ok(JsEvent::Visible { value }) => {
                    brain.handle(MascotEvent::Visible(value), Instant::now(), &mut rng);
                }
                Err(EvalError::Serialization(e)) => tracing::warn!(%e, "unreadable mascot stage report"),
                Err(e) => {
                    // Without the stage he can neither be placed nor follow the layout: hide him.
                    tracing::warn!(%e, "mascot stage stopped");
                    js_alive = false;
                    out.geo.set(Geo::default());
                }
            },
            () = sleep_until(deadline) => brain.tick(Instant::now(), &mut rng),
        }
    }
}

/// The phase the bus remembers, else the first one delivered; `None` when the bus is gone.
async fn known_phase(
    bus: &MascotBus,
    inbox: &mut broadcast::Receiver<MascotEvent>,
) -> Option<MascotPhase> {
    if let Some(phase) = bus.facts().phase {
        return Some(phase);
    }
    loop {
        match inbox.recv().await {
            Ok(MascotEvent::Phase(phase)) => return Some(phase),
            Ok(_) | Err(RecvError::Lagged(_)) => {}
            Err(RecvError::Closed) => return None,
        }
    }
}

/// Writes the brain's view when it changed; remembers that the session's greeting was said.
fn publish(brain: &MascotBrain, out: &mut Out) {
    let view = brain.view();
    if out.view.peek().as_ref() == Some(&view) {
        return;
    }
    if view
        .speech
        .as_ref()
        .is_some_and(|s| s.msg.key.starts_with("mascot.greet"))
    {
        GREETED.store(true, Ordering::Relaxed);
    }
    out.view.set(Some(view));
}

async fn sleep_until(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
        None => std::future::pending().await,
    }
}

/// Local wall-clock time since midnight (the greeting picks morning / day / evening / night).
fn local_time_of_day() -> Duration {
    let now = jiff::Zoned::now().time();
    now.duration_since(jiff::civil::Time::midnight())
        .unsigned_abs()
}
