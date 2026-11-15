//! Protocol between the host task and the stage half in `assets/js/mascot.js`.
//!
//! Geometry (perch measurement, free-gap search, surface colour, the hop parabola, pointer
//! tracking and stroke detection) runs in the page: it needs DOM text rects and must move at frame
//! rate without a round trip. The page writes the position as CSS custom properties on the overlay
//! root; Rust renders constant `var()` styles, so the two never fight over inline geometry. Rust
//! decides where he goes (`MascotBrain::perch`), the page reports what it observed.
use serde::{Deserialize, Serialize};

use super::face::Surface;

/// Started once per host with `document::eval`; returns when the overlay leaves the document or a
/// newer host takes over. `id` is the host's `data-mascot-stage` value (a number: nothing untrusted
/// reaches `eval`).
pub(super) fn script(id: u32) -> String {
    format!(
        "for (let i = 0; !window.vpnteMascot && i < 100; i++) \
         await new Promise((r) => setTimeout(r, 50));\n\
         if (!window.vpnteMascot) throw new Error('mascot.js is not loaded');\n\
         await window.vpnteMascot.run(dioxus, {id});"
    )
}

/// Box of the mascot inside the overlay (`MascotStage.tsx`: 96 x 89, anchored bottom centre).
pub(super) const BOX_STYLE: &str = "left: calc(var(--mx) - 48px); top: calc(var(--my) - 89px); \
     width: 96px; height: 89px; transform: scale(var(--ms)) rotate(var(--mr)); \
     transform-origin: center bottom;";

/// Speech bubble anchor (`Bubble`: over his head, or under him when there is no room above).
pub(super) const BUBBLE_STYLE: &str =
    "left: var(--bx); top: var(--by); transform: translate(var(--bk), var(--bt));";

/// Tail of the bubble, under the point that sits over him.
pub(super) const TAIL_STYLE: &str = "left: var(--bkl);";

/// Pupils that follow the pointer (`look`, ±4 px).
pub(super) const LOOK: &str = "translate(var(--lx, 0px), var(--ly, 0px))";

/// Rust -> page.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(tag = "cmd", rename_all = "lowercase")]
pub(super) enum Cmd {
    /// Go to this perch (hop when placed, else place; unchanged names are ignored).
    Perch { name: &'static str },
    /// The dashboard is shown (measure and glue) or not (stop all DOM work, drop the placement).
    Active { value: bool },
    /// The tunnel phase changed: the layout and the surface colours may have changed.
    Glue,
}

/// What the stage observed: re-sent whole whenever a field changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
pub(super) struct Geo {
    /// A position is known (and written to the overlay); nothing is drawn before.
    pub placed: bool,
    /// Mid-hop: excited face, tilted, palette as on paper.
    pub airborne: bool,
    pub surface: Surface,
    /// No room above his head: the bubble hangs below him.
    pub below: bool,
    /// Counts landings; each one replays the squash.
    pub land: u32,
}

/// Page -> Rust.
#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
#[serde(tag = "ev", rename_all = "lowercase")]
pub(super) enum JsEvent {
    Geo(Geo),
    /// The current perch vanished or has no free gap: hop home instead of snapping.
    Home,
    /// A stroke over him.
    Pet,
    /// Pointer / key / wheel activity (leading edge, at most a few per second).
    Activity {
        mascot: bool,
    },
    /// `document.visibilityState` changed.
    Visible {
        value: bool,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stage_script_names_its_host() {
        let js = script(7);
        assert!(
            js.ends_with("await window.vpnteMascot.run(dioxus, 7);"),
            "{js}"
        );
        assert_eq!(js.lines().count(), 3);
    }

    #[test]
    fn commands_serialize_as_the_page_expects() {
        let perch = serde_json::to_value(Cmd::Perch { name: "toggle" }).unwrap();
        assert_eq!(perch, serde_json::json!({"cmd": "perch", "name": "toggle"}));
        let active = serde_json::to_value(Cmd::Active { value: false }).unwrap();
        assert_eq!(active, serde_json::json!({"cmd": "active", "value": false}));
        assert_eq!(
            serde_json::to_value(Cmd::Glue).unwrap(),
            serde_json::json!({"cmd": "glue"})
        );
    }

    #[test]
    fn page_events_parse() {
        let geo: JsEvent = serde_json::from_value(serde_json::json!({
            "ev": "geo", "placed": true, "airborne": false, "surface": "signal", "below": true, "land": 3
        }))
        .unwrap();
        let expected = Geo {
            placed: true,
            airborne: false,
            surface: Surface::Signal,
            below: true,
            land: 3,
        };
        assert_eq!(geo, JsEvent::Geo(expected));
        let parse = |v| serde_json::from_value::<JsEvent>(v).unwrap();
        assert_eq!(parse(serde_json::json!({"ev": "home"})), JsEvent::Home);
        assert_eq!(parse(serde_json::json!({"ev": "pet"})), JsEvent::Pet);
        assert_eq!(
            parse(serde_json::json!({"ev": "activity", "mascot": true})),
            JsEvent::Activity { mascot: true }
        );
        assert_eq!(
            parse(serde_json::json!({"ev": "visible", "value": false})),
            JsEvent::Visible { value: false }
        );
        assert!(serde_json::from_value::<JsEvent>(serde_json::json!({"ev": "nope"})).is_err());
    }
}
