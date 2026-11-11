//! The faces of «Пломбик», one per mood, built from plain squares, and his palette by surface
//! (`Mascot.tsx` FACES / LOOP / colours / CONFETTI, ported value for value).
use vpnte_view::mascot::Mood;

/// What he stands on (decided by the stage's surface scan in `assets/js/mascot.js`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Surface {
    /// Paper or anything light: the normal ink body.
    #[default]
    Paper,
    /// The orange slab: black body, orange eyes.
    Signal,
    /// An ink-filled surface such as the action button: light body, dark eyes.
    Inverse,
}

/// Animation wrapper around a pupil.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EyeAnim {
    Orbit,
    Tremble,
    Scan,
}

impl EyeAnim {
    /// CSS animation class of the wrapper span.
    pub fn class(self) -> &'static str {
        match self {
            EyeAnim::Orbit => "m-orbit",
            EyeAnim::Tremble => "m-tremble",
            EyeAnim::Scan => "m-scan",
        }
    }
}

/// One eye: a square (or a diamond) with an optional pupil.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Eye {
    pub w: u8,
    pub h: u8,
    /// Pupil size in px; 0 = no pupil.
    pub pupil: u8,
    pub diamond: bool,
    /// Vertical shift of the whole eye in px.
    pub dy: i8,
    pub anim: Option<EyeAnim>,
    /// Pupil pinned at this offset instead of following the pointer.
    pub fixed: Option<(i8, i8)>,
    pub blink: bool,
}

impl Eye {
    /// The pupil follows the pointer (not pinned, not driven by its own animation).
    pub fn free(&self) -> bool {
        self.fixed.is_none() && !matches!(self.anim, Some(EyeAnim::Scan | EyeAnim::Orbit))
    }
}

const OPEN: Eye = Eye {
    w: 18,
    h: 18,
    pupil: 8,
    diamond: false,
    dy: 0,
    anim: None,
    fixed: None,
    blink: true,
};

const fn bar(h: u8, dy: i8) -> Eye {
    Eye {
        w: 18,
        h,
        pupil: 0,
        diamond: false,
        dy,
        anim: None,
        fixed: None,
        blink: false,
    }
}

/// The mouth: a filled rectangle (optionally moved) or a hollow ring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mouth {
    Rect {
        w: u8,
        h: u8,
        transform: Option<&'static str>,
    },
    Ring(u8),
}

const fn rect(w: u8, h: u8) -> Mouth {
    Mouth::Rect {
        w,
        h,
        transform: None,
    }
}

/// Eyes, mouth, cheeks and the idle loop of one mood.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Face {
    pub left: Eye,
    pub right: Eye,
    pub mouth: Mouth,
    pub cheeks: bool,
    /// Looping body animation class while the mood lasts.
    pub idle: Option<&'static str>,
}

/// The face of `mood` (FACES + LOOP of the old markup).
pub fn face(mood: Mood) -> Face {
    let plain = |left: Eye, mouth: Mouth| Face {
        left,
        right: left,
        mouth,
        cheeks: false,
        idle: None,
    };
    let moved = |w, h, t| Mouth::Rect {
        w,
        h,
        transform: Some(t),
    };
    match mood {
        Mood::Calm => Face {
            idle: Some("m-breathe"),
            ..plain(OPEN, rect(26, 4))
        },
        Mood::Worried => plain(
            Eye {
                w: 22,
                h: 24,
                pupil: 6,
                anim: Some(EyeAnim::Tremble),
                ..OPEN
            },
            Mouth::Ring(10),
        ),
        Mood::Scared => plain(
            Eye {
                w: 22,
                h: 24,
                pupil: 5,
                anim: Some(EyeAnim::Tremble),
                ..OPEN
            },
            Mouth::Ring(13),
        ),
        Mood::Scan => plain(
            Eye {
                anim: Some(EyeAnim::Scan),
                ..OPEN
            },
            rect(14, 3),
        ),
        Mood::Happy => plain(bar(5, -3), rect(24, 9)),
        Mood::Love => plain(
            Eye {
                pupil: 0,
                diamond: true,
                blink: false,
                ..OPEN
            },
            rect(22, 8),
        ),
        Mood::Squint => plain(
            Eye {
                h: 6,
                pupil: 4,
                blink: false,
                ..OPEN
            },
            moved(10, 3, "translateX(8px)"),
        ),
        Mood::Think => plain(
            Eye {
                fixed: Some((-4, -4)),
                ..OPEN
            },
            moved(6, 6, "translateX(10px)"),
        ),
        Mood::Dizzy => plain(
            Eye {
                pupil: 6,
                anim: Some(EyeAnim::Orbit),
                blink: false,
                ..OPEN
            },
            moved(18, 3, "rotate(-14deg)"),
        ),
        Mood::Wink => Face {
            right: bar(3, 4),
            ..plain(OPEN, moved(18, 4, "rotate(-8deg)"))
        },
        Mood::Excited => Face {
            idle: Some("m-bounce"),
            ..plain(
                Eye {
                    w: 20,
                    h: 20,
                    pupil: 10,
                    ..OPEN
                },
                rect(22, 11),
            )
        },
        Mood::Sleep => Face {
            idle: Some("m-breathe-slow"),
            ..plain(bar(3, 5), rect(8, 4))
        },
        Mood::Petted => Face {
            cheeks: true,
            idle: Some("m-purr"),
            ..plain(bar(4, -1), rect(20, 6))
        },
    }
}

/// CSS colours of one rendering (values are `var(--…)` references, resolved by the theme).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Colors {
    pub body: &'static str,
    pub eye: &'static str,
    pub tag_fill: &'static str,
    /// Cheeks and petting hearts.
    pub blush: &'static str,
    pub on_signal: bool,
}

/// Palette for the tunnel being on (`on`) and the surface under him; in the air he is always
/// drawn as on paper.
pub fn colors(on: bool, surface: Surface) -> Colors {
    let on_signal = surface == Surface::Signal;
    let inverse = surface == Surface::Inverse;
    Colors {
        body: if on_signal {
            "var(--on-signal)"
        } else if inverse {
            "var(--paper)"
        } else {
            "var(--ink)"
        },
        eye: if on_signal || on {
            "var(--signal)"
        } else if inverse {
            "var(--ink)"
        } else {
            "var(--paper)"
        },
        tag_fill: match (on, on_signal) {
            (false, _) => "transparent",
            (true, true) => "var(--paper)",
            (true, false) => "var(--signal)",
        },
        blush: if on_signal {
            "var(--paper)"
        } else {
            "var(--signal)"
        },
        on_signal,
    }
}

/// One confetti square: offset at the end of its flight, spin and size.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Confetto {
    pub dx: f64,
    pub dy: f64,
    pub rot: i32,
    pub size: u8,
    pub delay_ms: u32,
}

/// The 14 squares of the confetti burst (`CONFETTI` of the old markup).
pub fn confetti() -> impl Iterator<Item = Confetto> {
    (0..14u8).map(|i| {
        let odd = i % 2 == 1;
        let a = f64::from(i) / 14.0 * std::f64::consts::TAU + if odd { 0.2 } else { -0.1 };
        let d = 56.0 + f64::from(i % 3) * 16.0;
        Confetto {
            dx: a.cos() * d,
            dy: a.sin() * d - 20.0,
            rot: (if odd { 1 } else { -1 }) * (180 + i32::from(i) * 30),
            size: if i % 3 == 0 { 8 } else { 6 },
            delay_ms: u32::from(i % 4) * 20,
        }
    })
}

/// Confetti colours, cycled over the squares.
pub fn confetti_colors(c: &Colors) -> Vec<&'static str> {
    if c.on_signal {
        vec![c.body, "var(--paper)"]
    } else {
        vec!["var(--signal)", c.body, "var(--mute)"]
    }
}

#[cfg(test)]
mod tests;
