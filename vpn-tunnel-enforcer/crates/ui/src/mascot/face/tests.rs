use super::*;

/// The FACES table of `Mascot.tsx:45-61` (spec ui-dashboard §2.10), mood by mood.
#[test]
fn faces_match_the_old_markup() {
    // (mood, left eye (w, h, pupil, dy, blink), mouth, cheeks, idle loop)
    type Row = (
        Mood,
        (u8, u8, u8, i8, bool),
        Mouth,
        bool,
        Option<&'static str>,
    );
    let table: [Row; 13] = [
        (
            Mood::Calm,
            (18, 18, 8, 0, true),
            rect(26, 4),
            false,
            Some("m-breathe"),
        ),
        (
            Mood::Worried,
            (22, 24, 6, 0, true),
            Mouth::Ring(10),
            false,
            None,
        ),
        (
            Mood::Scared,
            (22, 24, 5, 0, true),
            Mouth::Ring(13),
            false,
            None,
        ),
        (Mood::Scan, (18, 18, 8, 0, true), rect(14, 3), false, None),
        (Mood::Happy, (18, 5, 0, -3, false), rect(24, 9), false, None),
        (Mood::Love, (18, 18, 0, 0, false), rect(22, 8), false, None),
        (
            Mood::Squint,
            (18, 6, 4, 0, false),
            Mouth::Rect {
                w: 10,
                h: 3,
                transform: Some("translateX(8px)"),
            },
            false,
            None,
        ),
        (
            Mood::Think,
            (18, 18, 8, 0, true),
            Mouth::Rect {
                w: 6,
                h: 6,
                transform: Some("translateX(10px)"),
            },
            false,
            None,
        ),
        (
            Mood::Dizzy,
            (18, 18, 6, 0, false),
            Mouth::Rect {
                w: 18,
                h: 3,
                transform: Some("rotate(-14deg)"),
            },
            false,
            None,
        ),
        (
            Mood::Wink,
            (18, 18, 8, 0, true),
            Mouth::Rect {
                w: 18,
                h: 4,
                transform: Some("rotate(-8deg)"),
            },
            false,
            None,
        ),
        (
            Mood::Excited,
            (20, 20, 10, 0, true),
            rect(22, 11),
            false,
            Some("m-bounce"),
        ),
        (
            Mood::Sleep,
            (18, 3, 0, 5, false),
            rect(8, 4),
            false,
            Some("m-breathe-slow"),
        ),
        (
            Mood::Petted,
            (18, 4, 0, -1, false),
            rect(20, 6),
            true,
            Some("m-purr"),
        ),
    ];
    for (mood, (w, h, pupil, dy, blink), mouth, cheeks, idle) in table {
        let f = face(mood);
        let l = f.left;
        assert_eq!(
            (l.w, l.h, l.pupil, l.dy, l.blink),
            (w, h, pupil, dy, blink),
            "{mood:?}"
        );
        assert_eq!(
            (f.mouth, f.cheeks, f.idle),
            (mouth, cheeks, idle),
            "{mood:?}"
        );
        if mood != Mood::Wink {
            assert_eq!(f.right, f.left, "{mood:?}");
        }
    }
    assert_eq!(face(Mood::Wink).right, bar(3, 4));
    assert!(face(Mood::Love).left.diamond);
    assert_eq!(face(Mood::Think).left.fixed, Some((-4, -4)));
}

#[test]
fn only_unpinned_unanimated_pupils_follow_the_pointer() {
    assert!(face(Mood::Calm).left.free());
    assert!(
        face(Mood::Worried).left.free(),
        "trembling pupils still look around"
    );
    assert!(!face(Mood::Think).left.free());
    assert!(!face(Mood::Scan).left.free());
    assert!(!face(Mood::Dizzy).left.free());
}

/// `Mascot.tsx:114-117`: body / eye / tag by phase and surface.
#[test]
fn palette_follows_phase_and_surface() {
    let c = colors(false, Surface::Paper);
    assert_eq!(
        (c.body, c.eye, c.tag_fill),
        ("var(--ink)", "var(--paper)", "transparent")
    );
    let c = colors(true, Surface::Paper);
    assert_eq!(
        (c.body, c.eye, c.tag_fill),
        ("var(--ink)", "var(--signal)", "var(--signal)")
    );
    let c = colors(true, Surface::Signal);
    assert_eq!(
        (c.body, c.eye, c.tag_fill),
        ("var(--on-signal)", "var(--signal)", "var(--paper)")
    );
    assert_eq!(c.blush, "var(--paper)");
    let c = colors(false, Surface::Inverse);
    assert_eq!(
        (c.body, c.eye, c.tag_fill),
        ("var(--paper)", "var(--ink)", "transparent")
    );
    let c = colors(true, Surface::Inverse);
    assert_eq!(
        (c.body, c.eye, c.tag_fill),
        ("var(--paper)", "var(--signal)", "var(--signal)")
    );
    assert_eq!(c.blush, "var(--signal)");
}

#[test]
fn confetti_is_the_old_burst() {
    let pieces: Vec<Confetto> = confetti().collect();
    assert_eq!(pieces.len(), 14);
    let first = pieces[0];
    assert!((first.dx - (-0.1f64).cos() * 56.0).abs() < 1e-9);
    assert!((first.dy - ((-0.1f64).sin() * 56.0 - 20.0)).abs() < 1e-9);
    assert_eq!((first.rot, first.size, first.delay_ms), (-180, 8, 0));
    let second = pieces[1];
    let a = std::f64::consts::TAU / 14.0 + 0.2;
    assert!((second.dx - a.cos() * 72.0).abs() < 1e-9);
    assert_eq!((second.rot, second.size, second.delay_ms), (210, 6, 20));
    let last = pieces[13];
    assert_eq!((last.rot, last.size, last.delay_ms), (570, 6, 20));
    let paper = colors(true, Surface::Paper);
    assert_eq!(
        confetti_colors(&paper),
        ["var(--signal)", "var(--ink)", "var(--mute)"]
    );
    let slab = colors(true, Surface::Signal);
    assert_eq!(confetti_colors(&slab), ["var(--on-signal)", "var(--paper)"]);
}
