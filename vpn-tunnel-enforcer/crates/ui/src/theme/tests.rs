use super::*;

const BASE_CSS: &str = include_str!("../../assets/css/base.css");
const SWISS_CSS: &str = include_str!("../../assets/css/swiss.css");

/// Declarations `name: value` of the first rule whose selector line is exactly `selector`.
fn block(css: &str, selector: &str) -> Vec<(String, String)> {
    let start = css
        .find(&format!("\n{selector} {{"))
        .unwrap_or_else(|| panic!("{selector} not found"));
    let body = &css[start..];
    let body = &body[body.find('{').unwrap() + 1..body.find('}').unwrap()];
    body.split(';')
        .filter_map(|decl| {
            let decl = decl.trim();
            let decl = decl.rsplit("*/").next().unwrap_or(decl).trim();
            let (k, v) = decl.split_once(':')?;
            Some((k.trim().to_owned(), v.trim().to_owned()))
        })
        .collect()
}

fn get<'a>(decls: &'a [(String, String)], name: &str) -> &'a str {
    decls
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
        .unwrap_or_else(|| panic!("{name} missing"))
}

fn luminance(c: Rgb) -> f64 {
    let lin = |v: u8| {
        let c = f64::from(v) / 255.0;
        if c <= 0.03928 {
            c / 12.92
        } else {
            ((c + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * lin(c.0) + 0.7152 * lin(c.1) + 0.0722 * lin(c.2)
}

fn contrast(a: Rgb, b: Rgb) -> f64 {
    let (la, lb) = (luminance(a), luminance(b));
    (la.max(lb) + 0.05) / (la.min(lb) + 0.05)
}

#[test]
fn hex_parsing() {
    assert_eq!(Rgb::from_hex("#1f1f1f"), Some(Rgb(31, 31, 31)));
    assert_eq!(Rgb::from_hex("FF4F00"), Some(Rgb(255, 79, 0)));
    assert_eq!(Rgb::from_hex("#abc"), Some(Rgb(0xaa, 0xbb, 0xcc)));
    for bad in ["", "#", "#12345", "#1234567", "#ggg", "#12 456", "#ффф"] {
        assert_eq!(Rgb::from_hex(bad), None, "{bad}");
    }
    assert_eq!(Rgb(0x0, 0x60, 0xc0).hex(), "#0060c0");
    assert_eq!(Rgb(0, 96, 192).channels(), "0 96 192");
}

/// ui-dashboard §7.9 (themePalette.test.ts): the built-in palettes equal the base.css
/// fallbacks painted on the first frame, the accent hover included.
#[test]
fn builtin_palettes_match_base_css() {
    for (scheme, selector) in [
        (Scheme::Light, ":root"),
        (Scheme::Dark, "[data-theme=\"dark\"]"),
    ] {
        let decls = block(BASE_CSS, selector);
        let palette = Palette::builtin(scheme);
        for ((key, var), rgb) in LEVELS.iter().zip(palette.levels()) {
            assert_eq!(get(&decls, var), rgb.channels(), "{selector} {var} ({key})");
        }
        let hover = accent_hover(palette.accent, scheme).channels();
        assert_eq!(
            get(&decls, "--rgb-accent-hover"),
            hover,
            "{selector} accent hover"
        );
    }
}

/// ui-dashboard §2.18: the window colours equal the «Пломба» `--paper` / `--ink` of swiss.css.
#[test]
fn paper_and_ink_match_swiss_css() {
    for (scheme, selector) in [
        (Scheme::Light, ".c-swiss"),
        (Scheme::Dark, "[data-theme='dark'] .c-swiss"),
    ] {
        let decls = block(SWISS_CSS, selector);
        assert_eq!(
            get(&decls, "--paper"),
            scheme.paper().hex(),
            "{selector} paper"
        );
        assert_eq!(get(&decls, "--ink"), scheme.ink().hex(), "{selector} ink");
    }
}

/// ui-dashboard §7.9: every surface step is visible, not merely distinct.
#[test]
fn surface_steps_are_visible() {
    for scheme in [Scheme::Light, Scheme::Dark] {
        let p = Palette::builtin(scheme);
        assert_ne!(p.sidebar, p.background, "{scheme:?}");
        assert_ne!(p.card, p.background, "{scheme:?}");
        assert_ne!(p.card_elevated, p.card, "{scheme:?}");
        assert!(
            contrast(p.card, p.background) >= 1.15,
            "{scheme:?} card vs canvas"
        );
        assert!(
            contrast(p.border, p.card) >= 1.15,
            "{scheme:?} border vs card"
        );
        assert!(
            contrast(p.border_strong, p.card) >= 1.3,
            "{scheme:?} strong border"
        );
        assert!(
            contrast(p.sidebar, p.background) >= 1.05,
            "{scheme:?} rail vs canvas"
        );
        // A light card is already near-white, so the elevated step is carried by the border.
        let floor = if scheme.is_dark() { 1.12 } else { 1.02 };
        assert!(
            contrast(p.card_elevated, p.card) >= floor,
            "{scheme:?} elevated vs card"
        );
    }
}

/// ui-dashboard §7.9: text clears WCAG AA on every surface it lands on; UI colours clear 3:1.
#[test]
fn text_and_state_colours_are_legible() {
    let white = Rgb(255, 255, 255);
    for scheme in [Scheme::Light, Scheme::Dark] {
        let p = Palette::builtin(scheme);
        for surface in [p.background, p.sidebar, p.card, p.card_elevated] {
            assert!(
                contrast(p.text, surface) >= 4.5,
                "{scheme:?} text on {surface:?}"
            );
            let secondary = contrast(p.text_secondary, surface);
            assert!(secondary >= 4.5, "{scheme:?} secondary on {surface:?}");
        }
        assert!(
            contrast(p.text_muted, p.card) >= 3.0,
            "{scheme:?} muted on card"
        );
        assert!(
            contrast(p.accent, p.card) >= 3.0,
            "{scheme:?} accent on card"
        );
        assert!(
            contrast(p.accent, p.background) >= 3.0,
            "{scheme:?} accent on canvas"
        );
        for state in [p.success, p.warning, p.danger] {
            assert!(
                contrast(state, p.card) >= 3.0,
                "{scheme:?} {state:?} on card"
            );
        }
        assert!(
            contrast(white, p.accent) >= 4.5,
            "{scheme:?} white on accent"
        );
    }
}

/// ui-dashboard §7.9: applying a theme writes all 13 levels plus the hover, and the block
/// wins over base.css `[data-theme="dark"]` by specificity.
#[test]
fn vars_block_writes_every_level() {
    let css = vars_css(&Palette::DARK, Scheme::Dark);
    assert!(css.starts_with("html:root{") && css.ends_with('}'));
    for (_, var) in LEVELS {
        assert_eq!(css.matches(&format!("{var}:")).count(), 1, "{var}");
    }
    assert!(css.contains("--rgb-bg:31 31 31;"));
    assert!(css.contains("--rgb-accent-hover:71 158 224;"));
    assert_eq!(css.matches(';').count(), 14);
}

/// ui-dashboard §7.9 / storage §2.4: themes stored with only the original seven colours are
/// completed from the built-in palette of their mode (light for light, dark otherwise).
#[test]
fn old_custom_themes_are_completed() {
    let seven = [
        ("background", "#101010"),
        ("sidebar", "#202020"),
        ("cardBackground", "#303030"),
        ("accent", "#ff0000"),
        ("text", "#fefefe"),
        ("textSecondary", "#eeeeee"),
        ("border", "#404040"),
    ];
    let lookup = |key: &str| seven.iter().find(|(k, _)| *k == key).map(|(_, v)| *v);
    for (mode, fallback) in [
        (ThemeMode::Light, Palette::LIGHT),
        (ThemeMode::Dark, Palette::DARK),
        (ThemeMode::System, Palette::DARK),
    ] {
        let p = Palette::complete(mode, lookup);
        assert_eq!(p.background, Rgb(0x10, 0x10, 0x10));
        assert_eq!(p.accent, Rgb(0xff, 0, 0));
        assert_eq!(p.border, Rgb(0x40, 0x40, 0x40));
        assert_eq!(p.card_elevated, fallback.card_elevated, "{mode:?}");
        assert_eq!(p.text_muted, fallback.text_muted, "{mode:?}");
        assert_eq!(p.border_strong, fallback.border_strong, "{mode:?}");
        assert_eq!(p.danger, fallback.danger, "{mode:?}");
    }
    let malformed = Palette::complete(ThemeMode::Light, |k| (k == "accent").then_some("blue"));
    assert_eq!(malformed, Palette::LIGHT);
}

#[test]
fn modes_resolve_and_round_trip() {
    assert_eq!(ThemeMode::System.resolve(true), Scheme::Dark);
    assert_eq!(ThemeMode::System.resolve(false), Scheme::Light);
    assert_eq!(ThemeMode::Light.resolve(true), Scheme::Light);
    assert_eq!(ThemeMode::Dark.resolve(false), Scheme::Dark);
    for mode in [ThemeMode::Light, ThemeMode::Dark, ThemeMode::System] {
        assert_eq!(ThemeMode::from_name(mode.name()), Some(mode));
    }
    assert_eq!(ThemeMode::from_name("auto"), None);
    assert_eq!(ThemeMode::default(), ThemeMode::System);
    let custom = Theme {
        mode: ThemeMode::Dark,
        custom: Some(Palette::LIGHT),
    };
    assert_eq!(custom.palette(Scheme::Dark), Palette::LIGHT);
    assert_eq!(Theme::default().palette(Scheme::Dark), Palette::DARK);
}
