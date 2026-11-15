//! Built-in light / dark / system themes.
//!
//! A theme has two layers. The «Пломба» tokens (`--paper`, `--ink`, `--signal`…) live in swiss.css
//! and follow `data-theme` on `<html>` only. The legacy `--rgb-*` palette of base.css (13 levels
//! plus the derived accent hover) is written into a `<style id="theme-vars">` block, so a custom
//! theme recolours the non-«Пломба» surfaces. The window itself is painted with `--paper` until
//! WebView2 shows the first frame, so no theme ever flashes a colour it does not use.
use dioxus::desktop::tao::event::{Event, WindowEvent};
use dioxus::desktop::tao::window::Theme as TaoTheme;
use dioxus::desktop::{DesktopContext, use_window, use_wry_event_handler};
use dioxus::prelude::*;

/// An sRGB colour.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Rgb(pub u8, pub u8, pub u8);

impl Rgb {
    /// Parses `#rrggbb`, `rrggbb` or `#rgb` (the old `hexToRgbChannels` input).
    pub fn from_hex(s: &str) -> Option<Rgb> {
        let hex = s.strip_prefix('#').unwrap_or(s);
        if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let full: String = match hex.len() {
            3 => hex.chars().flat_map(|c| [c, c]).collect(),
            6 => hex.to_owned(),
            _ => return None,
        };
        let channel = |i: usize| u8::from_str_radix(&full[i..i + 2], 16).ok();
        Some(Rgb(channel(0)?, channel(2)?, channel(4)?))
    }

    /// `#rrggbb`.
    pub fn hex(self) -> String {
        format!("#{:02x}{:02x}{:02x}", self.0, self.1, self.2)
    }

    /// Space-separated channels (`"r g b"`), so CSS can splice in an alpha: `rgb(var(--x) / .6)`.
    pub fn channels(self) -> String {
        format!("{} {} {}", self.0, self.1, self.2)
    }

    /// The colour as an opaque RGBA tuple (tao and dioxus window APIs).
    pub fn rgba(self) -> (u8, u8, u8, u8) {
        (self.0, self.1, self.2, 255)
    }
}

/// What the user picked (`builtin-light`, `builtin-dark`, `builtin-system` or a custom theme's mode).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum ThemeMode {
    Light,
    Dark,
    #[default]
    System,
}

impl ThemeMode {
    /// Light or dark; `System` follows the Windows app mode.
    pub fn resolve(self, os_dark: bool) -> Scheme {
        match self {
            ThemeMode::Light => Scheme::Light,
            ThemeMode::Dark => Scheme::Dark,
            ThemeMode::System if os_dark => Scheme::Dark,
            ThemeMode::System => Scheme::Light,
        }
    }

    /// `light` / `dark` / `system`, as stored and as accepted on the command line.
    pub fn name(self) -> &'static str {
        match self {
            ThemeMode::Light => "light",
            ThemeMode::Dark => "dark",
            ThemeMode::System => "system",
        }
    }

    /// Inverse of [`ThemeMode::name`].
    pub fn from_name(name: &str) -> Option<ThemeMode> {
        match name {
            "light" => Some(ThemeMode::Light),
            "dark" => Some(ThemeMode::Dark),
            "system" => Some(ThemeMode::System),
            _ => None,
        }
    }
}

/// Light or dark after resolving `System`: the value of `data-theme`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Scheme {
    Light,
    Dark,
}

impl Scheme {
    /// `data-theme` value.
    pub fn name(self) -> &'static str {
        match self {
            Scheme::Light => "light",
            Scheme::Dark => "dark",
        }
    }

    /// True for the dark scheme.
    pub fn is_dark(self) -> bool {
        self == Scheme::Dark
    }

    /// «Пломба» `--paper` (swiss.css): window background before the first paint.
    pub const fn paper(self) -> Rgb {
        match self {
            Scheme::Light => Rgb(0xf2, 0xf0, 0xeb),
            Scheme::Dark => Rgb(0x1c, 0x1b, 0x18),
        }
    }

    /// «Пломба» `--ink` (swiss.css): text and glyphs on paper.
    pub const fn ink(self) -> Rgb {
        match self {
            Scheme::Light => Rgb(0x26, 0x24, 0x1f),
            Scheme::Dark => Rgb(0xed, 0xeb, 0xe6),
        }
    }

    pub(crate) fn tao(self) -> TaoTheme {
        match self {
            Scheme::Light => TaoTheme::Light,
            Scheme::Dark => TaoTheme::Dark,
        }
    }
}

/// `(ThemeConfig.colors key, CSS variable)` for each palette level, in [`Palette::levels`] order.
pub const LEVELS: [(&str, &str); 13] = [
    ("background", "--rgb-bg"),
    ("sidebar", "--rgb-sidebar"),
    ("cardBackground", "--rgb-card"),
    ("cardElevated", "--rgb-card-elevated"),
    ("accent", "--rgb-accent"),
    ("text", "--rgb-text"),
    ("textSecondary", "--rgb-text-secondary"),
    ("textMuted", "--rgb-text-muted"),
    ("border", "--rgb-border"),
    ("borderStrong", "--rgb-border-strong"),
    ("success", "--rgb-success"),
    ("warning", "--rgb-warning"),
    ("danger", "--rgb-danger"),
];

/// The 13 colour levels of a theme (`ThemeConfig.colors`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Palette {
    pub background: Rgb,
    pub sidebar: Rgb,
    pub card: Rgb,
    pub card_elevated: Rgb,
    pub accent: Rgb,
    pub text: Rgb,
    pub text_secondary: Rgb,
    pub text_muted: Rgb,
    pub border: Rgb,
    pub border_strong: Rgb,
    pub success: Rgb,
    pub warning: Rgb,
    pub danger: Rgb,
}

impl Palette {
    /// `builtin-light`: canvas tinted down, cards near-white (equals base.css `:root`).
    pub const LIGHT: Palette = Palette {
        background: Rgb(0xe6, 0xe9, 0xf0),
        sidebar: Rgb(0xdd, 0xe1, 0xeb),
        card: Rgb(0xfb, 0xfc, 0xfe),
        card_elevated: Rgb(0xff, 0xff, 0xff),
        accent: Rgb(0x00, 0x60, 0xc0),
        text: Rgb(0x14, 0x16, 0x1c),
        text_secondary: Rgb(0x5a, 0x61, 0x6f),
        text_muted: Rgb(0x8a, 0x91, 0xa0),
        border: Rgb(0xce, 0xd4, 0xe0),
        border_strong: Rgb(0xb0, 0xb8, 0xc8),
        success: Rgb(0x1e, 0x9b, 0x3c),
        warning: Rgb(0xb8, 0x72, 0x00),
        danger: Rgb(0xc6, 0x2d, 0x23),
    };

    /// `builtin-dark`: VS Code "Dark Modern" base (equals base.css `[data-theme="dark"]`).
    pub const DARK: Palette = Palette {
        background: Rgb(0x1f, 0x1f, 0x1f),
        sidebar: Rgb(0x18, 0x18, 0x18),
        card: Rgb(0x2d, 0x2d, 0x2d),
        card_elevated: Rgb(0x38, 0x38, 0x38),
        accent: Rgb(0x00, 0x78, 0xd4),
        text: Rgb(0xcc, 0xcc, 0xcc),
        text_secondary: Rgb(0xa3, 0xa3, 0xa3),
        text_muted: Rgb(0x7a, 0x7a, 0x7a),
        border: Rgb(0x3c, 0x3c, 0x3c),
        border_strong: Rgb(0x4d, 0x4d, 0x4d),
        success: Rgb(0x30, 0xd1, 0x58),
        warning: Rgb(0xff, 0xd6, 0x0a),
        danger: Rgb(0xff, 0x45, 0x3a),
    };

    /// The built-in palette of a scheme.
    pub const fn builtin(scheme: Scheme) -> Palette {
        match scheme {
            Scheme::Light => Palette::LIGHT,
            Scheme::Dark => Palette::DARK,
        }
    }

    /// The levels in [`LEVELS`] order.
    pub fn levels(&self) -> [Rgb; 13] {
        [
            self.background,
            self.sidebar,
            self.card,
            self.card_elevated,
            self.accent,
            self.text,
            self.text_secondary,
            self.text_muted,
            self.border,
            self.border_strong,
            self.success,
            self.warning,
            self.danger,
        ]
    }

    fn from_levels(levels: [Rgb; 13]) -> Palette {
        let [
            background,
            sidebar,
            card,
            card_elevated,
            accent,
            text,
            text_secondary,
            text_muted,
            border,
            border_strong,
            success,
            warning,
            danger,
        ] = levels;
        Palette {
            background,
            sidebar,
            card,
            card_elevated,
            accent,
            text,
            text_secondary,
            text_muted,
            border,
            border_strong,
            success,
            warning,
            danger,
        }
    }

    /// Builds a stored custom theme's palette (`colors` looks up a `ThemeConfig.colors` key). Themes
    /// saved before the palette was widened hold only seven levels: a missing or malformed level
    /// comes from the built-in palette of the theme's mode, light for `Light`, dark for `Dark` and
    /// `System` (`withFullPalette`).
    pub fn complete<'a>(mode: ThemeMode, colors: impl Fn(&str) -> Option<&'a str>) -> Palette {
        let fallback = if mode == ThemeMode::Light {
            Palette::LIGHT
        } else {
            Palette::DARK
        };
        let mut levels = fallback.levels();
        for (slot, (key, _)) in levels.iter_mut().zip(LEVELS) {
            if let Some(rgb) = colors(key).and_then(Rgb::from_hex) {
                *slot = rgb;
            }
        }
        Palette::from_levels(levels)
    }
}

/// The active theme: a mode and, for a custom theme, its own palette.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Theme {
    pub mode: ThemeMode,
    /// `None`: the built-in palette of the resolved scheme.
    pub custom: Option<Palette>,
}

impl Theme {
    /// A built-in theme (`builtin-light` / `builtin-dark` / `builtin-system`).
    pub const fn builtin(mode: ThemeMode) -> Theme {
        Theme { mode, custom: None }
    }

    /// The palette shown in `scheme`.
    pub fn palette(&self, scheme: Scheme) -> Palette {
        self.custom.unwrap_or(Palette::builtin(scheme))
    }
}

/// `--rgb-accent-hover`: the hover always moves away from the surface, lighter in dark mode and
/// darker in light mode.
pub fn accent_hover(accent: Rgb, scheme: Scheme) -> Rgb {
    let shift = |c: u8| {
        let c = f64::from(c);
        let v = if scheme.is_dark() {
            c + (255.0 - c) * 0.28
        } else {
            c * 0.78
        };
        v.round().clamp(0.0, 255.0) as u8
    };
    Rgb(shift(accent.0), shift(accent.1), shift(accent.2))
}

/// The `--rgb-*` block of `<style id="theme-vars">`: all 13 levels plus the accent hover.
/// `html:root` (specificity 0,1,1) beats base.css `[data-theme="dark"]` (0,1,0) whatever the
/// order, so a custom palette never falls back to the built-in dark ladder.
pub fn vars_css(palette: &Palette, scheme: Scheme) -> String {
    let mut css = String::from("html:root{");
    for ((_, var), rgb) in LEVELS.iter().zip(palette.levels()) {
        css.push_str(&format!("{var}:{};", rgb.channels()));
    }
    let hover = accent_hover(palette.accent, scheme);
    css.push_str(&format!("--rgb-accent-hover:{};}}", hover.channels()));
    css
}

/// Windows app mode: `AppsUseLightTheme` = 0 means dark; light when the value is unreadable.
pub fn os_prefers_dark() -> bool {
    use windows::Win32::System::Registry::{HKEY_CURRENT_USER, RRF_RT_REG_DWORD, RegGetValueW};
    use windows::core::w;
    let mut value: u32 = 1;
    let mut size = size_of::<u32>() as u32;
    // SAFETY: `value` and `size` describe a writable DWORD, the only type RRF_RT_REG_DWORD allows.
    let rc = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            w!(r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"),
            w!("AppsUseLightTheme"),
            RRF_RT_REG_DWORD,
            None,
            Some((&raw mut value).cast()),
            Some(&mut size),
        )
    };
    rc.is_ok() && value == 0
}

static INITIAL: std::sync::OnceLock<Theme> = std::sync::OnceLock::new();

/// The theme of the first frame (from [`crate::launch::LaunchOptions`]).
pub(crate) fn set_initial(theme: Theme) {
    let _ = INITIAL.set(theme);
}

fn initial() -> Theme {
    INITIAL.get().copied().unwrap_or_default()
}

/// The active theme. Write it to switch; the frame applies it to the page and the window.
pub static THEME: GlobalSignal<Theme> = Signal::global(initial);

static SCHEME: GlobalSignal<Scheme> = Signal::global(|| initial().mode.resolve(os_prefers_dark()));

/// Light or dark as currently shown; subscribes the caller.
pub fn scheme() -> Scheme {
    *SCHEME.read()
}

/// Script that sets `data-theme` and replaces the palette block. Built from numbers only, so it
/// never carries an untrusted string into `eval`.
fn apply_js(theme: &Theme, scheme: Scheme) -> String {
    format!(
        "(()=>{{const h=document.documentElement;h.dataset.theme='{name}';\
         let e=document.getElementById('theme-vars');\
         if(!e){{e=document.createElement('style');e.id='theme-vars';document.head.append(e);}}\
         e.textContent='{css}';}})()",
        name = scheme.name(),
        css = vars_css(&theme.palette(scheme), scheme),
    )
}

fn sync(desktop: &DesktopContext, theme: Theme) {
    let scheme = theme.mode.resolve(os_prefers_dark());
    if *SCHEME.peek() != scheme {
        *SCHEME.write() = scheme;
    }
    let _ = document::eval(&apply_js(&theme, scheme));
    // Following the OS (`None`) is what makes tao report light/dark flips as `ThemeChanged`.
    let tao = (theme.mode != ThemeMode::System).then(|| scheme.tao());
    desktop.window.set_theme(tao);
    crate::launch::set_window_background(desktop, scheme.paper());
}

/// Keeps `<html data-theme>`, the palette block and the window colours in sync with [`THEME`]
/// and, for `System`, with the Windows app mode. Called once by the frame root.
pub(crate) fn use_theme_sync() {
    let desktop = use_window();
    let on_os_change = desktop.clone();
    use_wry_event_handler(move |event, _| {
        if let Event::WindowEvent {
            event: WindowEvent::ThemeChanged(_),
            ..
        } = event
        {
            let theme = *THEME.peek();
            if theme.mode == ThemeMode::System {
                sync(&on_os_change, theme);
            }
        }
    });
    use_effect(move || sync(&desktop, *THEME.read()));
}

#[cfg(test)]
mod tests;
