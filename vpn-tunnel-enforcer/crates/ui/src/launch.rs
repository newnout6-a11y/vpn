//! Process entry for every UI binary: window and WebView2 configuration, our own tokio runtime,
//! the frame root (cloak until painted, minimum size, WebView2 hardening, theme and language
//! sync, WebView2 crash watch and window rebuild), and the command line of the demo binaries.
mod recover;
mod remount;
mod stand_in;

use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;

use dioxus::desktop::tao::platform::windows::{IconExtWindows, WindowExtWindows};
use dioxus::desktop::tao::window::{Icon, Window};
use dioxus::desktop::{Config, DesktopContext, LogicalSize, WindowBuilder, use_window};
use dioxus::prelude::*;
use vpnte_base::i18n::Lang;

use remount::{Mount, Rebuild};
pub use remount::{RootContext, once};

use crate::theme::{Rgb, Theme, ThemeMode};
use crate::{assets, lang, theme};

/// Product name: window title, message box caption.
pub const APP_NAME: &str = "VPN Tunnel Enforcer";

/// How the main window starts.
#[derive(Clone, Debug, PartialEq)]
pub struct LaunchOptions {
    /// Native window title (taskbar, Alt+Tab).
    pub title: String,
    /// Inner size in logical px; the CSS viewport equals it.
    pub size: (f64, f64),
    /// Minimum inner size in logical px.
    pub min_size: (f64, f64),
    /// Start in the tray only (autostart).
    pub start_hidden: bool,
    /// WebView2 user-data folder. An elevated process must use a folder of its own: it must not
    /// attach to a browser process a non-elevated instance started (options differ, the
    /// environment creation fails with ERROR_INVALID_STATE).
    pub data_dir: PathBuf,
    /// Language of the first frame.
    pub lang: Lang,
    /// Theme of the first frame.
    pub theme: Theme,
}

impl Default for LaunchOptions {
    fn default() -> Self {
        // Not next to the exe (Program Files is read-only) and not the dioxus default
        // `%LOCALAPPDATA%\<exe stem>`; WebView2 renderers run as the interactive user even when
        // the host is elevated, and the user can write here.
        let local = std::env::var_os("LOCALAPPDATA").map_or_else(std::env::temp_dir, PathBuf::from);
        LaunchOptions {
            title: APP_NAME.to_owned(),
            size: (1100.0, 720.0),
            min_size: (860.0, 600.0),
            start_hidden: false,
            data_dir: local.join(APP_NAME).join("WebView2"),
            lang: lang::os_lang(),
            theme: Theme::default(),
        }
    }
}

impl LaunchOptions {
    /// Options for a demo binary: its own WebView2 folder under `%TEMP%` (one per binary, so
    /// several demos run side by side) and the demo command line applied.
    pub fn demo(name: &str, args: &DemoArgs) -> LaunchOptions {
        let mut options = LaunchOptions {
            title: format!("{APP_NAME} · {name}"),
            data_dir: std::env::temp_dir().join("vpnte-webview2").join(name),
            ..LaunchOptions::default()
        };
        if let Some(mode) = args.theme {
            options.theme = Theme::builtin(mode);
        }
        if let Some(lang) = args.lang {
            options.lang = lang;
        }
        if let Some((w, h)) = args.size {
            let (w, h) = (f64::from(w), f64::from(h));
            options.size = (w, h);
            options.min_size = (options.min_size.0.min(w), options.min_size.1.min(h));
        }
        options
    }
}

/// Command line of the demo binaries: `--theme light|dark|system`, `--lang ru|en`, `--size WxH`,
/// `--scene <name>`, `--page <id>`, as `--key value` or `--key=value`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DemoArgs {
    pub theme: Option<ThemeMode>,
    pub lang: Option<Lang>,
    /// Inner window size in logical px.
    pub size: Option<(u32, u32)>,
    /// Scenario of the demo data (each demo defines its names).
    pub scene: Option<String>,
    /// Page to open (each demo defines its ids).
    pub page: Option<String>,
}

impl DemoArgs {
    /// Parses `std::env::args()`.
    pub fn parse() -> DemoArgs {
        DemoArgs::parse_from(std::env::args().skip(1))
    }

    /// Parses `args` (program name excluded). Unknown flags and bad values are logged and
    /// ignored: a demo always starts.
    pub fn parse_from<S: Into<String>>(args: impl IntoIterator<Item = S>) -> DemoArgs {
        let mut out = DemoArgs::default();
        let mut args = args.into_iter().map(Into::into);
        while let Some(arg) = args.next() {
            let (key, inline) = match arg.split_once('=') {
                Some((k, v)) => (k.to_owned(), Some(v.to_owned())),
                None => (arg, None),
            };
            let known = ["--theme", "--lang", "--size", "--scene", "--page"];
            if !known.contains(&key.as_str()) {
                tracing::warn!(arg = %key, "unknown demo argument ignored");
                continue;
            }
            let Some(value) = inline.or_else(|| args.next()) else {
                tracing::warn!(arg = %key, "demo argument without a value ignored");
                break;
            };
            let bad = |key: &str, value: &str| {
                tracing::warn!(arg = %key, %value, "bad demo argument value ignored");
            };
            match key.as_str() {
                "--theme" => match ThemeMode::from_name(&value) {
                    Some(mode) => out.theme = Some(mode),
                    None => bad(&key, &value),
                },
                "--lang" => match Lang::from_tag(&value) {
                    Some(lang) => out.lang = Some(lang),
                    None => bad(&key, &value),
                },
                "--size" => match parse_size(&value) {
                    Some(size) => out.size = Some(size),
                    None => bad(&key, &value),
                },
                "--scene" => out.scene = Some(value),
                _ => out.page = Some(value),
            }
        }
        out
    }
}

/// `1100x720` (also `X` or `*`) → `(1100, 720)`.
fn parse_size(value: &str) -> Option<(u32, u32)> {
    let (w, h) = value.split_once(['x', 'X', '*'])?;
    let (w, h) = (w.trim().parse().ok()?, h.trim().parse().ok()?);
    (w > 0 && h > 0).then_some((w, h))
}

/// The exe's icon resource 32512 (embedded by the app's build script); demo binaries have none and
/// use `assets/icon.png`.
fn window_icon() -> Option<Icon> {
    Icon::from_resource(32512, None).ok().or_else(|| {
        let png = assets::file("icon.png")?;
        dioxus::desktop::icon_from_memory::<Icon>(png).ok()
    })
}

fn hwnd(window: &Window) -> windows::Win32::Foundation::HWND {
    windows::Win32::Foundation::HWND(window.hwnd() as *mut _)
}

/// DWM cloaking: Windows and WebView2 treat the window as visible (it lays out and renders) but
/// DWM does not draw it. dioxus shows the window on the page's `initialize` message, before
/// WebView2 has presented: without the cloak 4 of 33 spike starts showed a black first frame.
pub fn set_cloaked(window: &Window, cloaked: bool) {
    use windows::Win32::Graphics::Dwm::{DWMWA_CLOAK, DwmSetWindowAttribute};
    let value = windows::core::BOOL::from(cloaked);
    // SAFETY: the pointer and size describe a live BOOL, the type DWMWA_CLOAK expects.
    let result = unsafe {
        DwmSetWindowAttribute(
            hwnd(window),
            DWMWA_CLOAK,
            (&raw const value).cast(),
            size_of::<windows::core::BOOL>() as u32,
        )
    };
    if let Err(err) = result {
        tracing::warn!(%err, cloaked, "DWMWA_CLOAK failed");
    }
}

/// tao applies the minimum to the outer rect, invisible resize borders included, so the OS size
/// loop stopped ~13×7.5 px short of the minimum (847×592 for 860×600); add the measured insets.
/// Once, at start: Windows scales the borders with the DPI and tao converts the logical minimum
/// at the current scale, so it holds on every monitor. Re-applying on `ScaleFactorChanged` read
/// the old monitor's insets, and tao's bounds re-check (`set_inner_size`) restores a maximized
/// window.
pub fn apply_min_size(window: &Window, (min_w, min_h): (f64, f64)) {
    let scale = window.scale_factor();
    let (outer, inner) = (window.outer_size(), window.inner_size());
    let extra_w = f64::from(outer.width.saturating_sub(inner.width)) / scale;
    let extra_h = f64::from(outer.height.saturating_sub(inner.height)) / scale;
    window.set_min_inner_size(Some(LogicalSize::new(min_w + extra_w, min_h + extra_h)));
}

/// Tightens the WebView2 settings wry and dioxus leave at their defaults: no native context menu
/// in release, no status bar, no built-in error page, no autofill or password saving. UI thread
/// only (the COM objects are STA-bound).
pub fn harden_webview(desktop: &DesktopContext) {
    use dioxus::desktop::wry::WebViewExtWindows;
    use webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2Settings4;
    use windows_core_061::Interface;
    // SAFETY: plain COM property setters on live interfaces, called on the UI (STA) thread.
    let result = unsafe {
        desktop.webview.webview().Settings().and_then(|settings| {
            settings.SetAreDefaultContextMenusEnabled(cfg!(debug_assertions))?;
            settings.SetIsStatusBarEnabled(false)?;
            settings.SetIsBuiltInErrorPageEnabled(false)?;
            let s4 = settings.cast::<ICoreWebView2Settings4>()?;
            s4.SetIsGeneralAutofillEnabled(false)?;
            s4.SetIsPasswordAutosaveEnabled(false)
        })
    };
    if let Err(err) = result {
        tracing::warn!(%err, "WebView2 settings hardening failed");
    }
}

/// Repaints what shows before and while WebView2 paints (start, resize, theme switch): the window
/// background and the WebView2 default background.
pub fn set_window_background(desktop: &DesktopContext, color: Rgb) {
    desktop.window.set_background_color(Some(color.rgba()));
    if let Err(err) = desktop.webview.set_background_color(color.rgba()) {
        tracing::warn!(%err, "WebView2 default background not set");
    }
}

/// Removes the variables that redirect the WebView2 runtime or profile or add arbitrary browser
/// switches (`--remote-debugging-port`). An elevated process must not honour them.
///
/// # Safety
/// Call at the top of `main`, before any other thread exists (`std::env::remove_var`).
pub unsafe fn scrub_webview2_env() {
    for var in [
        "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS",
        "WEBVIEW2_BROWSER_EXECUTABLE_FOLDER",
        "WEBVIEW2_USER_DATA_FOLDER",
        "WEBVIEW2_RELEASE_CHANNEL_PREFERENCE",
        "WEBVIEW2_PIPE_FOR_SCRIPT_DEBUGGER",
    ] {
        // SAFETY: single-threaded per this function's contract.
        unsafe { std::env::remove_var(var) };
    }
}

/// The message box shown instead of a window when the WebView2 runtime is missing (wry would
/// fail and dioxus would panic silently).
fn show_webview2_missing(lang: Lang) {
    use windows::Win32::UI::WindowsAndMessaging::{
        MB_ICONERROR, MB_OK, MB_SETFOREGROUND, MessageBoxW,
    };
    let text = vpnte_base::Msg::new("ui.frame.webview2Missing").render(lang);
    let (text, caption) = (
        windows::core::HSTRING::from(text),
        windows::core::HSTRING::from(APP_NAME),
    );
    // SAFETY: both strings are NUL-terminated HSTRINGs that outlive the call.
    unsafe {
        MessageBoxW(
            None,
            &text,
            &caption,
            MB_OK | MB_ICONERROR | MB_SETFOREGROUND,
        )
    };
}

/// The dioxus desktop configuration: a frameless window that keeps the DWM shadow, rounded
/// corners and resize borders (the 36 px title strip is HTML, `app-region: drag`), painted with
/// `--paper` and cloaked until the first frame; our index page and the `app` protocol; the
/// WebView2 folder; no native context menu in release.
pub fn desktop_config(options: &LaunchOptions) -> Config {
    window_config(
        options,
        &Mount::First {
            hidden: options.start_hidden,
        },
    )
}

/// [`desktop_config`] for a window that starts as `mount` says. A rebuilt window opens hidden
/// (dioxus applies its edits without animation frames only to a window built hidden) in the old
/// one's place, with the language and theme shown before the crash, cloaked until it settles.
fn window_config(options: &LaunchOptions, mount: &Mount) -> Config {
    use dioxus::desktop::tao::platform::windows::WindowBuilderExtWindows;
    let (lang, theme) = match mount {
        Mount::First { .. } => (options.lang, options.theme),
        Mount::Again { lang, theme, .. } => (*lang, *theme),
    };
    let scheme = theme.mode.resolve(theme::os_prefers_dark());
    let paper = scheme.paper().rgba();
    let icon = window_icon();
    let (w, h) = options.size;
    let (min_w, min_h) = options.min_size;
    let mut window = WindowBuilder::new()
        .with_title(&options.title)
        .with_inner_size(LogicalSize::new(w, h))
        .with_min_inner_size(LogicalSize::new(min_w, min_h))
        .with_decorations(false)
        .with_undecorated_shadow(true)
        .with_resizable(true)
        .with_visible(matches!(mount, Mount::First { hidden: false }))
        .with_background_color(paper)
        // `None` follows the OS, which is what makes tao report light/dark flips.
        .with_theme((theme.mode != ThemeMode::System).then(|| scheme.tao()))
        .with_window_icon(icon.clone())
        .with_taskbar_icon(icon)
        .with_window_classname("VpnteMainWindow");
    if let Mount::Again { shape, .. } = mount {
        if let Some((position, size)) = shape.place {
            window = window.with_position(position).with_inner_size(size);
        }
        window = window.with_maximized(shape.maximized);
    }
    let cloak = !matches!(mount, Mount::First { hidden: true });
    Config::new()
        .with_menu(None)
        .with_window(window)
        .with_background_color(paper)
        .with_custom_index(assets::index_html(&options.title, lang, &theme, scheme))
        .with_custom_protocol("app", assets::serve)
        .with_data_directory(&options.data_dir)
        .with_disable_context_menu(!cfg!(debug_assertions))
        .with_on_window(move |window, _dom| {
            if cloak {
                set_cloaked(&window, true);
            }
        })
}

#[derive(Clone)]
struct FrameProps {
    root: fn() -> Element,
    min_size: (f64, f64),
    mount: Mount,
    rebuild: Rc<Rebuild>,
}

/// Root of every UI binary: the frame hooks, then the caller's root component.
#[allow(non_snake_case)]
fn Frame(props: FrameProps) -> Element {
    use_frame(props.min_size, props.mount, &props.rebuild);
    recover::use_crash_watch(props.rebuild.clone());
    let Root = props.root;
    rsx! {
        Root {}
    }
}

fn use_frame(min_size: (f64, f64), mount: Mount, rebuild: &Rc<Rebuild>) {
    let desktop = use_window();
    remount::use_carry(rebuild, mount);
    theme::use_theme_sync();
    lang::use_lang_sync();
    use_hook({
        let (desktop, rebuild) = (desktop.clone(), rebuild.clone());
        move || {
            // A rebuilt window has mounted: the one it replaces goes.
            rebuild.mounted();
            harden_webview(&desktop);
            apply_min_size(&desktop.window, min_size);
            // A start in the tray hides only the window; the page would render unseen at full
            // cost until the first show. The first render is the earliest point we hold the
            // webview (the page has just loaded).
            if mount.hidden() {
                crate::tray::set_webview_hidden(&desktop, true);
            }
        }
    });
    use_future(move || {
        let desktop = desktop.clone();
        async move {
            match mount {
                Mount::First { hidden: true } => {}
                Mount::First { hidden: false } => {
                    painted().await;
                    set_cloaked(&desktop.window, false);
                }
                Mount::Again { shape, .. } => remount::settle(&desktop, shape).await,
            }
        }
    });
}

/// Two animation frames after the first edits: WebView2 has presented them. The timeout is a
/// safety net, a cloaked window must never stay invisible.
async fn painted() {
    let painted = document::eval(
        "await new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r))); return 1;",
    );
    let _ = tokio::time::timeout(Duration::from_secs(2), painted.join::<u8>()).await;
}

/// Runs the UI and never returns: registers the UI locales (unless the app already registered
/// them with its backend layers), shows a message box and exits with code 3 when the WebView2
/// runtime is missing, builds our multi-thread tokio runtime, calls `contexts` once inside it
/// (backend handles may spawn tasks) and provides a value of each context to the window's
/// VirtualDom (and to the new one a WebView2 crash gets, see [`RootContext`]), then runs the event
/// loop on this thread.
pub fn launch(
    options: LaunchOptions,
    root: fn() -> Element,
    contexts: impl FnOnce() -> Vec<Box<dyn RootContext>>,
) -> ! {
    lang::init_locales(&[]);
    lang::set_initial(options.lang);
    theme::set_initial(options.theme);
    if let Err(err) = dioxus::desktop::wry::webview_version() {
        tracing::error!(%err, "WebView2 runtime missing");
        show_webview2_missing(options.lang);
        std::process::exit(3);
    }
    // Four workers: backend work is I/O-bound; the event loop and every dioxus task stay on this
    // (main) thread.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .thread_name("backend")
        .enable_all()
        .build();
    let runtime = match runtime {
        Ok(runtime) => runtime,
        Err(err) => {
            tracing::error!(%err, "tokio runtime not created");
            std::process::exit(1);
        }
    };
    let _entered = runtime.enter();
    let config = desktop_config(&options);
    let hidden = options.start_hidden;
    let rebuild = Rebuild::new(options, root, contexts());
    let vdom = rebuild.dom(Mount::First { hidden });
    dioxus::desktop::launch::launch_virtual_dom(vdom, config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_args_parse_both_forms() {
        let args = DemoArgs::parse_from([
            "--theme",
            "dark",
            "--lang=en",
            "--size",
            "860x600",
            "--scene",
            "connected",
            "--page=servers",
        ]);
        assert_eq!(
            args,
            DemoArgs {
                theme: Some(ThemeMode::Dark),
                lang: Some(Lang::En),
                size: Some((860, 600)),
                scene: Some("connected".into()),
                page: Some("servers".into()),
            }
        );
    }

    #[test]
    fn demo_args_ignore_noise() {
        let args = DemoArgs::parse_from([
            "--bogus", "--theme", "sepia", "--lang", "de", "--size", "0x5",
        ]);
        assert_eq!(args, DemoArgs::default());
        let args = DemoArgs::parse_from(["--size", "1440X900", "--theme"]);
        assert_eq!(args.size, Some((1440, 900)));
        assert_eq!(args.theme, None);
        assert_eq!(parse_size("1100*720"), Some((1100, 720)));
        assert_eq!(parse_size("1100"), None);
        assert_eq!(parse_size("-1x5"), None);
    }

    #[test]
    fn default_window_is_1100_by_720() {
        let options = LaunchOptions::default();
        assert_eq!(options.title, APP_NAME);
        assert_eq!(options.size, (1100.0, 720.0));
        assert_eq!(options.min_size, (860.0, 600.0));
        assert!(!options.start_hidden);
        assert!(options.data_dir.ends_with(r"VPN Tunnel Enforcer\WebView2"));
        assert_eq!(options.theme, Theme::builtin(ThemeMode::System));
    }

    #[test]
    fn demos_get_their_own_webview_folder() {
        let args = DemoArgs::parse_from(["--theme", "light", "--lang", "ru", "--size", "800x500"]);
        let a = LaunchOptions::demo("demo_a", &args);
        let b = LaunchOptions::demo("demo_b", &DemoArgs::default());
        assert!(a.data_dir.starts_with(std::env::temp_dir()));
        assert_ne!(a.data_dir, b.data_dir);
        assert!(a.data_dir.ends_with("demo_a"));
        assert_eq!(a.theme, Theme::builtin(ThemeMode::Light));
        assert_eq!(a.lang, Lang::Ru);
        assert_eq!(a.size, (800.0, 500.0));
        // a demo smaller than the app minimum lowers the minimum instead of growing the window
        assert_eq!(a.min_size, (800.0, 500.0));
        assert_eq!(b.size, (1100.0, 720.0));
        assert_eq!(b.min_size, (860.0, 600.0));
    }
}
