//! UI language: the reactive [`LANG`] signal, the [`t!`](crate::t) macro and [`tr`] on top of
//! `vpnte_base::i18n`, and the registration of every locale layer.
use std::sync::{Once, OnceLock};

use dioxus::prelude::*;
use vpnte_base::Msg;
pub use vpnte_base::i18n::Lang;

/// The current UI language. Every `t!` / [`tr`] caller re-renders when it changes.
pub static LANG: GlobalSignal<Lang> = Signal::global(initial);

static INITIAL: OnceLock<Lang> = OnceLock::new();

/// The language of the first frame (from [`crate::launch::LaunchOptions`]).
pub(crate) fn set_initial(lang: Lang) {
    let _ = INITIAL.set(lang);
}

fn initial() -> Lang {
    INITIAL.get().copied().unwrap_or_else(os_lang)
}

/// The Windows display language: Russian → `ru`, anything else → `en`.
pub fn os_lang() -> Lang {
    // SAFETY: no arguments and no preconditions.
    let id = unsafe { windows::Win32::Globalization::GetUserDefaultUILanguage() };
    // PRIMARYLANGID(id) == LANG_RUSSIAN
    if id & 0x3ff == 0x19 {
        Lang::Ru
    } else {
        Lang::En
    }
}

/// Registers the locale layers once, later layers overriding earlier ones: the old app's strings
/// (`assets/locales/{ru,en}.json`), this crate's fragments ([`crate::LOCALES`]), then
/// `extra_layers` (the backend crates' `LOCALES`, `vpnte-base`'s fragment). Calls after the first
/// are ignored, so the app must register its backend layers before [`crate::launch::launch`].
pub fn init_locales(extra_layers: &[(&str, &str)]) {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let text = |path: &str| {
            crate::assets::file(path)
                .and_then(|b| std::str::from_utf8(b).ok())
                .unwrap_or("{}")
        };
        let mut layers = vec![(text("locales/ru.json"), text("locales/en.json"))];
        layers.extend_from_slice(crate::LOCALES);
        layers.extend_from_slice(extra_layers);
        vpnte_base::i18n::init(&layers);
    });
}

/// Translates `key` in the current language; subscribes the caller to [`LANG`] (UI thread only).
pub fn translate(key: &str, vars: &[(&str, String)], default: Option<&str>) -> String {
    vpnte_base::i18n::lookup(*LANG.read(), key, vars, default)
}

/// Renders a backend [`Msg`] in the current language; subscribes the caller to [`LANG`].
pub fn tr(msg: &Msg) -> String {
    msg.render(*LANG.read())
}

/// Translates `key` in the current language without subscribing: event handlers and tasks.
pub fn translate_now(key: &str, vars: &[(&str, String)]) -> String {
    vpnte_base::i18n::lookup(*LANG.peek(), key, vars, None)
}

/// Renders a backend [`Msg`] in the current language without subscribing: event handlers and
/// tasks (toasts, clipboard texts).
pub fn tr_now(msg: &Msg) -> String {
    msg.render(*LANG.peek())
}

/// `t!("a.b")`, `t!("a.b", "Default text")`, `t!("a.b", count = n, name = x)`.
#[macro_export]
macro_rules! t {
    ($key:expr) => {
        $crate::lang::translate($key, &[], None)
    };
    ($key:expr, $default:literal) => {
        $crate::lang::translate($key, &[], Some($default))
    };
    ($key:expr, $($name:ident = $val:expr),+ $(,)?) => {
        $crate::lang::translate($key, &[$((stringify!($name), ($val).to_string())),+], None)
    };
}

/// Keeps `<html lang>` equal to [`LANG`] (screen readers, hyphenation, `:lang()`). Called once by
/// the frame root.
pub(crate) fn use_lang_sync() {
    use_effect(|| {
        let code = LANG.read().code();
        let _ = document::eval(&format!("document.documentElement.lang='{code}'"));
    });
}

#[cfg(test)]
mod tests {
    use vpnte_base::i18n::lookup;

    use super::*;

    /// Every test registers the same layers: the first registration wins for the whole process.
    fn init() {
        crate::test_locales::init_locales();
        // a second registration is ignored
        init_locales(&[(r#"{"tunnel":{"x":"другое"}}"#, "{}")]);
    }

    #[test]
    fn layers_are_registered_in_order() {
        init();
        // the old app's strings
        let n = |c: u32| vec![("count", c.to_string())];
        assert_eq!(
            lookup(Lang::Ru, "servers.groups.serverCount", &n(3), None),
            "3 сервера"
        );
        assert_eq!(
            lookup(Lang::En, "servers.groups.serverCount", &n(1), None),
            "1 server"
        );
        // this package's fragment
        assert_eq!(
            lookup(Lang::En, "ui.frame.demo.title", &[], None),
            "UI frame"
        );
        assert_eq!(
            lookup(Lang::Ru, "ui.frame.demo.title", &[], None),
            "Каркас интерфейса"
        );
        // caller layers come last and override
        assert_eq!(
            lookup(Lang::Ru, "ui.frame.demo.close", &[], None),
            "Закрыть окно"
        );
        assert_eq!(lookup(Lang::En, "ui.frame.demo.close", &[], None), "Close");
        assert_eq!(lookup(Lang::Ru, "tunnel.x", &[], None), "икс");
        assert_eq!(lookup(Lang::En, "tunnel.x", &[], None), "ex");
    }

    #[test]
    fn backend_messages_render_through_the_catalog() {
        init();
        let msg = Msg::new("ui.frame.demo.scheme").arg("scheme", "dark");
        assert_eq!(msg.render(Lang::En), "Now: dark");
        assert_eq!(msg.render(Lang::Ru), "Сейчас: dark");
        assert!(
            Msg::new("ui.frame.webview2Missing")
                .render(Lang::Ru)
                .contains("WebView2 Runtime")
        );
    }
}
