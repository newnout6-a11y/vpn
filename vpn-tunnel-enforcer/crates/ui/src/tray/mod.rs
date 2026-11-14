//! Tray icon and menu, close-to-tray and the quit flow.
//!
//! The app pushes a [`TrayState`] through [`TrayApi::state`]; [`TrayHost`] (mount it once around
//! the app's root) turns it into a [`TrayModel`], keeps the notification-area icon in sync by
//! diff, routes menu clicks to the [`TrayApi`] actions, shows the window on a left click, hides
//! the window on close (asking first while protection is on) and runs the quit cleanup before
//! the window goes away. Besides the app's feed it reads the root's Settings and Updates backends
//! ([`TrayExtras`]): in "Always" the paused menu turns "Always" off, and an offered app version
//! gets a line that opens the window.
mod demo;
mod host;
mod icon;
mod model;
mod native;

pub use demo::{DemoTray, data_uri};
pub use host::{QuitMode, TrayApi, TrayContext, TrayHost, hide_to_tray, show_window};
pub(crate) use host::{WindowLost, set_webview_hidden};
pub use icon::{TrayIcons, base_icon, ico_entries, tray_icon_size, variant, variant_png};
pub use model::{
    Badge, CloseAction, ProxyStatus, TOOLTIP_MAX, Transition, TrayExtras, TrayItem, TrayItemId,
    TrayModel, TrayState, TrayStatus, TunnelState, fit_tooltip, format_speed,
};
pub use native::{
    Changes, Differ, NativeCalls, NativeReport, NativeTray, Rendered, SPEED_REFRESH, UPDATE_MENU_ID,
};

#[cfg(test)]
mod tests {
    use vpnte_base::Msg;
    use vpnte_base::i18n::Lang;

    use super::*;

    /// Every text the tray can produce exists in both languages (a missing key renders as itself).
    #[test]
    fn every_tray_text_is_translated() {
        crate::test_locales::init_locales();
        let mut msgs: Vec<Msg> = Vec::new();
        for status in TrayStatus::ALL {
            let state = TrayState {
                public_ip: Some("198.51.100.7".into()),
                proxy_addr: Some("127.0.0.1:2080".into()),
                engine_running: true,
                ..DemoTray::scene(status)
            };
            let always = TrayExtras {
                always: true,
                update: Some("2.0.1".into()),
                window_lost: true,
            };
            for (extras, quitting) in [
                (TrayExtras::default(), false),
                (TrayExtras::default(), true),
                (always, false),
            ] {
                let model = TrayModel::build_with(&state, &extras, quitting);
                msgs.extend(model.tooltip);
                msgs.extend(model.tooltip_speed);
                msgs.extend(model.update);
                msgs.extend(model.items.into_iter().map(|item| item.label));
            }
            msgs.push(Msg::new(format!("ui.tray.demo.status.{}", status.key())));
        }
        let none = TrayModel::build(&TrayState::default(), false);
        msgs.extend(none.items.into_iter().map(|item| item.label));
        for key in [
            "ui.tray.quitFailed.title",
            "ui.tray.quitFailed.note",
            "ui.tray.quitFailed.retry",
            "ui.tray.quitFailed.exitAnyway",
            "ui.tray.demo.restoreFailed",
        ] {
            msgs.push(Msg::new(key));
        }
        for msg in &msgs {
            for lang in [Lang::Ru, Lang::En] {
                let text = msg.render(lang);
                assert_ne!(text, msg.key, "{lang:?} misses {}", msg.key);
                assert!(
                    !text.contains("{{"),
                    "{lang:?} {} leaves a placeholder: {text}",
                    msg.key
                );
            }
        }
        // the Russian wording of the spec, verbatim
        let ru = |key: &str| Msg::new(key.to_owned()).render(Lang::Ru);
        assert_eq!(
            ru("ui.tray.menu.status.killSwitch"),
            "Статус: Kill-switch: требуется проверка"
        );
        assert_eq!(ru("ui.tray.menu.show"), "Показать окно");
        assert_eq!(ru("ui.tray.menu.open"), "Открыть окно");
        assert_eq!(
            ru("ui.tray.quitFailed.exitAnyway"),
            "Выйти без восстановления"
        );
    }
}
