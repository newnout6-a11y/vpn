//! The notification-area icon and its menu (tray-icon + muda; UI thread only), kept equal to a
//! [`TrayModel`] by diff: only changed texts, flags, tooltip and icon reach Win32. The old tray
//! re-read the icon from disk and rebuilt the whole menu on every traffic tick (L-03).
use std::time::{Duration, Instant};

use dioxus::desktop::trayicon::menu::{IsMenuItem, Menu, MenuItem, PredefinedMenuItem};
use dioxus::desktop::trayicon::{TrayIcon, TrayIconBuilder};
use vpnte_base::i18n::Lang;

use super::icon::{TrayIcons, tray_icon_size};
use super::model::{Badge, TrayItemId, TrayModel, fit_tooltip};

/// The speed line and the tooltip change on every traffic tick; Win32 gets them once a second.
pub const SPEED_REFRESH: Duration = Duration::from_secs(1);

/// muda id of the «Доступна версия X» line (shown only while a version is offered, so it is not
/// one of the fixed [`TrayItemId`] entries).
pub const UPDATE_MENU_ID: &str = "tray.update";

/// The model rendered in one language: what the tray should show.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rendered {
    /// `(text, enabled)` per entry, [`TrayItemId::ALL`] order; `&` doubled (Win32 mnemonics).
    pub items: Vec<(String, bool)>,
    /// Status / IP / proxy lines.
    pub tooltip_head: Vec<String>,
    /// The speed line, while an engine runs.
    pub tooltip_speed: Option<String>,
    pub badge: Badge,
    /// The update line, while a version is offered.
    pub update: Option<String>,
}

impl Rendered {
    /// Renders `model` in `lang`.
    pub fn of(model: &TrayModel, lang: Lang) -> Rendered {
        Rendered {
            items: model
                .items
                .iter()
                .map(|item| (item.label.render(lang).replace('&', "&&"), item.enabled))
                .collect(),
            tooltip_head: model.tooltip.iter().map(|m| m.render(lang)).collect(),
            tooltip_speed: model.tooltip_speed.as_ref().map(|m| m.render(lang)),
            badge: model.status.badge(),
            update: (model.update.as_ref()).map(|m| m.render(lang).replace('&', "&&")),
        }
    }

    /// The tooltip text, cut to the shell's limit.
    pub fn tooltip(&self) -> String {
        let mut lines = self.tooltip_head.clone();
        lines.extend(self.tooltip_speed.clone());
        fit_tooltip(&lines)
    }
}

/// Native calls one update needs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Changes {
    pub texts: Vec<(TrayItemId, String)>,
    pub enabled: Vec<(TrayItemId, bool)>,
    pub tooltip: Option<String>,
    pub badge: Option<Badge>,
    /// The update line changed: `Some(None)` removes it.
    pub update: Option<Option<String>>,
}

impl Changes {
    /// Nothing to send.
    pub fn is_empty(&self) -> bool {
        self.texts.is_empty()
            && self.enabled.is_empty()
            && self.tooltip.is_none()
            && self.badge.is_none()
            && self.update.is_none()
    }
}

/// Remembers what Win32 shows and decides what an update must change.
#[derive(Debug, Default)]
pub struct Differ {
    shown: Option<Rendered>,
    speed_at: Option<Instant>,
}

impl Differ {
    /// The calls that bring the tray from what it shows to `next`. A change of the speed figures
    /// alone waits until [`SPEED_REFRESH`] has passed since the last one (the caller re-applies
    /// periodically, so the latest figures still arrive).
    pub fn changes(&mut self, next: &Rendered, now: Instant) -> Changes {
        let prev = self.shown.as_ref();
        let mut changes = Changes::default();
        for (i, id) in TrayItemId::ALL.into_iter().enumerate() {
            let (text, enabled) = &next.items[i];
            let old = prev.map(|p| &p.items[i]);
            if old.map(|(t, _)| t) != Some(text) {
                changes.texts.push((id, text.clone()));
            }
            if old.map(|(_, e)| *e) != Some(*enabled) {
                changes.enabled.push((id, *enabled));
            }
        }
        let tooltip = next.tooltip();
        if prev.map(Rendered::tooltip).as_ref() != Some(&tooltip) {
            changes.tooltip = Some(tooltip);
        }
        if prev.map(|p| p.badge) != Some(next.badge) {
            changes.badge = Some(next.badge);
        }
        if prev.map(|p| &p.update) != Some(&next.update) {
            changes.update = Some(next.update.clone());
        }
        let speed_only = prev.is_some_and(|p| p.tooltip_head == next.tooltip_head)
            && changes.enabled.is_empty()
            && changes.badge.is_none()
            && changes.update.is_none()
            && changes.texts.iter().all(|(id, _)| *id == TrayItemId::Speed);
        let too_soon = self
            .speed_at
            .is_some_and(|at| now.saturating_duration_since(at) < SPEED_REFRESH);
        if speed_only && too_soon {
            return Changes::default();
        }
        if changes.tooltip.is_some() || changes.texts.iter().any(|(id, _)| *id == TrayItemId::Speed)
        {
            self.speed_at = Some(now);
        }
        self.shown = Some(next.clone());
        changes
    }

    /// Marks `rendered` as shown (the tray was just built with it).
    pub fn shown(&mut self, rendered: Rendered, now: Instant) {
        self.shown = Some(rendered);
        self.speed_at = Some(now);
    }
}

/// Counts of Win32 updates since start (the demo shows them: diffs keep them low).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NativeCalls {
    pub text: u32,
    pub enabled: u32,
    pub tooltip: u32,
    pub icon: u32,
}

/// What the native tray holds right now, read back from the muda items.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NativeReport {
    /// `(text, enabled)` per entry as muda holds them.
    pub items: Vec<(String, bool)>,
    pub tooltip: String,
    pub badge: Option<Badge>,
    pub calls: NativeCalls,
    /// The update line as muda holds it.
    pub update: Option<String>,
}

/// The tray icon with its menu. Dropping it removes the icon (the old tray was never destroyed,
/// F-134).
pub struct NativeTray {
    icon: TrayIcon,
    /// The menu (muda shares it with the icon): the update line comes and goes.
    menu: Menu,
    items: Vec<MenuItem>,
    update: Option<MenuItem>,
    icons: Option<TrayIcons>,
    differ: Differ,
    tooltip: String,
    badge: Option<Badge>,
    calls: NativeCalls,
}

impl NativeTray {
    /// Builds the icon and menu showing `model`. `None` (logged) when Windows refuses; the app
    /// then runs without a tray, and the close button must not hide the window.
    pub fn new(model: &TrayModel, lang: Lang) -> Option<NativeTray> {
        let rendered = Rendered::of(model, lang);
        let items: Vec<MenuItem> = TrayItemId::ALL
            .into_iter()
            .zip(&rendered.items)
            .map(|(id, (text, enabled))| MenuItem::with_id(id.menu_id(), text, *enabled, None))
            .collect();
        let separators: Vec<Option<PredefinedMenuItem>> = TrayItemId::ALL
            .into_iter()
            .map(|id| id.separator_after().then(PredefinedMenuItem::separator))
            .collect();
        let mut entries: Vec<&dyn IsMenuItem> = Vec::new();
        for (item, separator) in items.iter().zip(&separators) {
            entries.push(item);
            if let Some(separator) = separator {
                entries.push(separator);
            }
        }
        let menu = Menu::new();
        if let Err(err) = menu.append_items(&entries) {
            tracing::error!(%err, "tray menu not built");
            return None;
        }
        let icons = TrayIcons::new(tray_icon_size());
        let icon = icons.as_ref().and_then(|icons| icons.get(rendered.badge));
        if icon.is_none() {
            tracing::warn!("tray status icons unavailable; using the exe icon");
        }
        let icon =
            icon.or_else(|| dioxus::desktop::trayicon::Icon::from_resource(32512, None).ok());
        let tooltip = rendered.tooltip();
        let mut builder = TrayIconBuilder::new()
            .with_id("vpnte")
            .with_tooltip(&tooltip)
            .with_menu(Box::new(menu.clone()))
            .with_menu_on_left_click(false);
        if let Some(icon) = icon {
            builder = builder.with_icon(icon);
        }
        let icon = match builder.build() {
            Ok(icon) => icon,
            Err(err) => {
                tracing::error!(%err, "tray icon not created");
                return None;
            }
        };
        let badge = icons.as_ref().map(|_| rendered.badge);
        let update = rendered.update.clone();
        let mut differ = Differ::default();
        differ.shown(rendered, Instant::now());
        let mut tray = NativeTray {
            icon,
            menu,
            items,
            update: None,
            icons,
            differ,
            tooltip,
            badge,
            calls: NativeCalls::default(),
        };
        tray.set_update(update);
        Some(tray)
    }

    /// Adds, changes or removes the update line (right above «Показать окно»).
    fn set_update(&mut self, text: Option<String>) {
        match (text, &self.update) {
            (Some(text), Some(item)) => {
                item.set_text(text);
                self.calls.text += 1;
            }
            (Some(text), None) => {
                let item = MenuItem::with_id(UPDATE_MENU_ID, text, true, None);
                match self.menu.insert(&item, update_position()) {
                    Ok(()) => self.update = Some(item),
                    Err(err) => tracing::warn!(%err, "tray update line not added"),
                }
            }
            (None, Some(item)) => {
                if let Err(err) = self.menu.remove(item) {
                    tracing::warn!(%err, "tray update line not removed");
                }
                self.update = None;
            }
            (None, None) => {}
        }
    }

    /// Brings the tray to `model` with the fewest Win32 calls.
    pub fn apply(&mut self, model: &TrayModel, lang: Lang, now: Instant) {
        let changes = self.differ.changes(&Rendered::of(model, lang), now);
        for (id, text) in changes.texts {
            self.items[id as usize].set_text(text);
            self.calls.text += 1;
        }
        for (id, enabled) in changes.enabled {
            self.items[id as usize].set_enabled(enabled);
            self.calls.enabled += 1;
        }
        if let Some(update) = changes.update {
            self.set_update(update);
        }
        if let Some(tooltip) = changes.tooltip {
            match self.icon.set_tooltip(Some(&tooltip)) {
                Ok(()) => self.calls.tooltip += 1,
                Err(err) => tracing::warn!(%err, "tray tooltip not set"),
            }
            self.tooltip = tooltip;
        }
        if let Some(badge) = changes.badge
            && let Some(icon) = self.icons.as_ref().and_then(|icons| icons.get(badge))
        {
            match self.icon.set_icon(Some(icon)) {
                Ok(()) => self.calls.icon += 1,
                Err(err) => tracing::warn!(%err, "tray icon not set"),
            }
            self.badge = Some(badge);
        }
    }

    /// The current native state.
    pub fn report(&self) -> NativeReport {
        NativeReport {
            items: self
                .items
                .iter()
                .map(|item| (item.text(), item.is_enabled()))
                .collect(),
            tooltip: self.tooltip.clone(),
            badge: self.badge,
            calls: self.calls,
            update: self.update.as_ref().map(MenuItem::text),
        }
    }
}

/// Menu position of the update line: the entries (and separators) before «Показать окно».
fn update_position() -> usize {
    TrayItemId::ALL
        .into_iter()
        .take_while(|id| *id != TrayItemId::Show)
        .map(|id| 1 + usize::from(id.separator_after()))
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tray::model::{TrayExtras, TrayState, TunnelState};

    fn render(state: &TrayState) -> Rendered {
        crate::test_locales::init_locales();
        Rendered::of(&TrayModel::build(state, false), Lang::Ru)
    }

    fn connected(down: u64) -> TrayState {
        TrayState {
            tunnel: TunnelState::Connected,
            engine_running: true,
            public_ip: Some("198.51.100.7".into()),
            down_bps: down,
            ..TrayState::default()
        }
    }

    #[test]
    fn renders_in_the_current_language() {
        crate::test_locales::init_locales();
        let model = TrayModel::build(&connected(125_000), false);
        let ru = Rendered::of(&model, Lang::Ru);
        assert_eq!(ru.items[0].0, "Статус: Защищено");
        assert_eq!(ru.items[1].0, "IP: 198.51.100.7");
        assert_eq!(ru.items[2].0, "Proxy: не выбран");
        assert_eq!(ru.items[3].0, "Скорость: ↓ 1.0 Mbps / ↑ 0 Kbps");
        assert_eq!(
            ru.tooltip(),
            "VPN Tunnel Enforcer — Защищено\nIP: 198.51.100.7\n↓ 1.0 Mbps / ↑ 0 Kbps"
        );
        let en = Rendered::of(&model, Lang::En);
        assert_eq!(en.items[0].0, "Status: Protected");
        assert_eq!(en.items[9].0, "Exit");
        // `&` would underline the next letter in a Win32 menu
        let odd = TrayState {
            proxy_addr: Some("a&b:1".into()),
            ..connected(0)
        };
        assert_eq!(render(&odd).items[2].0, "Proxy: a&&b:1");
        assert_eq!(render(&odd).tooltip_head[2], "Proxy: a&b:1");
    }

    /// L-03: unchanged state costs no Win32 call; the speed line alone refreshes once a second.
    #[test]
    fn updates_are_diffs_and_speed_is_throttled() {
        let t0 = Instant::now();
        let mut differ = Differ::default();
        differ.shown(render(&connected(1_000)), t0);
        assert!(differ.changes(&render(&connected(1_000)), t0).is_empty());
        // speed only, too soon: deferred
        let ms = Duration::from_millis;
        assert!(
            differ
                .changes(&render(&connected(2_000)), t0 + ms(300))
                .is_empty()
        );
        // a second later the same figures go out: speed item + tooltip, nothing else
        let late = differ.changes(&render(&connected(2_000)), t0 + ms(1_000));
        assert_eq!(late.texts.len(), 1);
        assert_eq!(late.texts[0].0, TrayItemId::Speed);
        assert!(late.tooltip.is_some());
        assert!(late.enabled.is_empty() && late.badge.is_none());
        // a status change goes out at once, with the current speed
        let leak = TrayState {
            leak: true,
            ..connected(3_000)
        };
        let now = differ.changes(&render(&leak), t0 + ms(1_100));
        assert_eq!(now.badge, Some(Badge::Red));
        let ids: Vec<TrayItemId> = now.texts.iter().map(|(id, _)| *id).collect();
        assert_eq!(ids, [TrayItemId::Status, TrayItemId::Speed]);
        assert!(
            now.tooltip
                .is_some_and(|t| t.starts_with("VPN Tunnel Enforcer — утечка IP"))
        );
        // disconnect: icon, texts and the start/stop flags change together
        let off = differ.changes(&render(&TrayState::default()), t0 + ms(1_200));
        assert_eq!(off.badge, Some(Badge::Off));
        let flags: Vec<(TrayItemId, bool)> = off.enabled.clone();
        assert_eq!(
            flags,
            [(TrayItemId::Start, true), (TrayItemId::Stop, false)]
        );
    }

    #[test]
    fn language_switch_rewrites_every_text() {
        crate::test_locales::init_locales();
        let t0 = Instant::now();
        let model = TrayModel::build(&TrayState::default(), false);
        let mut differ = Differ::default();
        differ.shown(Rendered::of(&model, Lang::Ru), t0);
        let changes = differ.changes(&Rendered::of(&model, Lang::En), t0);
        // «IP: …» lines read the same in both languages except the unknown/none words
        assert!(changes.texts.len() >= 8, "{changes:?}");
        assert!(changes.tooltip.is_some());
        assert!(changes.enabled.is_empty() && changes.badge.is_none());
    }

    /// p-follow: the update line comes, changes and goes as one change of its own, right above
    /// «Показать окно» (after the four status lines and their separator).
    #[test]
    fn the_update_line_comes_and_goes() {
        crate::test_locales::init_locales();
        let t0 = Instant::now();
        let offered = |version: Option<&str>| {
            let extras = TrayExtras {
                always: false,
                update: version.map(str::to_owned),
            };
            Rendered::of(
                &TrayModel::build_with(&connected(0), &extras, false),
                Lang::Ru,
            )
        };
        let mut differ = Differ::default();
        differ.shown(offered(None), t0);
        let shown = differ.changes(&offered(Some("2.0.1")), t0);
        assert_eq!(shown.update, Some(Some("Доступна версия 2.0.1".to_owned())));
        assert!(shown.texts.is_empty() && shown.enabled.is_empty());
        assert!(differ.changes(&offered(Some("2.0.1")), t0).is_empty());
        assert_eq!(differ.changes(&offered(None), t0).update, Some(None));
        assert_eq!(update_position(), 5);
    }
}
