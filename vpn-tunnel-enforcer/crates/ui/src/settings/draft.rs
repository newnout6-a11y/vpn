//! The Settings draft: a sparse patch over the live settings (ui-pages §6.4, fixes U-01). Fields
//! the user did not touch always show the live value, so a change made elsewhere (the dashboard
//! Smart RU toggle, a config import, the wizard) is never hidden or overwritten by «Сохранить»,
//! and the save sends only what the user changed.
use super::model::{SettingsPatch, SettingsView};

/// Edits not saved yet.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SettingsDraft {
    edits: SettingsPatch,
}

impl SettingsDraft {
    /// What the page shows: the live settings with the edits on top (nothing is clamped here;
    /// number fields clamp on commit).
    pub fn view(&self, live: &SettingsView) -> SettingsView {
        let mut view = live.clone();
        self.edits.apply_to(&mut view);
        view
    }

    /// Records an edit; an edit back to the live value is dropped at once.
    pub fn edit(&mut self, live: &SettingsView, f: impl FnOnce(&mut SettingsPatch)) {
        f(&mut self.edits);
        self.edits.prune(live);
    }

    /// Edited fields that differ from the live value, in page order.
    pub fn changed(&self, live: &SettingsView) -> Vec<&'static str> {
        self.edits.changed(live)
    }

    /// The save bar is shown iff this holds.
    pub fn is_dirty(&self, live: &SettingsView) -> bool {
        !self.changed(live).is_empty()
    }

    /// Drops edits that equal the live value (after the live settings changed).
    pub fn prune(&mut self, live: &SettingsView) {
        self.edits.prune(live);
    }

    /// «Сбросить»: forget every edit.
    pub fn reset(&mut self) {
        self.edits = SettingsPatch::default();
    }

    /// The patch «Сохранить» sends: only the fields that differ from `live`.
    pub fn to_save(&self, live: &SettingsView) -> SettingsPatch {
        let mut patch = self.edits.clone();
        patch.prune(live);
        patch
    }

    /// After a successful save of `sent`: those edits are now live.
    pub fn saved(&mut self, sent: &SettingsPatch) {
        self.edits.forget(sent);
    }

    pub fn edits(&self) -> &SettingsPatch {
        &self.edits
    }
}

#[cfg(test)]
mod tests {
    //! Port of ui-pages §7.1 (`R/pages/Settings.test.ts`); the old generic-object vectors use
    //! real fields: a = `check_interval_ms`, b = `proxy_override`, c = `leak_protection`.
    use super::*;

    fn live() -> SettingsView {
        SettingsView {
            check_interval_ms: 1_000,
            proxy_override: "x".into(),
            leak_protection: true,
            ..SettingsView::default()
        }
    }

    /// §7.1 `changedSettingKeys`: same values → nothing; differing values → their names.
    #[test]
    fn changed_keys_follow_the_old_vectors() {
        let live = live();
        let mut same = SettingsPatch {
            check_interval_ms: Some(1_000),
            proxy_override: Some("x".into()),
            leak_protection: Some(true),
            ..SettingsPatch::default()
        };
        assert!(same.changed(&live).is_empty());
        let mut other = same.clone();
        other.proxy_override = Some("y".into());
        other.leak_protection = Some(false);
        assert_eq!(other.changed(&live), ["leak_protection", "proxy_override"]);
        // ({a:1}, {a:1,b:2}) → ['b']
        same.leak_protection = None;
        same.proxy_override = Some("2".into());
        assert_eq!(same.changed(&live), ["proxy_override"]);
        // (null, undefined) → [] ; (undefined, {a:1}) → ['a']
        assert!(SettingsPatch::default().changed(&live).is_empty());
        let a = SettingsPatch {
            check_interval_ms: Some(5_000),
            ..SettingsPatch::default()
        };
        assert_eq!(a.changed(&live), ["check_interval_ms"]);
        // ({a:NaN},{a:NaN}) → [] has no counterpart: the settings hold no floats (PartialEq).
    }

    fn base() -> SettingsView {
        SettingsView {
            leak_protection: false,
            check_interval_ms: 30_000,
            ..SettingsView::default()
        }
    }

    /// §7.1 'starts clean and flips dirty on an edit'.
    #[test]
    fn starts_clean_and_flips_dirty_on_an_edit() {
        let live = base();
        let mut draft = SettingsDraft::default();
        assert!(!draft.is_dirty(&live));
        draft.edit(&live, |p| p.leak_protection = Some(true));
        assert!(draft.is_dirty(&live));
        assert_eq!(draft.changed(&live), ["leak_protection"]);
        assert!(draft.view(&live).leak_protection);
    }

    /// §7.1 'reset() restores every edited value'.
    #[test]
    fn reset_restores_every_edited_value() {
        let live = base();
        let mut draft = SettingsDraft::default();
        draft.edit(&live, |p| p.leak_protection = Some(true));
        draft.edit(&live, |p| p.stealth_mode = Some(true));
        draft.reset();
        assert!(!draft.is_dirty(&live));
        assert_eq!(draft.view(&live), live);
    }

    /// §7.1 'commit() advances the baseline … (no stale-store stomp)': after a successful save
    /// the sent edits are live; the value stays and nothing is dirty.
    #[test]
    fn a_save_clears_the_sent_edits_only() {
        let mut live = base();
        let mut draft = SettingsDraft::default();
        draft.edit(&live, |p| p.stealth_mode = Some(true));
        let sent = draft.to_save(&live);
        // an edit made while the save is running survives it
        draft.edit(&live, |p| p.autopilot = Some(false));
        live.stealth_mode = true; // the saved settings the backend returned
        draft.saved(&sent);
        assert!(draft.view(&live).stealth_mode);
        assert_eq!(draft.changed(&live), ["autopilot"]);
    }

    /// §7.1 'commitPartial() moves draft and baseline together' (location privacy applied out
    /// of band) and the new U-01 vector: an outside change of an untouched field shows up, is
    /// never counted as an edit, and the save sends only the edited field.
    #[test]
    fn outside_changes_show_and_are_never_saved_back() {
        let mut live = base();
        let mut draft = SettingsDraft::default();
        draft.edit(&live, |p| p.stealth_mode = Some(true));
        live.smart_ru_split = true; // the dashboard toggle saved it meanwhile
        assert!(draft.view(&live).smart_ru_split);
        assert_eq!(draft.changed(&live), ["stealth_mode"]);
        let patch = draft.to_save(&live);
        assert_eq!(
            patch,
            SettingsPatch {
                stealth_mode: Some(true),
                ..SettingsPatch::default()
            }
        );
        let mut saved = live.clone();
        patch.apply_to(&mut saved);
        assert!(saved.smart_ru_split && saved.stealth_mode);
    }

    /// §7.1 'adopts a genuine external store change while the draft is clean'.
    #[test]
    fn a_clean_draft_shows_the_new_live_value() {
        let mut live = base();
        let draft = SettingsDraft::default();
        live.check_interval_ms = 45_000;
        assert_eq!(draft.view(&live).check_interval_ms, 45_000);
        assert!(!draft.is_dirty(&live));
    }

    /// §7.1 'keeps the user's edit when an external store change lands mid-edit'.
    #[test]
    fn an_edit_wins_over_a_later_live_change() {
        let mut live = base();
        let mut draft = SettingsDraft::default();
        draft.edit(&live, |p| p.check_interval_ms = Some(60_000));
        live.check_interval_ms = 45_000;
        assert_eq!(draft.view(&live).check_interval_ms, 60_000);
        assert!(draft.is_dirty(&live));
    }

    /// §7.1 new: an edit put back to the live value is not a change.
    #[test]
    fn an_edit_reverted_by_hand_is_clean() {
        let live = base();
        let mut draft = SettingsDraft::default();
        draft.edit(&live, |p| p.public_wifi_compatibility = Some(false));
        assert!(draft.is_dirty(&live));
        draft.edit(&live, |p| p.public_wifi_compatibility = Some(true));
        assert!(!draft.is_dirty(&live));
        assert!(draft.edits().is_empty());
    }

    /// The live value catching up with an edit (made elsewhere) also cleans it.
    #[test]
    fn prune_drops_edits_equal_to_live() {
        let mut live = base();
        let mut draft = SettingsDraft::default();
        draft.edit(&live, |p| p.autopilot = Some(false));
        live.autopilot = false;
        draft.prune(&live);
        assert!(draft.edits().is_empty());
    }
}
