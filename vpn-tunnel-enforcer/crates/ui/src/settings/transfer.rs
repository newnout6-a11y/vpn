//! «Импорт / Экспорт» (ui-pages §3.7): export without / with secrets, import with a preview
//! (sections, conflicts, replace or merge). The picked file is single use: a failed apply keeps
//! the panel for inspection but cannot be retried; a new pick starts over.
use std::time::Duration;

use dioxus::prelude::*;

use super::model::{ConfigSection, ExportMode, ImportMode, ImportPreview};
use super::use_api;
use crate::lang::tr;
use crate::t;
use crate::widgets::{
    Badge, Button, ButtonKind, Checkbox, Modal, ModalSize, Segmented, Tone, UiError, use_job,
};

/// The import panel: what the file holds and the user's choices.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct ImportPanel {
    pub preview: ImportPreview,
    pub selected: Vec<ConfigSection>,
    pub mode: ImportMode,
    /// An apply was attempted: the file is used up.
    pub consumed: bool,
}

impl ImportPanel {
    /// Every section selected, «Заменить» preselected.
    pub fn new(preview: ImportPreview) -> Self {
        Self {
            selected: preview.sections.clone(),
            preview,
            mode: ImportMode::Replace,
            consumed: false,
        }
    }

    pub fn toggle(&mut self, section: ConfigSection, on: bool) {
        self.selected.retain(|s| *s != section);
        if on {
            self.selected.push(section);
            self.selected.sort();
        }
    }

    /// Conflicting sections among the selected ones (the replace / merge choice is shown only
    /// when there are some).
    pub fn conflicts(&self) -> Vec<ConfigSection> {
        let conflicts = &self.preview.conflicts;
        self.selected
            .iter()
            .copied()
            .filter(|s| conflicts.contains(s))
            .collect()
    }

    pub fn can_apply(&self, applying: bool) -> bool {
        !applying && !self.consumed && !self.selected.is_empty()
    }
}

/// A flash line that disappears after 3 s (the old success flash).
#[derive(Clone, Copy, PartialEq)]
enum Flash {
    Exported,
    Imported,
}

#[component]
pub(super) fn Transfer() -> Element {
    let api = use_api();
    let export_job = use_job::<()>();
    let pick_job = use_job::<Option<ImportPreview>>();
    let apply_job = use_job::<()>();
    let mut panel = use_signal(|| None::<ImportPanel>);
    let mut flash = use_signal(|| None::<Flash>);
    let mut modal_error = use_signal(|| None::<(&'static str, UiError)>);
    let mut show_flash = move |kind: Flash| {
        flash.set(Some(kind));
        spawn(async move {
            tokio::time::sleep(Duration::from_secs(3)).await;
            if *flash.peek() == Some(kind) {
                flash.set(None);
            }
        });
    };
    let export_api = api.clone();
    let export = move |mode: ExportMode| {
        let api = export_api.clone();
        export_job.start(move |_| async move {
            let result = api.export_config(mode).await;
            match &result {
                Ok(()) => show_flash(Flash::Exported),
                Err(err) if err.kind != vpnte_base::ErrorKind::Cancelled => {
                    modal_error.set(Some((
                        "ui.settings.transfer.exportError",
                        UiError::from(err),
                    )));
                }
                Err(_) => {}
            }
            result
        });
    };
    let export_secrets = export.clone();
    let pick_api = api.clone();
    let pick = move |_| {
        if pick_job.running() || apply_job.running() {
            return;
        }
        let api = pick_api.clone();
        pick_job.start(move |_| async move {
            let result = api.pick_config_import().await;
            match &result {
                Ok(Some(preview)) => panel.set(Some(ImportPanel::new(preview.clone()))),
                Ok(None) => {}
                Err(err) if err.kind != vpnte_base::ErrorKind::Cancelled => {
                    modal_error.set(Some(("settings.importError", UiError::from(err))));
                }
                Err(_) => {}
            }
            result
        });
    };
    let exporting = export_job.running();
    rsx! {
        crate::widgets::Panel { title: t!("settings.importExport"), id: "set-transfer",
            p { class: "set-hint", {t!("settings.importExportDescription")} }
            div { class: "set-form-actions",
                Button { kind: ButtonKind::Ghost, busy: exporting, onclick: move |_| export(ExportMode::Redacted),
                    {t!("settings.exportSettings")}
                }
                Button { kind: ButtonKind::Ghost, disabled: exporting, onclick: move |_| export_secrets(ExportMode::WithSecrets),
                    {t!("settings.exportSettingsWithSecrets")}
                }
                Button { kind: ButtonKind::Ghost, busy: pick_job.running(), disabled: apply_job.running(), onclick: pick,
                    {t!("settings.importSettings")}
                }
            }
            match flash() {
                Some(Flash::Exported) => rsx! { p { class: "set-result", role: "status", {t!("settings.exportSuccess")} } },
                Some(Flash::Imported) => rsx! { p { class: "set-result", role: "status", {t!("settings.importSuccess")} } },
                None => rsx! {},
            }
            if panel.read().is_some() {
                ImportBox { panel, apply_job, modal_error, on_applied: move |()| show_flash(Flash::Imported) }
            }
            Modal {
                open: modal_error.read().is_some(),
                title: modal_error.read().as_ref().map_or_else(String::new, |(key, _)| t!(key)),
                close_label: t!("common.close"),
                size: ModalSize::Sm,
                on_close: move |()| modal_error.set(None),
                footer: rsx! {
                    Button { kind: ButtonKind::Primary, initial_focus: true, onclick: move |_| modal_error.set(None),
                        {t!("common.ok")}
                    }
                },
                if let Some((_, err)) = modal_error() {
                    p { class: "w-confirm-text", {tr(&err.msg)} }
                }
            }
        }
    }
}

#[component]
fn ImportBox(
    panel: Signal<Option<ImportPanel>>,
    apply_job: crate::widgets::JobSlot<()>,
    modal_error: Signal<Option<(&'static str, UiError)>>,
    on_applied: EventHandler<()>,
) -> Element {
    let api = use_api();
    let Some(current) = panel() else {
        return rsx! {};
    };
    let applying = apply_job.running();
    let conflicts = current.conflicts();
    let discard_api = api.clone();
    let cancel = move |_| {
        let api = discard_api.clone();
        spawn(async move { api.discard_config_import().await });
        panel.set(None);
    };
    let apply = move |_| {
        let Some(state) = panel.peek().clone() else {
            return;
        };
        if !state.can_apply(false) {
            return;
        }
        if let Some(p) = panel.write().as_mut() {
            p.consumed = true;
        }
        let api = api.clone();
        apply_job.start(move |_| async move {
            let result = api
                .apply_config_import(state.selected.clone(), state.mode)
                .await;
            match &result {
                Ok(()) => {
                    tracing::info!(target: "ui", sections = ?state.selected, "config imported");
                    panel.set(None);
                    on_applied.call(());
                }
                Err(err) if err.kind != vpnte_base::ErrorKind::Cancelled => {
                    tracing::warn!(target: "ui", error = %err, "config import failed");
                    modal_error.set(Some(("settings.importError", UiError::from(err))));
                }
                Err(_) => {}
            }
            result
        });
    };
    rsx! {
        div { class: "set-note set-import", role: "group", aria_label: t!("settings.importSections"),
            p { class: "set-note-title",
                {t!("ui.settings.transfer.file", name = current.preview.file_name.clone())}
            }
            if current.preview.redacted {
                p { class: "set-hint", {t!("ui.settings.transfer.redacted")} }
            }
            if current.preview.invalid_entries > 0 {
                p { class: "set-result is-warn", {t!("ui.settings.transfer.invalid", count = current.preview.invalid_entries)} }
            }
            p { class: "set-subgroup-title", {t!("settings.importSections")} }
            div { class: "set-checklist",
                for section in current.preview.sections.iter().copied() {
                    div { key: "{section.label_key()}", class: "set-check-line",
                        Checkbox {
                            label: t!(section.label_key()),
                            checked: current.selected.contains(&section),
                            disabled: applying || current.consumed,
                            on_change: move |on| {
                                if let Some(p) = panel.write().as_mut() {
                                    p.toggle(section, on);
                                }
                            },
                        }
                        if current.preview.conflicts.contains(&section) {
                            Badge { tone: Tone::Warn, title: t!("settings.importConflictsDescription"),
                                {t!("ui.settings.transfer.hasData")}
                            }
                        }
                    }
                }
            }
            if !conflicts.is_empty() {
                div { class: "set-subgroup",
                    p { class: "set-subgroup-title", {t!("settings.importConflicts")} }
                    p { class: "set-hint", {t!("settings.importConflictsDescription")} }
                    Segmented {
                        label: t!("settings.importConflicts"),
                        options: vec![
                            (ImportMode::Replace, t!("settings.conflictReplace")),
                            (ImportMode::Merge, t!("settings.conflictMerge")),
                        ],
                        value: current.mode,
                        disabled: applying || current.consumed,
                        on_change: move |mode| {
                            if let Some(p) = panel.write().as_mut() {
                                p.mode = mode;
                            }
                        },
                    }
                }
            }
            if current.consumed && !applying {
                p { class: "set-hint", {t!("ui.settings.transfer.consumed")} }
            }
            div { class: "set-form-actions",
                Button {
                    kind: ButtonKind::Primary,
                    small: true,
                    busy: applying,
                    disabled: !current.can_apply(applying),
                    onclick: apply,
                    {t!("settings.applyImport")}
                }
                Button { kind: ButtonKind::Ghost, small: true, disabled: applying, onclick: cancel,
                    {t!("common.cancel")}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn preview() -> ImportPreview {
        ImportPreview {
            file_name: "selected.json".into(),
            sections: vec![ConfigSection::Dns, ConfigSection::Notifications],
            conflicts: vec![ConfigSection::Dns],
            redacted: true,
            invalid_entries: 0,
        }
    }

    /// §7.11 Import/Export: all sections preselected, replace by default; the conflict choice
    /// follows the selection; nothing selected → no apply.
    #[test]
    fn panel_selection_and_conflicts() {
        let mut panel = ImportPanel::new(preview());
        assert_eq!(
            panel.selected,
            [ConfigSection::Dns, ConfigSection::Notifications]
        );
        assert_eq!(panel.mode, ImportMode::Replace);
        assert_eq!(panel.conflicts(), [ConfigSection::Dns]);
        panel.toggle(ConfigSection::Dns, false);
        assert!(panel.conflicts().is_empty());
        assert!(panel.can_apply(false));
        panel.toggle(ConfigSection::Notifications, false);
        assert!(!panel.can_apply(false));
    }

    /// §7.11: after a failed apply the panel stays but Apply is disabled (the file is used up);
    /// a new pick starts with a fresh panel that can be applied.
    #[test]
    fn a_consumed_file_cannot_be_applied_again() {
        let mut panel = ImportPanel::new(preview());
        panel.consumed = true;
        assert!(!panel.can_apply(false));
        let fresh = ImportPanel::new(preview());
        assert!(fresh.can_apply(false));
        assert!(!fresh.can_apply(true));
    }

    /// U-10: every section has a label key, `serverGroups` included.
    #[test]
    fn every_section_has_a_label() {
        for section in ConfigSection::ALL {
            assert_eq!(section.label_key().split('.').next(), Some("settings"));
        }
        assert_eq!(
            ConfigSection::ServerGroups.label_key(),
            "settings.sectionServerGroups"
        );
    }
}
