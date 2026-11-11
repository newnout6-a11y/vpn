//! DNS profiles and domain rules (`rules.json`). Every change is one `Store::update`; the
//! tunnel regenerates its routing fragments from the store change (app-tunnel).
use std::path::PathBuf;
use std::sync::Arc;

use vpnte_base::{AppError, AppResult, Msg};
use vpnte_engine::routing::RulesDoc;
use vpnte_engine::routing::dns::DnsAddr;
use vpnte_engine::routing::domain::{self, DomainPattern, DomainRule};
use vpnte_ui::settings as ui;

use super::dialog::{self, FileDialog};
use super::project::{core_rule_action, dns_kind};
use super::{Shared, blocking, detached};
use crate::services::Backend;

/// A domain list read and checked, waiting for the user's action choice.
pub(crate) struct PickedList {
    pub file_name: String,
    pub patterns: Vec<DomainPattern>,
}

/// Parses a resolver address; the error message says what is wrong.
pub fn validate_dns(address: &str) -> AppResult<ui::DnsKind> {
    let addr: DnsAddr = address.parse()?;
    Ok(dns_kind(&addr))
}

pub fn create_dns(backend: &Backend, name: &str, address: &str) -> AppResult<()> {
    let addr: DnsAddr = address.parse()?;
    backend
        .rules
        .update(|d| d.add_dns_profile(name, addr, None))?
        .map(drop)
}

/// Deleting a profile that is already gone is not an error (the end state is the asked one).
pub fn delete_dns(backend: &Backend, id: &str) -> AppResult<()> {
    backend
        .rules
        .update(|d| d.delete_dns_profile(id))?
        .map(drop)
}

/// `None` = the automatic entry (DoH through the VPN).
pub fn select_dns(backend: &Backend, id: Option<&str>) -> AppResult<()> {
    backend.rules.update(|d| d.select_dns(id))?
}

pub fn add_domain_rule(
    backend: &Backend,
    pattern: &str,
    action: ui::DomainAction,
) -> AppResult<()> {
    let pattern = DomainPattern::parse(pattern)?;
    backend
        .rules
        .update(|d| d.add_domain_rule(pattern, core_rule_action(action)))?
        .map(drop)
}

pub fn update_domain_rule(
    backend: &Backend,
    id: &str,
    pattern: &str,
    action: ui::DomainAction,
) -> AppResult<()> {
    let pattern = DomainPattern::parse(pattern)?;
    backend.rules.update(|d| {
        let uuid = find_rule(d, id).map(|r| r.id).ok_or_else(rule_gone)?;
        d.update_domain_rule(uuid, Some(pattern), Some(core_rule_action(action)))
    })?
}

/// Deleting a rule that is already gone is not an error.
pub fn delete_domain_rule(backend: &Backend, id: &str) -> AppResult<()> {
    backend.rules.update(|d| {
        if let Some(uuid) = find_rule(d, id).map(|r| r.id) {
            d.delete_domain_rule(uuid);
        }
    })
}

/// The full new order; unknown and repeated ids are ignored.
pub fn reorder_domain_rules(backend: &Backend, ids: &[String]) -> AppResult<()> {
    backend.rules.update(|d| {
        let order: Vec<_> = ids
            .iter()
            .filter_map(|id| find_rule(d, id).map(|r| r.id))
            .collect();
        d.reorder_domain_rules(&order);
    })
}

/// Open dialog + read + check a domain list against the current rules (nothing is written);
/// the pick replaces an earlier one. `None` = dismissed.
pub async fn pick_domain_list(shared: &Arc<Shared>) -> AppResult<Option<ui::DomainImportPreview>> {
    let opts = FileDialog::open(
        dialog::lang(&shared.backend),
        "app.settings.dialog.domainList",
        &[
            ("app.settings.dialog.textFiles", "*.txt;*.list;*.conf"),
            ("app.settings.dialog.allFiles", "*.*"),
        ],
    );
    let Some(path) = dialog::show(opts).await? else {
        return Ok(None);
    };
    let shared = shared.clone();
    detached(async move {
        let (picked, preview) = {
            let backend = shared.backend.clone();
            blocking(move || read_list(&backend, path)).await?
        };
        shared.touch(|l| l.domain_list = Some(picked));
        Ok(Some(preview))
    })
    .await
}

/// Reads the list and previews its import on a copy of the rules.
pub fn read_list(
    backend: &Backend,
    path: PathBuf,
) -> AppResult<(PickedList, ui::DomainImportPreview)> {
    let text = domain::read_list_file(&path)?;
    let list = domain::parse_list(&text);
    let mut copy = backend.rules.snapshot();
    let report = copy.import_domains(&list.patterns, domain::DomainAction::Vpn);
    let count = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let preview = ui::DomainImportPreview {
        file_name: file_name.clone(),
        new_rules: count(report.added),
        duplicates: count(list.duplicates + report.duplicates),
        invalid: count(list.invalid),
        over_limit: count(report.over_limit),
    };
    let picked = PickedList {
        file_name,
        patterns: list.patterns,
    };
    Ok((picked, preview))
}

/// Imports the picked list with one action for all of its domains; the pick is consumed.
pub fn import_domain_list(
    shared: &Shared,
    action: ui::DomainAction,
) -> AppResult<ui::DomainImportReport> {
    let picked = shared.local.lock().domain_list.take();
    shared.dirty.notify_one();
    let picked =
        picked.ok_or_else(|| AppError::conflict(Msg::new("app.settings.domains.noList")))?;
    let report = shared
        .backend
        .rules
        .update(|d| d.import_domains(&picked.patterns, core_rule_action(action)))?;
    tracing::info!(file = %picked.file_name, added = report.added, "domain list imported");
    Ok(ui::DomainImportReport {
        added: u32::try_from(report.added).unwrap_or(u32::MAX),
    })
}

/// The stored rule the page means (it only ever has the id's text form).
fn find_rule<'a>(doc: &'a RulesDoc, id: &str) -> Option<&'a DomainRule> {
    doc.domain_rules.iter().find(|r| r.id.to_string() == id)
}

fn rule_gone() -> AppError {
    AppError::conflict(Msg::new("app.settings.domains.ruleGone"))
}
