//! Key copy and exports. Exports are not redacted (that is their point): the page shows the
//! secret-export warning, keys go to the self-clearing secret clipboard or to a file the user
//! picked in the Save dialog (written atomically). File exports run as `Export` operations whose
//! budget pauses while the dialog is open.
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use vpnte_base::types::{UnixMs, now_ms};
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use vpnte_core::ops::{FeatureKind, RunOpts, Source};
use vpnte_profiles::export::{Shared as SharedKey, export_proxy_line, export_share};
use vpnte_servers::model::{ProfileId, ServerRow};
use vpnte_ui::servers::ExportReport;

use super::import::count;
use super::{Shared, server_not_found};
use crate::support::blocking;
use crate::support::files::{self, SaveFile, StartFolder};

/// Copies the share key of `id` to the secret clipboard; answers when it clears itself.
pub(super) async fn copy_key(shared: Arc<Shared>, id: ProfileId) -> AppResult<Duration> {
    let row = shared
        .backend
        .servers
        .get(&id)
        .ok_or_else(server_not_found)?;
    let text = share(&row)?.text();
    let backend = shared.backend.clone();
    blocking(move || backend.clipboard().copy(&text)).await
}

/// Saves the share key of `id` to a file; `None` when the dialog was dismissed.
pub(super) async fn save_key(
    shared: Arc<Shared>,
    id: ProfileId,
    cancel: CancellationToken,
) -> AppResult<Option<String>> {
    let row = shared
        .backend
        .servers
        .get(&id)
        .ok_or_else(server_not_found)?;
    let key = share(&row)?;
    let json = matches!(key, SharedKey::Json(_));
    let ext = if json { "json" } else { "txt" };
    let req = save_dialog(
        "app.servers.dialog.saveKey",
        format!(
            "{}-{}.{ext}",
            row.protocol,
            safe_name(&row.name, &row.protocol)
        ),
        json,
    );
    let body = format!("{}\n", key.text());
    let path = save_file(&shared, "export:key", req, body, cancel).await?;
    Ok(path.map(|p| p.display().to_string()))
}

/// Saves every key of the list that is not archived (servers §3.13, S-32).
pub(super) async fn all_keys(
    shared: Arc<Shared>,
    cancel: CancellationToken,
) -> AppResult<Option<ExportReport>> {
    let shares: Vec<Option<SharedKey>> = current_rows(&shared)
        .iter()
        .map(|row| row.profile().ok().and_then(|p| export_share(&p)))
        .collect();
    let now = now_ms();
    let file = keys_file(&shares, now)
        .ok_or_else(|| AppError::validation(Msg::new("app.servers.export.nothing")))?;
    let ext = if file.json { "json" } else { "txt" };
    let req = save_dialog(
        "app.servers.dialog.saveAllKeys",
        format!("vpn-keys-{}.{ext}", stamp(now)),
        file.json,
    );
    let path = save_file(&shared, "export:keys", req, file.body, cancel).await?;
    Ok(path.map(|p| report(&p, file.exported, file.skipped)))
}

/// Saves a proxy list (one `socks5://` / `http://` / `https://` proxy per line, no header).
pub(super) async fn proxy_list(
    shared: Arc<Shared>,
    cancel: CancellationToken,
) -> AppResult<Option<ExportReport>> {
    let rows = current_rows(&shared);
    let lines: Vec<String> = rows
        .iter()
        .filter_map(|row| row.profile().ok().and_then(|p| export_proxy_line(&p)))
        .collect();
    if lines.is_empty() {
        return Err(AppError::validation(Msg::new(
            "app.servers.export.noProxies",
        )));
    }
    let now = now_ms();
    let req = save_dialog(
        "app.servers.dialog.saveProxyList",
        format!("proxy-list-{}.txt", stamp(now)),
        false,
    );
    let body = format!("{}\n", lines.join("\n"));
    let path = save_file(&shared, "export:proxies", req, body, cancel).await?;
    Ok(path.map(|p| report(&p, lines.len(), rows.len() - lines.len())))
}

/// The share form of a row: a lossless link, else a JSON document.
fn share(row: &ServerRow) -> AppResult<SharedKey> {
    let profile = row.profile()?;
    export_share(&profile)
        .ok_or_else(|| AppError::validation(Msg::new("app.servers.export.unsupported")))
}

fn current_rows(shared: &Shared) -> Vec<ServerRow> {
    shared.backend.servers.read(|doc| {
        doc.profiles
            .iter()
            .filter(|row| row.archived.is_none())
            .cloned()
            .collect()
    })
}

fn report(path: &std::path::Path, exported: usize, skipped: usize) -> ExportReport {
    ExportReport {
        path: path.display().to_string(),
        exported: count(exported),
        skipped: count(skipped),
    }
}

/// Asks for a file and writes `body` there as one `Export` operation; `None` = dismissed.
async fn save_file(
    shared: &Shared,
    resource: &'static str,
    req: SaveFile,
    body: String,
    cancel: CancellationToken,
) -> AppResult<Option<PathBuf>> {
    let run = RunOpts {
        source: Source::Ui,
        resource: Some(resource.into()),
        cancel: Some(cancel),
        ..RunOpts::default()
    };
    let lang = shared.backend.lang();
    let ops = &shared.backend.ops;
    ops.run(FeatureKind::Export, run, move |lease| async move {
        let Some(path) = lease.wait_for_user(files::save_file(req, lang)).await?? else {
            return Ok(None);
        };
        lease.commit(|| {
            vpnte_core::store::write_atomic(&path, body.as_bytes()).map_err(|err| {
                AppError::msg(
                    ErrorKind::Internal,
                    Msg::new("app.servers.export.writeFailed"),
                )
                .with_source(err)
            })?;
            Ok(Some(path))
        })
    })
    .await
}

/// A bulk key file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct KeysFile {
    pub body: String,
    /// A JSON array (some key had no lossless link) instead of a text list.
    pub json: bool,
    pub exported: usize,
    pub skipped: usize,
}

/// The old app's bulk format (servers §2.12): a text list with a header, or, as soon as one key
/// is a JSON document, one compact JSON array of links and documents. `None`: nothing exportable.
pub(super) fn keys_file(shares: &[Option<SharedKey>], now: UnixMs) -> Option<KeysFile> {
    let found: Vec<&SharedKey> = shares.iter().flatten().collect();
    if found.is_empty() {
        return None;
    }
    let (exported, skipped) = (found.len(), shares.len() - found.len());
    let json = found.iter().any(|s| matches!(s, SharedKey::Json(_)));
    let body = if json {
        let items: Vec<serde_json::Value> = found
            .iter()
            .map(|s| match s {
                SharedKey::Uri(uri) => serde_json::Value::String(uri.clone()),
                SharedKey::Json(doc) => doc.clone(),
            })
            .collect();
        format!("{}\n", serde_json::Value::Array(items))
    } else {
        let mut text = format!(
            "# VPN keys exported by VPN Tunnel Enforcer\n# Profiles: {exported} exported, {skipped} skipped\n# Generated: {}\n\n",
            iso(now)
        );
        for key in &found {
            text.push_str(&key.text());
            text.push('\n');
        }
        text
    };
    Some(KeysFile {
        body,
        json,
        exported,
        skipped,
    })
}

/// File-name stamp of the old app: the UTC ISO time with `:` and `.` as `-`, to the second.
pub(super) fn stamp(now: UnixMs) -> String {
    iso(now).replace([':', '.'], "-").chars().take(19).collect()
}

fn iso(now: UnixMs) -> String {
    jiff::Timestamp::from_millisecond(now).map_or_else(|_| now.to_string(), |t| t.to_string())
}

/// The old app's file-name rule: Windows-reserved and control characters dropped, whitespace
/// runs as `-`, at most 60 characters; empty -> the protocol.
pub(super) fn safe_name(name: &str, protocol: &str) -> String {
    let kept: String = name
        .chars()
        .filter(|c| {
            !c.is_control() && !matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*')
        })
        .collect();
    let name: String = kept
        .split_whitespace()
        .collect::<Vec<_>>()
        .join("-")
        .chars()
        .take(60)
        .collect();
    if name.is_empty() {
        protocol.to_owned()
    } else {
        name
    }
}

/// The Save dialog of an export (on the Desktop): JSON first for a JSON export, then text, then
/// everything.
fn save_dialog(title: &'static str, file_name: String, json: bool) -> SaveFile {
    let ext = if json { "json" } else { "txt" };
    let mut req = SaveFile::new(Msg::new(title), file_name, ext).in_folder(StartFolder::Desktop);
    if json {
        req = req.filter(Msg::new("app.servers.dialog.jsonFile"), "*.json");
    }
    req.filter(Msg::new("app.servers.dialog.textFile"), "*.txt")
        .filter(Msg::new("app.servers.dialog.allFiles"), "*.*")
}
