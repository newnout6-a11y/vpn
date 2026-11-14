//! Key copy and exports. Exports are not redacted (that is their point): the page notes that the
//! files hold access keys, keys go to the self-clearing secret clipboard or to a file the user
//! picked in the Save dialog (written atomically). File exports run as `Export` operations whose
//! budget pauses while the dialog is open. Servers whose provider sent `hide-settings` are never
//! exported: a single key is refused (`servers.hidden.refused`), a bulk export leaves them out.
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use vpnte_base::types::{UnixMs, now_ms};
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use vpnte_core::ops::{FeatureKind, RunOpts, Source};
use vpnte_profiles::export::{Shared as SharedKey, export_mihomo, export_proxy_line, export_share};
use vpnte_profiles::model::Profile;
use vpnte_servers::model::{ProfileId, ServerRow};
use vpnte_servers::store::hidden_refused;
use vpnte_ui::servers::ExportReport;

use super::import::count;
use super::{Shared, server_not_found};
use crate::support::blocking;
use crate::support::files::{self, SaveFile, StartFolder};

/// Copies the share key of `id` to the secret clipboard; answers when it clears itself.
pub(super) async fn copy_key(shared: Arc<Shared>, id: ProfileId) -> AppResult<Duration> {
    let profile = shared.backend.servers.shareable_profile(&id)?;
    let text = share(&profile)?.text();
    let backend = shared.backend.clone();
    blocking(move || backend.clipboard().copy(&text)).await
}

/// Saves the share key of `id` to a file; `None` when the dialog was dismissed. An AmneziaWG
/// server goes out as its `.conf`, or as a mihomo proxy entry when the user picks that file type.
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
    let profile = shared.backend.servers.shareable_profile(&id)?;
    let key = share(&profile)?;
    let kind = match key {
        SharedKey::Uri(_) => FileKind::Text,
        SharedKey::Json(_) => FileKind::Json,
        SharedKey::Conf(_) => FileKind::Conf {
            mihomo: export_mihomo(&profile),
        },
    };
    let name = format!(
        "{}-{}.{}",
        row.protocol,
        safe_name(&row.name, &row.protocol),
        kind.extension()
    );
    let req = save_dialog("app.servers.dialog.saveKey", name, &kind);
    let text = format!("{}\n", key.text());
    let body = move |path: &Path| match kind {
        FileKind::Conf { mihomo: Some(yaml) } if is_yaml(path) => yaml,
        _ => text,
    };
    let path = save_file(&shared, "export:key", req, body, cancel).await?;
    Ok(path.map(|p| p.display().to_string()))
}

/// Saves every key of the list that is not archived (servers §3.13, S-32).
pub(super) async fn all_keys(
    shared: Arc<Shared>,
    cancel: CancellationToken,
) -> AppResult<Option<ExportReport>> {
    let (rows, hidden) = current_rows(&shared);
    let keys: Vec<Option<BulkKey>> = rows
        .iter()
        .map(|row| row.profile().ok().and_then(|p| BulkKey::of(&p)))
        .collect();
    let now = now_ms();
    let file = keys_file(&keys, now)
        .ok_or_else(|| nothing_to_export(hidden, "app.servers.export.nothing"))?;
    let kind = if file.json {
        FileKind::Json
    } else {
        FileKind::Text
    };
    let req = save_dialog(
        "app.servers.dialog.saveAllKeys",
        format!("vpn-keys-{}.{}", stamp(now), kind.extension()),
        &kind,
    );
    let body = file.body;
    let path = save_file(&shared, "export:keys", req, move |_| body, cancel).await?;
    Ok(path.map(|p| report(&p, file.exported, file.skipped, hidden)))
}

/// Saves a proxy list (one `socks5://` / `http://` / `https://` proxy per line, no header).
pub(super) async fn proxy_list(
    shared: Arc<Shared>,
    cancel: CancellationToken,
) -> AppResult<Option<ExportReport>> {
    let (rows, hidden) = current_rows(&shared);
    let lines: Vec<String> = rows
        .iter()
        .filter_map(|row| row.profile().ok().and_then(|p| export_proxy_line(&p)))
        .collect();
    if lines.is_empty() {
        return Err(nothing_to_export(hidden, "app.servers.export.noProxies"));
    }
    let now = now_ms();
    let req = save_dialog(
        "app.servers.dialog.saveProxyList",
        format!("proxy-list-{}.txt", stamp(now)),
        &FileKind::Text,
    );
    let body = format!("{}\n", lines.join("\n"));
    let path = save_file(&shared, "export:proxies", req, move |_| body, cancel).await?;
    let skipped = rows.len() - lines.len();
    Ok(path.map(|p| report(&p, lines.len(), skipped, hidden)))
}

/// The share form of a profile: a lossless link, else a JSON document.
pub(super) fn share(profile: &Profile) -> AppResult<SharedKey> {
    export_share(profile)
        .ok_or_else(|| AppError::validation(Msg::new("app.servers.export.unsupported")))
}

/// Rows a bulk export may write (not archived, not hidden by their provider) and how many rows
/// were left out because their provider hides the configs.
fn current_rows(shared: &Shared) -> (Vec<ServerRow>, usize) {
    shared.backend.servers.read(|doc| {
        let current = doc.profiles.iter().filter(|row| row.archived.is_none());
        let (shown, held): (Vec<&ServerRow>, Vec<&ServerRow>) =
            current.partition(|row| !doc.hides(row));
        (shown.into_iter().cloned().collect(), held.len())
    })
}

/// Nothing to write: when only provider-hidden servers could have been written, say that.
fn nothing_to_export(hidden: usize, key: &'static str) -> AppError {
    if hidden > 0 {
        return hidden_refused();
    }
    AppError::validation(Msg::new(key))
}

fn report(path: &std::path::Path, exported: usize, skipped: usize, hidden: usize) -> ExportReport {
    ExportReport {
        path: path.display().to_string(),
        exported: count(exported),
        skipped: count(skipped),
        hidden: count(hidden),
    }
}

/// Asks for a file and writes `body(path)` there as one `Export` operation (the file type the
/// user picked may choose the format); `None` = dismissed.
async fn save_file(
    shared: &Shared,
    resource: &'static str,
    req: SaveFile,
    body: impl FnOnce(&Path) -> String + Send + 'static,
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
        let body = body(&path);
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

/// One server of a bulk export: its share form and, for an AmneziaWG `.conf`, its mihomo entry.
/// No `Debug`: both are the credentials.
#[derive(Clone, PartialEq)]
pub(super) struct BulkKey {
    pub share: SharedKey,
    pub mihomo: Option<String>,
}

impl BulkKey {
    /// `None` when `p` has no share form.
    pub(super) fn of(p: &Profile) -> Option<Self> {
        let share = export_share(p)?;
        let conf = matches!(share, SharedKey::Conf(_));
        let mihomo = conf.then(|| export_mihomo(p)).flatten();
        Some(Self { share, mihomo })
    }
}

/// The old app's bulk format (servers §2.12): a text list with a header, or, as soon as one key
/// is a JSON document, one compact JSON array of links and documents. `None`: nothing exportable.
///
/// AmneziaWG servers have no link form and are written so that the import reads them back
/// (PR review 4547397546): it takes one `.conf` next to links, or one mihomo `proxies:`
/// document next to links and inside a JSON string, but never two `.conf` files in one text.
/// So a text file carries a single AmneziaWG server as its `.conf`, several as one `proxies:`
/// document (one without a mihomo form is left out and counted as skipped); a JSON file carries
/// each as its mihomo document, else its `.conf`.
pub(super) fn keys_file(keys: &[Option<BulkKey>], now: UnixMs) -> Option<KeysFile> {
    let found: Vec<&BulkKey> = keys.iter().flatten().collect();
    let json = found.iter().any(|k| matches!(k.share, SharedKey::Json(_)));
    let (body, exported) = if json {
        let items: Vec<serde_json::Value> = found.iter().map(|k| json_item(k)).collect();
        let exported = items.len();
        (format!("{}\n", serde_json::Value::Array(items)), exported)
    } else {
        let (lines, exported) = text_lines(&found);
        let skipped = keys.len() - exported;
        let mut text = format!(
            "# VPN keys exported by VPN Tunnel Enforcer\n# Profiles: {exported} exported, {skipped} skipped\n# Generated: {}\n\n",
            iso(now)
        );
        for line in &lines {
            text.push_str(line);
            text.push('\n');
        }
        (text, exported)
    };
    (exported > 0).then(|| KeysFile {
        body,
        json,
        exported,
        skipped: keys.len() - exported,
    })
}

/// The lines of a text file and how many servers they carry.
fn text_lines(found: &[&BulkKey]) -> (Vec<String>, usize) {
    let confs = found
        .iter()
        .filter(|k| matches!(k.share, SharedKey::Conf(_)))
        .count();
    let (mut lines, mut proxies, mut carried) = (Vec::new(), String::new(), 0);
    for key in found {
        match (&key.share, &key.mihomo) {
            (SharedKey::Conf(conf), _) if confs == 1 => lines.push(conf.trim_end().to_owned()),
            (SharedKey::Conf(_), Some(doc)) => {
                proxies.push_str(doc.strip_prefix("proxies:\n").unwrap_or(doc));
            }
            (SharedKey::Conf(_), None) => continue,
            (share, _) => lines.push(share.text()),
        }
        carried += 1;
    }
    if !proxies.is_empty() {
        lines.push(format!("proxies:\n{}", proxies.trim_end()));
    }
    (lines, carried)
}

/// One item of a JSON file; an AmneziaWG server as its mihomo document (the import reads YAML
/// inside a string, not a `.conf`), else as its `.conf`.
fn json_item(key: &BulkKey) -> serde_json::Value {
    match &key.share {
        SharedKey::Uri(uri) => serde_json::Value::String(uri.clone()),
        SharedKey::Json(doc) => doc.clone(),
        SharedKey::Conf(conf) => {
            serde_json::Value::String(key.mihomo.clone().unwrap_or_else(|| conf.clone()))
        }
    }
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

/// What an export file holds, for its Save dialog.
enum FileKind {
    Text,
    Json,
    /// An AmneziaWG `.conf`, with the server's mihomo document when mihomo can carry it.
    Conf {
        mihomo: Option<String>,
    },
}

impl FileKind {
    fn extension(&self) -> &'static str {
        match self {
            FileKind::Text => "txt",
            FileKind::Json => "json",
            FileKind::Conf { .. } => "conf",
        }
    }
}

/// The Save dialog of an export (on the Desktop): the file's own type first (`.conf` and the
/// mihomo YAML for AmneziaWG: the dialog switches the extension with the type, and the chosen
/// extension picks the format), then text for JSON, then everything.
fn save_dialog(title: &'static str, file_name: String, kind: &FileKind) -> SaveFile {
    let mut req =
        SaveFile::new(Msg::new(title), file_name, kind.extension()).in_folder(StartFolder::Desktop);
    req = match kind {
        FileKind::Text => req.filter(Msg::new("app.servers.dialog.textFile"), "*.txt"),
        FileKind::Json => req
            .filter(Msg::new("app.servers.dialog.jsonFile"), "*.json")
            .filter(Msg::new("app.servers.dialog.textFile"), "*.txt"),
        FileKind::Conf { mihomo } => {
            req = req.filter(Msg::new("app.servers.dialog.confFile"), "*.conf");
            match mihomo {
                Some(_) => req.filter(Msg::new("app.servers.dialog.mihomoFile"), "*.yaml;*.yml"),
                None => req,
            }
        }
    };
    req.filter(Msg::new("app.servers.dialog.allFiles"), "*.*")
}

/// A `.yaml` / `.yml` path: the mihomo file type.
pub(super) fn is_yaml(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("yaml") || e.eq_ignore_ascii_case("yml"))
}
