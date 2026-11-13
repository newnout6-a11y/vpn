//! Keys and subscriptions from phones and messengers (RU-2026 item 4): links Windows hands over
//! (`--open-link`), the add dialog's clipboard, key-file and QR sources, the QR export of a key,
//! and the link-scheme panel. Everything lands in the add dialog first: nothing is imported until
//! the user confirms there. Keys and links are never logged.
use std::path::Path;
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::{oneshot, watch};
use vpnte_base::i18n::Lang;
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use vpnte_profiles::text::{MAX_INPUT_BYTES, decode_body};
use vpnte_servers::model::ProfileId;
use vpnte_servers::parse::too_large;
use vpnte_ui::servers::{LinkScheme, LinkSchemes, QrCode, SchemeOwner};
use vpnte_winnet::url_scheme::{CLIENT_SCHEMES, Owner, Registrar};

use super::{Shared, export, qr};
use crate::support::files::{self, OpenFile};
use crate::support::{blocking, clipboard};

/// Links Windows handed to the app, kept until the Servers page takes one into its add dialog.
/// The root offers them (`--open-link` at start, later launches through the single-instance
/// pipe); the page reads them through `ServersApi::{link_arrivals, take_link}`.
#[derive(Clone, Default)]
pub struct LinkInbox(Arc<Inbox>);

#[derive(Default)]
struct Inbox {
    arrivals: watch::Sender<u64>,
    pending: Mutex<Option<String>>,
}

impl LinkInbox {
    /// A link to show in the add dialog; a newer one replaces one not yet taken.
    pub fn offer(&self, link: String) {
        *self.0.pending.lock() = Some(link);
        self.0.arrivals.send_modify(|n| *n += 1);
    }

    pub(super) fn arrivals(&self) -> watch::Receiver<u64> {
        self.0.arrivals.subscribe()
    }

    pub(super) fn take(&self) -> Option<String> {
        self.0.pending.lock().take()
    }
}

/// The clipboard's text (read on the user's click only).
pub(super) async fn read_clipboard() -> AppResult<String> {
    clipboard::read_text().await?.ok_or_else(clipboard::no_text)
}

/// Asks for a key file and answers its text (UTF-8 or UTF-16, at most the paste limit).
pub(super) async fn read_key_file(lang: Lang) -> AppResult<Option<String>> {
    let req = OpenFile::new(Msg::new("app.phones.dialog.openKeys"))
        .filter(
            Msg::new("app.phones.dialog.keyFiles"),
            "*.txt;*.conf;*.json;*.yaml;*.yml",
        )
        .filter(Msg::new("app.phones.dialog.allFiles"), "*.*");
    let Some(path) = files::open_file(req, lang).await? else {
        return Ok(None);
    };
    blocking(move || {
        let bytes = read_limited(&path, MAX_INPUT_BYTES as u64)?;
        let text = decode_body(&bytes, MAX_INPUT_BYTES).map_err(|_| too_large(MAX_INPUT_BYTES))?;
        let text = text.trim_matches(|c: char| c.is_whitespace() || c == '\u{feff}');
        if text.is_empty() {
            return Err(AppError::validation(Msg::new("app.phones.file.empty")));
        }
        Ok(Some(text.to_owned()))
    })
    .await
}

/// Asks for a picture and answers the keys and links of its QR codes, one per line.
pub(super) async fn scan_qr_file(lang: Lang) -> AppResult<Option<String>> {
    let req = OpenFile::new(Msg::new("app.phones.dialog.openQr"))
        .filter(
            Msg::new("app.phones.dialog.pictures"),
            "*.png;*.jpg;*.jpeg;*.gif;*.bmp;*.webp",
        )
        .filter(Msg::new("app.phones.dialog.allFiles"), "*.*");
    let Some(path) = files::open_file(req, lang).await? else {
        return Ok(None);
    };
    blocking(move || {
        let bytes = read_limited(&path, qr::MAX_FILE_BYTES)?;
        qr::importable(qr::decode_picture(&bytes)?).map(Some)
    })
    .await
}

/// Reads every screen now and answers the keys and links of the QR codes on it. `captured` fires
/// as soon as the screen is read (or could not be), before the decoding: the page shows its
/// window again right then.
pub(super) async fn scan_qr_screen(captured: oneshot::Sender<()>) -> AppResult<String> {
    blocking(move || {
        let shot = qr::screen::capture();
        let _ = captured.send(());
        qr::importable(qr::decode_gray(shot?)?)
    })
    .await
}

/// The share key of `id` as a QR code, through `shareable_profile`: a key its provider hides is
/// refused (`servers.hidden.refused`) like copy and save.
pub(super) async fn key_qr(shared: Arc<Shared>, id: ProfileId) -> AppResult<QrCode> {
    blocking(move || {
        let profile = shared.backend.servers.shareable_profile(&id)?;
        qr::encode(&export::share(&profile)?.text())
    })
    .await
}

/// A file's bytes, refused above `limit` before anything is read.
fn read_limited(path: &Path, limit: u64) -> AppResult<Vec<u8>> {
    let unreadable = |e: std::io::Error| {
        AppError::validation(Msg::new("app.phones.file.unreadable")).with_source(e)
    };
    let size = std::fs::metadata(path).map_err(unreadable)?.len();
    if size > limit {
        return Err(too_large(usize::try_from(limit).unwrap_or(usize::MAX)));
    }
    std::fs::read(path).map_err(unreadable)
}

/// Who answers each scheme, for this exe; a client that registered machine-wide since gets its
/// scheme back first (psmall-b6).
pub(super) async fn link_schemes(registrar: Registrar) -> AppResult<LinkSchemes> {
    blocking(move || {
        let exe = own_exe()?;
        give_back(&registrar, &exe);
        states(&registrar, &exe)
    })
    .await
}

/// A link of another client's scheme was taken into the add dialog: that client may have
/// registered since the app started, and its next link goes to it (psmall-b6). On a thread of
/// its own: registry reads, and the caller is the window's.
pub(super) fn after_client_link(registrar: &Registrar, link: &str) {
    let scheme = link.split_once(':').map(|(s, _)| s.to_ascii_lowercase());
    if !scheme.is_some_and(|s| CLIENT_SCHEMES.contains(&s.as_str())) {
        return;
    }
    let registrar = registrar.clone();
    std::thread::spawn(move || match own_exe() {
        Ok(exe) => give_back(&registrar, &exe),
        Err(err) => tracing::warn!(%err, "link schemes not checked: own path unknown"),
    });
}

/// Client schemes go back to clients installed meanwhile; a failure changes nothing.
fn give_back(registrar: &Registrar, exe: &Path) {
    match registrar.give_back(exe) {
        Ok(released) if !released.is_empty() => {
            registrar.notify_shell();
            tracing::info!(?released, "link schemes given back to their clients");
        }
        Ok(_) => {}
        Err(err) => tracing::warn!(%err, "link schemes not checked"),
    }
}

/// A portable copy's «open links here»: the free schemes and ours open this exe from now on.
pub(super) async fn adopt_link_schemes(registrar: Registrar) -> AppResult<LinkSchemes> {
    blocking(move || {
        let exe = own_exe()?;
        let done = registrar.adopt(&exe).map_err(scheme_failed)?;
        registrar.notify_shell();
        tracing::info!(
            registered = ?done.registered,
            repointed = done.repointed,
            "link schemes adopted by the user"
        );
        states(&registrar, &exe)
    })
    .await
}

/// Takes `scheme` for this exe (also from another program, whose key is kept aside) or gives it
/// back; answers the list after the change. A scheme the user gave another program in Windows'
/// own settings stays there (the list then still says so; nothing was written).
pub(super) async fn set_link_scheme(
    registrar: Registrar,
    scheme: String,
    on: bool,
) -> AppResult<LinkSchemes> {
    blocking(move || {
        let exe = own_exe()?;
        let changed = if on {
            registrar.take(&scheme, &exe).map(drop)
        } else {
            registrar.unregister(&scheme, &exe).map(drop)
        };
        changed.map_err(scheme_failed)?;
        registrar.notify_shell();
        tracing::info!(scheme, on, "link scheme changed by the user");
        states(&registrar, &exe)
    })
    .await
}

fn states(registrar: &Registrar, exe: &Path) -> AppResult<LinkSchemes> {
    let states = registrar.states(exe).map_err(scheme_failed)?;
    let list = states
        .into_iter()
        .map(|state| LinkScheme {
            scheme: state.scheme.to_owned(),
            owner: match state.owner {
                Owner::Free => SchemeOwner::Free,
                Owner::Ours => SchemeOwner::Ours,
                Owner::Other(name) => SchemeOwner::Other(name),
                Owner::Chosen(prog_id) => SchemeOwner::Chosen(prog_id),
            },
        })
        .collect();
    Ok(LinkSchemes {
        list,
        portable: crate::setup::links::is_portable(exe),
    })
}

fn own_exe() -> AppResult<std::path::PathBuf> {
    std::env::current_exe().map_err(AppError::internal)
}

fn scheme_failed(err: windows::core::Error) -> AppError {
    let kind = if err.code() == windows::Win32::Foundation::E_ACCESSDENIED {
        ErrorKind::Permission
    } else {
        ErrorKind::Internal
    };
    AppError::msg(kind, Msg::new("app.phones.schemes.failed")).with_source(err)
}
