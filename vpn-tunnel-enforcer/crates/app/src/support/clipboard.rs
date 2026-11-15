//! Text from the clipboard for «add key from clipboard» (winnet's clipboard only copies). Read on
//! the user's click only: the app never watches the clipboard. The text may carry keys and
//! subscription links, so it is never logged.
use std::time::Duration;

use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use vpnte_profiles::model::TooLarge;
use vpnte_profiles::text::MAX_INPUT_BYTES;
use windows::Win32::Foundation::HGLOBAL;
use windows::Win32::System::DataExchange::{
    CloseClipboard, GetClipboardData, IsClipboardFormatAvailable, OpenClipboard,
};
use windows::Win32::System::Memory::{GlobalLock, GlobalSize, GlobalUnlock};
use windows::Win32::System::Ole::CF_UNICODETEXT;

/// Pause between attempts to open a clipboard another program holds (as winnet's copy).
const RETRY_PAUSE: Duration = Duration::from_millis(20);
/// Attempts to open the clipboard: about 0.2 s in all.
const ATTEMPTS: u32 = 10;

/// The clipboard's text, trimmed; `None` when it holds no text (an image, files, only spaces).
/// Over the paste limit (`vpnte_profiles::text::MAX_INPUT_BYTES`, 1 MiB) it is the paste field's
/// own `Validation` `servers.parse.tooLarge`; a clipboard another program keeps open is `Conflict`.
/// Blocks for up to ~0.2 s, and until a program that renders its text on request delivered it:
/// call it from a blocking thread.
pub fn read_text_blocking() -> AppResult<Option<String>> {
    let format = u32::from(CF_UNICODETEXT.0);
    // SAFETY: a plain query that needs no open clipboard. Windows also offers ANSI / OEM text as
    // Unicode text, so this one format covers every text on the clipboard.
    if unsafe { IsClipboardFormatAvailable(format) }.is_err() {
        return Ok(None);
    }
    let _open = Open::with_retries().map_err(|err| {
        AppError::msg(
            ErrorKind::Conflict,
            Msg::new("app.clickjack.clipboard.busy"),
        )
        .with_source(err)
    })?;
    // SAFETY: the clipboard is open (`_open`); the handle stays the clipboard's, never freed here.
    let data = HGLOBAL(unsafe { GetClipboardData(format) }.map_err(failed)?.0);
    // SAFETY: a global memory block owned by the clipboard, locked only while we copy out of it.
    let ptr = unsafe { GlobalLock(data) }.cast::<u16>();
    if ptr.is_null() {
        return Err(failed(windows::core::Error::from_thread()));
    }
    // SAFETY: `data` is locked; its size in bytes, rounded down to whole UTF-16 units.
    let capacity = unsafe { GlobalSize(data) } / 2;
    // SAFETY: `block_text` reads only indices below `capacity`, inside the locked block, which
    // Windows aligns for any unit type.
    let text = block_text(capacity, MAX_INPUT_BYTES, |i| unsafe { ptr.add(i).read() });
    // SAFETY: balances the lock above. It "fails" with NO_ERROR once unlocked: nothing to handle.
    let _ = unsafe { GlobalUnlock(data) };
    text.map_err(|TooLarge| vpnte_servers::parse::too_large(MAX_INPUT_BYTES))
}

/// [`read_text_blocking`] on tokio's blocking pool.
pub async fn read_text() -> AppResult<Option<String>> {
    super::blocking(read_text_blocking).await
}

/// `Validation` «В буфере обмена нет текста» for a caller that got `None` and must say so.
pub fn no_text() -> AppError {
    AppError::validation(Msg::new("app.clickjack.clipboard.noText"))
}

/// The text of a clipboard block of `capacity` UTF-16 units (`unit(i)` reads one): up to the
/// first NUL, trimmed as the paste field trims (whitespace, byte-order marks); `None` when nothing
/// is left. `TooLarge` when the trimmed text has more than `limit` UTF-8 bytes (the paste field's
/// rule) or the copied text more than `limit` units: that bound reads at most `limit + 1` units,
/// however large the block is.
pub(super) fn block_text(
    capacity: usize,
    limit: usize,
    unit: impl Fn(usize) -> u16,
) -> Result<Option<String>, TooLarge> {
    let max = capacity.min(limit.saturating_add(1));
    let len = match (0..max).find(|&i| unit(i) == 0) {
        Some(nul) => nul,
        // A block without a terminator is all text, as long as it can still fit.
        None if capacity <= limit => capacity,
        // Every UTF-16 unit takes at least one UTF-8 byte: more than `limit` units cannot fit.
        None => return Err(TooLarge),
    };
    let text: String = char::decode_utf16((0..len).map(unit))
        .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect();
    let text = text.trim_matches(|c: char| c.is_whitespace() || c == '\u{feff}');
    if text.len() > limit {
        return Err(TooLarge);
    }
    Ok((!text.is_empty()).then(|| text.to_owned()))
}

/// The open clipboard, closed on drop (on the thread that opened it).
struct Open;

impl Open {
    /// Another program may hold the clipboard for a moment: [`ATTEMPTS`] tries, [`RETRY_PAUSE`]
    /// apart.
    fn with_retries() -> windows::core::Result<Self> {
        let mut attempt = 1;
        loop {
            // SAFETY: no owner window (reading needs none); closed by `drop` on this thread.
            match unsafe { OpenClipboard(None) } {
                Ok(()) => return Ok(Open),
                Err(err) if attempt == ATTEMPTS => return Err(err),
                Err(_) => {
                    attempt += 1;
                    std::thread::sleep(RETRY_PAUSE);
                }
            }
        }
    }
}

impl Drop for Open {
    fn drop(&mut self) {
        // SAFETY: this thread opened the clipboard in `Open::with_retries`.
        let _ = unsafe { CloseClipboard() };
    }
}

fn failed(source: impl Into<anyhow::Error>) -> AppError {
    AppError::msg(
        ErrorKind::Internal,
        Msg::new("app.clickjack.clipboard.failed"),
    )
    .with_source(source)
}
