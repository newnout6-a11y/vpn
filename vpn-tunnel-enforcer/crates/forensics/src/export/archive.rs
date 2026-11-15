//! The streamed ZIP: a partial file in the destination directory, every entry redacted as it is
//! written, renamed over the destination only when complete (no staging directory, B-16). Any
//! error, cancellation or drop removes the partial file; the previous destination stays.
use std::fs::{File, OpenOptions};
use std::hash::{BuildHasher, Hasher};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use vpnte_base::{AppError, AppResult};
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

use super::redaction::{Policy, Redactor};
use super::{ExportProgress, ExportStage, NoticeSink, cleanup_notice};

/// JSON files larger than this are redacted line by line as text instead of parsed.
const JSON_PARSE_MAX: u64 = 16 * 1024 * 1024;
/// Lines between cancellation checks while streaming a file.
const CHECK_EVERY: u64 = 4096;
/// Rename attempts when a scanner briefly holds the new file (sharing violation / access denied).
const RENAME_ATTEMPTS: u32 = 10;

/// A file left out of the archive, with a machine-readable reason.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(super) struct Excluded {
    pub name: String,
    pub reason: &'static str,
}

/// The archive file while it is written; removed on drop unless committed.
pub(super) struct Partial {
    path: PathBuf,
    committed: bool,
    notices: Option<NoticeSink>,
}

impl Partial {
    /// Creates `.<dest name>.<random>.partial` next to `dest` (same volume, so the commit is a
    /// rename).
    pub(super) fn create(dest: &Path, notices: Option<NoticeSink>) -> AppResult<(Self, File)> {
        let dir = dest
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let name = dest
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "diagnostics.zip".into());
        let mut hasher = std::hash::RandomState::new().build_hasher();
        hasher.write_u128(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos()),
        );
        let path = dir.join(format!(".{name}.{:016x}.partial", hasher.finish()));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        let partial = Self {
            path,
            committed: false,
            notices,
        };
        Ok((partial, file))
    }

    /// Replaces `dest` with the finished archive.
    pub(super) fn commit(mut self, dest: &Path) -> AppResult<()> {
        let mut attempt = 0;
        loop {
            match std::fs::rename(&self.path, dest) {
                Ok(()) => {
                    self.committed = true;
                    return Ok(());
                }
                Err(e)
                    if attempt + 1 < RENAME_ATTEMPTS
                        && matches!(e.raw_os_error(), Some(5 | 32)) =>
                {
                    attempt += 1;
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(e) => return Err(e.into()),
            }
        }
    }
}

impl Drop for Partial {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        match std::fs::remove_file(&self.path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => {
                // F-178 / owner §10.6 «A»: never silent. No result reaches the UI on this path,
                // so the user gets one notification.
                tracing::warn!("diagnostics export: partial archive not removed: {e}");
                if let Some(sink) = &self.notices {
                    sink(cleanup_notice());
                }
            }
        }
    }
}

/// The ZIP being written: entries, exclusions, progress and the archive's redactor.
pub(super) struct Archive {
    zip: ZipWriter<BufWriter<File>>,
    options: SimpleFileOptions,
    cancel: CancellationToken,
    progress: watch::Sender<ExportProgress>,
    pub(super) redactor: Redactor,
    pub(super) entries: Vec<String>,
    pub(super) excluded: Vec<Excluded>,
}

impl Archive {
    pub(super) fn new(
        file: File,
        redactor: Redactor,
        cancel: CancellationToken,
        progress: watch::Sender<ExportProgress>,
        modified: zip::DateTime,
    ) -> Self {
        let options = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .last_modified_time(modified);
        Self {
            zip: ZipWriter::new(BufWriter::new(file)),
            options,
            cancel,
            progress,
            redactor,
            entries: Vec::new(),
            excluded: Vec::new(),
        }
    }

    /// `Err(cancelled)` once the operation was cancelled (checked before every entry and every
    /// few thousand lines).
    pub(super) fn check(&self) -> AppResult<()> {
        if self.cancel.is_cancelled() {
            Err(AppError::cancelled())
        } else {
            Ok(())
        }
    }

    /// Announces the next section.
    pub(super) fn stage(&self, stage: ExportStage) -> AppResult<()> {
        self.check()?;
        self.progress.send_modify(|p| p.stage = stage);
        Ok(())
    }

    fn start(&mut self, name: &str) -> AppResult<()> {
        self.check()?;
        self.zip.start_file(name, self.options).map_err(zip_err)?;
        self.entries.push(name.to_string());
        self.progress.send_modify(|p| p.entries += 1);
        Ok(())
    }

    fn write(&mut self, data: &[u8]) -> AppResult<()> {
        self.zip.write_all(data)?;
        self.progress.send_modify(|p| p.bytes += data.len() as u64);
        Ok(())
    }

    /// An entry from memory, written as is (our own documents).
    pub(super) fn bytes(&mut self, name: &str, data: &[u8]) -> AppResult<()> {
        self.start(name)?;
        self.write(data)
    }

    /// A JSON document, redacted with `policy`, pretty-printed.
    pub(super) fn json(&mut self, name: &str, mut v: Value, policy: Policy) -> AppResult<()> {
        self.redactor.json(&mut v, policy);
        let data = crate::pretty_json(&v).map_err(AppError::internal)?;
        self.bytes(name, &data)
    }

    /// Leaves `name` out and says so in a `<name>.excluded.txt` entry (fail closed, AT-08-010).
    pub(super) fn exclude(&mut self, name: &str, reason: &'static str) -> AppResult<()> {
        self.excluded.push(Excluded {
            name: name.to_string(),
            reason,
        });
        let note = format!(
            "Артефакт {name} не включён в архив: не удалось прочитать и отредактировать как текст.\nПричина: {reason}\n"
        );
        self.bytes(&format!("{name}.excluded.txt"), note.as_bytes())
    }

    /// Lists a raw capture as excluded (no note: it is never exported, by policy).
    pub(super) fn skip(&mut self, name: &str, reason: &'static str) {
        self.excluded.push(Excluded {
            name: name.to_string(),
            reason,
        });
    }

    /// A file from disk: `.json` parsed and walked, `.ndjson` / `.jsonl` line by line as JSON,
    /// anything else line by line as text. A file that is not UTF-8 is excluded whole; nothing
    /// of it enters the archive. Returns whether it was included.
    pub(super) fn file(&mut self, name: &str, path: &Path, policy: Policy) -> AppResult<bool> {
        self.check()?;
        match is_text(path, &self.cancel) {
            Ok(true) => {}
            Ok(false) => {
                self.exclude(name, "not-utf8")?;
                return Ok(false);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => return Err(AppError::cancelled()),
            Err(_) => {
                self.exclude(name, "unreadable")?;
                return Ok(false);
            }
        }
        let lower = name.to_ascii_lowercase();
        if lower.ends_with(".json")
            && std::fs::metadata(path).is_ok_and(|m| m.len() <= JSON_PARSE_MAX)
        {
            let mut bytes = Vec::new();
            File::open(path)?.read_to_end(&mut bytes)?;
            let body = crate::strip_bom(&bytes);
            if let Ok(v) = serde_json::from_slice::<Value>(body) {
                self.json(name, v, policy)?;
                return Ok(true);
            }
        }
        let json_lines = lower.ends_with(".ndjson") || lower.ends_with(".jsonl");
        self.lines(name, path, json_lines, policy)?;
        Ok(true)
    }

    /// Streams a file line by line (`\r\n` becomes `\n`, blank lines are kept).
    fn lines(
        &mut self,
        name: &str,
        path: &Path,
        json_lines: bool,
        policy: Policy,
    ) -> AppResult<()> {
        let mut reader = BufReader::new(File::open(path)?);
        self.start(name)?;
        let mut buf = Vec::new();
        let mut n = 0u64;
        loop {
            buf.clear();
            if reader.read_until(b'\n', &mut buf)? == 0 {
                break;
            }
            n += 1;
            if n.is_multiple_of(CHECK_EVERY) {
                self.check()?;
            }
            let mut line = buf.as_slice();
            if n == 1 {
                line = crate::strip_bom(line);
            }
            let line = line.strip_suffix(b"\n").unwrap_or(line);
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            // Validated above; a writer still appending may leave a torn last character.
            let text = String::from_utf8_lossy(line);
            let mut out = if text.trim().is_empty() {
                String::new()
            } else if json_lines {
                self.redactor.ndjson_line(&text, policy)
            } else {
                self.redactor.text(&text, policy)
            };
            out.push('\n');
            self.write(out.as_bytes())?;
        }
        Ok(())
    }

    /// Finishes the ZIP and flushes it to disk; the file is closed before the commit rename.
    pub(super) fn finish(self) -> AppResult<()> {
        let mut writer = self.zip.finish().map_err(zip_err)?;
        writer.flush()?;
        let file = writer
            .into_inner()
            .map_err(|e| AppError::from(e.into_error()))?;
        file.sync_all()?;
        Ok(())
    }
}

/// Whether a file is UTF-8 text. A torn multi-byte character at the very end of a file that is
/// still being written does not count against it. `Interrupted` = cancelled.
fn is_text(path: &Path, cancel: &CancellationToken) -> io::Result<bool> {
    let mut reader = BufReader::new(File::open(path)?);
    let mut buf = Vec::new();
    let mut n = 0u64;
    loop {
        buf.clear();
        if reader.read_until(b'\n', &mut buf)? == 0 {
            return Ok(true);
        }
        n += 1;
        if n.is_multiple_of(CHECK_EVERY) && cancel.is_cancelled() {
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        match std::str::from_utf8(&buf) {
            Ok(_) => {}
            Err(e) if e.error_len().is_none() && !buf.ends_with(b"\n") => {}
            Err(_) => return Ok(false),
        }
    }
}

fn zip_err(e: zip::result::ZipError) -> AppError {
    match e {
        zip::result::ZipError::Io(io) => io.into(),
        other => AppError::internal(other),
    }
}
