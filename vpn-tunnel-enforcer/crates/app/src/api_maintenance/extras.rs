//! What «Сохранить для поддержки» adds to the forensics pack (p-noadmin-ui): the event journal
//! (`events.jsonl` and its previous file, as the journal wrote them) and this user's helper
//! service lines while the service is installed. The forensics crate packs everything else;
//! these entries are appended to its finished archive before it takes its place, scrubbed like
//! the archive's logs: secrets and public addresses masked (`redact::for_log`), secret-named
//! fields `<redacted>`, the Windows user name `<user>`.
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

use regex::Regex;
use serde_json::Value;
use vpnte_core::redact;
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

use crate::api_logs::ServiceAnswer;
use crate::svc_journal;

/// The entry of the service's lines.
pub(crate) const SERVICE_LOG: &str = "service-log.txt";
/// The first line of [`SERVICE_LOG`] when the service left older lines out.
const TRUNCATED: &str = "[older lines not included]";

/// One entry to add.
#[derive(Debug)]
pub(crate) struct Extra {
    pub name: &'static str,
    pub body: String,
}

/// The entries for the data folder `root` and the service's answer (`None`: not asked).
/// `user` is the Windows user name to mask (`None` = `%USERNAME%`).
pub(crate) fn gather(
    root: &Path,
    service: Option<ServiceAnswer>,
    user: Option<&str>,
) -> Vec<Extra> {
    let scrub = Scrub::new(
        user.map(str::to_owned)
            .or_else(|| std::env::var("USERNAME").ok()),
    );
    let mut out = Vec::new();
    // Older first, as a reader goes through them.
    for name in [svc_journal::PREVIOUS, svc_journal::FILE] {
        match std::fs::read_to_string(root.join(name)) {
            Ok(text) => out.push(Extra {
                name,
                body: scrub.json_lines(&text),
            }),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => {
                tracing::warn!(file = name, error = %e, "support archive: journal unreadable")
            }
        }
    }
    if let Some(ServiceAnswer::Lines(log)) = service {
        let mut body = String::new();
        if log.truncated {
            body.push_str(TRUNCATED);
            body.push('\n');
        }
        for line in &log.lines {
            body.push_str(&scrub.text(&line.text));
            body.push('\n');
        }
        out.push(Extra {
            name: SERVICE_LOG,
            body,
        });
    }
    out
}

/// Appends `extras` to the finished archive `zip` (Deflate, stamped `modified`).
pub(crate) fn append(zip: &Path, extras: &[Extra], modified: zip::DateTime) -> io::Result<()> {
    let file = File::options().read(true).write(true).open(zip)?;
    let mut writer = ZipWriter::new_append(file).map_err(io::Error::other)?;
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .last_modified_time(modified);
    for extra in extras {
        writer
            .start_file(extra.name, options)
            .map_err(io::Error::other)?;
        writer.write_all(extra.body.as_bytes())?;
    }
    writer.finish().map_err(io::Error::other)?;
    Ok(())
}

/// Local civil time for the entries' DOS timestamps (as the forensics pack stamps its own).
pub(crate) fn zip_time() -> zip::DateTime {
    let now = jiff::Zoned::now();
    zip::DateTime::from_date_and_time(
        now.year().try_into().unwrap_or(1980),
        now.month().try_into().unwrap_or(1),
        now.day().try_into().unwrap_or(1),
        now.hour().try_into().unwrap_or(0),
        now.minute().try_into().unwrap_or(0),
        now.second().try_into().unwrap_or(0),
    )
    .unwrap_or_default()
}

/// The archive's Log policy for what the forensics pack does not see.
struct Scrub {
    /// The literal Windows user name (at least 3 characters, whole words, any case).
    user: Option<Regex>,
}

impl Scrub {
    fn new(user: Option<String>) -> Self {
        let user = user
            .as_deref()
            .map(str::trim)
            .filter(|u| u.chars().count() >= 3)
            .and_then(|u| {
                let word = |c: Option<char>| c.is_some_and(|c| c.is_alphanumeric() || c == '_');
                let lead = if word(u.chars().next()) { r"\b" } else { "" };
                let tail = if word(u.chars().next_back()) {
                    r"\b"
                } else {
                    ""
                };
                Regex::new(&format!("(?i){lead}{}{tail}", regex::escape(u))).ok()
            });
        Self { user }
    }

    /// Free text: secrets and public addresses masked, then the user name.
    fn text(&self, s: &str) -> String {
        let base = redact::for_log(s);
        match &self.user {
            Some(user) => user.replace_all(&base, "<user>").into_owned(),
            None => base.into_owned(),
        }
    }

    /// JSON lines: each record walked as JSON (so a mask never breaks its quoting); a line that
    /// is not JSON (a write cut by a crash) is left out.
    fn json_lines(&self, text: &str) -> String {
        let mut out = String::new();
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            let Ok(mut record) = serde_json::from_str::<Value>(line) else {
                continue;
            };
            self.json(&mut record);
            out.push_str(&record.to_string());
            out.push('\n');
        }
        out
    }

    fn json(&self, v: &mut Value) {
        match v {
            Value::String(s) => *s = self.text(s),
            Value::Array(items) => items.iter_mut().for_each(|x| self.json(x)),
            Value::Object(map) => {
                for (key, value) in map.iter_mut() {
                    if redact::is_secret_field(key) {
                        *value = Value::String(redact::REDACTED.to_owned());
                    } else {
                        self.json(value);
                    }
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }
}
