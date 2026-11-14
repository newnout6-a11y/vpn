//! Script errors of the window's page in the app log: `window.onerror` and unhandled promise
//! rejections. A script started with the root component reports them over dioxus' IPC (its eval
//! channel); at most [`PER_MINUTE`] a minute are logged, each as one bounded line, and the rest
//! are counted into the next one. The page shows nothing. Redaction is the app log's own: its
//! layer runs every string field through `vpnte_core::redact::for_log`; this module adds what
//! only it knows: page text is untrusted, so only known fields, one line each, cut short, and a
//! rejected value is never serialised (it may be page data); the page's own script addresses are
//! written short, as the log would redact them as URLs.
use std::collections::VecDeque;
use std::time::{Duration, Instant};

use dioxus::prelude::*;
use serde::Deserialize;

/// Logged reports per sliding minute; a page stuck in an error loop costs a few lines a minute.
pub const PER_MINUTE: usize = 5;
const SPAN: Duration = Duration::from_secs(60);
/// Characters kept of the message, the source and each stack frame.
const TEXT_MAX: usize = 300;
/// Stack frames kept: the top of the stack is what tells where it broke.
const FRAMES_MAX: usize = 6;

/// Registers the listeners once per page (a second start only takes the reporting over) and
/// sends at most 30 reports a minute, so an error in an animation frame cannot flood the IPC.
/// Only an `Error`'s message and stack leave the page; any other rejected value is reported by
/// its type name.
const SCRIPT: &str = r#"
const cut = (s, n) => { s = String(s ?? ''); return s.length > n ? s.slice(0, n) : s; };
let sent = [];
const report = r => {
  const now = Date.now();
  sent = sent.filter(t => now - t < 60000);
  if (sent.length >= 30) return;
  sent.push(now);
  dioxus.send(r);
};
const first = !window.__vpnteReport;
window.__vpnteReport = report;
if (first) {
  window.addEventListener('error', e => window.__vpnteReport({
    kind: 'error', message: cut(e.message, 1000), source: cut(e.filename, 1000),
    line: e.lineno | 0, col: e.colno | 0, stack: cut(e.error && e.error.stack, 4000),
  }));
  window.addEventListener('unhandledrejection', e => {
    const r = e.reason, error = r instanceof Error;
    const message = error ? r.message : typeof r === 'string' ? r : Object.prototype.toString.call(r);
    window.__vpnteReport({ kind: 'rejection', message: cut(message, 1000), stack: cut(error ? r.stack : '', 4000) });
  });
}
await new Promise(() => {});
"#;

/// Reports the page's script errors to the app log for the life of the calling component; call
/// it once, in the root component (a rebuilt window's root starts it again in its new page).
pub fn use_script_errors() {
    use_future(|| async {
        let mut page = document::eval(SCRIPT);
        let mut errors = ScriptErrors::default();
        // `Err`: the page (or its channel) is gone.
        while let Ok(value) = page.recv::<serde_json::Value>().await {
            errors.take(value, Instant::now());
        }
    });
}

/// One page's reports on their way to the log: what [`use_script_errors`] does with each message
/// the page sends. Public for the app, which owns the log's redaction and tests the line.
#[derive(Debug, Default)]
pub struct ScriptErrors {
    limit: Limit,
}

impl ScriptErrors {
    /// Logs the page's message `value` (received at `now`) as one WARN line, within the limit; a
    /// message that is not a report is dropped.
    pub fn take(&mut self, value: serde_json::Value, now: Instant) {
        let Ok(report) = serde_json::from_value::<Report>(value) else {
            return;
        };
        if let Some(suppressed) = self.limit.admit(now) {
            report.clean().log(suppressed);
        }
    }
}

/// What the page sends; anything else in its message is ignored.
#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(default)]
struct Report {
    /// `error` or `rejection`.
    kind: String,
    message: String,
    /// Script address of an `error`.
    source: String,
    line: u32,
    col: u32,
    stack: String,
}

impl Report {
    /// One line per field, cut to [`TEXT_MAX`] characters; at most [`FRAMES_MAX`] stack frames.
    fn clean(self) -> Report {
        let kind = match self.kind.as_str() {
            "rejection" => "rejection",
            _ => "error",
        };
        let frames: Vec<String> = (self.stack.lines())
            .map(one_line)
            .filter(|frame| !frame.is_empty())
            .take(FRAMES_MAX)
            .collect();
        Report {
            kind: kind.to_owned(),
            message: one_line(&self.message),
            source: one_line(&self.source),
            stack: frames.join(" | "),
            ..self
        }
    }

    fn log(&self, suppressed: u32) {
        tracing::warn!(
            kind = %self.kind,
            error = %self.message,
            source = %self.source,
            line = self.line,
            col = self.col,
            stack = %self.stack,
            suppressed,
            "page script error"
        );
    }
}

/// The page's own origins, written short: the address of one of the app's own scripts is no
/// secret, and the app log redacts every URL, with the line and column it carries.
const OWN_ORIGINS: [(&str, &str); 2] = [
    ("http://dioxus.index.html", "page:"),
    (crate::assets::ORIGIN, "app:"),
];

/// The page's own origins written short ([`OWN_ORIGINS`]), control characters and runs of
/// whitespace as one space; cut to [`TEXT_MAX`] characters.
fn one_line(text: &str) -> String {
    let text = (OWN_ORIGINS.iter()).fold(text.to_owned(), |text, (origin, short)| {
        text.replace(origin, short)
    });
    let words = text.split(|c: char| c.is_whitespace() || c.is_control());
    let mut line = words
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    if let Some((at, _)) = line.char_indices().nth(TEXT_MAX) {
        line.truncate(at);
        line.push('…');
    }
    line
}

/// A sliding one-minute budget of [`PER_MINUTE`] reports that counts what it turns away.
#[derive(Debug, Default)]
struct Limit {
    logged: VecDeque<Instant>,
    dropped: u32,
}

impl Limit {
    /// `Some(reports turned away since the last one logged)` when one may be logged at `now`.
    fn admit(&mut self, now: Instant) -> Option<u32> {
        while (self.logged.front()).is_some_and(|at| now.duration_since(*at) >= SPAN) {
            self.logged.pop_front();
        }
        if self.logged.len() >= PER_MINUTE {
            self.dropped = self.dropped.saturating_add(1);
            return None;
        }
        self.logged.push_back(now);
        Some(std::mem::take(&mut self.dropped))
    }
}

#[cfg(test)]
mod tests;
