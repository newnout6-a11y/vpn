//! Script errors of the window's page in the app log: `window.onerror` and unhandled promise
//! rejections. A script started with the root component reports them over dioxus' IPC (its eval
//! channel); at most [`PER_MINUTE`] a minute are logged, each as one bounded INFO line (a page
//! error is no problem the user could act on: it never turns the Diagnostics log check yellow,
//! review tailsa-b2), and the rest are counted into the next one. The page shows nothing.
//! Redaction is the app log's own: its layer runs every string field through
//! `vpnte_core::redact::for_log`; this module adds what only it knows: page text is untrusted, so
//! only known fields, one line each, cut short between words (a word cut in two could be half a
//! secret the redaction no longer recognises: the cut word goes whole, tailsa-a1), and a rejected
//! value that is not an `Error` is reported by its type name only (it may be page data:
//! tailsa-a3); the page's own script addresses are written short, as the log would redact them as
//! URLs.
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
/// Only an `Error`'s message and stack leave the page, cut between words; any other rejected
/// value is reported by its type name. Chromium's "ResizeObserver loop" notice (a resize the
/// observer delivers next frame, nothing broken) is not reported.
const SCRIPT: &str = r#"
const cut = (s, n) => { s = String(s ?? ''); return s.length > n ? s.slice(0, n).replace(/\S*$/, '') : s; };
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
  window.addEventListener('error', e => {
    if (/^ResizeObserver loop/.test(String(e.message))) return;
    window.__vpnteReport({
      kind: 'error', message: cut(e.message, 1000), source: cut(e.filename, 1000),
      line: e.lineno | 0, col: e.colno | 0, stack: cut(e.error && e.error.stack, 4000),
    });
  });
  window.addEventListener('unhandledrejection', e => {
    const r = e.reason, error = r instanceof Error;
    const message = error ? r.message : Object.prototype.toString.call(r);
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
    /// Logs the page's message `value` (received at `now`) as one INFO line, within the limit; a
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
        tracing::info!(
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
/// whitespace as one space; cut to at most [`TEXT_MAX`] characters between words, the word the
/// cut would split dropped whole.
fn one_line(text: &str) -> String {
    let text = (OWN_ORIGINS.iter()).fold(text.to_owned(), |text, (origin, short)| {
        text.replace(origin, short)
    });
    let words = text.split(|c: char| c.is_whitespace() || c.is_control());
    let mut line = words
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    if let Some((at, next)) = line.char_indices().nth(TEXT_MAX) {
        let end = if next == ' ' {
            at
        } else {
            line[..at].rfind(' ').unwrap_or(0)
        };
        line.truncate(end);
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
