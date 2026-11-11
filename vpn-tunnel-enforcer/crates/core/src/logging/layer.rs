//! The tracing layer behind `app.log`: filters events, redacts them and formats one JSON line
//! per event (storage spec §6.5).
use std::collections::VecDeque;
use std::fmt;
use std::io::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use parking_lot::Mutex;
use serde_json::{Map, Value};
use tracing::field::{Field, Visit};
use tracing::level_filters::LevelFilter;
use tracing::span::{Attributes, Id, Record};
use tracing::subscriber::Interest;
use tracing::{Event, Level, Metadata, Subscriber};
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::registry::LookupSpan;
use vpnte_base::types::now_ms;

use super::lane::Lane;
use super::{LogLine, Problem};
use crate::redact::{self, REDACTED};

/// Longest message or string field kept, in chars (§2.9).
const FIELD_MAX_CHARS: usize = 4000;
const TRUNCATED: &str = "...<truncated>";
/// Warn/error events kept in memory for the diagnostics report.
const RECENT_PROBLEMS: usize = 200;
/// Identifier fields written verbatim (besides `corr`): they are ids, and support needs them intact.
const ID_FIELDS: &[&str] = &["profile", "group", "op", "slot"];

/// State shared by the layer and the module-level controls.
pub(super) struct Shared {
    debug: AtomicBool,
    recent: Mutex<VecDeque<Problem>>,
}

impl Shared {
    pub(super) fn new(debug: bool) -> Self {
        Self {
            debug: AtomicBool::new(debug),
            recent: Mutex::new(VecDeque::with_capacity(RECENT_PROBLEMS)),
        }
    }

    pub(super) fn set_debug(&self, on: bool) {
        self.debug.store(on, Ordering::Relaxed);
    }

    pub(super) fn recent(&self) -> Vec<Problem> {
        self.recent.lock().iter().cloned().collect()
    }

    fn remember(&self, level: Level, line: &LogLine) {
        let mut recent = self.recent.lock();
        if recent.len() == RECENT_PROBLEMS {
            recent.pop_front();
        }
        recent.push_back(Problem {
            at: now_ms(),
            level,
            target: line.target.clone(),
            msg: line.msg.clone(),
        });
    }
}

/// What the file gets: own crates (`vpnte*` targets) from info, or from debug when the debug
/// toggle is on; libraries (hyper, h2, wry, dioxus, …) only warn and error, they are noisy below.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    Always,
    Debug,
    Never,
}

fn class(meta: &Metadata<'_>) -> Class {
    let level = *meta.level();
    if meta.target().starts_with("vpnte") {
        match level {
            Level::TRACE => Class::Never,
            Level::DEBUG => Class::Debug,
            _ => Class::Always,
        }
    } else if level <= Level::WARN {
        Class::Always
    } else {
        Class::Never
    }
}

pub(super) struct JsonLayer {
    shared: Arc<Shared>,
    lane: Arc<Lane>,
    /// Also print lines on stderr (debug builds: `cargo run` shows the log).
    echo: bool,
}

impl JsonLayer {
    pub(super) fn new(shared: Arc<Shared>, lane: Arc<Lane>, echo: bool) -> Self {
        Self { shared, lane, echo }
    }
}

impl<S> Layer<S> for JsonLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn register_callsite(&self, meta: &'static Metadata<'static>) -> Interest {
        match class(meta) {
            Class::Always => Interest::always(),
            Class::Debug => Interest::sometimes(),
            Class::Never => Interest::never(),
        }
    }

    fn enabled(&self, meta: &Metadata<'_>, _ctx: Context<'_, S>) -> bool {
        match class(meta) {
            Class::Always => true,
            Class::Debug => self.shared.debug.load(Ordering::Relaxed),
            Class::Never => false,
        }
    }

    fn max_level_hint(&self) -> Option<LevelFilter> {
        Some(LevelFilter::DEBUG)
    }

    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(id) {
            let mut fields = Fields::default();
            attrs.record(&mut fields);
            span.extensions_mut().insert(fields);
        }
    }

    fn on_record(&self, id: &Id, values: &Record<'_>, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(id)
            && let Some(fields) = span.extensions_mut().get_mut::<Fields>()
        {
            values.record(fields);
        }
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let mut fields = Fields::default();
        if let Some(scope) = ctx.event_scope(event) {
            for span in scope.from_root() {
                if let Some(outer) = span.extensions().get::<Fields>() {
                    fields.inherit(outer);
                }
            }
        }
        event.record(&mut fields);
        let meta = event.metadata();
        let line = fields.into_line(meta);
        if *meta.level() <= Level::WARN {
            self.shared.remember(*meta.level(), &line);
        }
        let bytes = encode(&line);
        if self.echo {
            let _ = std::io::stderr().write_all(&bytes);
        }
        self.lane.send(bytes);
    }
}

/// The record written when the lane had to drop lines.
pub(super) fn overflow_line(lost: u64) -> Vec<u8> {
    let mut fields = Map::new();
    fields.insert("dropped".into(), lost.into());
    encode(&LogLine {
        ts: timestamp(),
        level: Level::WARN.as_str().into(),
        target: module_path!().into(),
        msg: "log queue overflow: lines dropped".into(),
        fields,
        corr: None,
    })
}

fn encode(line: &LogLine) -> Vec<u8> {
    // Serializing strings, numbers and maps cannot fail; an empty result writes nothing.
    let mut bytes = serde_json::to_vec(line).unwrap_or_default();
    if !bytes.is_empty() {
        bytes.push(b'\n');
    }
    bytes
}

fn timestamp() -> String {
    format!("{:.3}", jiff::Timestamp::now())
}

/// Cuts at [`FIELD_MAX_CHARS`] chars (after redaction, so a mask is never half cut).
fn clip(s: &str) -> String {
    match s.char_indices().nth(FIELD_MAX_CHARS) {
        Some((cut, _)) => format!("{}{TRUNCATED}", &s[..cut]),
        None => s.to_owned(),
    }
}

/// Fields of a span or an event, redacted as they are recorded.
#[derive(Default)]
struct Fields {
    msg: Option<String>,
    corr: Option<String>,
    values: Map<String, Value>,
}

impl Fields {
    /// Span fields apply to the events inside; the event's own fields win.
    fn inherit(&mut self, outer: &Fields) {
        if outer.corr.is_some() {
            self.corr.clone_from(&outer.corr);
        }
        for (name, value) in &outer.values {
            self.values.insert(name.clone(), value.clone());
        }
    }

    fn into_line(self, meta: &Metadata<'_>) -> LogLine {
        LogLine {
            ts: timestamp(),
            level: meta.level().as_str().into(),
            target: meta.target().into(),
            msg: self.msg.unwrap_or_default(),
            fields: self.values,
            corr: self.corr,
        }
    }

    fn text(&mut self, name: &str, raw: &str) {
        match name {
            "message" => self.msg = Some(clip(&redact::for_log(raw))),
            "corr" => self.corr = Some(clip(raw)),
            _ if redact::is_secret_field(name) => self.put(name, REDACTED.into()),
            _ if ID_FIELDS.contains(&name) => self.put(name, clip(raw).into()),
            _ => self.put(name, clip(&redact::for_log(raw)).into()),
        }
    }

    /// Numbers and booleans pass unchanged, unless the name itself marks a secret.
    fn plain(&mut self, name: &str, value: Value) {
        if redact::is_secret_field(name) {
            self.put(name, REDACTED.into());
        } else {
            self.put(name, value);
        }
    }

    fn put(&mut self, name: &str, value: Value) {
        self.values.insert(name.to_owned(), value);
    }
}

impl Visit for Fields {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.text(field.name(), value);
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.text(field.name(), &format!("{value:?}"));
    }

    /// The whole cause chain: support needs the failure location, not just the top message.
    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        let mut chain = value.to_string();
        let mut source = value.source();
        while let Some(cause) = source {
            chain.push_str(": ");
            chain.push_str(&cause.to_string());
            source = cause.source();
        }
        self.text(field.name(), &chain);
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.plain(field.name(), value.into());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.plain(field.name(), value.into());
    }

    fn record_i128(&mut self, field: &Field, value: i128) {
        let value = i64::try_from(value).map_or_else(|_| value.to_string().into(), Value::from);
        self.plain(field.name(), value);
    }

    fn record_u128(&mut self, field: &Field, value: u128) {
        let value = u64::try_from(value).map_or_else(|_| value.to_string().into(), Value::from);
        self.plain(field.name(), value);
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        let value = serde_json::Number::from_f64(value)
            .map_or_else(|| value.to_string().into(), Value::Number);
        self.plain(field.name(), value);
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.plain(field.name(), value.into());
    }
}
