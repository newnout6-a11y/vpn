//! The service's own log (p-logs): redacted JSON lines in the private folder
//! (`service\service.log` + `service.1.log`, 1 MiB each), in the app log's format, each tagged
//! with the Windows user it concerns, so a user's app can read the lines of its own sessions and
//! the service-wide ones through the pipe (`Request::ServiceLog`) and never another user's.
//!
//! Attribution: the user of the session the runtime runs or ran last, else the controlling
//! connection's user, else none (service-wide: start-up, updates). The host is asked without
//! waiting; a line logged while its locks are held is tagged busy and shown to nobody.
use std::io;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde_json::Value;
use tracing::{Event, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::{Context, SubscriberExt as _};
use vpnte_core::logging::{self, LogFile, RotatingFile};

use crate::proto::{ServiceLogLine, ServiceLogWire};

/// File stem in the private folder (`service.log`, `service.1.log`).
pub const STEM: &str = "service";
/// Size at which the log starts a new generation.
pub const MAX_BYTES: u64 = 1 << 20;
/// Lines a reply carries at most (the app shows the last 2 000).
pub const REPLY_LINES: usize = 2000;
/// The tag of a line logged while the host was busy: nobody's.
const BUSY: &str = "?";

/// Whom a line concerns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Owner {
    /// The service itself (no session, no client).
    Service,
    /// A Windows user (SID).
    User(String),
    /// Not known without waiting: shown to nobody.
    Busy,
}

/// Whom a line concerns: the user of the session the runtime runs or ran last (its exit and
/// faults are his), else the controlling connection's user, else the service itself.
pub fn owner_of(session: Option<&str>, controller: Option<&str>) -> Owner {
    match session.or(controller) {
        Some(user) => Owner::User(user.to_owned()),
        None => Owner::Service,
    }
}

type Attribution = Box<dyn Fn() -> Owner + Send + Sync>;

struct Log {
    dir: PathBuf,
    owner: OnceLock<Attribution>,
}

static LOG: OnceLock<Log> = OnceLock::new();

/// Installs the global subscriber writing `<dir>\service.log` (info and above). Lines before
/// [`attribute`] count as the service's own.
pub fn init(dir: &Path) -> io::Result<()> {
    let file = RotatingFile::open(dir, STEM, MAX_BYTES, 0)?;
    let log = LOG.get_or_init(|| Log {
        dir: dir.to_owned(),
        owner: OnceLock::new(),
    });
    let layer = ServiceLayer::new(file, || log.owner.get().map_or(Owner::Service, |f| f()));
    let subscriber = tracing_subscriber::registry().with(layer.with_filter(LevelFilter::INFO));
    tracing::subscriber::set_global_default(subscriber).map_err(io::Error::other)
}

/// Tells the log whom the next lines concern (set once, after the host exists).
pub fn attribute(owner: impl Fn() -> Owner + Send + Sync + 'static) {
    if let Some(log) = LOG.get() {
        let _ = log.owner.set(Box::new(owner));
    }
}

/// The last lines `user` may read, from the global log; empty before [`init`].
pub fn for_user(user: &str) -> io::Result<ServiceLogWire> {
    match LOG.get() {
        Some(log) => lines_for(&log.dir, user),
        None => Ok(ServiceLogWire::default()),
    }
}

/// The last lines of the log in `dir` that `user` may read: the service-wide ones and his own,
/// without the tag. Lines of another user, busy lines and lines in no known format (the plain
/// text of an older build) are left out.
pub fn lines_for(dir: &Path, user: &str) -> io::Result<ServiceLogWire> {
    let tail = logging::tail_lines(dir, &LogFile::engine(STEM), logging::TAIL_MAX_BYTES)?;
    let mut lines: Vec<ServiceLogLine> = tail
        .lines
        .into_iter()
        .filter_map(|line| {
            visible(&line.text, user).map(|text| ServiceLogLine {
                offset: line.offset,
                text,
            })
        })
        .collect();
    let truncated = tail.truncated || lines.len() > REPLY_LINES;
    if lines.len() > REPLY_LINES {
        lines.drain(..lines.len() - REPLY_LINES);
    }
    Ok(ServiceLogWire { lines, truncated })
}

/// The line as `user` sees it (tag removed), or `None` when it is not his to read.
fn visible(text: &str, user: &str) -> Option<String> {
    let Ok(Value::Object(mut obj)) = serde_json::from_str::<Value>(text) else {
        return None;
    };
    match obj.remove("user") {
        None => {}
        Some(Value::String(tag)) if tag == user => {}
        Some(_) => return None,
    }
    serde_json::to_string(&obj).ok()
}

/// Writes every event as a tagged, redacted app-log line.
struct ServiceLayer<F> {
    file: RotatingFile,
    owner: F,
}

impl<F: Fn() -> Owner> ServiceLayer<F> {
    fn new(file: RotatingFile, owner: F) -> Self {
        Self { file, owner }
    }

    fn line(&self, event: &Event<'_>) -> Option<String> {
        let mut value = serde_json::to_value(logging::event_line(event)).ok()?;
        if let Value::Object(obj) = &mut value {
            match (self.owner)() {
                Owner::Service => {}
                Owner::User(sid) => {
                    obj.insert("user".into(), sid.into());
                }
                Owner::Busy => {
                    obj.insert("user".into(), BUSY.into());
                }
            }
        }
        serde_json::to_string(&value).ok()
    }
}

impl<S, F> Layer<S> for ServiceLayer<F>
where
    S: Subscriber,
    F: Fn() -> Owner + Send + Sync + 'static,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        if let Some(line) = self.line(event) {
            // A full disk must not take the service down with it.
            let _ = self.file.write_line(&line);
        }
    }
}

#[cfg(test)]
mod tests;
