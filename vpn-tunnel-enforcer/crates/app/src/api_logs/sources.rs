//! Where the technical tab's logs come from: the engine logs of the current (or last) session
//! wherever it ran, and the helper service's own lines for this Windows user (p-logs).
use std::path::{Path, PathBuf};
use std::time::Duration;

use vpnte_base::{AppError, AppResult};
use vpnte_core::logging::{self, LogFile};
use vpnte_service::pipe::client::{CallError, Client, ServerCheck};
use vpnte_service::proto::{EngineLog, ErrorCode, Reply, Request, ServiceLogWire};
use vpnte_tunnel::api::CaptureKind;
use vpnte_tunnel::history::{Entry, Route};
use vpnte_ui::logs::{LogTail, TailLine, TailNote, XraySlot};

use crate::boot::service::Presence;

/// A first frame and its answer on a local pipe.
const ASK: Duration = Duration::from_secs(5);

/// The folders the logs are read from: the helper service's engine logs come through its pipe
/// (p-owner-logs O-4), never from its folder.
#[derive(Debug, Clone)]
pub struct Folders {
    /// The user's logs folder (app.log; engines of Proxy mode and of a Tunnel run in this app).
    pub user: PathBuf,
}

impl Folders {
    /// The real folder of this user.
    pub fn of(user: PathBuf) -> Self {
        Self { user }
    }
}

/// The end of one log file in `dir`: whole lines with their offsets, oldest first (the writer
/// redacted them).
pub fn read_tail(dir: &Path, stem: &str, note: TailNote) -> AppResult<LogTail> {
    let tail = logging::tail_lines(dir, &LogFile::engine(stem), logging::TAIL_MAX_BYTES)?;
    Ok(LogTail {
        lines: tail
            .lines
            .into_iter()
            .map(|l| TailLine {
                offset: l.offset,
                text: l.text,
                slot: None,
            })
            .collect(),
        exists: tail.exists,
        truncated: tail.truncated,
        note,
    })
}

/// Xray's two slots as one tail (p-owner-logs follow-up): a server switch starts the other
/// slot, whose log starts anew, so after a switch the running server's lines are in it. Both
/// current logs are merged by their lines' time, each line tagged with its slot; without lines
/// of slot B the tail is slot A's as before (untagged).
pub fn slots_tail(a: LogTail, b: LogTail) -> LogTail {
    if b.lines.is_empty() {
        return a;
    }
    let stamped = |lines: Vec<TailLine>, slot| {
        let mut last: Option<String> = None;
        let mut out = Vec::with_capacity(lines.len());
        for mut line in lines {
            // A line without its own time (a continuation) keeps the one before it.
            if let Some(at) = stamp(&line.text) {
                last = Some(at.to_owned());
            }
            line.slot = Some(slot);
            out.push((last.clone(), line));
        }
        out.into_iter().peekable()
    };
    let (mut a_lines, mut b_lines) = (stamped(a.lines, XraySlot::A), stamped(b.lines, XraySlot::B));
    let mut lines = Vec::with_capacity(a_lines.len() + b_lines.len());
    loop {
        let take_a = match (a_lines.peek(), b_lines.peek()) {
            (Some((at_a, _)), Some((at_b, _))) => at_a <= at_b,
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (None, None) => break,
        };
        let next = if take_a {
            a_lines.next()
        } else {
            b_lines.next()
        };
        lines.extend(next.map(|(_, line)| line));
    }
    LogTail {
        lines,
        exists: a.exists || b.exists,
        truncated: a.truncated || b.truncated,
        note: a.note,
    }
}

/// The time an Xray line starts with (`2026/11/15 04:44:45.123456`), comparable as text.
fn stamp(text: &str) -> Option<&str> {
    let b = text.as_bytes();
    let shape = b.len() > 19
        && b[..4].iter().all(u8::is_ascii_digit)
        && b[4] == b'/'
        && b[7] == b'/'
        && b[10] == b' '
        && b[13] == b':'
        && b[16] == b':';
    if !shape {
        return None;
    }
    let end = text[11..].find(' ').map_or(text.len(), |i| i + 11);
    Some(&text[..end])
}

/// Which folder holds the engine log of a session with `capture` and what the calm line says:
/// Tunnel mode runs in the helper service while it is installed, else in this (elevated) app;
/// Proxy mode always runs here. No session known: the user's folder, nothing said.
pub fn engine_place(capture: Option<CaptureKind>, service: bool) -> (bool, TailNote) {
    match capture {
        Some(CaptureKind::Tun) if service => (true, TailNote::ServiceSession),
        Some(CaptureKind::Tun) => (false, TailNote::TunnelSession),
        Some(CaptureKind::Proxy) => (false, TailNote::ProxySession),
        None => (false, TailNote::None),
    }
}

/// The capture of the newest stored session (before this app saw one run).
pub fn last_capture(entries: &[Entry]) -> Option<CaptureKind> {
    let newest = entries.iter().max_by_key(|e| e.started_at)?;
    match newest.provenance.as_ref()?.route {
        Route::Tun => Some(CaptureKind::Tun),
        Route::SoftEnv => Some(CaptureKind::Proxy),
        Route::Unconfirmed => None,
    }
}

/// What the service answered to `ServiceLog`.
#[derive(Debug)]
pub enum ServiceAnswer {
    NotInstalled,
    /// Installed, and Windows is starting it: its pipe opens in a moment.
    Starting,
    /// Installed and stopped (or stopping).
    Stopped,
    /// An older service that does not know the request.
    Old,
    Lines(ServiceLogWire),
}

/// The helper service's lines for this user (a fake in tests).
#[async_trait::async_trait(?Send)]
pub trait ServiceLogs {
    async fn read(&self) -> AppResult<ServiceAnswer>;
    /// One engine log of this user's Tunnel session in the service (p-owner-logs O-4: its folder
    /// is SYSTEM and Administrators only). Default: an older service's answer.
    async fn engine(&self, _log: EngineLog) -> AppResult<ServiceAnswer> {
        Ok(ServiceAnswer::Old)
    }
}

/// Over the installed service's pipe (see [`ask_service`]).
pub struct PipeServiceLogs;

#[async_trait::async_trait(?Send)]
impl ServiceLogs for PipeServiceLogs {
    async fn read(&self) -> AppResult<ServiceAnswer> {
        ask_service().await
    }

    async fn engine(&self, log: EngineLog) -> AppResult<ServiceAnswer> {
        ask_for(Request::EngineLog(log)).await
    }
}

/// This user's lines from the installed service: a connection of its own, the request as its
/// first frame (no controller slot taken, no `Hello`: reading a log never ends anyone's kept
/// session). The service is found through `boot::service`, the one gate to it (tests never
/// reach a service installed on this PC).
pub async fn ask_service() -> AppResult<ServiceAnswer> {
    ask_for(Request::ServiceLog).await
}

/// [`ask_service`] for `request` (`ServiceLog` or `EngineLog`).
pub async fn ask_for(request: Request) -> AppResult<ServiceAnswer> {
    let Some(exe) = crate::boot::service::installed_binary().map_err(AppError::internal)? else {
        return Ok(ServiceAnswer::NotInstalled);
    };
    let check = ServerCheck::Image(exe);
    let ask = async {
        let mut client = match Client::connect(vpnte_service::sddl::PIPE_NAME, &check, ASK).await {
            Ok(client) => client,
            Err(err) => {
                return match not_answering(crate::boot::service::presence()) {
                    Some(answer) => Ok(answer),
                    None => Err(err),
                };
            }
        };
        match client.call(request).await {
            Ok(Reply::ServiceLog(log) | Reply::EngineLog(log)) => Ok(ServiceAnswer::Lines(log)),
            Ok(other) => {
                tracing::warn!(?other, "unexpected service reply to its log");
                Ok(ServiceAnswer::Old)
            }
            Err(CallError::Service(wire))
                if matches!(wire.code, ErrorCode::BadRequest | ErrorCode::HelloFirst) =>
            {
                Ok(ServiceAnswer::Old)
            }
            Err(CallError::Service(wire)) => Err(AppError::msg(wire.kind, wire.msg)),
            Err(CallError::Pipe(err)) => Err(err),
        }
    };
    match tokio::time::timeout(ASK, ask).await {
        Ok(answer) => answer,
        Err(_) => Err(AppError::new(vpnte_base::ErrorKind::Timeout)),
    }
}

/// An installed service whose pipe did not open, as the SCM has it: starting or stopped is
/// said as such (p-follow3: the page showed a failure); running or gone keeps the pipe's error.
pub fn not_answering(presence: Presence) -> Option<ServiceAnswer> {
    match presence {
        Presence::Starting => Some(ServiceAnswer::Starting),
        Presence::Stopped | Presence::Stopping => Some(ServiceAnswer::Stopped),
        Presence::Running | Presence::Missing => None,
    }
}

/// The answer as the page's tail.
pub fn service_tail(answer: ServiceAnswer) -> LogTail {
    let note = match answer {
        ServiceAnswer::NotInstalled => TailNote::NoService,
        ServiceAnswer::Starting => TailNote::ServiceStarting,
        ServiceAnswer::Stopped => TailNote::ServiceStopped,
        ServiceAnswer::Old => TailNote::OldService,
        ServiceAnswer::Lines(log) => return lines_tail(log),
    };
    LogTail {
        note,
        ..LogTail::default()
    }
}

/// An engine log the service answered with, under the session's calm line `note`; an answer
/// without lines says why, as the service log's does.
pub fn engine_tail(answer: ServiceAnswer, note: TailNote) -> LogTail {
    match answer {
        ServiceAnswer::Lines(log) => LogTail {
            note,
            ..lines_tail(log)
        },
        other => service_tail(other),
    }
}

fn lines_tail(log: ServiceLogWire) -> LogTail {
    LogTail {
        lines: log
            .lines
            .into_iter()
            .map(|l| TailLine {
                offset: l.offset,
                text: l.text,
                slot: None,
            })
            .collect(),
        exists: true,
        truncated: log.truncated,
        note: TailNote::ServiceLines,
    }
}
