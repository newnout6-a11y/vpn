//! One event of the journal as stored: Msg keys and their arguments (never rendered text),
//! redacted like the app log before they reach the disk.
use serde::{Deserialize, Serialize};
use vpnte_base::Msg;
use vpnte_base::types::{Engine, Level, Notice, UnixMs};
use vpnte_core::redact;
use vpnte_tunnel::history::{Entry, SessionMode};
use vpnte_tunnel::outcome::OutcomeKind;

use crate::svc_core::notify::NoticeCategory;

/// What an event is about (the page's chips).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Topic {
    Connection,
    Protection,
    Automation,
    Update,
    Other,
}

/// The status dot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Tone {
    Ok,
    Info,
    Warn,
    Error,
}

/// Facts of a session start or end.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionFacts {
    pub profile: String,
    pub mode: SessionMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(default)]
    pub bytes_down: u64,
    #[serde(default)]
    pub bytes_up: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine: Option<Engine>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<OutcomeKind>,
}

/// An event before it is numbered.
#[derive(Debug, Clone, PartialEq)]
pub struct NewRecord {
    pub at: UnixMs,
    pub topic: Topic,
    pub tone: Tone,
    pub title: Msg,
    pub body: Option<Msg>,
    pub session: Option<SessionFacts>,
}

/// One line of `events.jsonl`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Record {
    /// Increasing number: the row key on the page.
    pub seq: u64,
    pub at: UnixMs,
    pub topic: Topic,
    pub tone: Tone,
    pub title: Msg,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<Msg>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionFacts>,
}

impl Record {
    /// `new` numbered `seq`, its arguments and profile name redacted like the app log: secrets
    /// in free text masked, public addresses pseudonymized, secret-named arguments dropped.
    pub fn redacted(seq: u64, new: NewRecord) -> Self {
        Record {
            seq,
            at: new.at,
            topic: new.topic,
            tone: new.tone,
            title: clean(new.title),
            body: new.body.map(clean),
            session: new.session.map(|mut s| {
                s.profile = redact::for_log(&s.profile).into_owned();
                s
            }),
        }
    }
}

fn clean(mut msg: Msg) -> Msg {
    for (name, value) in &mut msg.args {
        *value = if redact::is_secret_field(name) {
            redact::REDACTED.to_owned()
        } else {
            redact::for_log(value).into_owned()
        };
    }
    msg
}

/// A notice the app showed, as an event; `None` for the lifecycle's plain «connected» /
/// «disconnected» notices: the session lines say the same with their details.
pub fn from_notice(
    notice: &Notice,
    category: Option<NoticeCategory>,
    at: UnixMs,
) -> Option<NewRecord> {
    let plain = matches!(notice.level, Level::Info | Level::Success);
    if plain
        && matches!(
            category,
            Some(NoticeCategory::VpnConnect | NoticeCategory::VpnDisconnect)
        )
    {
        return None;
    }
    Some(NewRecord {
        at,
        topic: topic_of(&notice.title.key, category),
        tone: match notice.level {
            Level::Info => Tone::Info,
            Level::Success => Tone::Ok,
            Level::Warn => Tone::Warn,
            Level::Error => Tone::Error,
        },
        title: notice.title.clone(),
        body: notice.body.clone(),
        session: None,
    })
}

/// The chip of a notice: its category when it has one, else its message key's area.
pub fn topic_of(key: &str, category: Option<NoticeCategory>) -> Topic {
    match category {
        Some(
            NoticeCategory::VpnConnect
            | NoticeCategory::VpnDisconnect
            | NoticeCategory::ConnectionError,
        ) => return Topic::Connection,
        Some(NoticeCategory::LeakDetected) => return Topic::Protection,
        Some(NoticeCategory::ProfileRotation | NoticeCategory::ScheduleTriggered) => {
            return Topic::Automation;
        }
        None => {}
    }
    let key = key.to_ascii_lowercase();
    let has = |words: &[&str]| words.iter().any(|w| key.contains(w));
    if has(&["update"]) {
        Topic::Update
    } else if has(&[
        "killswitch",
        "kill_switch",
        "protection",
        "leak",
        "wfp",
        "hardening",
    ]) {
        Topic::Protection
    } else if key.starts_with("automation.") || has(&["schedule", "rotation", "autopilot"]) {
        Topic::Automation
    } else if ["tunnel.", "engine.", "service.", "proxies."]
        .iter()
        .any(|p| key.starts_with(p))
    {
        Topic::Connection
    } else {
        Topic::Other
    }
}

/// Title key of a session start (also how a start already written is recognised).
pub const SESSION_UP: &str = "logs.events.sessionUp";

/// A session that came up.
pub fn session_up(
    at: UnixMs,
    profile: &str,
    mode: SessionMode,
    engine: Option<Engine>,
) -> NewRecord {
    NewRecord {
        at,
        topic: Topic::Connection,
        tone: Tone::Ok,
        title: Msg::new(SESSION_UP).arg("profile", profile),
        body: None,
        session: Some(SessionFacts {
            profile: profile.to_owned(),
            mode,
            duration_ms: None,
            bytes_down: 0,
            bytes_up: 0,
            engine,
            outcome: None,
        }),
    }
}

/// A stored session's end (or its failed start), with how it ended.
pub fn session_end(entry: &Entry) -> NewRecord {
    let kind = entry.outcome.as_ref().map(|o| o.kind);
    let failed = kind == Some(OutcomeKind::StartFailed);
    let title = if failed {
        "logs.events.sessionFailed"
    } else {
        "logs.events.sessionEnd"
    };
    let body = entry
        .outcome
        .as_ref()
        .map(|o| o.headline.clone())
        .or_else(|| entry.error_message.clone());
    NewRecord {
        at: entry.ended_at.unwrap_or(entry.started_at),
        topic: Topic::Connection,
        tone: tone_of(kind, entry),
        title: Msg::new(title).arg("profile", &entry.profile_name),
        body,
        session: Some(SessionFacts {
            profile: entry.profile_name.clone(),
            mode: entry.mode,
            duration_ms: Some(entry.connection_ms()),
            bytes_down: entry.bytes_down,
            bytes_up: entry.bytes_up,
            engine: entry.outcome.as_ref().and_then(|o| o.evidence.proxy_engine),
            outcome: kind,
        }),
    }
}

/// Intended ends are plain, the network's or the machine's are warnings, failures are errors.
fn tone_of(kind: Option<OutcomeKind>, entry: &Entry) -> Tone {
    use OutcomeKind as K;
    use vpnte_tunnel::outcome::DisconnectReason as R;
    match kind {
        Some(K::UserStop | K::AppQuit | K::ServerSwitch | K::Rotation | K::Schedule) => Tone::Info,
        Some(K::ProxyUnreachable | K::NetworkLost | K::SystemSleep | K::Unknown) => Tone::Warn,
        Some(_) => Tone::Error,
        // Rows of the old version: only the coarse reason is known.
        None => match entry.disconnect_reason {
            R::Error | R::Crash => Tone::Warn,
            R::User | R::Rotation | R::Schedule => Tone::Info,
        },
    }
}
