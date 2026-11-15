//! Per-profile bookkeeping while reading one sing-box object: which keys were understood, which
//! allow-listed keys go to `singbox_extra` verbatim, and the Notes for everything that was dropped.
use serde_json::{Map, Value};

use crate::model::Note;

/// Where the object came from: legacy outbounds carry defaults the old parsers invented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Origin {
    /// Pasted or fetched sing-box JSON (the provider wrote every key).
    Json,
    /// `outbound` JSON stored by the Electron app (profiles spec §2.3).
    Legacy,
}

/// Dial options sing-box accepts but this app refuses to take from a provider: they bind to local
/// interfaces, chain through outbounds the app does not have, or pick networks behind its back.
const DIAL_DROPPED: &[&str] = &[
    "detour",
    "bind_interface",
    "inet4_bind_address",
    "inet6_bind_address",
    "bind_address_no_port",
    "routing_mark",
    "reuse_addr",
    "netns",
    "network_strategy",
    "network_type",
    "fallback_network_type",
    "fallback_delay",
];

/// Dial keys that are harmless and kept verbatim.
const DIAL_EXTRA: &[&str] = &[
    "disable_tcp_keep_alive",
    "tcp_keep_alive",
    "tcp_keep_alive_interval",
];

/// Annotations written by other apps or by the Electron app itself; never sing-box options.
const ANNOTATIONS: &[&str] = &[
    "remarks",
    "ps",
    "name",
    "sourceUri",
    "source_uri",
    "uri",
    "udp",
];

/// Accumulates the notes and the verbatim extras of one profile.
#[derive(Debug, Default)]
pub(crate) struct Scan {
    pub(crate) notes: Vec<Note>,
    pub(crate) extra: Map<String, Value>,
}

impl Scan {
    /// Sorts every key of `obj` that the caller does not read itself (`typed`): allow-listed keys
    /// (`extra`) are kept under their dotted path, file references and dial binds become Notes,
    /// anything else becomes `Note::UnsupportedField`. `prefix` is the dotted path of `obj`.
    pub(crate) fn sort_keys(
        &mut self,
        obj: &Map<String, Value>,
        prefix: &str,
        typed: &[&str],
        extra: &[&str],
    ) {
        let top = prefix.is_empty();
        for (key, value) in obj {
            let key = key.as_str();
            if typed.contains(&key) || (top && ANNOTATIONS.contains(&key)) {
                continue;
            }
            let path = join(prefix, key);
            if extra.contains(&key) || (top && DIAL_EXTRA.contains(&key)) {
                self.extra.insert(path, value.clone());
            } else if key.ends_with("_path") || key.ends_with("File") {
                self.note(Note::FileReferenceDropped(path));
            } else if top && DIAL_DROPPED.contains(&key) {
                self.note(Note::DialFieldDropped(path));
            } else {
                self.note(Note::UnsupportedField(path));
            }
        }
    }

    /// Records a dropped key (unknown or invalid value) once.
    pub(crate) fn unsupported(&mut self, path: impl Into<String>) {
        self.note(Note::UnsupportedField(path.into()));
    }

    pub(crate) fn note(&mut self, note: Note) {
        if !self.notes.contains(&note) {
            self.notes.push(note);
        }
    }
}

/// `prefix.key`, or `key` at the top level.
pub(crate) fn join(prefix: &str, key: &str) -> String {
    if prefix.is_empty() {
        key.to_owned()
    } else {
        format!("{prefix}.{key}")
    }
}
