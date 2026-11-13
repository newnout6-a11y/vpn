//! `state.json`: per engine the active and previous choice, the trial of a fresh install and
//! when each downloaded version arrived. Written atomically (temp file + rename).
use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use vpnte_base::types::UnixMs;

use crate::version::{BadVersion, Version};

pub(super) const STATE_FILE: &str = "state.json";
/// Failed starts in a row that end a trial: back to the previous engine.
pub(super) const TRIAL_FAILURES: u8 = 3;

/// Which copy of an engine runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    Bundled,
    Downloaded(Version),
}

impl fmt::Display for Choice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Choice::Bundled => f.write_str("bundled"),
            Choice::Downloaded(v) => v.fmt(f),
        }
    }
}

impl FromStr for Choice {
    type Err = BadVersion;

    fn from_str(s: &str) -> Result<Self, BadVersion> {
        match s {
            "bundled" => Ok(Choice::Bundled),
            other => other.parse().map(Choice::Downloaded),
        }
    }
}

impl Serialize for Choice {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Choice {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// One engine's record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EngineState {
    pub active: Choice,
    #[serde(default)]
    pub previous: Option<Choice>,
    /// Failed starts so far while a fresh install is on trial; `None` = proven or bundled.
    #[serde(default)]
    pub trial: Option<u8>,
    /// When each downloaded version was installed.
    #[serde(default)]
    pub installed: BTreeMap<String, UnixMs>,
}

impl EngineState {
    /// When `version` was installed (0 when unknown).
    pub fn installed_on(&self, version: Version) -> UnixMs {
        self.installed
            .get(&version.to_string())
            .copied()
            .unwrap_or(0)
    }
}

impl Default for EngineState {
    fn default() -> Self {
        Self {
            active: Choice::Bundled,
            previous: None,
            trial: None,
            installed: BTreeMap::new(),
        }
    }
}

/// The whole file: engine id -> record.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreState {
    #[serde(flatten)]
    pub engines: BTreeMap<String, EngineState>,
}

impl StoreState {
    /// The record of engine `id`, if any.
    pub fn engine(&self, id: &str) -> Option<&EngineState> {
        self.engines.get(id)
    }

    /// The record of engine `id`, created bundled when missing.
    pub(super) fn engine_mut(&mut self, id: &str) -> &mut EngineState {
        self.engines.entry(id.to_owned()).or_default()
    }
}

/// Reads `<root>\state.json`; missing or unreadable reads as "everything bundled".
pub(super) fn read(root: &Path) -> StoreState {
    std::fs::read(root.join(STATE_FILE))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

/// Writes `<root>\state.json` atomically.
pub(super) fn write(root: &Path, state: &StoreState) -> std::io::Result<()> {
    let mut bytes = serde_json::to_vec_pretty(state).map_err(std::io::Error::other)?;
    bytes.push(b'\n');
    vpnte_core::store::write_atomic(&root.join(STATE_FILE), &bytes)
}
