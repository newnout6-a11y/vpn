//! The active rule sets as the app hands them to the helper service (pipe protocol 3, re-check
//! item 12a). The service runs as SYSTEM and never reads a user's folder, so the app sends the
//! bytes; the service checks them again (names, size, canaries with its own pinned sing-box)
//! before it writes them into its own admin-only folder, and otherwise keeps its pinned files.
use std::fmt;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use super::validate::validate;
use super::{GEN_PREFIX, RULE_SETS, RefreshFault, STAGING, complete};

/// Largest hand-over, all files together: a start travels in one pipe frame of at most 4 MiB,
/// base64 adds a third, and the user's own rules ride in the same frame (today ~0.8 MB).
pub const MAX_HANDOVER_BYTES: usize = 2 * 1024 * 1024;

/// Every file of `smart_ru::RULE_SETS`, in that order.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuleSetFiles {
    files: Vec<RuleSetFile>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RuleSetFile {
    name: String,
    #[serde(serialize_with = "to_base64", deserialize_with = "from_base64")]
    data: Vec<u8>,
}

/// Names and sizes only: the bytes would flood a log.
impl fmt::Debug for RuleSetFiles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entries(self.files.iter().map(|x| (&x.name, x.data.len())))
            .finish()
    }
}

impl RuleSetFiles {
    /// Every rule-set file of `dir` (blocking); `None` when one is missing or empty, or all
    /// together are over [`MAX_HANDOVER_BYTES`].
    pub fn read(dir: &Path) -> Option<Self> {
        let files = RULE_SETS
            .iter()
            .map(|(_, name, _)| {
                let data = std::fs::read(dir.join(name)).ok()?;
                Some(RuleSetFile {
                    name: (*name).to_owned(),
                    data,
                })
            })
            .collect::<Option<Vec<_>>>()?;
        let set = Self { files };
        set.well_formed().then_some(set)
    }

    /// SHA-256 over the names and the contents, hex: a set is checked once.
    pub fn digest(&self) -> String {
        let mut sha = Sha256::new();
        for f in &self.files {
            sha.update(f.name.as_bytes());
            sha.update((f.data.len() as u64).to_le_bytes());
            sha.update(&f.data);
        }
        hex::encode(sha.finalize())
    }

    /// Exactly the files of `RULE_SETS` in order, none empty, within the size cap.
    fn well_formed(&self) -> bool {
        let total: usize = self.files.iter().map(|f| f.data.len()).sum();
        self.files.len() == RULE_SETS.len()
            && self
                .files
                .iter()
                .zip(RULE_SETS)
                .all(|(f, (_, name, _))| f.name == name && !f.data.is_empty())
            && total <= MAX_HANDOVER_BYTES
    }
}

/// The service's side: `files` checked again (shape, then each file parsed by `engine` with its
/// canaries) and written into `store` as `gen-<digest>`, whose folder is returned. A folder of
/// that digest already there was checked before (the store admits writes by administrators
/// only), so it is used as is. Anything wrong: `Err`, nothing is used.
pub async fn accept(
    files: &RuleSetFiles,
    engine: &Path,
    store: &Path,
) -> Result<PathBuf, RefreshFault> {
    let invalid = |file: &str| RefreshFault::Invalid {
        file: file.to_owned(),
    };
    if !files.well_formed() {
        return Err(invalid("rule sets"));
    }
    let digest = files.digest();
    let dir = store.join(format!("{GEN_PREFIX}{}", &digest[..16]));
    if complete(&dir) {
        return Ok(dir);
    }
    let storage = |err: std::io::Error| {
        tracing::warn!(%err, "handed-over rule sets not stored");
        RefreshFault::Storage
    };
    let staging = store.join(STAGING);
    let _ = tokio::fs::remove_dir_all(&staging).await;
    tokio::fs::create_dir_all(&staging).await.map_err(storage)?;
    let checked = async {
        for (f, (tag, _, _)) in files.files.iter().zip(RULE_SETS) {
            let path = staging.join(&f.name);
            tokio::fs::write(&path, &f.data).await.map_err(storage)?;
            match validate(engine, &path, tag).await {
                Some(true) => {}
                Some(false) => return Err(invalid(&f.name)),
                None => return Err(RefreshFault::EngineUnavailable),
            }
        }
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::rename(&staging, &dir).await.map_err(storage)
    };
    let result = checked.await;
    if result.is_err() {
        let _ = tokio::fs::remove_dir_all(&staging).await;
    }
    result.map(|()| dir)
}

/// Removes the generations in `store` other than `keep` (blocking; call before an engine
/// start, never while an engine may read an older one: pass the running one in `keep`).
pub fn prune_store(store: &Path, keep: &[&Path]) {
    let gens = std::fs::read_dir(store).into_iter().flatten().flatten();
    for entry in gens {
        let path = entry.path();
        let ours = entry.file_name().to_string_lossy().starts_with(GEN_PREFIX);
        if ours
            && !keep.contains(&path.as_path())
            && let Err(err) = std::fs::remove_dir_all(&path)
        {
            tracing::warn!(%err, "old handed-over rule sets not removed");
        }
    }
}

#[cfg(test)]
mod tests;

fn to_base64<S: Serializer>(data: &[u8], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&STANDARD.encode(data))
}

fn from_base64<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let text = String::deserialize(d)?;
    STANDARD.decode(text).map_err(serde::de::Error::custom)
}
