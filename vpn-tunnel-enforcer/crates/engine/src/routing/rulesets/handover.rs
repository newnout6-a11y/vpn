//! The active rule sets as the app hands them to the helper service (pipe protocol 3, re-check
//! item 12a). The service runs as SYSTEM and never reads a user's folder, so the app sends the
//! bytes; the service checks them again (names, size, canaries and the content bounds against
//! its own pinned copies, with its own pinned sing-box) before it writes them into its own
//! admin-only folder, and otherwise keeps its pinned files. The last set that passed is noted in
//! that folder per Windows user and kept across a restart while its bytes still hash to it: one
//! user's lists never steer another's routing (speed3 P-1).
use std::fmt;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use super::validate::validate;
use super::{CHECKS, GEN_PREFIX, RULE_SETS, RefreshFault, STAGING, write_synced};

/// The store's note of the last set that passed for one user (its digest), read after a
/// restart: `accepted-<hash of the user>`.
const ACCEPTED: &str = "accepted";

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
        let total: usize = set.files.iter().map(|f| f.data.len()).sum();
        if total > MAX_HANDOVER_BYTES {
            // The service then keeps the lists it has: say so where the cause can be seen.
            tracing::warn!(total, "Smart RU lists over the hand-over cap; not sent");
        }
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
/// canaries and bounded against `reference`, the pinned copies) and written into `store` as
/// `gen-<digest>`, whose folder is returned and noted as `owner`'s (a Windows user's SID).
/// Anything wrong: `Err`, nothing is used. A folder that already holds the bytes is not checked
/// again, whoever sent them.
pub async fn accept(
    files: &RuleSetFiles,
    engine: &Path,
    store: &Path,
    reference: &Path,
    owner: &str,
) -> Result<PathBuf, RefreshFault> {
    let invalid = |file: &str| RefreshFault::Invalid {
        file: file.to_owned(),
    };
    if !files.well_formed() {
        return Err(invalid("rule sets"));
    }
    let digest = files.digest();
    let dir = folder(store, &digest);
    // A folder's name proves nothing (psmart-a4): after a power loss a renamed folder can hold
    // files whose data never reached the disk. Its bytes must still hash to the set.
    if !holds(&dir, &digest).await {
        check_into(files, engine, store, reference, &dir).await?;
    }
    remember(store, owner, &digest).await;
    Ok(dir)
}

/// The last set [`accept`] passed for `owner`, after a restart (fixlists-a5: a refused
/// hand-over keeps it, not the pinned files): `(digest, folder)` while the folder's bytes still
/// hash to it.
pub async fn recall(store: &Path, owner: &str) -> Option<(String, PathBuf)> {
    let digest = tokio::fs::read_to_string(note(store, owner)).await.ok()?;
    let digest = digest.trim();
    let dir = folder(store, digest);
    holds(&dir, digest).await.then(|| (digest.to_owned(), dir))
}

/// `gen-<digest>-c<checks>`: a set stored by older checks is never reused (fixlists-a7).
fn folder(store: &Path, digest: &str) -> PathBuf {
    let short = digest.get(..16).unwrap_or(digest);
    store.join(format!("{GEN_PREFIX}{short}-c{CHECKS}"))
}

/// Writes the set into a staging folder, checks every file and renames it to `dir`.
async fn check_into(
    files: &RuleSetFiles,
    engine: &Path,
    store: &Path,
    reference: &Path,
    dir: &Path,
) -> Result<(), RefreshFault> {
    let invalid = |file: &str| RefreshFault::Invalid {
        file: file.to_owned(),
    };
    let storage = |err: std::io::Error| {
        tracing::warn!(%err, "handed-over rule sets not stored");
        RefreshFault::Storage
    };
    let staging = store.join(STAGING);
    let _ = tokio::fs::remove_dir_all(&staging).await;
    tokio::fs::create_dir_all(&staging).await.map_err(storage)?;
    let checked = async {
        let paths: Vec<PathBuf> = files.files.iter().map(|f| staging.join(&f.name)).collect();
        for (f, path) in files.files.iter().zip(&paths) {
            write_synced(path, &f.data).await.map_err(storage)?;
        }
        // Lab live-9 L9-2: one engine run after another made 4.7 s of a first connect. The
        // files are checked side by side, each with every check it had; the verdict is read in
        // file order, so the answer is the one a check in turn would give.
        let checks = paths.iter().zip(RULE_SETS);
        let checks = checks.map(|(path, (tag, _, _))| validate(engine, path, tag, reference));
        let verdicts = futures_util::future::join_all(checks).await;
        for (f, verdict) in files.files.iter().zip(verdicts) {
            match verdict {
                Some(true) => {}
                Some(false) => return Err(invalid(&f.name)),
                None => return Err(RefreshFault::EngineUnavailable),
            }
        }
        let _ = tokio::fs::remove_dir_all(dir).await;
        tokio::fs::rename(&staging, dir).await.map_err(storage)
    };
    let result = checked.await;
    if result.is_err() {
        let _ = tokio::fs::remove_dir_all(&staging).await;
    }
    result
}

/// `owner`'s note in `store` (a hash: a SID never becomes part of a path).
fn note(store: &Path, owner: &str) -> PathBuf {
    let hash = Sha256::digest(owner.as_bytes());
    let short: String = hash[..8].iter().map(|b| format!("{b:02x}")).collect();
    store.join(format!("{ACCEPTED}-{short}"))
}

/// Notes `digest` as `owner`'s last set that passed (written aside and renamed: a torn note
/// names no folder that holds it, so it is ignored).
async fn remember(store: &Path, owner: &str, digest: &str) {
    let path = note(store, owner);
    let temp = path.with_extension("tmp");
    let saved = async {
        write_synced(&temp, digest.as_bytes()).await?;
        tokio::fs::rename(&temp, &path).await
    };
    if let Err(err) = saved.await {
        tracing::warn!(%err, "the accepted rule sets were not noted");
    }
}

/// `dir` holds exactly the set of `digest` (read back and hashed, off the async threads).
async fn holds(dir: &Path, digest: &str) -> bool {
    let dir = dir.to_owned();
    tokio::task::spawn_blocking(move || RuleSetFiles::read(&dir))
        .await
        .ok()
        .flatten()
        .is_some_and(|set| set.digest() == digest)
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
