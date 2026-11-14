//! The service's own exe swap (task point 4, decisions D-S3 / D-S5). The verified new exe waits in
//! the staging folder; the swap gives the running image a second name (a hard link: Windows
//! refuses to replace the entry of a running exe that has only one), replaces the entry with the
//! new file in one step written through to the disk, and the service exits for the SCM to start
//! what is there now. The new exe is on trial: each start counts first, a start that runs
//! [`TRIAL_RUN`] ends the trial, and the start after [`TRIAL_STARTS`] that did not brings the
//! previous exe back the same way; that version is never taken again.
//!
//! Power loss at any step leaves `vpnte-service.exe` the old or the new file, never neither (the
//! replace is one directory operation): before the marker, the old exe and the staged file (the
//! next start swaps it in); marker and link written, entry not replaced, the old exe (its start
//! drops both and swaps the staged file in again); entry replaced, the new exe (its start counts
//! the trial); during a rollback before the entry went back, the new exe (it rolls back again);
//! rollback done, the old exe (the kept marker skips the failed version from then on).
use std::fs::OpenOptions;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use vpnte_update::download::{open_held, parse_sha, sha256_of};
use vpnte_update::feed::{FEED_FILE, PublicKey, SIG_FILE, verify};
use vpnte_update::version::Version;
use windows::Win32::Storage::FileSystem::{
    MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
};
use windows::core::HSTRING;

mod probe;

pub use probe::probe;

/// Starts of a fresh exe that may end early; the next one rolls back.
pub const TRIAL_STARTS: u32 = 3;
/// A start that runs this long ends the trial.
pub const TRIAL_RUN: Duration = Duration::from_secs(30);

/// The files of a swap, all inside the install folder (one volume: every move is a rename).
#[derive(Debug, Clone)]
pub struct SwapFiles {
    /// `vpnte-service.exe`, what the SCM starts.
    pub exe: PathBuf,
    /// `update\`, admin-only: the staged exe with the signed feed it came from, the marker.
    pub staging: PathBuf,
    /// Why a staged file may not run (`crate::sddl::untrusted_reason`; tests: temp folders).
    pub vet: fn(&Path) -> Option<String>,
}

impl SwapFiles {
    /// The files around the service exe `exe`.
    pub fn new(exe: &Path) -> Self {
        let dir = exe.parent().unwrap_or(Path::new(""));
        Self {
            exe: exe.to_owned(),
            staging: dir.join("update"),
            vet: crate::sddl::untrusted_reason,
        }
    }

    /// Over a temp folder (which users may write): nothing is vetted.
    #[cfg(test)]
    pub(crate) fn unvetted(exe: &Path) -> Self {
        Self {
            vet: |_| None,
            ..Self::new(exe)
        }
    }

    fn marker(&self) -> PathBuf {
        self.staging.join("swap.json")
    }

    fn prev(&self) -> PathBuf {
        self.staging.join("vpnte-service.prev.exe")
    }

    fn failed(&self) -> PathBuf {
        self.staging.join("vpnte-service.failed.exe")
    }

    /// Where the exe of `version` is staged.
    pub fn staged(&self, version: Version) -> PathBuf {
        self.staging.join(format!("vpnte-service-{version}.exe"))
    }
}

/// A swap in progress, or the record of one that failed its trial.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Marker {
    pub from: Version,
    pub to: Version,
    /// Starts of `to` so far.
    pub starts: u32,
}

impl Marker {
    /// `to` used up its trial: rolled back, never taken again.
    pub fn spent(&self) -> bool {
        self.starts >= TRIAL_STARTS
    }
}

/// The marker, when one is there and reads.
pub fn marker(files: &SwapFiles) -> Option<Marker> {
    serde_json::from_slice(&std::fs::read(files.marker()).ok()?).ok()
}

fn write_marker(files: &SwapFiles, marker: &Marker) -> io::Result<()> {
    crate::paths::write_synced(&files.marker(), &serde_json::to_vec(marker)?)
}

/// What the start of the service found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtStart {
    /// Nothing pending (leftovers of an earlier swap removed).
    Normal,
    /// This exe is a fresh swap on trial, start `n`: [`settled`] ends the trial once it ran
    /// [`TRIAL_RUN`].
    Trial(u32),
    /// The previous exe (this version) is back in place: exit for the SCM to start it.
    RolledBack(Version),
}

/// The first thing at every start of the service `own`: counts the trial of a fresh exe or
/// rolls a failed one back.
pub fn at_start(files: &SwapFiles, own: Version) -> io::Result<AtStart> {
    let Some(mut m) = marker(files) else {
        remove(&files.prev());
        remove(&files.failed());
        return Ok(AtStart::Normal);
    };
    if own == m.to {
        if m.spent() {
            rollback(files)?;
            return Ok(AtStart::RolledBack(m.from));
        }
        m.starts += 1;
        write_marker(files, &m)?;
        return Ok(AtStart::Trial(m.starts));
    }
    // The old exe (power lost before the replace, or rolled back) or one an installer put here.
    // A spent trial's marker stays: it is the record that `to` failed.
    if !(own == m.from && m.spent()) {
        remove(&files.marker());
    }
    remove(&files.prev());
    remove(&files.failed());
    Ok(AtStart::Normal)
}

/// The trial ended well: the marker and the previous exe go.
pub fn settled(files: &SwapFiles) {
    remove(&files.marker());
    remove(&files.prev());
}

/// Removes the staged exes and the feed kept with them (a release the newest feed no longer
/// offers, or one the app did not ask for: svcupd-a3).
pub fn drop_staged(files: &SwapFiles) {
    let Ok(entries) = std::fs::read_dir(&files.staging) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let staged = name.starts_with("vpnte-service-") && name.ends_with(".exe");
        if staged || name == FEED_FILE || name == SIG_FILE {
            remove(&entry.path());
        }
    }
}

/// An installer put its own exe in place: nothing the feed staged or swapped counts any more
/// (a rollback's older service must not take the newer one back at its start: svcupd-a7).
pub fn forget(files: &SwapFiles) {
    drop_staged(files);
    for path in [files.marker(), files.prev(), files.failed()] {
        remove(&path);
    }
}

/// `to` is never taken here (its exe does not start on this Windows): the same record a spent
/// trial leaves.
pub fn refuse(files: &SwapFiles, from: Version, to: Version) {
    let starts = TRIAL_STARTS;
    if let Err(err) = write_marker(files, &Marker { from, to, starts }) {
        tracing::warn!(%err, "refused service update not recorded");
    }
}

/// The fresh exe on trial cannot work here (svcupd-a8): its trial ends now, the previous exe goes
/// back and this version is skipped from then on; the caller exits for the SCM to start it.
pub fn give_up(files: &SwapFiles) -> io::Result<Version> {
    let mut m = marker(files).ok_or(io::ErrorKind::NotFound)?;
    m.starts = TRIAL_STARTS;
    write_marker(files, &m)?;
    rollback(files)?;
    Ok(m.from)
}

/// `version` failed its trial here earlier: never taken again.
pub fn failed_before(files: &SwapFiles, version: Version) -> bool {
    marker(files).is_some_and(|m| m.spent() && m.to == version)
}

/// Puts the staged exe of `to` in place of the running one (`from`); the caller then exits for
/// the SCM to start it.
pub fn swap_in(files: &SwapFiles, staged: &Path, from: Version, to: Version) -> io::Result<()> {
    // The new bytes reach the disk before any name points at them.
    OpenOptions::new().write(true).open(staged)?.sync_all()?;
    write_marker(
        files,
        &Marker {
            from,
            to,
            starts: 0,
        },
    )?;
    let prev = files.prev();
    match std::fs::remove_file(&prev) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    std::fs::hard_link(&files.exe, &prev)?;
    replace(staged, &files.exe)
}

/// Back to the previous exe: the failing running image gets a second name first (a power loss
/// right after it leaves that name behind: the repeat skips it).
fn rollback(files: &SwapFiles) -> io::Result<()> {
    if !files.failed().exists() {
        std::fs::hard_link(&files.exe, files.failed())?;
    }
    replace(&files.prev(), &files.exe)
}

/// `from` takes the place of `to` in one directory operation, on the disk before it returns.
fn replace(from: &Path, to: &Path) -> io::Result<()> {
    let flags = MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH;
    // SAFETY: two valid, NUL-terminated paths that outlive the call.
    unsafe {
        MoveFileExW(
            &HSTRING::from(from.as_os_str()),
            &HSTRING::from(to.as_os_str()),
            flags,
        )
    }
    .map_err(|e| io::Error::from_raw_os_error(e.code().0 & 0xFFFF))
}

fn remove(path: &Path) {
    if let Err(e) = std::fs::remove_file(path)
        && e.kind() != io::ErrorKind::NotFound
    {
        tracing::debug!(path = %path.display(), error = %e, "update leftover kept for now");
    }
}

/// The staged exe that may go in for the service `own`: the signed feed kept next to it
/// verifies with `keys`, is not older than the newest one accepted (`max_seq`: a release the
/// owner withdrew stays out, svcupd-a3) and lists a service above `own` that did not fail its
/// trial here, the file has that entry's size and SHA-256, and neither it nor the folder admits
/// writes by users (it will run as SYSTEM).
pub fn ready(
    files: &SwapFiles,
    keys: &[PublicKey],
    own: Version,
    max_seq: u64,
) -> Option<(PathBuf, Version)> {
    let bytes = std::fs::read(files.staging.join(FEED_FILE)).ok()?;
    let sig = std::fs::read_to_string(files.staging.join(SIG_FILE)).ok()?;
    let feed = verify(&bytes, &sig, keys).ok()?;
    let entry = feed.service.filter(|_| feed.seq >= max_seq)?;
    if entry.version <= own || failed_before(files, entry.version) {
        return None;
    }
    let path = files.staged(entry.version);
    if let Some(reason) = [&files.staging, &path]
        .into_iter()
        .find_map(|p| (files.vet)(p))
    {
        tracing::error!(%reason, "staged service update not used");
        return None;
    }
    let mut file = open_held(&path).ok()?;
    let size = file.metadata().ok()?.len();
    let sha = sha256_of(&mut file).ok()?;
    (size == entry.size && Some(sha) == parse_sha(&entry.sha256)).then_some((path, entry.version))
}

#[cfg(test)]
mod tests;
