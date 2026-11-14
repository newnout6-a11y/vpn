//! Processes by image-path prefix, and the bounded terminate-and-wait that sweeps orphaned
//! engines of older builds. Only directories we own are ever swept; a candidate whose image path
//! cannot be read is reported as unknown, never treated as absent.
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use vpnte_base::{AppError, ErrorKind, Msg};
use windows::Win32::Foundation::{ERROR_NO_MORE_FILES, HANDLE, WAIT_OBJECT_0, WIN32_ERROR};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE, TerminateProcess,
    WaitForSingleObject,
};
use windows::core::Owned;

use super::image::{self, ImageError, STILL_ACTIVE};
use crate::win;

/// How long one name group may take to exit after termination (the old stop script's 3 s).
const EXIT_WAIT: Duration = Duration::from_secs(3);
/// Longest accepted prefix, in characters (old validator).
const MAX_PREFIX: usize = 2048;

/// Why a scan or sweep could not run.
#[derive(Debug, thiserror::Error)]
pub enum SweepError {
    /// A prefix is not a plain absolute local directory; rejected before any process is read.
    #[error("unsafe directory prefix {0:?}")]
    UnsafePrefix(String),
    /// The process list could not be read to its end: nothing can be proven.
    #[error("process enumeration failed")]
    Enumeration(#[source] windows::core::Error),
    /// A candidate had PID 0 or appeared twice in one snapshot.
    #[error("inconsistent process snapshot")]
    Inconsistent,
}

/// A process whose image lies under one of our directories.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedProc {
    pub pid: u32,
    pub path: PathBuf,
}

/// Why a candidate's ownership is unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownReason {
    /// Listed by two snapshots in a row but gone each time it was opened.
    Vanished,
    /// The process could not be opened (access denied or another OS error).
    OpenFailed,
    /// Opened, but its image path is unreadable and it has not provably exited.
    PathUnreadable,
}

/// A candidate (matching name) whose ownership could not be established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownProc {
    pub pid: u32,
    pub name: String,
    pub reason: UnknownReason,
}

/// Result of [`find_under`].
#[derive(Debug, Default)]
pub struct ProcessScan {
    pub owned: Vec<OwnedProc>,
    pub unknown: Vec<UnknownProc>,
}

/// Result of [`sweep_orphans`].
#[derive(Debug, Default)]
pub struct SweepReport {
    /// Orphans whose exit we observed (a signalled process handle is the proof).
    pub stopped: Vec<OwnedProc>,
    /// Orphans still running after the wait, or that we are not allowed to terminate.
    pub survived: Vec<OwnedProc>,
    /// Candidates of unknown ownership: reported, never treated as absent.
    pub unknown: Vec<UnknownProc>,
}

impl SweepReport {
    /// True when no orphan is left running and nothing is unknown.
    pub fn is_clean(&self) -> bool {
        self.survived.is_empty() && self.unknown.is_empty()
    }

    /// The most important fact for the user (survivors, then unknowns, then stopped orphans);
    /// `None` when nothing was found.
    pub fn summary(&self) -> Option<Msg> {
        let (key, count) = if !self.survived.is_empty() {
            ("winnet.process.sweep.survived", self.survived.len())
        } else if !self.unknown.is_empty() {
            ("winnet.process.sweep.unknown", self.unknown.len())
        } else if !self.stopped.is_empty() {
            ("winnet.process.sweep.stopped", self.stopped.len())
        } else {
            return None;
        };
        Some(Msg::new(key).arg("count", count))
    }
}

impl From<SweepError> for AppError {
    fn from(err: SweepError) -> Self {
        let (kind, key) = match &err {
            SweepError::UnsafePrefix(_) => (ErrorKind::Validation, "winnet.process.unsafeDir"),
            SweepError::Enumeration(_) | SweepError::Inconsistent => {
                (ErrorKind::Internal, "winnet.process.listUnreadable")
            }
        };
        AppError::msg(kind, Msg::new(key)).with_source(err)
    }
}

/// Accepts only a plain absolute local directory (`X:\…`) and returns it as UTF-16 with exactly
/// one trailing backslash. Rejects empty, relative, UNC and `\\?\` forms, forward slashes, empty,
/// `.`/`..` or dot/space-terminated segments (Windows strips those, so they alias other folders),
/// alternate data streams, control characters, quotes, wildcards, a bare drive and > 2048 chars.
fn validate_prefix(prefix: &Path) -> Result<Vec<u16>, SweepError> {
    let reject = || SweepError::UnsafePrefix(prefix.display().to_string());
    let s = prefix.to_str().ok_or_else(reject)?;
    let b = s.as_bytes();
    let drive = b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\';
    if !drive || s.chars().count() > MAX_PREFIX {
        return Err(reject());
    }
    let rest = &s[3..];
    let bad =
        |c: char| c.is_control() || matches!(c, '/' | '"' | ':' | '*' | '?' | '<' | '>' | '|');
    let rest = rest.strip_suffix('\\').unwrap_or(rest);
    let bad_segment = |seg: &str| seg.is_empty() || seg.ends_with('.') || seg.ends_with(' ');
    if rest.is_empty() || rest.chars().any(bad) || rest.split('\\').any(bad_segment) {
        return Err(reject());
    }
    Ok(format!("{}\\{rest}\\", &s[..2]).encode_utf16().collect())
}

/// What a candidate is, from what could be read about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    Owned,
    Foreign,
    Exited,
    Unknown,
}

/// `path` is `None` when unreadable; then only an exit code other than STILL_ACTIVE proves the
/// candidate gone (259 can also be a real exit code, which stays unknown).
fn classify(path: Option<&[u16]>, exit_code: Option<u32>, dirs: &[Vec<u16>]) -> Class {
    match path {
        Some(p) if dirs.iter().any(|d| image::is_under(p, d)) => Class::Owned,
        Some(_) => Class::Foreign,
        None if exit_code.is_some_and(|c| c != STILL_ACTIVE) => Class::Exited,
        None => Class::Unknown,
    }
}

/// One snapshot row.
struct Entry {
    pid: u32,
    name: Vec<u16>,
}

/// A candidate under our directories, with the handle its path was read from: terminating
/// through the same handle leaves no PID-reuse window.
struct Candidate {
    group: usize,
    pid: u32,
    path: PathBuf,
    handle: Owned<HANDLE>,
    can_terminate: bool,
}

struct Scan {
    owned: Vec<Candidate>,
    unknown: Vec<UnknownProc>,
    vanished: bool,
}

fn snapshot() -> Result<Vec<Entry>, SweepError> {
    // SAFETY: plain call; the handle is owned right below.
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
        .map_err(SweepError::Enumeration)?;
    // SAFETY: the snapshot handle is ours and closed only by `Owned`.
    let snap = unsafe { Owned::new(snap) };
    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut rows = Vec::new();
    // SAFETY: `entry` is a valid PROCESSENTRY32W with `dwSize` set, for both calls.
    let mut step = unsafe { Process32FirstW(*snap, &mut entry) };
    loop {
        if let Err(err) = step {
            end_of_list(err)?;
            return Ok(rows);
        }
        rows.push(Entry {
            pid: entry.th32ProcessID,
            name: win::until_nul(&entry.szExeFile).to_vec(),
        });
        // SAFETY: as above.
        step = unsafe { Process32NextW(*snap, &mut entry) };
    }
}

/// The walk must end with ERROR_NO_MORE_FILES; any other error leaves the list incomplete.
fn end_of_list(err: windows::core::Error) -> Result<(), SweepError> {
    match WIN32_ERROR::from_error(&err) {
        Some(ERROR_NO_MORE_FILES) => Ok(()),
        _ => Err(SweepError::Enumeration(err)),
    }
}

/// PID 0 or a duplicate PID among the candidates means the snapshot cannot be trusted.
fn check_candidates(pids: &[u32]) -> Result<(), SweepError> {
    let mut seen = std::collections::HashSet::new();
    if pids.iter().any(|&pid| pid == 0 || !seen.insert(pid)) {
        return Err(SweepError::Inconsistent);
    }
    Ok(())
}

fn scan(prefixes: &[PathBuf], names: &[&str], terminate: bool) -> Result<Scan, SweepError> {
    let dirs = prefixes
        .iter()
        .map(|p| validate_prefix(p))
        .collect::<Result<Vec<_>, _>>()?;
    let names: Vec<Vec<u16>> = names.iter().map(|n| n.encode_utf16().collect()).collect();
    let first = scan_once(&dirs, &names, terminate, false)?;
    // One fresh full re-scan when a candidate vanished mid-scan; a second time it stays unknown.
    if first.vanished {
        scan_once(&dirs, &names, terminate, true)
    } else {
        Ok(first)
    }
}

fn scan_once(
    dirs: &[Vec<u16>],
    names: &[Vec<u16>],
    terminate: bool,
    last: bool,
) -> Result<Scan, SweepError> {
    let me = std::process::id();
    let entries = snapshot()?;
    let matches: Vec<(usize, &Entry)> = entries
        .iter()
        .filter_map(|e| {
            names
                .iter()
                .position(|n| win::eq_ignore_case(&e.name, n))
                .map(|g| (g, e))
        })
        .collect();
    check_candidates(&matches.iter().map(|(_, e)| e.pid).collect::<Vec<_>>())?;
    let mut scan = Scan {
        owned: Vec::new(),
        unknown: Vec::new(),
        vanished: false,
    };
    for (group, e) in matches.into_iter().filter(|(_, e)| e.pid != me) {
        let unknown = |reason| UnknownProc {
            pid: e.pid,
            name: String::from_utf16_lossy(&e.name),
            reason,
        };
        match probe(e.pid, dirs, terminate) {
            Probe::Owned {
                path,
                handle,
                can_terminate,
            } => {
                scan.owned.push(Candidate {
                    group,
                    pid: e.pid,
                    path,
                    handle,
                    can_terminate,
                });
            }
            Probe::Skip => {}
            Probe::Vanished if !last => scan.vanished = true,
            Probe::Vanished => scan.unknown.push(unknown(UnknownReason::Vanished)),
            Probe::Unknown(reason) => scan.unknown.push(unknown(reason)),
        }
    }
    Ok(scan)
}

enum Probe {
    Owned {
        path: PathBuf,
        handle: Owned<HANDLE>,
        can_terminate: bool,
    },
    Skip,
    Vanished,
    Unknown(UnknownReason),
}

fn probe(pid: u32, dirs: &[Vec<u16>], terminate: bool) -> Probe {
    let base = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE;
    let opened = match terminate.then(|| image::open(pid, base | PROCESS_TERMINATE)) {
        Some(Ok(handle)) => Ok((handle, true)),
        // Without elevation an elevated orphan is readable but not killable: still report it.
        Some(Err(ImageError::Denied)) | None => image::open(pid, base).map(|h| (h, false)),
        Some(Err(err)) => Err(err),
    };
    let (handle, can_terminate) = match opened {
        Ok(opened) => opened,
        Err(ImageError::Gone) => return Probe::Vanished,
        Err(err) => {
            tracing::debug!(pid, error = %err, "process scan: candidate cannot be opened");
            return Probe::Unknown(UnknownReason::OpenFailed);
        }
    };
    let path = image::query_image(*handle).ok();
    let wide: Option<Vec<u16>> = path.as_ref().map(|p| p.as_os_str().encode_wide().collect());
    match (
        classify(wide.as_deref(), image::exit_code(*handle), dirs),
        path,
    ) {
        (Class::Owned, Some(path)) => Probe::Owned {
            path,
            handle,
            can_terminate,
        },
        (Class::Unknown, _) => Probe::Unknown(UnknownReason::PathUnreadable),
        _ => Probe::Skip,
    }
}

/// Processes named one of `names` (case-insensitive) whose image lies under one of `prefixes`,
/// plus the candidates whose ownership is unknown. Our own process is never listed.
pub fn find_under(prefixes: &[PathBuf], names: &[&str]) -> Result<ProcessScan, SweepError> {
    let scan = scan(prefixes, names, false)?;
    Ok(ProcessScan {
        owned: scan
            .owned
            .into_iter()
            .map(|c| OwnedProc {
                pid: c.pid,
                path: c.path,
            })
            .collect(),
        unknown: scan.unknown,
    })
}

/// Terminates the processes [`find_under`] finds and waits for them, group by group in the
/// order of `names` (pass the TUN consumer first: `vpnte-sing-box.exe` before its upstreams),
/// each group at most 3 s. A failed group does not stop the next one; everything is reported.
/// Blocking: run it on a blocking thread.
pub fn sweep_orphans(prefixes: &[PathBuf], names: &[&str]) -> Result<SweepReport, SweepError> {
    let Scan {
        mut owned, unknown, ..
    } = scan(prefixes, names, true)?;
    let mut report = SweepReport {
        unknown,
        ..SweepReport::default()
    };
    owned.sort_by_key(|c| c.group);
    for group in owned.chunk_by(|a, b| a.group == b.group) {
        for c in group.iter().filter(|c| c.can_terminate) {
            // SAFETY: the handle is valid and was opened with PROCESS_TERMINATE.
            if let Err(err) = unsafe { TerminateProcess(*c.handle, 1) } {
                // Typically "access denied" because it has already exited; the wait decides.
                tracing::debug!(pid = c.pid, error = %err, "orphan sweep: terminate failed");
            }
        }
        let deadline = Instant::now() + EXIT_WAIT;
        for c in group {
            let wait = if c.can_terminate {
                deadline.saturating_duration_since(Instant::now())
            } else {
                Duration::ZERO
            };
            // SAFETY: the handle is valid and was opened with SYNCHRONIZE.
            let exited =
                unsafe { WaitForSingleObject(*c.handle, wait.as_millis() as u32) } == WAIT_OBJECT_0;
            let proc = OwnedProc {
                pid: c.pid,
                path: c.path.clone(),
            };
            if exited {
                report.stopped.push(proc)
            } else {
                report.survived.push(proc)
            }
        }
    }
    if !(report.stopped.is_empty() && report.is_clean()) {
        tracing::info!(
            stopped = report.stopped.len(),
            survived = report.survived.len(),
            unknown = report.unknown.len(),
            "orphan sweep finished"
        );
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use windows::Win32::Foundation::ERROR_ACCESS_DENIED;

    use super::super::job::tests::{long_ping, system_ping};
    use super::super::{Job, spawn_hidden};
    use super::*;
    use crate::test_support::TempDir;

    fn w(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    /// AT-02-009 (ownedRuntimePidCore.test.ts): unsafe directories are rejected before any read.
    #[test]
    fn unsafe_prefixes_are_rejected() {
        let long = format!("C:\\{}", "a".repeat(2050));
        for bad in [
            "",
            "relative",
            r"\\server\share",
            "C:/runtime",
            r"C:\..\runtime",
            r"C:\.\runtime",
            r"C:\runtime:stream",
            "C:\\run\u{1}time",
            "C:\\run\"time",
            r"C:\",
            r"C:\a\\b",
            r"C:\runtime.",
            r"C:\runtime ",
            r"\\?\C:\runtime",
            r"C:\run*",
            long.as_str(),
        ] {
            assert!(
                validate_prefix(Path::new(bad)).is_err(),
                "{bad:?} must be rejected"
            );
        }
        assert_eq!(
            validate_prefix(Path::new(r"C:\VPNTE\runtime")).unwrap(),
            w(r"C:\VPNTE\runtime\")
        );
        assert_eq!(
            validate_prefix(Path::new(r"c:\VPNTE\runtime\")).unwrap(),
            w(r"c:\VPNTE\runtime\")
        );
    }

    /// AT-02-001 / AT-02-009: path identity of orphan candidates (tunnel-core §7.24, firewall §7.7).
    #[test]
    fn candidates_are_classified_by_path_and_exit_code() {
        let dirs = [w(r"C:\runtime\"), w(r"C:\VPN\runtime\")];
        let class = |p: Option<&str>, code| classify(p.map(w).as_deref(), code, &dirs);
        assert_eq!(class(Some(r"C:\runtime\xray.exe"), None), Class::Owned);
        assert_eq!(
            class(Some(r"c:\vpn\RUNTIME\sub\vpnte-sing-box.exe"), None),
            Class::Owned
        );
        assert_eq!(class(Some(r"C:\foreign\xray.exe"), None), Class::Foreign);
        assert_eq!(
            class(Some(r"C:\VPN\runtime-evil\vpnte-xray.exe"), None),
            Class::Foreign
        );
        assert_eq!(class(None, Some(0)), Class::Exited);
        assert_eq!(class(None, Some(STILL_ACTIVE)), Class::Unknown);
        assert_eq!(class(None, None), Class::Unknown);
    }

    /// AT-02-009: the walk must end with ERROR_NO_MORE_FILES (18); PID 0 / duplicates are errors.
    #[test]
    fn incomplete_or_inconsistent_snapshots_are_errors() {
        assert!(end_of_list(ERROR_NO_MORE_FILES.into()).is_ok());
        assert!(matches!(
            end_of_list(ERROR_ACCESS_DENIED.into()),
            Err(SweepError::Enumeration(_))
        ));
        assert!(check_candidates(&[8, 12]).is_ok());
        assert!(matches!(
            check_candidates(&[0]),
            Err(SweepError::Inconsistent)
        ));
        assert!(matches!(
            check_candidates(&[8, 12, 8]),
            Err(SweepError::Inconsistent)
        ));
    }

    #[test]
    fn summary_names_the_most_important_fact() {
        let p = |pid| OwnedProc {
            pid,
            path: PathBuf::from(r"C:\e\vpnte-xray.exe"),
        };
        let mut report = SweepReport::default();
        assert_eq!(report.summary(), None);
        report.stopped.push(p(8));
        let stopped = Msg::new("winnet.process.sweep.stopped").arg("count", 1);
        assert_eq!(report.summary(), Some(stopped));
        report.survived.push(p(12));
        assert_eq!(
            report.summary().unwrap().key,
            "winnet.process.sweep.survived"
        );
        let err: AppError = SweepError::UnsafePrefix(String::new()).into();
        assert_eq!(err.kind, ErrorKind::Validation);
    }

    #[test]
    fn our_own_process_is_never_a_candidate() {
        let exe = std::env::current_exe().unwrap();
        let dir = exe.parent().unwrap().to_path_buf();
        let name = exe.file_name().unwrap().to_str().unwrap();
        let scan = find_under(&[dir], &[name]).unwrap();
        assert!(scan.owned.iter().all(|p| p.pid != std::process::id()));
    }

    /// AT-02-001: an orphan under our directory is found and stopped; the same image elsewhere
    /// is foreign. The orphan is a copy of ping.exe started by this test (loopback only), inside a
    /// kill-on-close job so that a failed assertion cannot leave it running.
    #[tokio::test]
    async fn sweep_stops_an_orphan_under_our_directory() {
        let dir = TempDir::new("sweep");
        let exe = dir.path().join("vpnte-test-orphan.exe");
        std::fs::copy(system_ping(), &exe).unwrap();
        let job = Job::kill_on_close().unwrap();
        let mut orphan = spawn_hidden(&mut long_ping(&exe), &job).unwrap();
        let pid = orphan.id().unwrap();
        let (dirs, names) = ([dir.path().to_path_buf()], ["VPNTE-TEST-ORPHAN.EXE"]);

        let found = find_under(&dirs, &names).unwrap();
        assert!(found.owned.iter().any(|p| p.pid == pid), "{found:?}");
        let other = TempDir::new("sweep-other");
        let elsewhere = find_under(&[other.path().to_path_buf()], &names).unwrap();
        assert!(elsewhere.owned.is_empty() && elsewhere.unknown.is_empty());

        let report = sweep_orphans(&dirs, &names).unwrap();
        assert!(report.stopped.iter().any(|p| p.pid == pid), "{report:?}");
        assert!(report.is_clean());
        orphan.wait().await.unwrap();
    }
}
