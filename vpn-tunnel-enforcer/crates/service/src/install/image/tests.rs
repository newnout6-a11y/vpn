//! What Windows does with a running exe, checked on the machine rather than assumed: it can be
//! renamed (not deleted) while it runs, `read_running_exe` then refuses the file put at its old
//! path, and once the exe is locked it cannot be renamed. Each case runs in a copy of this test
//! binary started as a child process: the image under test must be a process's own exe.
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use windows::Win32::System::LibraryLoader::LoadLibraryW;
use windows::Win32::System::ProcessStatus::GetMappedFileNameW;
use windows::Win32::System::Threading::GetCurrentProcess;
use windows::core::HSTRING;

use super::*;

/// Set in the child: the folder the parent and the child signal through.
const PROBE_ENV: &str = "VPNTE_IMAGE_PROBE";
/// A copy of a system DLL the parent plants next to the probe exe.
const PLANTED_DLL: &str = "vpnte-probe.dll";
const WAIT: Duration = Duration::from_secs(60);

fn wait_for(path: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while !path.exists() {
        if Instant::now() > deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    true
}

/// What `GetMappedFileNameW` reports for this process's exe image (an NT path).
fn mapped_name() -> String {
    let mut buf = [0u16; 1024];
    // SAFETY: this process's own exe image base and a local buffer.
    let len = unsafe {
        let Ok(image) = GetModuleHandleW(PCWSTR::null()) else {
            return String::new();
        };
        GetMappedFileNameW(GetCurrentProcess(), image.0, &mut buf)
    };
    String::from_utf16_lossy(&buf[..len as usize])
}

/// The child, set up like the install verb's `main`: waits for `go`, reads its own exe the way
/// `install` does, holds the lock while it reports (outcome, lock held, mapped name, whether a DLL
/// planted next to the exe loads by name) and until `done`.
#[test]
#[ignore = "child process of the running-image tests"]
fn image_probe_child() {
    let Some(dir) = std::env::var_os(PROBE_ENV).map(PathBuf::from) else {
        return;
    };
    crate::install::system_dlls_only();
    assert!(wait_for(&dir.join("go"), WAIT), "no go from the parent");
    let exe = std::env::current_exe().expect("own exe");
    let outcome = match read_running_exe() {
        Err(ImageError::Replaced) => "replaced".to_owned(),
        Err(e) => format!("failed: {e}"),
        Ok(bytes) if std::fs::read(&exe).is_ok_and(|b| b == bytes) => "read same".to_owned(),
        Ok(_) => "read different".to_owned(),
    };
    let lock = open_locked(&exe).ok().filter(is_running_image);
    // SAFETY: loads a copy of a system DLL (or nothing); the process ends right after.
    let planted = unsafe { LoadLibraryW(&HSTRING::from(PLANTED_DLL)) }.is_ok();
    let report = format!(
        "{outcome}\n{}\n{}\n{planted}",
        lock.is_some(),
        mapped_name()
    );
    std::fs::write(dir.join("result.tmp"), report).expect("report");
    std::fs::rename(dir.join("result.tmp"), dir.join("result")).expect("report");
    if lock.is_some() {
        wait_for(&dir.join("done"), WAIT);
    }
}

/// A copy of this test binary in a fresh folder, started as the probe child.
fn probe(tag: &str) -> (PathBuf, Child) {
    let dir = std::env::temp_dir().join(format!("vpnte-image-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("probe dir");
    let exe = dir.join("probe.exe");
    std::fs::copy(std::env::current_exe().expect("test exe"), &exe).expect("copy");
    let child = Command::new(&exe)
        .args([
            "install::image::tests::image_probe_child",
            "--exact",
            "--ignored",
        ])
        .env(PROBE_ENV, &dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("probe child");
    (dir, child)
}

/// The child's report (the child is killed when it does not report in time).
fn report(dir: &Path, child: &mut Child) -> Vec<String> {
    if !wait_for(&dir.join("result"), WAIT) {
        let _ = child.kill();
    }
    let text = std::fs::read_to_string(dir.join("result")).unwrap_or_default();
    text.lines().map(str::to_owned).collect()
}

fn end(dir: &Path, mut child: Child) {
    let _ = std::fs::write(dir.join("done"), b"");
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(dir);
}

/// A scanner may hold a fresh exe open for a moment: retried briefly.
fn rename_retrying(from: &Path, to: &Path) -> std::io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match std::fs::rename(from, to) {
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            done => return done,
        }
    }
}

/// Review service-a5: the swap the elevated install verb must survive, and a DLL planted next to
/// it after the start is not loaded by name.
#[test]
fn a_running_exe_renamed_and_replaced_is_refused() {
    let (dir, mut child) = probe("swap");
    let (exe, moved) = (dir.join("probe.exe"), dir.join("moved.exe"));
    let system = PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot"));
    std::fs::copy(system.join(r"System32\version.dll"), dir.join(PLANTED_DLL)).expect("plant");
    let renamed = rename_retrying(&exe, &moved);
    let deleted = std::fs::remove_file(&moved);
    std::fs::write(&exe, b"MZ not the running image").expect("a new file at the old path");
    std::fs::write(dir.join("go"), b"").expect("go");
    let lines = report(&dir, &mut child);
    end(&dir, child);
    renamed.expect("Windows lets a running exe be renamed");
    assert!(deleted.is_err(), "a running exe cannot be deleted");
    assert_eq!(
        lines.first().map(String::as_str),
        Some("replaced"),
        "{lines:?}"
    );
    assert_eq!(lines.get(1).map(String::as_str), Some("false"), "{lines:?}");
    // GetMappedFileNameW follows the rename: it names the image's new path.
    let mapped = lines
        .get(2)
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    assert!(mapped.ends_with(r"\moved.exe"), "{lines:?}");
    assert_eq!(lines.get(3).map(String::as_str), Some("false"), "{lines:?}");
}

/// The bytes are the running exe's, and while the lock is held the exe cannot be renamed.
#[test]
fn a_locked_exe_is_read_whole_and_cannot_be_renamed() {
    let (dir, mut child) = probe("lock");
    std::fs::write(dir.join("go"), b"").expect("go");
    let lines = report(&dir, &mut child);
    let renamed = std::fs::rename(dir.join("probe.exe"), dir.join("other.exe"));
    end(&dir, child);
    assert_eq!(
        lines.first().map(String::as_str),
        Some("read same"),
        "{lines:?}"
    );
    assert_eq!(lines.get(1).map(String::as_str), Some("true"), "{lines:?}");
    assert!(renamed.is_err(), "renamed while locked");
}
