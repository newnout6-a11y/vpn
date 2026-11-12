//! Self-removal never queues a path a reinstall could use again (review service-a3); a stop that
//! did not finish fails install and uninstall (review service-a13).
use std::path::PathBuf;

use windows::Win32::Foundation::{FreeLibrary, HMODULE};
use windows::Win32::System::LibraryLoader::{LOAD_LIBRARY_AS_IMAGE_RESOURCE, LoadLibraryExW};
use windows::core::HSTRING;

use super::*;

#[test]
fn a_stop_that_did_not_finish_is_a_failure() {
    assert!(stopped(Ok(true)).is_ok());
    let err = stopped(Ok(false)).expect_err("still stopping");
    assert_eq!(err.user_msg().key, "service.install.failed");
    assert!(
        stopped(Err(windows::core::Error::from_hresult(
            windows::core::HRESULT(-1)
        )))
        .is_err()
    );
}

/// A folder laid out like the install, its exe in use: a copy of a system DLL mapped as an image
/// stands in for the running exe (an image in use can be renamed, not deleted).
fn in_use(tag: &str) -> (PathBuf, PathBuf, HMODULE) {
    let dir = std::env::temp_dir().join(format!("vpnte-remove-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("sub")).expect("dirs");
    let exe = dir.join(EXE_NAME);
    let system = PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot"));
    std::fs::copy(system.join(r"System32\version.dll"), &exe).expect("stand-in exe");
    std::fs::write(dir.join("sing-box.exe"), b"engine").expect("engine");
    std::fs::write(dir.join(r"sub\x"), b"x").expect("file");
    // SAFETY: maps a copy of a system DLL as an image resource (no code runs); freed by the test.
    let image = unsafe {
        LoadLibraryExW(
            &HSTRING::from(exe.as_os_str()),
            None,
            LOAD_LIBRARY_AS_IMAGE_RESOURCE,
        )
    }
    .expect("mapped as an image");
    (dir, exe, image)
}

/// Unmaps the stand-in and removes the folder (tombstone included).
fn free(dir: &Path, image: HMODULE) {
    // SAFETY: the module `in_use` loaded, freed once.
    let _ = unsafe { FreeLibrary(image) };
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn an_exe_in_use_goes_to_a_tombstone_and_its_path_is_never_queued() {
    let (dir, exe, image) = in_use("unit");
    let deleted = std::fs::remove_file(&exe);
    let mut queued = Vec::new();
    remove_or_schedule(&dir, &mut |p: &Path| queued.push(p.to_owned()));
    // A reinstall before the restart writes the exe again at its path.
    let reinstalled = std::fs::write(&exe, b"reinstalled");
    free(&dir, image);
    assert!(deleted.is_err(), "an image in use cannot be deleted");
    reinstalled.expect("the exe's path is free again");
    assert!(!queued.contains(&exe), "{queued:?}");
    let tombstone = queued
        .first()
        .and_then(|p| p.file_name()?.to_str().map(str::to_owned));
    assert!(
        tombstone.is_some_and(|t| t.starts_with("vpnte-service.exe.") && t.ends_with(".deleted")),
        "{queued:?}"
    );
    // Then the folder (not empty while the tombstone exists); the engine and `sub` went now.
    assert_eq!(queued.get(1..), Some(&[dir.clone()][..]), "{queued:?}");
}

/// What Windows will do at the next restart: NT paths in pairs of source and target (an empty
/// target means "delete"), from both values the session manager reads at boot.
fn restart_queue() -> Vec<String> {
    [
        "PendingFileRenameOperations",
        "PendingFileRenameOperations2",
    ]
    .into_iter()
    .flat_map(session_manager_strings)
    .collect()
}

fn session_manager_strings(name: &str) -> Vec<String> {
    use windows::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_MULTI_SZ, RegGetValueW};
    let key = HSTRING::from(r"SYSTEM\CurrentControlSet\Control\Session Manager");
    let value = HSTRING::from(name);
    let mut len = 0u32;
    // SAFETY: a size query with a local out value.
    let _ = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            &key,
            &value,
            RRF_RT_REG_MULTI_SZ,
            None,
            None,
            Some(&mut len),
        )
    };
    // Room to spare: Windows Update may add entries between the two calls.
    let mut buf = vec![0u16; (len as usize).div_ceil(2) + 0x8000];
    let mut len = u32::try_from(buf.len() * 2).unwrap_or(u32::MAX);
    // SAFETY: `len` is the buffer's size in bytes; on return it says how much was written.
    let read = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            &key,
            &value,
            RRF_RT_REG_MULTI_SZ,
            None,
            Some(buf.as_mut_ptr().cast()),
            Some(&mut len),
        )
    };
    if read.is_err() {
        return Vec::new();
    }
    buf.truncate(len as usize / 2);
    buf.split(|&c| c == 0)
        .map(String::from_utf16_lossy)
        .collect()
}

/// Review service-a3 with the real queue: the tombstone and the folder are queued for deletion
/// at the next restart, the exe's own path never. The test deletes the queued files itself, and
/// Windows skips missing ones at that restart.
#[test]
#[ignore = "needs elevation"]
fn elevated_the_restart_queue_gets_the_tombstone_not_the_exe() {
    assert!(vpnte_winnet::elevation::is_elevated(), "run elevated");
    let (dir, exe, image) = in_use("queue");
    remove_or_schedule(&dir, &mut schedule);
    let queue = restart_queue();
    free(&dir, image);
    let nt = |p: &Path| format!(r"\??\{}", p.display());
    let tombstone_prefix = nt(&dir.join(format!("{EXE_NAME}.")));
    assert!(
        queue
            .iter()
            .any(|e| e.starts_with(&tombstone_prefix) && e.ends_with(".deleted")),
        "no tombstone queued: {queue:?}"
    );
    assert!(queue.contains(&nt(&dir)), "folder not queued");
    assert!(!queue.contains(&nt(&exe)), "the exe's path was queued");
}
