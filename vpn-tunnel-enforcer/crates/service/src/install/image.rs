//! The install verb's own exe. The verb runs elevated from the per-user app folder, which every
//! process of that user may change. Reading `vpnte-service.exe` by path seconds later (after the
//! old service stopped and the engines were copied) would let such a process rename the running
//! exe away and put its own file at the path, and SYSTEM would run code nobody approved. So the
//! verb starts by opening the running exe with read sharing only (from then on nobody can write,
//! rename or delete it, and nobody holds it open for writing), proves that this handle is the very
//! file the process was started from, and copies exactly the bytes read through it.
//!
//! The proof compares files, not names: `NtAreMappedFilesTheSame` takes the process's mapped
//! image and a read-only mapping of the handle, and the kernel answers whether both are backed by
//! the same file (it compares the files' section object pointers). Names could be fooled by
//! renaming folders between two queries.
use std::ffi::c_void;
use std::fs::File;
use std::io::Read;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::FILE_SHARE_READ;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Memory::{
    CreateFileMappingW, FILE_MAP_READ, MapViewOfFile, PAGE_READONLY, UnmapViewOfFile,
};
use windows::core::PCWSTR;

#[link(name = "ntdll", kind = "raw-dylib")]
unsafe extern "system" {
    /// `STATUS_SUCCESS` (0) when the image mapped at `image` and the file mapped at `file` are
    /// backed by the same file.
    fn NtAreMappedFilesTheSame(image: *const c_void, file: *const c_void) -> i32;
}

/// Why the running exe was not taken.
#[derive(Debug, thiserror::Error)]
pub enum ImageError {
    #[error("the running exe cannot be opened for a locked read: {0}")]
    Open(std::io::Error),
    /// Renamed away and replaced after the process started.
    #[error("the file at the exe's path is not the file this process runs")]
    Replaced,
    #[error("the running exe cannot be read: {0}")]
    Read(std::io::Error),
}

/// The bytes of the exe this process runs, read through a handle that denies writers, renames and
/// deletes, once that handle is proven to be the running image.
pub fn read_running_exe() -> Result<Vec<u8>, ImageError> {
    let path = std::env::current_exe().map_err(ImageError::Open)?;
    let file = open_locked(&path).map_err(ImageError::Open)?;
    if !is_running_image(&file) {
        return Err(ImageError::Replaced);
    }
    let mut bytes = Vec::new();
    (&file).read_to_end(&mut bytes).map_err(ImageError::Read)?;
    Ok(bytes)
}

/// Opens `path` for reading with read sharing only: the open fails while anyone holds the file
/// open for writing or deleting, and while the handle lives nobody can write, rename or delete it.
fn open_locked(path: &Path) -> std::io::Result<File> {
    std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ.0)
        .open(path)
}

/// The process's exe image and a read-only mapping of `file` are the same file (`false` when
/// either cannot be mapped or compared: an empty file cannot be our image).
fn is_running_image(file: &File) -> bool {
    let handle = HANDLE(file.as_raw_handle());
    // SAFETY: `handle` is a valid file handle for the call; the mapping handle is closed below
    // (a view keeps its section alive).
    let mapping = unsafe { CreateFileMappingW(handle, None, PAGE_READONLY, 0, 0, PCWSTR::null()) };
    let Ok(mapping) = mapping else {
        return false;
    };
    // SAFETY: a valid read-only mapping of the whole file.
    let view = unsafe { MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0) };
    // SAFETY: our own mapping handle, closed once.
    let _ = unsafe { CloseHandle(mapping) };
    if view.Value.is_null() {
        return false;
    }
    // SAFETY: `GetModuleHandleW(null)` is this process's exe image, mapped for the process's
    // lifetime; `view` is a live mapping until it is unmapped below.
    let same = unsafe {
        GetModuleHandleW(PCWSTR::null())
            .is_ok_and(|image| NtAreMappedFilesTheSame(image.0, view.Value) == 0)
    };
    // SAFETY: the view mapped above, unmapped once.
    let _ = unsafe { UnmapViewOfFile(view) };
    same
}

#[cfg(test)]
mod tests;
