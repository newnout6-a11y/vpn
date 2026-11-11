//! Typed helpers over the Reg* API.
//!
//! "Not found" is a value (`None` / `false`), never an error, so a caller can always tell an
//! absent value from one it could not read (the tweak journal must abort on the latter).
use windows::Win32::Foundation::{
    E_INVALIDARG, ERROR_FILE_NOT_FOUND, ERROR_INVALID_DATA, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS,
    ERROR_SUCCESS, ERROR_UNSUPPORTED_TYPE, WIN32_ERROR,
};
use windows::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_ENUMERATE_SUB_KEYS,
    KEY_QUERY_VALUE, KEY_READ, KEY_SET_VALUE, KEY_WOW64_32KEY, KEY_WOW64_64KEY, KEY_WRITE,
    REG_CREATE_KEY_DISPOSITION, REG_CREATED_NEW_KEY, REG_DWORD, REG_EXPAND_SZ, REG_MULTI_SZ,
    REG_NONE, REG_OPTION_NON_VOLATILE, REG_SAM_FLAGS, REG_SZ, REG_VALUE_TYPE, RegCreateKeyExW,
    RegDeleteKeyExW, RegDeleteTreeW, RegDeleteValueW, RegEnumKeyExW, RegEnumValueW, RegOpenKeyExW,
    RegQueryInfoKeyW, RegQueryValueExW, RegSetValueExW,
};
use windows::core::{Error, Owned, PCWSTR, PWSTR, Result};

/// The standard `DELETE` access right (not part of the generated `REG_SAM_FLAGS` constants).
const DELETE: REG_SAM_FLAGS = REG_SAM_FLAGS(0x0001_0000);
/// Rights `RegDeleteTreeW` needs on the key it empties.
const TREE_DELETE: REG_SAM_FLAGS =
    REG_SAM_FLAGS(DELETE.0 | KEY_ENUMERATE_SUB_KEYS.0 | KEY_QUERY_VALUE.0 | KEY_SET_VALUE.0);
/// Registry limits in UTF-16 units, plus the terminating NUL.
const MAX_KEY_NAME: usize = 255 + 1;
const MAX_VALUE_NAME: usize = 16_383 + 1;

/// Root of a registry path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Hive {
    /// The account this process runs as (an over-the-shoulder elevation makes it the admin's).
    CurrentUser,
    LocalMachine,
    /// `HKU`: loaded user hives by SID (`<sid>\Software\…`).
    Users,
}

impl Hive {
    fn hkey(self) -> HKEY {
        match self {
            Hive::CurrentUser => HKEY_CURRENT_USER,
            Hive::LocalMachine => HKEY_LOCAL_MACHINE,
            Hive::Users => HKEY_USERS,
        }
    }
}

/// Registry view a path resolves in (WOW64 redirects parts of `HKLM\SOFTWARE` for 32-bit code).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum View {
    /// The view of this process (64-bit for our x64 binary).
    #[default]
    Native,
    Bits64,
    Bits32,
}

impl View {
    fn sam(self) -> REG_SAM_FLAGS {
        match self {
            View::Native => REG_SAM_FLAGS(0),
            View::Bits64 => KEY_WOW64_64KEY,
            View::Bits32 => KEY_WOW64_32KEY,
        }
    }
}

/// What an opened key may be used for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Access {
    Read,
    ReadWrite,
}

impl Access {
    fn sam(self) -> REG_SAM_FLAGS {
        match self {
            Access::Read => KEY_READ,
            Access::ReadWrite => KEY_READ | KEY_WRITE,
        }
    }
}

/// A typed registry value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Sz(String),
    /// `REG_EXPAND_SZ`, kept unexpanded (`%VAR%` stays literal).
    ExpandSz(String),
    MultiSz(Vec<String>),
    Dword(u32),
    /// Any other type (`REG_BINARY`, `REG_QWORD`, ...), kept raw so it can be written back as is.
    Raw {
        kind: u32,
        data: Vec<u8>,
    },
}

/// An open registry key, closed on drop.
#[derive(Debug)]
pub struct Key {
    hkey: Owned<HKEY>,
    view: View,
}

// SAFETY: a registry handle is not bound to the thread that opened it.
unsafe impl Send for Key {}

impl Key {
    /// Opens `path` under `hive`; `None` when the key does not exist.
    pub fn open(hive: Hive, path: &str, access: Access, view: View) -> Result<Option<Key>> {
        open_raw(hive.hkey(), path, access.sam(), view)
    }

    /// Opens or creates `path` (with any missing parents) for reading and writing; the flag is
    /// `true` when this call created the key itself.
    pub fn create(hive: Hive, path: &str, view: View) -> Result<(Key, bool)> {
        let path = wide(path)?;
        let mut hkey = HKEY::default();
        let mut disposition = REG_CREATE_KEY_DISPOSITION::default();
        // SAFETY: `path` is NUL-terminated and outlives the call; both out-pointers are valid.
        unsafe {
            RegCreateKeyExW(
                hive.hkey(),
                PCWSTR(path.as_ptr()),
                None,
                PCWSTR::null(),
                REG_OPTION_NON_VOLATILE,
                Access::ReadWrite.sam() | view.sam(),
                None,
                &mut hkey,
                Some(&mut disposition),
            )
        }
        .ok()?;
        // SAFETY: the call succeeded, so `hkey` is a fresh handle we own.
        let key = Key {
            hkey: unsafe { Owned::new(hkey) },
            view,
        };
        Ok((key, disposition == REG_CREATED_NEW_KEY))
    }

    /// Opens a subkey of this key in the same view; `None` when it does not exist.
    pub fn open_subkey(&self, name: &str, access: Access) -> Result<Option<Key>> {
        open_raw(*self.hkey, name, access.sam(), self.view)
    }

    /// Reads a value of any type; `None` when it does not exist.
    pub fn value(&self, name: &str) -> Result<Option<Value>> {
        let name = wide(name)?;
        let mut buf: Vec<u8> = Vec::new();
        // The value can grow between the size query and the read: retry a few times.
        for _ in 0..8 {
            let mut kind = REG_NONE;
            let mut size = buf.len() as u32;
            let data = (!buf.is_empty()).then_some(buf.as_mut_ptr());
            // SAFETY: `name` is NUL-terminated; `data` is null or points to `size` writable bytes.
            let rc = unsafe {
                RegQueryValueExW(
                    *self.hkey,
                    PCWSTR(name.as_ptr()),
                    None,
                    Some(&mut kind),
                    data,
                    Some(&mut size),
                )
            };
            match rc {
                ERROR_SUCCESS if data.is_some() || size == 0 => {
                    buf.truncate(size as usize);
                    return decode(kind, buf).map(Some);
                }
                ERROR_SUCCESS | ERROR_MORE_DATA => buf.resize(size as usize, 0),
                ERROR_FILE_NOT_FOUND => return Ok(None),
                rc => return Err(rc.into()),
            }
        }
        Err(ERROR_MORE_DATA.into())
    }

    /// Reads a `REG_SZ` or `REG_EXPAND_SZ` value (unexpanded); another type is an error.
    pub fn string(&self, name: &str) -> Result<Option<String>> {
        match self.value(name)? {
            None => Ok(None),
            Some(Value::Sz(s) | Value::ExpandSz(s)) => Ok(Some(s)),
            Some(_) => Err(ERROR_UNSUPPORTED_TYPE.into()),
        }
    }

    /// Reads a `REG_DWORD` value; another type is an error.
    pub fn dword(&self, name: &str) -> Result<Option<u32>> {
        match self.value(name)? {
            None => Ok(None),
            Some(Value::Dword(v)) => Ok(Some(v)),
            Some(_) => Err(ERROR_UNSUPPORTED_TYPE.into()),
        }
    }

    /// Reads a `REG_MULTI_SZ` value; another type is an error.
    pub fn multi_string(&self, name: &str) -> Result<Option<Vec<String>>> {
        match self.value(name)? {
            None => Ok(None),
            Some(Value::MultiSz(v)) => Ok(Some(v)),
            Some(_) => Err(ERROR_UNSUPPORTED_TYPE.into()),
        }
    }

    /// Writes a value, replacing its data and type.
    pub fn set(&self, name: &str, value: &Value) -> Result<()> {
        let name = wide(name)?;
        let (kind, data) = encode(value)?;
        // SAFETY: `name` is NUL-terminated and both buffers outlive the call.
        unsafe { RegSetValueExW(*self.hkey, PCWSTR(name.as_ptr()), None, kind, Some(&data)) }.ok()
    }

    /// Writes a `REG_SZ` value.
    pub fn set_string(&self, name: &str, text: &str) -> Result<()> {
        self.set(name, &Value::Sz(text.to_owned()))
    }

    /// Writes a `REG_EXPAND_SZ` value.
    pub fn set_expand_string(&self, name: &str, text: &str) -> Result<()> {
        self.set(name, &Value::ExpandSz(text.to_owned()))
    }

    /// Writes a `REG_DWORD` value.
    pub fn set_dword(&self, name: &str, value: u32) -> Result<()> {
        self.set(name, &Value::Dword(value))
    }

    /// Writes a `REG_MULTI_SZ` value (empty items are refused: they would end the list).
    pub fn set_multi_string<S: AsRef<str>>(&self, name: &str, items: &[S]) -> Result<()> {
        let items = items.iter().map(|s| s.as_ref().to_owned()).collect();
        self.set(name, &Value::MultiSz(items))
    }

    /// Deletes a value; `false` when it did not exist.
    pub fn delete_value(&self, name: &str) -> Result<bool> {
        let name = wide(name)?;
        // SAFETY: `name` is NUL-terminated and outlives the call.
        found(unsafe { RegDeleteValueW(*self.hkey, PCWSTR(name.as_ptr())) })
    }

    /// Names of the direct subkeys (lossy UTF-16 decoding).
    pub fn subkey_names(&self) -> Result<Vec<String>> {
        let mut buf = vec![0u16; MAX_KEY_NAME];
        enumerate(|index| {
            let mut len = buf.len() as u32;
            let name = PWSTR(buf.as_mut_ptr());
            // SAFETY: `name` points to `len` writable UTF-16 units; the other outputs are unused.
            let rc = unsafe {
                RegEnumKeyExW(
                    *self.hkey,
                    index,
                    Some(name),
                    &mut len,
                    None,
                    None,
                    None,
                    None,
                )
            };
            (
                rc,
                String::from_utf16_lossy(&buf[..len.min(buf.len() as u32) as usize]),
            )
        })
    }

    /// Names of the values of this key (lossy UTF-16 decoding; `""` is the default value).
    pub fn value_names(&self) -> Result<Vec<String>> {
        let mut buf = vec![0u16; MAX_VALUE_NAME];
        enumerate(|index| {
            let mut len = buf.len() as u32;
            let name = PWSTR(buf.as_mut_ptr());
            // SAFETY: `name` points to `len` writable UTF-16 units; the other outputs are unused.
            let rc = unsafe {
                RegEnumValueW(
                    *self.hkey,
                    index,
                    Some(name),
                    &mut len,
                    None,
                    None,
                    None,
                    None,
                )
            };
            (
                rc,
                String::from_utf16_lossy(&buf[..len.min(buf.len() as u32) as usize]),
            )
        })
    }

    /// `true` when the key has neither subkeys nor values.
    pub fn is_empty(&self) -> Result<bool> {
        let (mut subkeys, mut values) = (0u32, 0u32);
        // SAFETY: only the two counters are requested; both point to live locals.
        unsafe {
            RegQueryInfoKeyW(
                *self.hkey,
                None,
                None,
                None,
                Some(&mut subkeys),
                None,
                None,
                Some(&mut values),
                None,
                None,
                None,
                None,
            )
        }
        .ok()?;
        Ok(subkeys == 0 && values == 0)
    }
}

/// Deletes `path` if it has no subkeys (its values go with it); `false` when it did not exist.
pub fn delete_key(hive: Hive, path: &str, view: View) -> Result<bool> {
    let path = wide(checked_path(path)?)?;
    // SAFETY: `path` is NUL-terminated and outlives the call.
    found(unsafe { RegDeleteKeyExW(hive.hkey(), PCWSTR(path.as_ptr()), view.sam().0, None) })
}

/// Deletes `path` with all its subkeys and values; `false` when it did not exist.
pub fn delete_tree(hive: Hive, path: &str, view: View) -> Result<bool> {
    let path = checked_path(path)?;
    let Some(key) = open_raw(hive.hkey(), path, TREE_DELETE, view)? else {
        return Ok(false);
    };
    // Empty the key through its own handle, then delete it by name: `RegDeleteTreeW` has no
    // view parameter, `RegDeleteKeyExW` has one.
    // SAFETY: `key` is open with the rights `RegDeleteTreeW` requires; a null subkey means "this key".
    unsafe { RegDeleteTreeW(*key.hkey, PCWSTR::null()) }.ok()?;
    drop(key);
    delete_key(hive, path, view)
}

/// An empty path would address the hive root itself: refuse it for deletions.
fn checked_path(path: &str) -> Result<&str> {
    let path = path.trim_matches('\\');
    if path.is_empty() {
        return Err(E_INVALIDARG.into());
    }
    Ok(path)
}

fn found(rc: WIN32_ERROR) -> Result<bool> {
    match rc {
        ERROR_SUCCESS => Ok(true),
        ERROR_FILE_NOT_FOUND => Ok(false),
        rc => Err(rc.into()),
    }
}

/// Runs an `RegEnum*` step for index 0, 1, ... until `ERROR_NO_MORE_ITEMS`.
fn enumerate(mut step: impl FnMut(u32) -> (WIN32_ERROR, String)) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for index in 0.. {
        match step(index) {
            (ERROR_SUCCESS, name) => names.push(name),
            (ERROR_NO_MORE_ITEMS, _) => break,
            (rc, _) => return Err(rc.into()),
        }
    }
    Ok(names)
}

fn open_raw(parent: HKEY, path: &str, sam: REG_SAM_FLAGS, view: View) -> Result<Option<Key>> {
    let path = wide(path)?;
    let mut hkey = HKEY::default();
    // SAFETY: `path` is NUL-terminated and outlives the call; `hkey` is a valid out-pointer.
    let rc = unsafe {
        RegOpenKeyExW(
            parent,
            PCWSTR(path.as_ptr()),
            None,
            sam | view.sam(),
            &mut hkey,
        )
    };
    match rc {
        // SAFETY: the call succeeded, so `hkey` is a fresh handle we own.
        ERROR_SUCCESS => Ok(Some(Key {
            hkey: unsafe { Owned::new(hkey) },
            view,
        })),
        ERROR_FILE_NOT_FOUND => Ok(None),
        rc => Err(rc.into()),
    }
}

/// NUL-terminated UTF-16; an interior NUL would silently cut the name, so it is refused.
fn wide(s: &str) -> Result<Vec<u16>> {
    if s.contains('\0') {
        return Err(E_INVALIDARG.into());
    }
    Ok(crate::win::wide(s))
}

fn encode(value: &Value) -> Result<(REG_VALUE_TYPE, Vec<u8>)> {
    fn utf16_bytes(units: impl Iterator<Item = u16>) -> Vec<u8> {
        units.flat_map(u16::to_le_bytes).collect()
    }
    fn sz(text: &str) -> Result<Vec<u8>> {
        Ok(utf16_bytes(wide(text)?.into_iter()))
    }
    Ok(match value {
        Value::Sz(text) => (REG_SZ, sz(text)?),
        Value::ExpandSz(text) => (REG_EXPAND_SZ, sz(text)?),
        Value::MultiSz(items) => {
            if items.iter().any(String::is_empty) {
                return Err(E_INVALIDARG.into());
            }
            let mut units = Vec::new();
            for item in items {
                units.extend(wide(item)?);
            }
            // The list ends with an empty string; an empty list is that terminator alone.
            units.push(0);
            (REG_MULTI_SZ, utf16_bytes(units.into_iter()))
        }
        Value::Dword(v) => (REG_DWORD, v.to_le_bytes().to_vec()),
        Value::Raw { kind, data } => (REG_VALUE_TYPE(*kind), data.clone()),
    })
}

fn decode(kind: REG_VALUE_TYPE, data: Vec<u8>) -> Result<Value> {
    // Strings may lack their terminator or carry several; text ends at the first NUL like for
    // every C consumer (Explorer reading the environment, for one).
    let units = || -> Vec<u16> {
        let (pairs, _odd_byte) = data.as_chunks::<2>();
        pairs.iter().map(|pair| u16::from_le_bytes(*pair)).collect()
    };
    let text =
        |units: &[u16]| String::from_utf16(units).map_err(|_| Error::from(ERROR_INVALID_DATA));
    let until_nul = |units: &[u16]| units.iter().position(|&u| u == 0).unwrap_or(units.len());
    match kind {
        REG_SZ | REG_EXPAND_SZ => {
            let units = units();
            let s = text(&units[..until_nul(&units)])?;
            Ok(if kind == REG_SZ {
                Value::Sz(s)
            } else {
                Value::ExpandSz(s)
            })
        }
        REG_MULTI_SZ => {
            let units = units();
            let items = units
                .split(|&u| u == 0)
                .take_while(|item| !item.is_empty())
                .map(text)
                .collect::<Result<Vec<_>>>()?;
            Ok(Value::MultiSz(items))
        }
        REG_DWORD => {
            let bytes: [u8; 4] = data
                .as_slice()
                .try_into()
                .map_err(|_| Error::from(ERROR_INVALID_DATA))?;
            Ok(Value::Dword(u32::from_le_bytes(bytes)))
        }
        _ => Ok(Value::Raw { kind: kind.0, data }),
    }
}

/// A throw-away key `HKCU\Software\VPNTE-Test-<unique>`, deleted with its contents on drop.
#[cfg(test)]
pub(crate) struct TestKey {
    pub path: String,
}

#[cfg(test)]
impl TestKey {
    pub fn new() -> Self {
        use std::sync::atomic::{AtomicU32, Ordering};
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = format!(
            r"Software\VPNTE-Test-{:x}-{nanos:x}-{n}",
            std::process::id()
        );
        Self { path }
    }
}

#[cfg(test)]
impl Drop for TestKey {
    fn drop(&mut self) {
        let _ = delete_tree(Hive::CurrentUser, &self.path, View::Native);
    }
}

#[cfg(test)]
mod tests;
