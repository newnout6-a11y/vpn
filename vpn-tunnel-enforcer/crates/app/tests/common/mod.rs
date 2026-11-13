//! Shared by the integration tests: a child process started as the app's main mode runs it,
//! unelevated. GitHub's Windows runners run the tests elevated (as the built-in Administrator),
//! and an elevated process ignores the `VPNTE_*` directory overrides (review 4533368399); the
//! child gets a LUA token like UAC's filtered one (Administrators and «local account and member of
//! Administrators» deny-only, no privileges, medium integrity), so it honours them and behaves as
//! an app the user started normally. The same token is used on an unelevated PC, so a local run
//! takes the path CI takes.
#![allow(dead_code)]

use std::ffi::{OsStr, OsString, c_void};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::time::Duration;

use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
use windows::Win32::Security::{
    CreateRestrictedToken, CreateWellKnownSid, DISABLE_MAX_PRIVILEGE, GetLengthSid,
    GetTokenInformation, LUA_TOKEN, PSID, SECURITY_MAX_SID_SIZE, SID_AND_ATTRIBUTES,
    SetTokenInformation, TOKEN_ADJUST_DEFAULT, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE,
    TOKEN_ELEVATION, TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TokenElevation, TokenIntegrityLevel,
    WELL_KNOWN_SID_TYPE, WinBuiltinAdministratorsSid, WinLocalAccountAndAdministratorSid,
    WinMediumLabelSid,
};
use windows::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW, GetCurrentProcess,
    GetExitCodeProcess, OpenProcessToken, PROCESS_INFORMATION, STARTUPINFOW, TerminateProcess,
    WaitForSingleObject,
};
use windows::core::{PCWSTR, PWSTR};

/// A started child, terminated on drop if it still runs.
pub struct Child {
    process: OwnedHandle,
    pid: u32,
}

impl Child {
    /// Starts `exe` with `args` and the test's environment plus `envs`, unelevated.
    pub fn spawn(exe: &Path, args: &[&str], envs: &[(&str, &OsStr)]) -> Self {
        let mut line = quote(exe.as_os_str());
        for arg in args {
            line.push(" ");
            line.push(quote(OsStr::new(arg)));
        }
        let mut line: Vec<u16> = line.encode_wide().chain([0]).collect();
        let app: Vec<u16> = exe.as_os_str().encode_wide().chain([0]).collect();
        let env = environment(envs);
        let startup = STARTUPINFOW {
            cb: size_of::<STARTUPINFOW>() as u32,
            ..Default::default()
        };
        let mut info = PROCESS_INFORMATION::default();
        let flags = CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW;
        let token = lowered_token();
        // SAFETY: NUL-terminated buffers that outlive the call, an environment block in the
        // format CREATE_UNICODE_ENVIRONMENT asks for, a token this process owns; the returned
        // handles are owned below.
        unsafe {
            CreateProcessAsUserW(
                Some(HANDLE(token.as_raw_handle())),
                PCWSTR(app.as_ptr()),
                Some(PWSTR(line.as_mut_ptr())),
                None,
                None,
                false,
                flags,
                Some(env.as_ptr().cast::<c_void>()),
                PCWSTR::null(),
                &startup,
                &mut info,
            )
            .unwrap();
            drop(OwnedHandle::from_raw_handle(info.hThread.0));
        }
        // SAFETY: a fresh process handle nothing else owns.
        let process = unsafe { OwnedHandle::from_raw_handle(info.hProcess.0) };
        let child = Self {
            process,
            pid: info.dwProcessId,
        };
        assert!(!child.elevated(), "the child runs unelevated");
        child
    }

    pub fn id(&self) -> u32 {
        self.pid
    }

    pub fn handle(&self) -> HANDLE {
        HANDLE(self.process.as_raw_handle())
    }

    /// The exit code within `limit`, `None` while it still runs.
    pub fn exit_within(&mut self, limit: Duration) -> Option<i32> {
        let ms = u32::try_from(limit.as_millis()).unwrap_or(u32::MAX);
        // SAFETY: our own child's handle.
        if unsafe { WaitForSingleObject(self.handle(), ms) } != WAIT_OBJECT_0 {
            return None;
        }
        let mut code = 0u32;
        // SAFETY: as above; the process has ended.
        unsafe { GetExitCodeProcess(self.handle(), &mut code) }.unwrap();
        Some(code as i32)
    }

    /// Ends the child and waits for it.
    pub fn kill(&mut self) {
        // SAFETY: our own child's handle.
        let _ = unsafe { TerminateProcess(self.handle(), 1) };
        let _ = self.exit_within(Duration::from_secs(10));
    }

    fn elevated(&self) -> bool {
        let mut token = HANDLE::default();
        // SAFETY: our own child's handle; the token is owned right after.
        unsafe { OpenProcessToken(self.handle(), TOKEN_QUERY, &mut token) }.unwrap();
        // SAFETY: a fresh token handle nothing else owns.
        let token = unsafe { OwnedHandle::from_raw_handle(token.0) };
        let mut elevation = TOKEN_ELEVATION::default();
        let mut len = 0u32;
        // SAFETY: a sized buffer of the asked class; the token has TOKEN_QUERY.
        unsafe {
            GetTokenInformation(
                HANDLE(token.as_raw_handle()),
                TokenElevation,
                Some((&raw mut elevation).cast::<c_void>()),
                size_of::<TOKEN_ELEVATION>() as u32,
                &mut len,
            )
        }
        .unwrap();
        elevation.TokenIsElevated != 0
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        if self.exit_within(Duration::ZERO).is_none() {
            self.kill();
        }
    }
}

/// A buffer holding the well-known SID `kind`.
fn well_known(kind: WELL_KNOWN_SID_TYPE) -> [u8; SECURITY_MAX_SID_SIZE as usize] {
    let mut sid = [0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut len = SECURITY_MAX_SID_SIZE;
    // SAFETY: a buffer of the maximum SID size, its size passed.
    unsafe { CreateWellKnownSid(kind, None, Some(PSID(sid.as_mut_ptr().cast())), &mut len) }
        .unwrap();
    sid
}

/// This process's token filtered the way UAC filters an administrator's (LUA_TOKEN; the
/// Administrators and «local account and member of Administrators» groups deny-only, no
/// privileges but SeChangeNotify) at medium integrity: without the second group the built-in
/// Administrator's token still counts as elevated. A restricted version of the caller's primary
/// token, which CreateProcessAsUserW accepts without SE_ASSIGNPRIMARYTOKEN.
fn lowered_token() -> OwnedHandle {
    let mut admins = well_known(WinBuiltinAdministratorsSid);
    let mut local_admin = well_known(WinLocalAccountAndAdministratorSid);
    let mut medium = well_known(WinMediumLabelSid);
    let medium = PSID(medium.as_mut_ptr().cast());
    let (mut process, mut lowered) = (HANDLE::default(), HANDLE::default());
    // SAFETY: the SID buffers live to the end of the block; the tokens are owned right after they
    // are opened; the label and its SID outlive SetTokenInformation.
    unsafe {
        let rights = TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ASSIGN_PRIMARY;
        OpenProcessToken(GetCurrentProcess(), rights, &mut process).unwrap();
        let _process = OwnedHandle::from_raw_handle(process.0);
        let deny = [admins.as_mut_ptr(), local_admin.as_mut_ptr()].map(|sid| SID_AND_ATTRIBUTES {
            Sid: PSID(sid.cast()),
            Attributes: 0,
        });
        CreateRestrictedToken(
            process,
            DISABLE_MAX_PRIVILEGE | LUA_TOKEN,
            Some(&deny),
            None,
            None,
            &mut lowered,
        )
        .unwrap();
        let lowered_owned = OwnedHandle::from_raw_handle(lowered.0);
        // 0x20 = SE_GROUP_INTEGRITY.
        let label = TOKEN_MANDATORY_LABEL {
            Label: SID_AND_ATTRIBUTES {
                Sid: medium,
                Attributes: 0x20,
            },
        };
        let size = size_of::<TOKEN_MANDATORY_LABEL>() as u32 + GetLengthSid(medium);
        SetTokenInformation(
            lowered,
            TokenIntegrityLevel,
            (&raw const label).cast(),
            size,
        )
        .unwrap();
        lowered_owned
    }
}

/// `arg` quoted for the command line when it holds a space (none of the tests' arguments holds a
/// quote or a trailing backslash).
fn quote(arg: &OsStr) -> OsString {
    let text = arg.to_string_lossy();
    assert!(!text.contains('"'), "no quotes in test arguments");
    if text.is_empty() || text.contains([' ', '\t']) {
        let mut quoted = OsString::from("\"");
        quoted.push(arg);
        quoted.push("\"");
        quoted
    } else {
        arg.to_owned()
    }
}

/// The test's environment with `envs` set, as a sorted CREATE_UNICODE_ENVIRONMENT block.
fn environment(envs: &[(&str, &OsStr)]) -> Vec<u16> {
    let mut vars: Vec<(OsString, OsString)> = std::env::vars_os()
        .filter(|(name, _)| {
            !envs
                .iter()
                .any(|(n, _)| name.to_string_lossy().eq_ignore_ascii_case(n))
        })
        .collect();
    vars.extend(
        envs.iter()
            .map(|(n, v)| (OsString::from(n), v.to_os_string())),
    );
    vars.sort_by_key(|(name, _)| name.to_string_lossy().to_uppercase());
    let mut block = Vec::new();
    for (name, value) in vars {
        block.extend(name.encode_wide());
        block.push(u16::from(b'='));
        block.extend(value.encode_wide());
        block.push(0);
    }
    block.push(0);
    block
}
