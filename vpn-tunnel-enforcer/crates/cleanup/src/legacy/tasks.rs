//! The old SYSTEM boot-recovery tasks (spec §2.7, §6.6 step 7). A task is deleted only when it
//! provably is ours: principal SYSTEM and exactly one action that runs `vpnte-recover.ps1`
//! through Windows PowerShell, in any of the three historical forms. The autostart task
//! `\VPN Tunnel Enforcer` is not touched here: the app's `autostart::sync` re-points or deletes
//! it (same task name as the old app).
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use vpnte_winnet::autostart::{self, ExecAction, TaskInfo};
use windows::Win32::Foundation::{ERROR_DIR_NOT_EMPTY, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{LookupAccountNameW, PSID, SID_NAME_USE};
use windows::core::{HSTRING, PWSTR};

use super::report::{Outcome, StepId, StepRecord};

/// `\VPNTE\BootRecoveryTask` (since 2026-09-30) and the older root task.
pub(crate) const BOOT_TASKS: [&str; 2] = [r"\VPNTE\BootRecoveryTask", r"\VPNTE Boot Recovery"];
pub(crate) const TASK_FOLDER: &str = r"\VPNTE";
const SCRIPT: &str = "vpnte-recover.ps1";
const SYSTEM_SID: &str = "S-1-5-18";

/// The old boot-recovery task, judged with `is_system` for the principal.
pub(crate) fn is_boot_task(task: &TaskInfo, is_system: impl Fn(&str) -> bool) -> bool {
    task.other_actions == 0
        && matches!(task.exec.as_slice(), [action] if runs_recover_script(action))
        && is_system(&task.user_id)
}

/// `powershell`, `powershell.exe` or `…\WindowsPowerShell\v1.0\powershell.exe`, with the script
/// named in the arguments (`-File "…\vpnte-recover.ps1"`) or inside `-EncodedCommand <b64>`.
fn runs_recover_script(action: &ExecAction) -> bool {
    let path = action.path.trim().trim_matches('"').to_lowercase();
    let powershell = path == "powershell"
        || path == "powershell.exe"
        || path.ends_with(r"\windowspowershell\v1.0\powershell.exe");
    powershell
        && (action.arguments.to_lowercase().contains(SCRIPT)
            || encoded_command(&action.arguments)
                .is_some_and(|c| c.to_lowercase().contains(SCRIPT)))
}

/// The UTF-16LE text of a `-EncodedCommand <base64>` argument.
fn encoded_command(arguments: &str) -> Option<String> {
    let mut tokens = arguments.split_whitespace();
    tokens.find(|t| t.eq_ignore_ascii_case("-EncodedCommand"))?;
    let bytes = STANDARD.decode(tokens.next()?.trim_matches('"')).ok()?;
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&pair| u16::from_le_bytes(pair))
        .collect();
    Some(String::from_utf16_lossy(&units))
}

/// The principal resolves to `S-1-5-18` (a SID string, or a possibly localized account name).
pub(crate) fn resolves_to_system(user_id: &str) -> bool {
    let user_id = user_id.trim();
    // `get`: a principal name may start with multi-byte characters.
    if user_id
        .get(..4)
        .is_some_and(|head| head.eq_ignore_ascii_case("S-1-"))
    {
        return user_id.eq_ignore_ascii_case(SYSTEM_SID);
    }
    account_sid(user_id).is_some_and(|sid| sid == SYSTEM_SID)
}

/// `LookupAccountNameW` + `ConvertSidToStringSidW`; `None` when the name does not resolve.
fn account_sid(name: &str) -> Option<String> {
    let name = HSTRING::from(name);
    let (mut sid_len, mut domain_len) = (0u32, 0u32);
    let mut kind = SID_NAME_USE::default();
    // SAFETY: size query with null buffers; the call fails with ERROR_INSUFFICIENT_BUFFER and
    // fills both lengths.
    let _ = unsafe {
        LookupAccountNameW(
            None,
            &name,
            None,
            &mut sid_len,
            None,
            &mut domain_len,
            &mut kind,
        )
    };
    if sid_len == 0 {
        return None;
    }
    let mut sid = vec![0u8; sid_len as usize];
    let mut domain = vec![0u16; domain_len.max(1) as usize];
    // SAFETY: both buffers have the sizes the first call asked for.
    unsafe {
        LookupAccountNameW(
            None,
            &name,
            Some(PSID(sid.as_mut_ptr().cast())),
            &mut sid_len,
            Some(PWSTR(domain.as_mut_ptr())),
            &mut domain_len,
            &mut kind,
        )
    }
    .ok()?;
    let mut text = PWSTR::null();
    // SAFETY: `sid` holds the SID just written; `text` is freed with LocalFree below.
    unsafe { ConvertSidToStringSidW(PSID(sid.as_mut_ptr().cast()), &mut text) }.ok()?;
    // SAFETY: a NUL-terminated string allocated by the call.
    let out = unsafe { text.to_string() }.ok();
    // SAFETY: allocated with LocalAlloc by ConvertSidToStringSidW, freed once.
    unsafe { LocalFree(Some(HLOCAL(text.0.cast()))) };
    out
}

/// Step 7 (deleting a SYSTEM task needs elevation).
pub(crate) fn clean() -> StepRecord {
    let step = StepId::Tasks;
    let (mut removed, mut kept, mut errors) = (Vec::new(), Vec::new(), Vec::new());
    for path in BOOT_TASKS {
        match autostart::read_task(path) {
            Ok(None) => {}
            Ok(Some(task)) if is_boot_task(&task, resolves_to_system) => {
                match autostart::delete_task(path) {
                    Ok(_) => removed.push(path),
                    Err(e) => errors.push(format!("{path}: {e}")),
                }
            }
            Ok(Some(_)) => kept.push(path),
            Err(e) => errors.push(format!("{path}: {e}")),
        }
    }
    let folder = match autostart::delete_task_folder(TASK_FOLDER) {
        Ok(true) => "folder removed",
        Ok(false) => "no folder",
        Err(e) if e.code() == ERROR_DIR_NOT_EMPTY.to_hresult() => "folder kept (not empty)",
        Err(e) => {
            errors.push(format!("{TASK_FOLDER}: {e}"));
            "folder not removed"
        }
    };
    let mut detail = format!("removed [{}]; {folder}", removed.join(", "));
    if !kept.is_empty() {
        detail.push_str(&format!("; not ours, kept [{}]", kept.join(", ")));
    }
    let outcome = match (errors.is_empty(), kept.is_empty()) {
        (false, _) => {
            detail.push_str(&format!("; failed: {}", errors.join("; ")));
            Outcome::Failed
        }
        (true, false) => Outcome::Skipped,
        (true, true) => Outcome::Done,
    };
    StepRecord::new(step, outcome, detail)
        .changed(!removed.is_empty() || folder == "folder removed")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task(user: &str, path: &str, arguments: &str) -> TaskInfo {
        TaskInfo {
            user_id: user.into(),
            enabled: true,
            exec: vec![ExecAction {
                path: path.into(),
                arguments: arguments.into(),
            }],
            other_actions: 0,
        }
    }

    fn encoded(script: &str) -> String {
        let units: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
        format!(
            "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {}",
            STANDARD.encode(units)
        )
    }

    const PS: &str = r"C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe";
    const FILE_ARGS: &str = r#"-NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\VPN Tunnel Enforcer\resources\vpnte-recover.ps1""#;
    const SCRIPT_CALL: &str =
        r"& 'C:\Program Files\VPN Tunnel Enforcer\resources\vpnte-recover.ps1'";

    /// §2.7 / §7.10: all three historical forms of the old task are recognised.
    #[test]
    fn recognises_every_historical_form() {
        let system = |u: &str| u == "SYSTEM";
        assert!(is_boot_task(
            &task("SYSTEM", "powershell", FILE_ARGS),
            system
        ));
        assert!(is_boot_task(
            &task("SYSTEM", "powershell.exe", &encoded(SCRIPT_CALL)),
            system
        ));
        assert!(is_boot_task(
            &task("SYSTEM", PS, &encoded(SCRIPT_CALL)),
            system
        ));
        assert!(is_boot_task(
            &task(
                "SYSTEM",
                r"%WINDIR%\System32\WindowsPowerShell\v1.0\powershell.exe",
                &encoded(SCRIPT_CALL)
            ),
            system
        ));
        assert!(is_boot_task(
            &task("SYSTEM", &format!("\"{PS}\""), FILE_ARGS),
            system
        ));
    }

    /// AT-03-003 (`bootRecoveryTaskReadBack.test.ts`): foreign tasks are kept.
    #[test]
    fn keeps_foreign_tasks() {
        let system = |u: &str| u == "SYSTEM";
        assert!(!is_boot_task(
            &task("SYSTEM", "cmd.exe", "/c foo.bat"),
            system
        ));
        assert!(!is_boot_task(
            &task("S-1-5-32-544", "powershell", FILE_ARGS),
            resolves_to_system
        ));
        assert!(!is_boot_task(
            &task("nobody-at-all", "powershell", FILE_ARGS),
            system
        ));
        assert!(!is_boot_task(
            &task("SYSTEM", r"C:\Tools\powershell.exe", FILE_ARGS),
            system
        ));
        assert!(!is_boot_task(
            &task("SYSTEM", r"C:\x\pwsh.exe", FILE_ARGS),
            system
        ));
        assert!(!is_boot_task(
            &task("SYSTEM", "powershell", "-File other.ps1"),
            system
        ));
        assert!(!is_boot_task(
            &task("SYSTEM", "powershell", &encoded("& 'C:\\other.ps1'")),
            system
        ));
        assert!(!is_boot_task(
            &task("SYSTEM", "powershell", "-EncodedCommand !!notbase64!!"),
            system
        ));
        let mut two = task("SYSTEM", "powershell", FILE_ARGS);
        two.exec.push(two.exec[0].clone());
        assert!(!is_boot_task(&two, system));
        let mut none = task("SYSTEM", "powershell", FILE_ARGS);
        none.exec.clear();
        assert!(!is_boot_task(&none, system));
        let mut extra = task("SYSTEM", "powershell", FILE_ARGS);
        extra.other_actions = 1;
        assert!(!is_boot_task(&extra, system));
    }

    /// §7.9 task ownership: `SYSTEM`, `S-1-5-18`, `NT AUTHORITY\SYSTEM` accepted; Administrators
    /// and unresolvable accounts rejected. Resolves names through the real account database
    /// (read-only); a principal starting with multi-byte characters must not panic.
    #[test]
    fn principal_resolution() {
        assert!(resolves_to_system("S-1-5-18"));
        assert!(resolves_to_system("s-1-5-18"));
        assert!(resolves_to_system("SYSTEM"));
        assert!(resolves_to_system(r"NT AUTHORITY\SYSTEM"));
        assert!(!resolves_to_system("S-1-5-32-544"));
        assert!(!resolves_to_system("S-1-5-18-1"));
        assert!(!resolves_to_system("no-such-account-vpnte-test"));
        assert!(!resolves_to_system("账户不存在vpnte"));
        assert!(!resolves_to_system(""));
        let me = std::env::var("USERNAME").unwrap_or_default();
        assert!(!resolves_to_system(&me));
    }
}
