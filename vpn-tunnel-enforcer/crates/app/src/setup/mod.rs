//! Command-line paths that never open the UI (work package `app-setup`): `--version`, the
//! installer helper `--setup <command>` (contract: `installer/PROGRESS.md`), `--cleanup` and
//! `--smoke`. They run first in `main`, before the single-instance check, logging and the data
//! dir; they never show a window, a message box or a UAC prompt. Output is plain ASCII (the
//! installer decodes it as ANSI): information on stdout, one line on stderr when a command
//! fails. Exit codes: 0 success, 1 failed or refused, 2 usage error.
//!
//! The installer runs `--setup` elevated; everything else stays unelevated (NOADMIN §0): the
//! privileged parts of `--cleanup` run only when the process happens to be elevated and are
//! reported as needing administrator rights otherwise.
use std::process::ExitCode;

use crate::args::Args;

#[cfg(feature = "app-setup")]
pub mod gate;
#[cfg(feature = "app-setup")]
mod procs;
#[cfg(feature = "app-setup")]
mod shell;
#[cfg(feature = "app-setup")]
mod smoke;
#[cfg(feature = "app-setup")]
pub mod system;
#[cfg(all(test, feature = "app-setup"))]
mod tests;

/// `Some(code)` = exit with it without opening the UI.
pub fn run(args: &Args) -> Option<ExitCode> {
    if args.version {
        return Some(finish(End::Done(vec![
            env!("CARGO_PKG_VERSION").to_owned(),
        ])));
    }
    command(args).map(finish)
}

/// How a command ended (the installer's exit-code table).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum End {
    /// Done: the lines go to stdout.
    Done(Vec<String>),
    /// Failed or refused: the informational lines, then the one line for stderr.
    Failed(Vec<String>, String),
    /// Unknown command, missing or invalid option: the line for stderr.
    Usage(String),
}

impl End {
    fn failed(line: impl Into<String>) -> Self {
        End::Failed(Vec::new(), line.into())
    }

    /// 0 success, 1 failed / refused, 2 usage error.
    pub fn code(&self) -> u8 {
        match self {
            End::Done(_) => 0,
            End::Failed(..) => 1,
            End::Usage(_) => 2,
        }
    }
}

/// Prints the lines and returns the exit code. A write error (the installer closed its pipe) is
/// ignored: the exit code still tells the outcome, where `println!` would panic with 101.
fn finish(end: End) -> ExitCode {
    use std::io::Write;

    let (lines, error) = match &end {
        End::Done(lines) => (lines.as_slice(), None),
        End::Failed(lines, line) => (lines.as_slice(), Some(line)),
        End::Usage(line) => (&[][..], Some(line)),
    };
    let mut out = std::io::stdout().lock();
    for line in lines {
        let _ = writeln!(out, "{}", ascii_line(line));
    }
    let _ = out.flush();
    if let Some(line) = error {
        let _ = writeln!(std::io::stderr(), "{}", ascii_line(line));
    }
    ExitCode::from(end.code())
}

/// One line of printable ASCII: anything else becomes `?` (never a second line).
fn ascii_line(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c == ' ' || c.is_ascii_graphic() {
                c
            } else {
                '?'
            }
        })
        .collect()
}

/// A build without this package: the installer helper refuses, the rest opens the UI.
#[cfg(not(feature = "app-setup"))]
fn command(args: &Args) -> Option<End> {
    match &args.setup {
        Some(Err(usage)) => Some(End::Usage(usage.clone())),
        Some(Ok(_)) => Some(End::failed("Setup helper is not available in this build.")),
        None => None,
    }
}

/// `--setup` first (the installer's helper), then `--cleanup`, then `--smoke`.
#[cfg(feature = "app-setup")]
fn command(args: &Args) -> Option<End> {
    if let Some(setup) = &args.setup {
        return Some(match setup {
            Err(usage) => End::Usage(usage.clone()),
            Ok(setup) => installer(setup),
        });
    }
    if args.cleanup {
        return Some(cleanup());
    }
    if args.smoke {
        return Some(match smoke::smoke(args) {
            Ok(line) => End::Done(vec![line]),
            Err(line) => End::failed(line),
        });
    }
    None
}

/// One `--setup` command. Everything comes from `--install-dir`, never from the helper's own
/// name or location (the installer runs a copy from its temp folder).
#[cfg(feature = "app-setup")]
fn installer(setup: &crate::args::Setup) -> End {
    use crate::args::SetupCommand;

    let dir = setup.install_dir.as_deref();
    match setup.command {
        SetupCommand::AwaitShutdown { timeout_s } => {
            let runtime = shell::legacy_runtime_dir();
            let timeout = std::time::Duration::from_secs(u64::from(timeout_s));
            match gate::await_shutdown(&procs::RealProcesses, dir, runtime.as_deref(), timeout) {
                Ok(()) => End::Done(Vec::new()),
                Err(refusal) => End::failed(refusal.to_string()),
            }
        }
        SetupCommand::Uninstall => match dir {
            Some(dir) => uninstall(dir),
            None => End::failed("Installation path is missing; nothing was removed."),
        },
        SetupCommand::StampShortcuts => match dir.map(shell::stamp_shortcuts) {
            Some(Ok(lines)) => End::Done(lines),
            Some(Err(line)) => End::failed(line),
            None => End::failed("Installation path is missing; shortcuts not stamped."),
        },
        SetupCommand::LaunchAsUser => match dir.map(shell::launch_as_user) {
            Some(Ok(())) => End::Done(Vec::new()),
            Some(Err(line)) => End::failed(line),
            None => End::failed("Installation path is missing; not started."),
        },
    }
}

/// `--setup uninstall` (standalone uninstall, after `await-shutdown`): the network protection
/// first, which decides the exit code (strict filters would keep the PC offline without the
/// app); then, as warnings only, this user's tweaks, autostart and jump list. User data stays.
#[cfg(feature = "app-setup")]
fn uninstall(dir: &std::path::Path) -> End {
    use system::{Step, app_err};

    if !vpnte_winnet::elevation::is_elevated() {
        return End::failed(
            "Administrator rights are required to remove the network protection; nothing was removed.",
        );
    }
    if system::app_running() {
        return End::failed(
            "VPN Tunnel Enforcer is still running; quit it and retry. Nothing was removed.",
        );
    }
    let network = system::network(&dir.join("resources"), true);
    let mut lines: Vec<String> = network.iter().map(ToString::to_string).collect();
    if let Some(step) = network.iter().find(|s| !s.is_done()) {
        return End::Failed(lines, format!("Network protection cleanup failed: {step}."));
    }
    let warn = |step: Step| {
        if step.is_done() {
            step.to_string()
        } else {
            format!("warning: {step}")
        }
    };
    lines.push(match vpnte_core::paths::DataDirs::resolve() {
        Ok(dirs) => warn(system::tweaks(&dirs, true)),
        Err(err) => format!(
            "warning: {}: FAILED ({})",
            system::AREA_TWEAKS,
            app_err(&err)
        ),
    });
    lines.push(warn(system::autostart_value(&dir.join(gate::MAIN_EXE))));
    lines.push(match shell::remove_jump_list() {
        Ok(()) => "jump list: cleared".to_owned(),
        // No destinations file: nothing was ever recorded for our AUMID.
        Err(err) if err.code() == windows::Win32::Foundation::ERROR_FILE_NOT_FOUND.to_hresult() => {
            "jump list: cleared".to_owned()
        }
        Err(err) => format!(
            "warning: jump list: not cleared (0x{:08X})",
            err.code().0.cast_unsigned()
        ),
    });
    End::Done(lines)
}

/// `--cleanup`: removes what the app put into the system for this user (tweaks, autostart) and,
/// when elevated, our WFP objects and the old version's leftovers (the `sing-tun` firewall rule
/// included). Refused while the app runs: its filters, proxy and journal belong to it.
#[cfg(feature = "app-setup")]
fn cleanup() -> End {
    use system::Outcome;

    if system::app_running() {
        return End::failed(
            "VPN Tunnel Enforcer is running: quit it first, then run --cleanup again. Nothing was removed.",
        );
    }
    let dirs = match vpnte_core::paths::DataDirs::resolve() {
        Ok(dirs) => dirs,
        Err(err) => {
            return End::failed(format!(
                "Cannot locate the data folder ({}); nothing was removed.",
                system::app_err(&err)
            ));
        }
    };
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(err) => {
            return End::failed(format!(
                "Cannot locate this program ({}); nothing was removed.",
                gate::os_code(&err)
            ));
        }
    };
    let elevated = vpnte_winnet::elevation::is_elevated();
    let mut steps = system::network(&dirs.resources, elevated);
    steps.push(system::tweaks(&dirs, elevated));
    steps.push(system::autostart_value(&exe));
    let lines = steps.iter().map(ToString::to_string).collect();
    match steps.iter().find(|s| !s.is_done() && s.outcome != Outcome::NeedsAdmin) {
        Some(step) => End::Failed(lines, format!("Cleanup incomplete: {step}.")),
        None if steps.iter().all(system::Step::is_done) => End::Done(lines),
        None => End::Failed(
            lines,
            "Cleaned up for this user; the parts marked 'not checked' need administrator rights: run --cleanup as administrator.".to_owned(),
        ),
    }
}
