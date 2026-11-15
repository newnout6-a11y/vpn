//! `vpnte-service.exe`.
//!
//! - `run`: started by the SCM (the registered command line); runs the service (its Settings >
//!   Apps entry first names this version).
//! - `install [--resources <dir>]`: elevated; copies this exe and the pinned engine files into
//!   Program Files, registers and starts the service.
//! - `uninstall`: stops and removes the service and its folders; run unelevated (a quiet-uninstall
//!   tool such as winget) it asks Windows to run `uninstall --approved` elevated, which never asks
//!   again, and returns that run's exit code.
//! - `request-install [--resources <dir>]`: unelevated (the per-user installer); asks Windows to
//!   run `install` elevated (Windows shows its one prompt) and returns that run's exit code.
//! - `request-uninstall`: unelevated (the service's entry in Settings > Apps); lets go of its
//!   console, asks Windows to run `uninstall --approved` elevated the same way, says the outcome in
//!   one calm message box (none when the service is gone or nobody approved) and returns that run's
//!   exit code.
//! - `forget-me`: unelevated (the per-user uninstaller); tells the service this user is gone.
//! - `status`: unelevated; the installed service answers over its pipe (CI's smoke run).
//!
//! Exit codes: 0 done, 1 failed (reason on stderr, English log text), 2 bad arguments,
//! 3 the service stays to remove its network filters later (`service.uninstall.filtersKept`),
//! 4 an upgrade failed and the service is stopped until Windows starts it
//! (`service.install.notRestarted`), 5 nobody approved the prompt (`request-install`,
//! `request-uninstall`), 6 the service is removed but files another program holds stay in its
//! folder (`service.uninstall.filesLeft`).
use std::path::PathBuf;
use std::process::ExitCode;

use vpnte_service::install::entry;
use vpnte_service::install::flow::{
    EXIT_FILES_LEFT, EXIT_FILTERS_KEPT, EXIT_NOT_RESTARTED, FILES_LEFT, FILTERS_KEPT, NOT_RESTARTED,
};
use vpnte_service::per_user::{self, Elevated};
use vpnte_service::pipe::client::CallError;
use vpnte_service::{install, scm, service};

const USAGE: &str = "usage: vpnte-service (run | install [--resources <dir>] | uninstall | \
request-install [--resources <dir>] | request-uninstall | forget-me | status)";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["run"] => match scm::dispatch::dispatch(run) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("not started by the Service Control Manager: {err}");
                ExitCode::FAILURE
            }
        },
        ["install", rest @ ..] => {
            let Some(resources) = resources(rest) else {
                return usage();
            };
            // First, before anything slow: this exe runs from the per-user app folder, so its
            // bytes are taken now through a locked handle, and later DLLs only from System32.
            install::system_dlls_only();
            let source = install::Source::current(resources);
            console_log();
            let done = source.and_then(|s| install::install(&s));
            report(done.map(|exe| eprintln!("installed: {}", exe.display())))
        }
        ["uninstall"] => uninstall(false),
        ["uninstall", per_user::APPROVED] => uninstall(true),
        ["request-install", rest @ ..] => {
            let Some(resources) = resources(rest) else {
                return usage();
            };
            request_install(resources)
        }
        ["request-uninstall"] => request_uninstall(),
        // Started by the service's own removal only (lab F-8): what its process held goes now.
        ["sweep", pid] => {
            install::system_dlls_only();
            console_log();
            report(install::sweep(pid))
        }
        ["forget-me"] => forget_me(),
        ["status"] => status(),
        _ => usage(),
    }
}

/// The service body: Settings > Apps names this version (a swap may have brought it), then the
/// service runs.
fn run(control: scm::dispatch::Control) -> u32 {
    install::relist();
    service::run(control)
}

/// `[]` or `["--resources", dir]`; `None` = bad arguments.
fn resources(rest: &[&str]) -> Option<Option<PathBuf>> {
    match rest {
        [] => Some(None),
        ["--resources", dir] => Some(Some(PathBuf::from(dir))),
        _ => None,
    }
}

fn usage() -> ExitCode {
    eprintln!("{USAGE}");
    ExitCode::from(2)
}

fn console_log() {
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_max_level(tracing::Level::INFO)
        .try_init();
}

/// The exit code of a result: the "kept" and "left" outcomes have their own codes.
fn code_of(key: &str) -> ExitCode {
    match key {
        FILTERS_KEPT => ExitCode::from(EXIT_FILTERS_KEPT),
        NOT_RESTARTED => ExitCode::from(EXIT_NOT_RESTARTED),
        FILES_LEFT => ExitCode::from(EXIT_FILES_LEFT),
        _ => ExitCode::FAILURE,
    }
}

/// `uninstall`: runs here when elevated (an elevated tool, SYSTEM, or the run Windows approved);
/// a quiet-uninstall tool with an ordinary token gets Windows' prompt instead of a refusal
/// (tailsa-b3). `approved`: Windows ran it after its prompt, so it never asks again.
fn uninstall(approved: bool) -> ExitCode {
    if !approved && !vpnte_winnet::elevation::is_elevated() {
        return match std::env::current_exe() {
            Ok(exe) => elevated_exit(
                "uninstall",
                per_user::request_uninstall(&exe),
                "nothing changed",
            ),
            Err(err) => {
                eprintln!("failed: own path unknown ({err})");
                ExitCode::FAILURE
            }
        };
    }
    install::system_dlls_only();
    console_log();
    report(install::uninstall().map(|()| eprintln!("uninstalled")))
}

fn report(result: vpnte_base::AppResult<()>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            let key = err.user_msg().key;
            eprintln!("failed: {key} ({:?})", err.source);
            code_of(&key)
        }
    }
}

fn request_install(resources: Option<PathBuf>) -> ExitCode {
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(err) => {
            eprintln!("failed: own path unknown ({err})");
            return ExitCode::FAILURE;
        }
    };
    if per_user::is_current(&exe) {
        eprintln!("the installed service is this build");
        return ExitCode::SUCCESS;
    }
    let asked = per_user::request_install(&exe, resources.as_deref());
    elevated_exit("install", asked, "the app works in proxy mode")
}

/// Settings > Apps: `uninstall` from this (installed) exe, approved in Windows' prompt. Settings
/// shows no exit code, and the console Windows opened for this exe is let go at once: the outcome
/// is said in one message box (tailsa-b1), nothing is printed.
fn request_uninstall() -> ExitCode {
    per_user::leave_console();
    let Ok(exe) = std::env::current_exe() else {
        return ExitCode::FAILURE;
    };
    let asked = per_user::request_uninstall(&exe);
    let lang = entry::user_lang();
    let folder = exe.parent().unwrap_or(&exe);
    if let Some(message) = per_user::uninstall_message(&asked, folder, lang) {
        per_user::tell(&message, lang);
    }
    exit_of(&asked)
}

/// The exit code of an elevated run of `verb`, said on stderr: its own, 5 when nobody approved
/// the prompt.
fn elevated_exit(verb: &str, asked: std::io::Result<Elevated>, declined: &str) -> ExitCode {
    match &asked {
        Ok(Elevated::Exited(code)) => eprintln!("{verb} exited with {code}"),
        Ok(Elevated::Declined) => eprintln!("not approved: {declined}"),
        Err(err) => eprintln!("failed: {err}"),
    }
    exit_of(&asked)
}

fn exit_of(asked: &std::io::Result<Elevated>) -> ExitCode {
    match asked {
        Ok(Elevated::Exited(code)) => ExitCode::from(u8::try_from(*code).unwrap_or(1)),
        Ok(Elevated::Declined) => ExitCode::from(5),
        Err(_) => ExitCode::FAILURE,
    }
}

fn block_on<T>(f: impl Future<Output = T>) -> Result<T, ExitCode> {
    match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => Ok(runtime.block_on(f)),
        Err(err) => {
            eprintln!("failed: {err}");
            Err(ExitCode::FAILURE)
        }
    }
}

fn status() -> ExitCode {
    match block_on(per_user::status()) {
        Ok(Ok(state)) => {
            eprintln!("{state}");
            ExitCode::SUCCESS
        }
        Ok(Err(err)) => {
            eprintln!("failed: {err}");
            ExitCode::FAILURE
        }
        Err(code) => code,
    }
}

fn forget_me() -> ExitCode {
    let forgotten = match block_on(per_user::forget_me()) {
        Ok(forgotten) => forgotten,
        Err(code) => return code,
    };
    match forgotten {
        Ok(None) => {
            eprintln!("no service installed");
            ExitCode::SUCCESS
        }
        Ok(Some(removing)) => {
            eprintln!("forgotten (service removing itself: {removing})");
            ExitCode::SUCCESS
        }
        Err(CallError::Service(error)) => {
            eprintln!("failed: {}", error.msg.key);
            code_of(&error.msg.key)
        }
        Err(CallError::Pipe(err)) => {
            // The service is installed but not reachable (stopped, or another build's pipe):
            // nothing to tell it now; an administrator can still remove it.
            eprintln!("service not reachable: {}", err.user_msg().key);
            ExitCode::FAILURE
        }
    }
}
