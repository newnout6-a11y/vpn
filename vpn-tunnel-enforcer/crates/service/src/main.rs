//! `vpnte-service.exe`.
//!
//! - `run`: started by the SCM (the registered command line); runs the service.
//! - `install [--resources <dir>]`: run elevated by the installer; copies this exe and the pinned
//!   engine files into Program Files, registers and starts the service.
//! - `uninstall`: run elevated by the installer; stops and removes the service and its folders.
//!
//! Exit codes: 0 done, 1 failed (reason on stderr, English log text), 2 bad arguments.
use std::path::PathBuf;
use std::process::ExitCode;

use vpnte_service::{install, scm, service};

const USAGE: &str = "usage: vpnte-service (run | install [--resources <dir>] | uninstall)";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["run"] => match scm::dispatch::dispatch(service::run) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("not started by the Service Control Manager: {err}");
                ExitCode::FAILURE
            }
        },
        ["install", rest @ ..] => {
            let resources = match rest {
                [] => None,
                ["--resources", dir] => Some(PathBuf::from(dir)),
                _ => return usage(),
            };
            console_log();
            let done = install::Source::current(resources).and_then(|s| install::install(&s));
            report(done.map(|exe| eprintln!("installed: {}", exe.display())))
        }
        ["uninstall"] => {
            console_log();
            report(install::uninstall().map(|()| eprintln!("uninstalled")))
        }
        _ => usage(),
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

fn report(result: vpnte_base::AppResult<()>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("failed: {} ({:?})", err.user_msg().key, err.source);
            ExitCode::FAILURE
        }
    }
}
