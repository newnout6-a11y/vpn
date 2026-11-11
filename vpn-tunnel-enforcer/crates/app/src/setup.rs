//! Command-line paths that never open the UI (work package `app-setup`).
use std::process::ExitCode;

use crate::args::Args;

/// `Some(code)` = exit with it without opening the UI.
pub fn run(args: &Args) -> Option<ExitCode> {
    if args.version {
        println!("{}", env!("CARGO_PKG_VERSION"));
        return Some(ExitCode::SUCCESS);
    }
    match &args.setup {
        Some(Err(usage)) => {
            eprintln!("{usage}");
            Some(ExitCode::from(2))
        }
        Some(Ok(_)) => {
            eprintln!("Setup helper is not available in this build.");
            Some(ExitCode::from(1))
        }
        None => None,
    }
}
