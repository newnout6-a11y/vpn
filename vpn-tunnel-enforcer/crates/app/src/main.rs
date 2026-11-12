//! VPN Tunnel Enforcer: the desktop application.
// GUI subsystem in every profile: no console window.
#![windows_subsystem = "windows"]

use std::process::ExitCode;

fn main() -> ExitCode {
    // SAFETY: the first statement of main; no other thread exists yet.
    unsafe { vpnte_app::boot::scrub_elevated_env() };
    // `args()` panics on an argument that is not valid Unicode; a link from a web page can carry
    // anything, so read the raw arguments and replace what does not decode.
    let argv = std::env::args_os()
        .skip(1)
        .map(|arg| arg.to_string_lossy().into_owned());
    let args = vpnte_app::args::Args::parse(argv);
    vpnte_app::root::run(&args)
}
