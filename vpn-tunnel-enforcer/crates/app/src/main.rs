//! VPN Tunnel Enforcer: the desktop application.
// GUI subsystem in every profile: no console window.
#![windows_subsystem = "windows"]

use std::process::ExitCode;

fn main() -> ExitCode {
    // SAFETY: the first statement of main; no other thread exists yet.
    unsafe { vpnte_app::boot::scrub_elevated_env() };
    let args = vpnte_app::args::Args::parse(std::env::args().skip(1));
    vpnte_app::root::run(&args)
}
