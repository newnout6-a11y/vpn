//! VPN Tunnel Enforcer: the desktop application.
// GUI subsystem in every profile: no console window.
#![windows_subsystem = "windows"]

fn main() -> std::process::ExitCode {
    let args = vpnte_app::args::Args::parse(std::env::args().skip(1));
    vpnte_app::setup::run(&args).unwrap_or(std::process::ExitCode::SUCCESS)
}
