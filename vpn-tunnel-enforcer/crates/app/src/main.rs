//! VPN Tunnel Enforcer: the desktop application.
// GUI subsystem in every profile: no console window. Logs go to the log file (and to the
// parent console when started from a terminal).
#![windows_subsystem = "windows"]

mod args;

fn main() -> std::process::ExitCode {
    let args = args::Args::parse(std::env::args().skip(1));
    if args.version {
        println!("{}", env!("CARGO_PKG_VERSION"));
    }
    std::process::ExitCode::SUCCESS
}
