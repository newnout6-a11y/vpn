//! Command line of the application. Unknown arguments are ignored on purpose: an old launcher,
//! shortcut or scheduled task must never make the app refuse to start. The one exception is the
//! installer helper (`--setup`), where an unknown command is a usage error and never opens the UI.
use std::path::PathBuf;

/// Default and allowed range of `--setup await-shutdown --timeout <seconds>`.
pub const AWAIT_SHUTDOWN_TIMEOUT_S: u32 = 120;
pub const AWAIT_SHUTDOWN_TIMEOUT_RANGE: std::ops::RangeInclusive<u32> = 1..=300;

/// What the installer asks the app to do (`--setup <command> --install-dir <dir>`). Runs without
/// UI, elevation prompt or data-dir access; the exact contract is `installer/PROGRESS.md`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetupCommand {
    /// Ask the running client to clean up and exit, and wait for its acknowledgement.
    AwaitShutdown { timeout_s: u32 },
    /// Undo what the app put into this user's system (tweaks with the system proxy, autostart,
    /// jump list); network filters only when the process happens to be elevated.
    Uninstall,
    /// Bind the shortcuts the installer created to the app identity (AUMID).
    StampShortcuts,
    /// Start the installed app as the desktop user, without elevation, and return at once.
    LaunchAsUser,
    /// Register the free link schemes for the installed exe (a first install), or point ours at
    /// it again (an upgrade); schemes the user turned off stay off.
    RegisterLinks,
}

/// A parsed `--setup` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setup {
    pub command: SetupCommand,
    /// `--install-dir`; `None` when missing or empty (each command reports that in its own words).
    pub install_dir: Option<PathBuf>,
}

/// Parsed command line.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Args {
    /// Started by the logon task: stay in the tray if the user asked for that.
    pub autostart: bool,
    /// Do not ask for administrator rights (development and UI checks; privileged features report an error).
    pub no_elevate: bool,
    /// Internal: this process is the elevated copy started by an unelevated launch.
    pub elevated_relaunch: bool,
    /// Sent to a running instance by the installer: clean up and exit with the acknowledge code.
    pub shutdown_for_update: bool,
    /// Remove every system change of the app and exit (emergency / uninstall).
    pub cleanup: bool,
    /// Initialise without UI and elevation, print one line and exit: the installer smoke test.
    pub smoke: bool,
    pub version: bool,
    /// A link Windows opened with us (`"<exe>" --open-link "%1"`, `vpnte_winnet::url_scheme`):
    /// shown in the add dialog of the Servers page for the user to confirm.
    pub open_link: Option<String>,
    /// `Err` is a usage error (one English line for stderr; exit code 2).
    pub setup: Option<Result<Setup, String>>,
    /// Internal (`--crash-watch <pid>`): this process is the crash watcher of the app `pid`
    /// (`crate::crash_watch`); main runs it before anything else.
    pub crash_watch: Option<u32>,
}

impl Args {
    /// Parses the arguments after the program name. `--open-link` ends the parsing: whatever
    /// follows it came from the link (a page can put `" --setup uninstall` into one), so it is
    /// never read as a flag.
    pub fn parse(args: impl IntoIterator<Item = String>) -> Self {
        let mut out = Args::default();
        let mut setup: Option<Result<SetupCommand, String>> = None;
        let mut install_dir = None;
        let mut timeout: Option<Result<u32, String>> = None;
        let mut iter = args.into_iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                vpnte_winnet::url_scheme::OPEN_LINK_FLAG => {
                    out.open_link = iter.next().filter(|link| !link.trim().is_empty());
                    break;
                }
                "--autostart" => out.autostart = true,
                "--no-elevate" => out.no_elevate = true,
                "--elevated-relaunch" => out.elevated_relaunch = true,
                "--shutdown-for-update" => out.shutdown_for_update = true,
                "--cleanup" => out.cleanup = true,
                "--smoke" => out.smoke = true,
                "--version" | "-V" => out.version = true,
                crate::crash_watch::FLAG => {
                    out.crash_watch = iter.next().and_then(|pid| pid.parse().ok());
                }
                "--setup" => {
                    setup = Some(match iter.next().as_deref() {
                        Some("await-shutdown") => Ok(SetupCommand::AwaitShutdown {
                            timeout_s: AWAIT_SHUTDOWN_TIMEOUT_S,
                        }),
                        Some("uninstall") => Ok(SetupCommand::Uninstall),
                        Some("stamp-shortcuts") => Ok(SetupCommand::StampShortcuts),
                        Some("launch-as-user") => Ok(SetupCommand::LaunchAsUser),
                        Some("register-links") => Ok(SetupCommand::RegisterLinks),
                        Some(other) => Err(format!("Unknown setup command: {}", ascii(other))),
                        None => Err("Missing setup command".to_owned()),
                    });
                }
                "--install-dir" => {
                    install_dir = iter
                        .next()
                        .filter(|dir| !dir.trim().is_empty())
                        .map(PathBuf::from)
                }
                "--timeout" => {
                    timeout = Some(match iter.next().and_then(|v| v.parse::<u32>().ok()) {
                        Some(s) if AWAIT_SHUTDOWN_TIMEOUT_RANGE.contains(&s) => Ok(s),
                        _ => Err("Invalid --timeout: expected 1..=300 seconds".to_owned()),
                    });
                }
                _ => {}
            }
        }
        out.setup = setup.map(|command| {
            let command = match (command?, timeout) {
                (SetupCommand::AwaitShutdown { .. }, Some(timeout)) => {
                    SetupCommand::AwaitShutdown {
                        timeout_s: timeout?,
                    }
                }
                (command, _) => command,
            };
            Ok(Setup {
                command,
                install_dir,
            })
        });
        if std::env::var_os("VPNTE_NO_ELEVATE").is_some_and(|v| v == "1") {
            out.no_elevate = true;
        }
        out
    }
}

/// The installer decodes our output as ANSI: echo only printable ASCII back to it.
fn ascii(text: &str) -> String {
    text.chars()
        .filter(|c| c.is_ascii_graphic())
        .take(40)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(list: &[&str]) -> Args {
        Args::parse(list.iter().map(|s| (*s).to_owned()))
    }

    fn setup(list: &[&str]) -> Result<Setup, String> {
        parse(list).setup.expect("a --setup request")
    }

    #[test]
    fn flags() {
        let a = parse(&["--autostart", "--no-elevate"]);
        assert!(a.autostart && a.no_elevate && a.setup.is_none());
    }

    #[test]
    fn setup_commands_follow_the_installer_contract() {
        let s = setup(&[
            "--setup",
            "await-shutdown",
            "--install-dir",
            r"C:\Program Files\VPN Tunnel Enforcer",
        ])
        .unwrap();
        assert_eq!(s.command, SetupCommand::AwaitShutdown { timeout_s: 120 });
        assert_eq!(
            s.install_dir,
            Some(PathBuf::from(r"C:\Program Files\VPN Tunnel Enforcer"))
        );
        let s = setup(&[
            "--setup",
            "await-shutdown",
            "--install-dir",
            "D:\\x",
            "--timeout",
            "5",
        ])
        .unwrap();
        assert_eq!(s.command, SetupCommand::AwaitShutdown { timeout_s: 5 });
        assert_eq!(
            setup(&["--setup", "uninstall", "--install-dir", "D:\\x"])
                .unwrap()
                .command,
            SetupCommand::Uninstall
        );
        assert_eq!(
            setup(&["--setup", "stamp-shortcuts"]).unwrap().command,
            SetupCommand::StampShortcuts
        );
        assert_eq!(
            setup(&["--setup", "launch-as-user"]).unwrap().command,
            SetupCommand::LaunchAsUser
        );
        assert_eq!(
            setup(&["--setup", "register-links", "--install-dir", "D:\\x"])
                .unwrap()
                .command,
            SetupCommand::RegisterLinks
        );
    }

    #[test]
    fn setup_usage_errors_never_fall_through_to_the_ui() {
        assert!(setup(&["--setup", "nope"]).is_err());
        assert!(setup(&["--setup"]).is_err());
        assert!(setup(&["--setup", "await-shutdown", "--timeout", "0"]).is_err());
        assert!(setup(&["--setup", "await-shutdown", "--timeout", "301"]).is_err());
        assert!(setup(&["--setup", "await-shutdown", "--timeout", "soon"]).is_err());
        // A missing or empty directory is reported by the command itself, in its own words.
        assert_eq!(
            setup(&["--setup", "uninstall", "--install-dir", " "])
                .unwrap()
                .install_dir,
            None
        );
    }

    #[test]
    fn unknown_arguments_are_ignored() {
        let a = parse(&["--updated", "--type=renderer", "whatever", "--smoke"]);
        assert!(a.smoke);
        assert!(!a.autostart && !a.cleanup && a.setup.is_none());
    }

    /// RU-2026 item 4: the registered command hands the link over as one argument; anything after
    /// it came from the link and is never a flag (a link cannot start the uninstall helper).
    #[test]
    fn a_link_ends_the_command_line() {
        let a = parse(&["--open-link", "vless://u@h.example:443?type=tcp#Мой ключ"]);
        assert_eq!(
            a.open_link.as_deref(),
            Some("vless://u@h.example:443?type=tcp#Мой ключ")
        );
        let a = parse(&[
            "--open-link",
            "vless://x",
            "--setup",
            "uninstall",
            "--cleanup",
            "--shutdown-for-update",
        ]);
        assert_eq!(a.open_link.as_deref(), Some("vless://x"));
        assert!(a.setup.is_none() && !a.cleanup && !a.shutdown_for_update);
        assert_eq!(parse(&["--open-link"]).open_link, None);
        assert_eq!(parse(&["--open-link", "  "]).open_link, None);
    }

    /// ks-b: the crash watcher's argument; a link can never carry it in.
    #[test]
    fn crash_watch_takes_the_app_pid() {
        assert_eq!(parse(&["--crash-watch", "4242"]).crash_watch, Some(4242));
        assert_eq!(parse(&["--crash-watch", "x"]).crash_watch, None);
        assert_eq!(parse(&["--crash-watch"]).crash_watch, None);
        let link = parse(&["--open-link", "vless://x", "--crash-watch", "4242"]);
        assert_eq!(link.crash_watch, None);
    }
}
