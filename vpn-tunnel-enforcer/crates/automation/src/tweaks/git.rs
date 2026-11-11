//! Git target: `http.proxy` / `https.proxy` in the user's global config through `git config
//! --global` (Git's curl backend speaks `socks5h://` natively; `http://` at a SOCKS port would
//! break every clone and fetch). A read failure aborts the apply: the old "error = no proxy"
//! baseline made the rollback delete the user's real proxy (spec G7).
use std::io::{self, Read};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use vpnte_base::types::ProxyKind;
use vpnte_core::net::HostPort;
use vpnte_winnet::registry::{Access, Hive, Key, View};
use windows::Win32::System::Threading::CREATE_NO_WINDOW;

use super::endpoint::proxy_url;
use super::journal::{Feature, GitKey, Target, Val};

/// A `git config` call that has not finished by then is killed (the old app used 10 s).
const TIMEOUT: Duration = Duration::from_secs(10);

/// How to run Git, and which file `--global` means for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitCli {
    /// `git.exe`.
    pub exe: PathBuf,
    /// Passed to the child as `GIT_CONFIG_GLOBAL` (tests use a temp file); `None` = the user's
    /// own global config. Our own environment is never changed.
    pub global_file: Option<PathBuf>,
}

impl GitCli {
    /// Git for Windows from its HKLM install record first (an admin-only directory: the app runs
    /// elevated and must not prefer a binary any user process could have replaced), else the
    /// first `git.exe` on `PATH`.
    pub fn find() -> Option<GitCli> {
        let exe = registered_git().or_else(|| {
            let path = std::env::var_os("PATH")?;
            std::env::split_paths(&path)
                .map(|dir| dir.join("git.exe"))
                .find(|exe| exe.is_absolute() && exe.is_file())
        })?;
        Some(GitCli {
            exe,
            global_file: None,
        })
    }

    /// Current value; exit code 1 = not set.
    pub fn read(&self, key: GitKey) -> io::Result<Val> {
        let out = self.run(&["--get", key.name()])?;
        match out.code {
            0 => {
                let value = out.stdout.strip_suffix('\n').unwrap_or(&out.stdout);
                Ok(Val::Text(
                    value.strip_suffix('\r').unwrap_or(value).to_owned(),
                ))
            }
            1 => Ok(Val::Absent),
            code => Err(failed("git config --get", code)),
        }
    }

    /// Sets (replacing every value of the key) or unsets; exit code 5 on unset = already absent.
    pub fn write(&self, key: GitKey, value: &Val) -> io::Result<bool> {
        let (args, ok): (Vec<&str>, &[i32]) = match value {
            Val::Text(v) if !v.chars().any(char::is_control) => {
                (vec!["--replace-all", key.name(), v], &[0])
            }
            Val::Absent => (vec!["--unset-all", key.name()], &[0, 5]),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "not a git config value",
                ));
            }
        };
        let out = self.run(&args)?;
        if ok.contains(&out.code) {
            Ok(false)
        } else {
            Err(failed("git config", out.code))
        }
    }

    fn run(&self, args: &[&str]) -> io::Result<Output> {
        let mut cmd = Command::new(&self.exe);
        cmd.args(["config", "--global"])
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW.0);
        if let Some(file) = &self.global_file {
            cmd.env("GIT_CONFIG_GLOBAL", file);
        }
        let mut child = cmd.spawn()?;
        let started = Instant::now();
        // `git config` prints one line at most, so the pipe cannot fill up while we poll.
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if started.elapsed() > TIMEOUT {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "git config timed out",
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let mut stdout = String::new();
        if let Some(mut pipe) = child.stdout.take() {
            pipe.read_to_string(&mut stdout)?;
        }
        Ok(Output {
            code: status.code().unwrap_or(-1),
            stdout,
        })
    }
}

struct Output {
    code: i32,
    stdout: String,
}

fn failed(what: &str, code: i32) -> io::Error {
    io::Error::other(format!("{what} exited with {code}"))
}

/// `HKLM\SOFTWARE\GitForWindows` `InstallPath` + `\cmd\git.exe` (location inferred, spec §6.8).
fn registered_git() -> Option<PathBuf> {
    let key = Key::open(
        Hive::LocalMachine,
        r"SOFTWARE\GitForWindows",
        Access::Read,
        View::Native,
    )
    .ok()??;
    let dir = key.string("InstallPath").ok()??;
    let exe = Path::new(&dir).join("cmd").join("git.exe");
    exe.is_file().then_some(exe)
}

/// Both keys = the proxy URL.
pub fn plan(addr: &HostPort, kind: ProxyKind) -> Vec<(Feature, Target, Val)> {
    let url = proxy_url(addr, kind);
    GitKey::ALL
        .into_iter()
        .map(|key| (Feature::DevGit, Target::Git { key }, Val::Text(url.clone())))
        .collect()
}

#[cfg(test)]
mod tests;
