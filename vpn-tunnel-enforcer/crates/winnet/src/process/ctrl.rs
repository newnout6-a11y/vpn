//! Graceful stop of a hidden child: CTRL_BREAK to the console process group it leads.
//!
//! Every child of [`super::spawn_hidden`] runs in its own windowless console (CREATE_NO_WINDOW)
//! as the leader of its own process group (CREATE_NEW_PROCESS_GROUP, group id = its PID). Go
//! programs (sing-box, Xray) turn CTRL_BREAK into SIGINT and shut down cleanly: sing-box closes
//! its Wintun adapter on the way (`WintunCloseAdapter` removes an adapter it created), which a
//! TerminateProcess never lets it do — the interface and one of our TUN aliases would stay behind.
use std::io;
use std::time::Duration;

use parking_lot::Mutex;
use windows::Win32::System::Console::{
    AttachConsole, CTRL_BREAK_EVENT, CTRL_C_EVENT, FreeConsole, GenerateConsoleCtrlEvent,
    SetConsoleCtrlHandler,
};
use windows::core::BOOL;

/// A process is attached to at most one console, process-wide: one CTRL_BREAK at a time.
static CONSOLE: Mutex<()> = Mutex::new(());

/// How long we stay attached after the event, with our own handler swallowing it (see
/// [`swallow`]). The console starts the handler threads while it handles the generate call, but
/// they may run later; this gives a misdirected one time to run before `FreeConsole` can reset
/// the handler table to the default handler, which would end this process.
const SETTLE: Duration = Duration::from_millis(50);

/// Our handler while attached: CTRL+C / CTRL+BREAK are not meant for us. The console delivers
/// a group's event to every attached process whose group id matches, and ours is inherited from
/// an ancestor that may be long gone: its recycled PID can equal the child's.
unsafe extern "system" fn swallow(ctrl: u32) -> BOOL {
    BOOL::from(ctrl == CTRL_C_EVENT || ctrl == CTRL_BREAK_EVENT)
}

/// Sends CTRL_BREAK to the console process group led by `pid`, a running child of
/// [`super::spawn_hidden`] whose process handle the caller still holds (Windows never reuses the
/// PID of a process with an open handle, so the event cannot reach a stranger). *Blocking*
/// (about 50 ms, serialised process-wide). Only asks: the caller waits for the exit and kills on
/// its own deadline.
///
/// Errors: `pid` has no console (it exited, or was not started by `spawn_hidden`), or this
/// process is attached to a console of its own (`AttachConsole` refuses with access denied; the
/// GUI app has none, console builds and test harnesses may). Nothing is changed then.
pub fn ctrl_break(pid: u32) -> io::Result<()> {
    if pid == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "no process id"));
    }
    let _serial = CONSOLE.lock();
    // SAFETY: plain call; it fails without side effects when we already have a console
    // (ERROR_ACCESS_DENIED) or `pid` has none / does not exist.
    unsafe { AttachConsole(pid) }?;
    // Registered after the attach: attaching resets the handler table. A NULL handler would
    // only ignore CTRL+C, and the default handler ends the process on CTRL+BREAK.
    // SAFETY: `swallow` is a plain `extern "system"` fn that lives for the whole process.
    let guarded = unsafe { SetConsoleCtrlHandler(Some(swallow), true) };
    let sent = match &guarded {
        // SAFETY: plain call; the group id is the child's PID (CREATE_NEW_PROCESS_GROUP).
        Ok(()) => unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid) },
        // Without our handler a misdirected event could end us: do not send.
        Err(err) => Err(err.clone()),
    };
    if sent.is_ok() {
        std::thread::sleep(SETTLE);
    }
    // SAFETY: detaches from the console attached above (we had none before).
    let freed = unsafe { FreeConsole() };
    if guarded.is_ok() {
        // The docs say Attach/Alloc/FreeConsole reset the handler table: if this one did, the
        // removal fails, which is fine.
        // SAFETY: removes the handler registered above.
        let _ = unsafe { SetConsoleCtrlHandler(Some(swallow), false) };
    }
    sent?;
    freed?;
    Ok(())
}

/// Detaches this process from the console it inherited, so that [`ctrl_break`] can attach to a
/// child's. For tests and console tools only: the GUI app (and a service) has no console. Refuses
/// while stdout or stderr is a terminal, whose output would be lost. `true` = this process has
/// no console now (also when it had none).
pub fn detach_console() -> bool {
    use std::io::IsTerminal;
    if std::io::stdout().is_terminal() || std::io::stderr().is_terminal() {
        return false;
    }
    // Never while a `ctrl_break` is attached to a child's console: we would detach from that.
    let _serial = CONSOLE.lock();
    // SAFETY: plain call; without a console it fails and changes nothing.
    let _ = unsafe { FreeConsole() };
    true
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use tokio::process::Command;
    use windows::Win32::System::Console::GetConsoleProcessList;

    use super::*;
    use crate::process::job::tests::{long_ping, system_ping};
    use crate::process::{Job, spawn_hidden};

    /// Exit code of a process ended by the default console control handler.
    const STATUS_CONTROL_C_EXIT: u32 = 0xC000_013A;

    /// Processes attached to this process's console (0 = none).
    fn own_console_processes() -> u32 {
        let mut list = [0u32; 8];
        // SAFETY: the buffer is valid for its length.
        unsafe { GetConsoleProcessList(&mut list) }
    }

    /// `findstr x` blocks on its open stdin pipe and installs no console handler.
    fn findstr() -> Command {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
        let mut cmd = Command::new(Path::new(&root).join("System32").join("findstr.exe"));
        cmd.arg("x");
        cmd
    }

    /// The test process stands in for the console-less app; skip when output is a terminal.
    fn console_free() -> bool {
        let free = detach_console();
        if !free {
            eprintln!("skipped: stdout / stderr is a terminal (graceful stops need no console)");
        }
        free
    }

    /// AT-02-009: CTRL_BREAK reaches exactly the hidden child (its own windowless console, its
    /// own group): a child without a handler dies of it, the test process does not.
    #[tokio::test]
    async fn ctrl_break_reaches_the_hidden_child() {
        if !console_free() {
            return;
        }
        let job = Job::kill_on_close().unwrap();
        let mut child = spawn_hidden(&mut findstr(), &job).unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            child.try_wait().unwrap().is_none(),
            "findstr waits on stdin"
        );
        ctrl_break(child.id().unwrap()).unwrap();
        let status = tokio::time::timeout(Duration::from_secs(5), child.wait())
            .await
            .expect("findstr ends on CTRL_BREAK")
            .unwrap();
        assert_eq!(
            status.code().map(i32::cast_unsigned),
            Some(STATUS_CONTROL_C_EXIT)
        );
        assert_eq!(own_console_processes(), 0, "detached again afterwards");
    }

    /// AT-02-009: the event is a request, not a kill: a child with its own CTRL_BREAK handler
    /// (ping prints statistics and goes on) keeps running; a PID of 0 is refused.
    #[tokio::test]
    async fn ctrl_break_only_asks() {
        assert_eq!(
            ctrl_break(0).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        if !console_free() {
            return;
        }
        let job = Job::kill_on_close().unwrap();
        let mut ping = spawn_hidden(&mut long_ping(&system_ping()), &job).unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        ctrl_break(ping.id().unwrap()).unwrap();
        tokio::time::sleep(Duration::from_millis(1000)).await;
        assert!(
            ping.try_wait().unwrap().is_none(),
            "ping survives CTRL_BREAK"
        );
    }
}
