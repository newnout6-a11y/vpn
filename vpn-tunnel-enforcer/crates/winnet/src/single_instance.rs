//! Single instance per Windows session: a named mutex decides who runs; a named pipe lets a
//! later launch hand its command (activate, or shut down for an installer update) to the running
//! instance.
//!
//! The app is installed per user and runs unelevated, so every signed-in user runs their own copy
//! (owner decision 12): the mutex lives in the session's `Local\` namespace, which other users
//! cannot create objects in, and the pipe name carries the session id because pipes have no
//! session namespace. The installer's `--shutdown-for-update` launch runs in the installing
//! user's session and so reaches that user's copy. Both objects keep the default DACL: an
//! elevated primary's pipe only accepts writers that are SYSTEM, administrators or the owner, so
//! a non-elevated process cannot make it quit. A non-elevated launch that cannot even open the
//! mutex still learns that it exists (access denied) and backs off.
use std::ffi::OsStr;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use windows::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, ERROR_IO_PENDING,
    ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, GENERIC_READ, GENERIC_WRITE, GetLastError, HANDLE,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, FILE_SHARE_NONE,
    OPEN_EXISTING, PIPE_ACCESS_DUPLEX, ReadFile, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
    WriteFile,
};
use windows::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientSessionId,
    GetNamedPipeServerProcessId, PIPE_READMODE_MESSAGE, PIPE_REJECT_REMOTE_CLIENTS,
    PIPE_TYPE_MESSAGE, PIPE_WAIT, SetNamedPipeHandleState, TransactNamedPipe,
};
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows::Win32::System::Threading::{
    CreateEventW, CreateMutexW, GetCurrentProcessId, INFINITE, ResetEvent, SetEvent,
    WaitForMultipleObjects,
};
use windows::Win32::UI::WindowsAndMessaging::AllowSetForegroundWindow;
use windows::core::{HSTRING, PCWSTR};

use crate::win;

/// Mutex of the installed app, in the caller's session namespace.
pub const MUTEX_NAME: &str = r"Local\VpnTunnelEnforcer.Instance";
/// Command pipe of the installed app: this prefix, a dot and the Windows session id.
pub const PIPE_PREFIX: &str = r"\\.\pipe\VpnTunnelEnforcer";

/// A command is one UTF-8 line of at most this many bytes.
const MAX_LINE: usize = 4096;
/// Bound for each read / write / close-wait of one hand-off, so a stuck peer cannot wedge us.
const IO_TIMEOUT_MS: u32 = 2_000;

/// Kernel object names of the instance lock and its command pipe (tests use random names).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceNames {
    /// Named mutex, e.g. [`MUTEX_NAME`].
    pub mutex: String,
    /// Pipe path, e.g. [`PIPE_PREFIX`]`.1`.
    pub pipe: String,
}

impl InstanceNames {
    /// The names of the installed app in this process's Windows session.
    pub fn production() -> AppResult<Self> {
        current_session()
            .map(Self::for_session)
            .map_err(AppError::internal)
    }

    fn for_session(session: u32) -> Self {
        Self {
            mutex: MUTEX_NAME.into(),
            pipe: format!("{PIPE_PREFIX}.{session}"),
        }
    }
}

/// What a later launch asks the running instance to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// Show and focus the main window.
    Activate,
    /// The installer is about to replace the exe: clean up and exit with code 73.
    ShutdownForUpdate,
}

impl Command {
    /// The command a launch with these arguments forwards.
    pub fn from_args<I, S>(args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        if args
            .into_iter()
            .any(|a| a.as_ref() == OsStr::new("--shutdown-for-update"))
        {
            Command::ShutdownForUpdate
        } else {
            Command::Activate
        }
    }

    fn wire(self) -> &'static str {
        match self {
            Command::Activate => "activate",
            Command::ShutdownForUpdate => "shutdown-for-update",
        }
    }

    fn parse(line: &[u8]) -> Option<Self> {
        match trim_line(line) {
            b"activate" => Some(Command::Activate),
            b"shutdown-for-update" => Some(Command::ShutdownForUpdate),
            _ => None,
        }
    }
}

fn trim_line(line: &[u8]) -> &[u8] {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    line.strip_suffix(b"\r").unwrap_or(line)
}

/// Outcome of [`acquire`].
pub enum Acquire {
    /// This process is the only instance; keep the guard alive until exit.
    Primary(Primary),
    /// Another instance runs: hand it the command with [`send`] and exit without touching anything.
    Secondary,
}

/// Held by the running instance for its whole lifetime; dropping it releases the lock.
pub struct Primary {
    commands: Option<mpsc::UnboundedReceiver<Command>>,
    listener: Option<Listener>,
    _mutex: OwnedHandle,
}

impl Primary {
    /// Commands sent by later launches, queued until the app is ready for them (taken once).
    pub fn take_commands(&mut self) -> Option<mpsc::UnboundedReceiver<Command>> {
        self.commands.take()
    }

    /// `false` when the command pipe could not be created (a later launch then gets no answer).
    pub fn is_listening(&self) -> bool {
        self.listener.is_some()
    }
}

/// Takes the instance lock named `names.mutex`; as the primary, also opens the command pipe.
pub fn acquire(names: &InstanceNames) -> AppResult<Acquire> {
    // Bound first so that no drop runs between CreateMutexW and GetLastError.
    let name = HSTRING::from(names.mutex.as_str());
    // SAFETY: plain call with a valid name; the handle is owned right below.
    let created = unsafe { CreateMutexW(None, false, &name) };
    // SAFETY: no preconditions; read before any other call can overwrite the last error.
    let existed = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
    let mutex = match created {
        // SAFETY: CreateMutexW returned a fresh handle that nothing else owns.
        Ok(h) => unsafe { OwnedHandle::from_raw_handle(h.0) },
        // The mutex exists but belongs to an elevated primary we may not open.
        Err(e) if e.code() == ERROR_ACCESS_DENIED.to_hresult() => return Ok(Acquire::Secondary),
        Err(e) => return Err(AppError::internal(e)),
    };
    if existed {
        return Ok(Acquire::Secondary);
    }
    let (tx, rx) = mpsc::unbounded_channel();
    let listener = match Listener::start(&names.pipe, tx) {
        Ok(l) => Some(l),
        Err(e) => {
            tracing::warn!(error = %e, "single instance: command pipe unavailable");
            None
        }
    };
    Ok(Acquire::Primary(Primary {
        commands: Some(rx),
        listener,
        _mutex: mutex,
    }))
}

/// The primary's pipe server: one instance, one client at a time, on its own thread.
struct Listener {
    stop: OwnedHandle,
    thread: Option<JoinHandle<()>>,
}

impl Listener {
    fn start(name: &str, tx: mpsc::UnboundedSender<Command>) -> AppResult<Self> {
        // SAFETY: valid name; default security on purpose (module docs); the handle is owned below.
        let pipe = unsafe {
            CreateNamedPipeW(
                &HSTRING::from(name),
                // FIRST_PIPE_INSTANCE: fail instead of joining a pipe someone else created first.
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                MAX_LINE as u32,
                MAX_LINE as u32,
                0,
                None,
            )
        };
        if pipe.is_invalid() {
            return Err(AppError::internal(windows::core::Error::from_thread()));
        }
        // SAFETY: a fresh handle that nothing else owns.
        let pipe = unsafe { OwnedHandle::from_raw_handle(pipe.0) };
        let stop = event()?;
        let thread_stop = stop.try_clone()?;
        let io_event = event()?;
        let session = current_session().ok();
        let thread = std::thread::Builder::new()
            .name("vpnte-single-instance".into())
            .spawn(move || serve(&pipe, &thread_stop, &io_event, session, &tx))?;
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        // SAFETY: `stop` is a live event owned by self.
        let _ = unsafe { SetEvent(raw(&self.stop)) };
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve(
    pipe: &OwnedHandle,
    stop: &OwnedHandle,
    event: &OwnedHandle,
    session: Option<u32>,
    tx: &mpsc::UnboundedSender<Command>,
) {
    let io = Io {
        pipe: raw(pipe),
        event: raw(event),
        stop: Some(raw(stop)),
    };
    loop {
        let served = io.connect().and_then(|()| serve_client(&io, session, tx));
        match served {
            Err(IoEnd::Stopped) => return,
            Err(IoEnd::Failed(e)) => {
                tracing::debug!(error = %e, "single instance: hand-off failed");
                // A client that vanished between connect and read lands here: pause, retry.
                // SAFETY: `stop` is a live event.
                let stopped = unsafe { WaitForMultipleObjects(&[raw(stop)], false, 100) };
                if stopped == WAIT_OBJECT_0 {
                    return;
                }
            }
            Err(IoEnd::TimedOut) => tracing::debug!("single instance: client too slow"),
            Ok(()) => {}
        }
        // SAFETY: the pipe handle is live; this drops the client so the next one can connect.
        let _ = unsafe { DisconnectNamedPipe(raw(pipe)) };
    }
}

fn serve_client(
    io: &Io,
    session: Option<u32>,
    tx: &mpsc::UnboundedSender<Command>,
) -> Result<(), IoEnd> {
    let mut buf = [0u8; MAX_LINE];
    let n = io.read(&mut buf)?;
    let reply = match Command::parse(&buf[..n]) {
        // Only a client that picked this session's pipe name on purpose comes from elsewhere:
        // our window cannot appear on its desktop.
        Some(Command::Activate) if !same_session(io.pipe, session) => "other-session",
        Some(cmd) => {
            tracing::info!(
                command = cmd.wire(),
                "single instance: command from a later launch"
            );
            let _ = tx.send(cmd);
            "ok"
        }
        None => "invalid",
    };
    io.write(format!("{reply}\n").as_bytes())?;
    // Disconnecting discards unread data: wait until the client has read the reply and closed.
    match io.read(&mut buf) {
        Err(IoEnd::Stopped) => Err(IoEnd::Stopped),
        _ => Ok(()),
    }
}

fn same_session(pipe: HANDLE, own: Option<u32>) -> bool {
    let mut client = 0;
    // SAFETY: live pipe handle with a connected client; valid out pointer.
    let known = unsafe { GetNamedPipeClientSessionId(pipe, &mut client) }.is_ok();
    !known || own.is_none_or(|own| own == client)
}

fn current_session() -> windows::core::Result<u32> {
    let mut id = 0;
    // SAFETY: valid out pointer.
    unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut id) }?;
    Ok(id)
}

fn event() -> AppResult<OwnedHandle> {
    // SAFETY: an unnamed manual-reset event (overlapped I/O wants manual reset).
    let h =
        unsafe { CreateEventW(None, true, false, PCWSTR::null()) }.map_err(AppError::internal)?;
    // SAFETY: a fresh handle that nothing else owns.
    Ok(unsafe { OwnedHandle::from_raw_handle(h.0) })
}

fn raw(h: &OwnedHandle) -> HANDLE {
    HANDLE(h.as_raw_handle())
}

/// Why an overlapped pipe operation did not complete.
#[derive(Debug)]
enum IoEnd {
    Stopped,
    TimedOut,
    Failed(windows::core::Error),
}

/// Overlapped I/O on one pipe handle, bounded by a timeout and an optional stop event.
struct Io {
    pipe: HANDLE,
    event: HANDLE,
    stop: Option<HANDLE>,
}

impl Io {
    fn connect(&self) -> Result<(), IoEnd> {
        let mut ov = self.overlapped()?;
        // SAFETY: `ov` lives on this frame until `finish` has seen the operation end.
        let started = unsafe { ConnectNamedPipe(self.pipe, Some(&raw mut ov)) };
        match started {
            // A client connected between creating / disconnecting the pipe and this call.
            Err(e) if e.code() == ERROR_PIPE_CONNECTED.to_hresult() => Ok(()),
            started => self.finish(&raw mut ov, started, INFINITE).map(drop),
        }
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize, IoEnd> {
        let mut ov = self.overlapped()?;
        // SAFETY: `buf` and `ov` outlive the operation: `finish` returns only after it ended.
        let started = unsafe { ReadFile(self.pipe, Some(buf), None, Some(&raw mut ov)) };
        self.finish(&raw mut ov, started, IO_TIMEOUT_MS)
            .map(|n| n as usize)
    }

    fn write(&self, data: &[u8]) -> Result<(), IoEnd> {
        let mut ov = self.overlapped()?;
        // SAFETY: `data` and `ov` outlive the operation: `finish` returns only after it ended.
        let started = unsafe { WriteFile(self.pipe, Some(data), None, Some(&raw mut ov)) };
        self.finish(&raw mut ov, started, IO_TIMEOUT_MS).map(drop)
    }

    /// Writes one message and reads the one-message reply.
    fn transact(&self, data: &[u8], out: &mut [u8]) -> Result<usize, IoEnd> {
        let mut ov = self.overlapped()?;
        // SAFETY: both buffers and `ov` outlive the operation: `finish` returns only after it ended.
        let started = unsafe {
            TransactNamedPipe(
                self.pipe,
                Some(data.as_ptr().cast()),
                data.len() as u32,
                Some(out.as_mut_ptr().cast()),
                out.len() as u32,
                std::ptr::null_mut(),
                Some(&raw mut ov),
            )
        };
        self.finish(&raw mut ov, started, IO_TIMEOUT_MS)
            .map(|n| n as usize)
    }

    fn overlapped(&self) -> Result<OVERLAPPED, IoEnd> {
        // SAFETY: `event` is a live event handle.
        unsafe { ResetEvent(self.event) }.map_err(IoEnd::Failed)?;
        Ok(OVERLAPPED {
            hEvent: self.event,
            ..Default::default()
        })
    }

    /// Waits for the operation `started` on `ov`. A cancelled operation is waited out before
    /// returning, so the caller's buffers are free again whatever the outcome.
    fn finish(
        &self,
        ov: *mut OVERLAPPED,
        started: windows::core::Result<()>,
        timeout_ms: u32,
    ) -> Result<u32, IoEnd> {
        match started {
            Ok(()) => {}
            Err(e) if e.code() == ERROR_IO_PENDING.to_hresult() => {
                let mut handles = vec![self.event];
                handles.extend(self.stop);
                // SAFETY: all handles are live events.
                let woke = unsafe { WaitForMultipleObjects(&handles, false, timeout_ms) };
                if woke != WAIT_OBJECT_0 {
                    let end = match woke {
                        WAIT_TIMEOUT => IoEnd::TimedOut,
                        w if w.0 == WAIT_OBJECT_0.0 + 1 => IoEnd::Stopped,
                        _ => IoEnd::Failed(windows::core::Error::from_thread()),
                    };
                    let mut n = 0;
                    // SAFETY: cancels only this operation, then blocks until the kernel let go of it.
                    unsafe {
                        let _ = CancelIoEx(self.pipe, Some(ov.cast_const()));
                        let _ = GetOverlappedResult(self.pipe, ov, &mut n, true);
                    }
                    return Err(end);
                }
            }
            Err(e) => return Err(IoEnd::Failed(e)),
        }
        let mut n = 0;
        // SAFETY: the operation on `ov` has completed.
        unsafe { GetOverlappedResult(self.pipe, ov, &mut n, false) }.map_err(IoEnd::Failed)?;
        Ok(n)
    }
}

/// Hands `cmd` to the instance listening on `pipe`, waiting up to `timeout` for its pipe (the
/// primary may still be starting). Every error carries `winnet.singleInstance.noAnswer`; a
/// refused command (an activation from another session's client, an unknown line) is one too.
pub fn send(pipe: &str, cmd: Command, timeout: Duration) -> AppResult<()> {
    let handle = open_client(pipe, timeout)?;
    let pipe = raw(&handle);
    let mode = PIPE_READMODE_MESSAGE;
    // SAFETY: live pipe handle; `mode` outlives the call.
    unsafe { SetNamedPipeHandleState(pipe, Some(&mode), None, None) }.map_err(no_answer)?;
    if cmd == Command::Activate {
        allow_foreground(pipe);
    }
    let event = event()?;
    let io = Io {
        pipe,
        event: raw(&event),
        stop: None,
    };
    let mut reply = [0u8; 64];
    let n = io
        .transact(format!("{}\n", cmd.wire()).as_bytes(), &mut reply)
        .map_err(|end| match end {
            IoEnd::Failed(e) => no_answer(e),
            IoEnd::TimedOut | IoEnd::Stopped => AppError::msg(
                ErrorKind::Timeout,
                Msg::new("winnet.singleInstance.noAnswer"),
            ),
        })?;
    match trim_line(&reply[..n]) {
        b"ok" => Ok(()),
        other => {
            let reply = String::from_utf8_lossy(other).into_owned();
            Err(AppError::msg(
                ErrorKind::Internal,
                Msg::new("winnet.singleInstance.noAnswer"),
            )
            .with_source(std::io::Error::other(format!("refused: reply {reply:?}"))))
        }
    }
}

fn open_client(pipe: &str, timeout: Duration) -> AppResult<OwnedHandle> {
    let name = HSTRING::from(pipe);
    let deadline = Instant::now() + timeout;
    loop {
        // SAFETY: valid name; the handle is owned right away.
        let opened = unsafe {
            CreateFileW(
                &name,
                (GENERIC_READ | GENERIC_WRITE).0,
                FILE_SHARE_NONE,
                None,
                OPEN_EXISTING,
                // Identification only: whoever serves the pipe (a squatter, if the name was taken
                // first) must not be able to impersonate this possibly elevated launch.
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                None,
            )
        };
        match opened {
            // SAFETY: a fresh handle that nothing else owns.
            Ok(h) => return Ok(unsafe { OwnedHandle::from_raw_handle(h.0) }),
            Err(e) if is_not_ready(&e) && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(no_answer(e)),
        }
    }
}

/// No pipe yet (the primary is still starting) or its single instance serves another launch.
fn is_not_ready(e: &windows::core::Error) -> bool {
    e.code() == ERROR_FILE_NOT_FOUND.to_hresult() || e.code() == ERROR_PIPE_BUSY.to_hresult()
}

fn no_answer(e: windows::core::Error) -> AppError {
    let kind = if is_not_ready(&e) {
        ErrorKind::Timeout
    } else {
        win::error_kind(&e)
    };
    AppError::msg(kind, Msg::new("winnet.singleInstance.noAnswer")).with_source(e)
}

/// We were just started by the user and own the foreground right: pass it to the primary.
fn allow_foreground(pipe: HANDLE) {
    let mut pid = 0;
    // SAFETY: live pipe handle; valid out pointer.
    if unsafe { GetNamedPipeServerProcessId(pipe, &mut pid) }.is_ok() {
        // SAFETY: plain call.
        let _ = unsafe { AllowSetForegroundWindow(pid) };
    }
}

#[cfg(test)]
mod tests;
