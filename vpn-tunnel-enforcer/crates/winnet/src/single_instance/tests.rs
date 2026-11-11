use std::sync::atomic::{AtomicU32, Ordering};
use std::time::SystemTime;

use super::*;

/// Random names, so tests never meet each other or a real installed instance.
fn names() -> InstanceNames {
    static N: AtomicU32 = AtomicU32::new(0);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    let tag = format!(
        "VPNTE-Test-{}-{}-{nanos}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    );
    InstanceNames {
        mutex: format!(r"Global\{tag}"),
        pipe: format!(r"\\.\pipe\{tag}"),
    }
}

fn primary(names: &InstanceNames) -> Primary {
    match acquire(names).unwrap() {
        Acquire::Primary(p) => p,
        Acquire::Secondary => panic!("expected to be the primary"),
    }
}

const WAIT: Duration = Duration::from_secs(5);

#[test]
fn command_follows_the_installer_flag() {
    assert_eq!(Command::from_args(["app.exe"]), Command::Activate);
    assert_eq!(
        Command::from_args(["app.exe", "--autostart"]),
        Command::Activate
    );
    assert_eq!(
        Command::from_args(["app.exe", "--shutdown-for-update"]),
        Command::ShutdownForUpdate
    );
}

#[test]
fn wire_lines_round_trip() {
    for cmd in [Command::Activate, Command::ShutdownForUpdate] {
        assert_eq!(
            Command::parse(format!("{}\n", cmd.wire()).as_bytes()),
            Some(cmd)
        );
        assert_eq!(
            Command::parse(format!("{}\r\n", cmd.wire()).as_bytes()),
            Some(cmd)
        );
    }
    assert_eq!(Command::parse(b""), None);
    assert_eq!(Command::parse(b"activate now\n"), None);
    assert_eq!(Command::parse(b"ACTIVATE\n"), None);
}

/// C-04: a second launch in the same session forwards its command and the first instance
/// receives it; the installer's request travels the same way.
#[test]
fn second_launch_hands_its_command_to_the_first() {
    let names = names();
    let mut first = primary(&names);
    assert!(first.is_listening());
    let mut commands = first.take_commands().unwrap();
    assert!(matches!(acquire(&names).unwrap(), Acquire::Secondary));

    assert_eq!(
        send(&names.pipe, Command::Activate, WAIT).unwrap(),
        Handoff::Delivered
    );
    assert_eq!(commands.try_recv().unwrap(), Command::Activate);
    let sent = send(&names.pipe, Command::ShutdownForUpdate, WAIT).unwrap();
    assert_eq!(sent, Handoff::Delivered);
    assert_eq!(commands.try_recv().unwrap(), Command::ShutdownForUpdate);
    assert!(commands.try_recv().is_err());
}

/// Dropping the guard stops the listener and frees the lock for the next start.
#[test]
fn dropping_the_primary_releases_the_lock() {
    let names = names();
    drop(primary(&names));
    let again = primary(&names);
    assert!(again.is_listening());
}

/// C-04: with nobody listening the hand-off fails fast instead of hanging.
#[test]
fn no_primary_means_no_answer() {
    let names = names();
    let err = send(
        &names.pipe,
        Command::ShutdownForUpdate,
        Duration::from_millis(200),
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Timeout);
    assert_eq!(err.user_msg().key, "winnet.singleInstance.noAnswer");
}

/// Sends raw bytes as one message and returns the raw reply.
fn exchange(pipe: &str, data: &[u8]) -> Result<Vec<u8>, IoEnd> {
    let handle = open_client(pipe, WAIT).unwrap();
    let mode = PIPE_READMODE_MESSAGE;
    // SAFETY: live pipe handle; `mode` outlives the call.
    unsafe { SetNamedPipeHandleState(raw(&handle), Some(&mode), None, None) }.unwrap();
    let event = event().unwrap();
    let io = Io {
        pipe: raw(&handle),
        event: raw(&event),
        stop: None,
    };
    let mut reply = [0u8; 64];
    let n = io.transact(data, &mut reply)?;
    Ok(reply[..n].to_vec())
}

/// Garbage and oversized lines are refused without queuing anything, and the listener keeps
/// serving the next launch.
#[test]
fn bad_lines_are_refused_and_the_listener_survives() {
    let names = names();
    let mut first = primary(&names);
    let mut commands = first.take_commands().unwrap();

    assert_eq!(exchange(&names.pipe, b"hello\n").unwrap(), b"invalid\n");
    assert!(exchange(&names.pipe, &[b'a'; MAX_LINE + 100]).is_err());
    assert!(commands.try_recv().is_err());

    assert_eq!(
        send(&names.pipe, Command::Activate, WAIT).unwrap(),
        Handoff::Delivered
    );
    assert_eq!(commands.try_recv().unwrap(), Command::Activate);
}

/// A pipe squatted by someone else is never joined: the primary keeps the lock but does not
/// listen on a pipe it does not own.
#[test]
fn squatted_pipe_is_not_joined() {
    let names = names();
    // SAFETY: valid name; the squatter's handle is owned right away.
    let squatter = unsafe {
        CreateNamedPipeW(
            &HSTRING::from(names.pipe.as_str()),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE,
            1,
            512,
            512,
            0,
            None,
        )
    };
    assert!(!squatter.is_invalid());
    // SAFETY: a fresh handle that nothing else owns.
    let _squatter = unsafe { OwnedHandle::from_raw_handle(squatter.0) };
    let first = primary(&names);
    assert!(!first.is_listening());
}

/// A pipe server driven by the test, standing in for a primary in another session or a squatter.
fn fake_server(names: &InstanceNames) -> OwnedHandle {
    // SAFETY: valid name; the handle is owned right away.
    let pipe = unsafe {
        CreateNamedPipeW(
            &HSTRING::from(names.pipe.as_str()),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE,
            1,
            512,
            512,
            0,
            None,
        )
    };
    assert!(!pipe.is_invalid());
    // SAFETY: a fresh handle that nothing else owns.
    unsafe { OwnedHandle::from_raw_handle(pipe.0) }
}

/// Serves one client: reads its line, runs `inspect` while the client is connected, answers
/// `reply` and waits for the client to close.
fn serve_once<T>(pipe: &OwnedHandle, reply: &[u8], inspect: impl FnOnce(&[u8]) -> T) -> T {
    let event = event().unwrap();
    let io = Io {
        pipe: raw(pipe),
        event: raw(&event),
        stop: None,
    };
    io.connect().unwrap();
    let mut buf = [0u8; MAX_LINE];
    let n = io.read(&mut buf).unwrap();
    let seen = inspect(&buf[..n]);
    io.write(reply).unwrap();
    let _ = io.read(&mut buf);
    seen
}

/// A primary in another Windows session answers `other-session` to an activation request;
/// the second launch then shows the decided message instead of waiting for a window.
#[test]
fn other_session_reply_is_reported() {
    let names = names();
    let pipe = fake_server(&names);
    let fake = std::thread::spawn(move || {
        serve_once(&pipe, b"other-session\n", |line| {
            assert_eq!(Command::parse(line), Some(Command::Activate));
        });
    });
    let sent = send(&names.pipe, Command::Activate, WAIT).unwrap();
    assert_eq!(sent, Handoff::OtherSession);
    fake.join().unwrap();
}

/// The client end grants identification only: whoever serves the pipe (a squatter that took
/// the name first) cannot act with the token of an elevated second launch.
#[test]
fn a_pipe_server_can_only_identify_the_client() {
    use windows::Win32::Security::{
        GetTokenInformation, RevertToSelf, SECURITY_IMPERSONATION_LEVEL, SecurityIdentification,
        TOKEN_QUERY, TokenImpersonationLevel,
    };
    use windows::Win32::System::Pipes::ImpersonateNamedPipeClient;
    use windows::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

    let names = names();
    let pipe = fake_server(&names);
    let fake = std::thread::spawn(move || {
        serve_once(&pipe, b"ok\n", |_| {
            let mut level = SECURITY_IMPERSONATION_LEVEL::default();
            let mut token = HANDLE::default();
            let mut len = 0;
            // SAFETY: a connected client has written a message, so it can be impersonated; the
            // thread token is opened as self (an identification token cannot open itself), read
            // into a value of the passed size, closed, and the thread reverts before returning.
            unsafe {
                ImpersonateNamedPipeClient(raw(&pipe)).unwrap();
                OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut token).unwrap();
                let token = OwnedHandle::from_raw_handle(token.0);
                GetTokenInformation(
                    raw(&token),
                    TokenImpersonationLevel,
                    Some((&raw mut level).cast()),
                    size_of::<SECURITY_IMPERSONATION_LEVEL>() as u32,
                    &mut len,
                )
                .unwrap();
                RevertToSelf().unwrap();
            }
            level
        })
    });
    let sent = send(&names.pipe, Command::Activate, WAIT).unwrap();
    assert_eq!(sent, Handoff::Delivered);
    assert_eq!(fake.join().unwrap(), SecurityIdentification);
}
