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
        mutex: format!(r"Local\{tag}"),
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
fn wire_lines_round_trip() {
    let link = Command::OpenLink(
        "vless://00000000-0000-4000-8000-000000000000@h.example:443?security=reality#Ключ".into(),
    );
    for cmd in [Command::Activate, Command::ShutdownForUpdate, link] {
        let line = cmd.line();
        assert_eq!(Command::parse(line.as_bytes()), Some(cmd.clone()));
        let crlf = format!("{}\r\n", line.trim_end());
        assert_eq!(Command::parse(crlf.as_bytes()), Some(cmd));
    }
    assert_eq!(Command::parse(b""), None);
    assert_eq!(Command::parse(b"activate now\n"), None);
    assert_eq!(Command::parse(b"ACTIVATE\n"), None);
    assert_eq!(Command::parse(b"open-link \n"), None);
    assert_eq!(Command::parse(b"open-link a\tb\n"), None);
    assert_eq!(Command::parse(b"open-link \xff\xfe\n"), None);
}

/// RU-2026 item 4: a link Windows passed to a second launch reaches the running instance whole;
/// links that are not one printable line within the limit are refused before the pipe.
#[test]
fn a_second_launch_hands_over_its_link() {
    let names = names();
    let mut first = primary(&names);
    let mut commands = first.take_commands().unwrap();
    let link = format!(
        "hiddify://import/https://sub.example/s/{}#Name",
        "x".repeat(4000)
    );
    send(&names.pipe, Command::OpenLink(link.clone()), WAIT).unwrap();
    assert_eq!(commands.try_recv().unwrap(), Command::OpenLink(link));
    for bad in ["", "  ", "vless://a\nvless://b", &"a".repeat(MAX_LINK + 1)] {
        let err = send(&names.pipe, Command::OpenLink(bad.to_owned()), WAIT).unwrap_err();
        assert_eq!(err.kind, ErrorKind::Validation);
    }
    assert!(commands.try_recv().is_err());
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

    send(&names.pipe, Command::Activate, WAIT).unwrap();
    assert_eq!(commands.try_recv().unwrap(), Command::Activate);
    send(&names.pipe, Command::ShutdownForUpdate, WAIT).unwrap();
    assert_eq!(commands.try_recv().unwrap(), Command::ShutdownForUpdate);
    assert!(commands.try_recv().is_err());
}

/// Owner decision 12: the installed app's lock lives in the session's own namespace and its
/// pipe name carries the session id, so every Windows session (every user) runs its own copy.
#[test]
fn production_names_are_per_session() {
    let names = InstanceNames::production().unwrap();
    assert_eq!(names.mutex, r"Local\VpnTunnelEnforcer.Instance");
    let session = current_session().unwrap();
    assert_eq!(names.pipe, format!(r"\\.\pipe\VpnTunnelEnforcer.{session}"));
    assert_ne!(
        InstanceNames::for_session(1).pipe,
        InstanceNames::for_session(2).pipe
    );
}

/// Owner decision 12: two sessions each run a listening primary (two mutex names stand in for
/// the two `Local\` namespaces); the session id in the pipe name keeps the command pipes apart,
/// so the installer's request reaches only the copy of its own session.
#[test]
fn each_session_runs_its_own_primary() {
    let base = names();
    let session = |id: u32| InstanceNames {
        mutex: format!("{}-{id}", base.mutex),
        pipe: format!("{}.{id}", base.pipe),
    };
    let (one, two) = (session(1), session(2));
    let mut first = primary(&one);
    let mut second = primary(&two);
    assert!(first.is_listening() && second.is_listening());
    let mut heard_by_one = first.take_commands().unwrap();
    let mut heard_by_two = second.take_commands().unwrap();

    send(&two.pipe, Command::ShutdownForUpdate, WAIT).unwrap();
    assert_eq!(heard_by_two.try_recv().unwrap(), Command::ShutdownForUpdate);
    assert!(heard_by_one.try_recv().is_err());
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

    send(&names.pipe, Command::Activate, WAIT).unwrap();
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

/// A primary that refuses the command (an activation from another session's client) is no
/// answer for the launch: it exits without waiting for a window.
#[test]
fn a_refused_command_is_no_answer() {
    let names = names();
    let pipe = fake_server(&names);
    let fake = std::thread::spawn(move || {
        serve_once(&pipe, b"other-session\n", |line| {
            assert_eq!(Command::parse(line), Some(Command::Activate));
        });
    });
    let err = send(&names.pipe, Command::Activate, WAIT).unwrap_err();
    assert_eq!(err.user_msg().key, "winnet.singleInstance.noAnswer");
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
    send(&names.pipe, Command::Activate, WAIT).unwrap();
    assert_eq!(fake.join().unwrap(), SecurityIdentification);
}

const KEY: &str = "vless://00000000-0000-4000-8000-000000000000@h.example:443#Key";

/// phones-b1: a link (a key, a subscription token) is written only to a pipe served by this exe
/// in this session. A server that is another program, or sits in another session, gets nothing.
#[test]
fn a_link_goes_only_to_this_exe_in_this_session() {
    let names = names();
    let mut first = primary(&names);
    let mut commands = first.take_commands().unwrap();
    let us = Peer::this_process().unwrap();
    let elsewhere = [
        Peer {
            exe: std::env::temp_dir(),
            ..us.clone()
        },
        Peer {
            session: us.session + 1,
            ..us.clone()
        },
    ];
    for peer in &elsewhere {
        let err =
            send_checked(&names.pipe, Command::OpenLink(KEY.into()), WAIT, Some(peer)).unwrap_err();
        assert_eq!(err.kind, ErrorKind::Permission);
        assert_eq!(err.user_msg().key, "winnet.singleInstance.noAnswer");
    }
    assert!(commands.try_recv().is_err());
    send(&names.pipe, Command::OpenLink(KEY.into()), WAIT).unwrap();
    assert_eq!(commands.try_recv().unwrap(), Command::OpenLink(KEY.into()));
}

/// phones-b1: a squatter that created the pipe name first (another user's program; here a pipe
/// whose server fails the exe check) reads nothing: the link is refused before any write.
#[test]
fn a_squatter_reads_no_link() {
    let names = names();
    let pipe = fake_server(&names);
    let squatter = std::thread::spawn(move || {
        let event = event().unwrap();
        let io = Io {
            pipe: raw(&pipe),
            event: raw(&event),
            stop: None,
        };
        // The launch may check the server and leave before this connect runs; Windows then ends
        // the connect with ERROR_NO_DATA ("the pipe is being closed"). Nothing was read either way.
        if io.connect().is_err() {
            return None;
        }
        let mut buf = [0u8; MAX_LINE];
        io.read(&mut buf).map(|n| buf[..n].to_vec()).ok()
    });
    let stranger = Peer {
        exe: std::env::temp_dir(),
        ..Peer::this_process().unwrap()
    };
    let err = send_checked(
        &names.pipe,
        Command::OpenLink(KEY.into()),
        WAIT,
        Some(&stranger),
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Permission);
    assert_eq!(squatter.join().unwrap(), None, "the squatter read a line");
}

/// phones-a7: the pipe admits exactly the user's launches with the rights they ask for: the
/// descriptor's owner is this user, the label is medium (no write up), and the user's grant is
/// the client's request (never FILE_APPEND_DATA, which would let them add pipe instances).
#[test]
fn the_pipe_admits_the_user_at_medium_integrity() {
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows::Win32::Security::{
        DACL_SECURITY_INFORMATION, LABEL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR,
    };
    use windows::core::PWSTR;

    let sd = PipeSecurity::new().unwrap();
    let attributes = sd.attributes();
    let mut text = PWSTR::null();
    // SAFETY: a valid descriptor; the string is freed right after reading it.
    let sddl = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            PSECURITY_DESCRIPTOR(attributes.lpSecurityDescriptor),
            SDDL_REVISION_1,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
            &mut text,
            None,
        )
        .unwrap();
        let sddl = text.to_string().unwrap();
        LocalFree(Some(HLOCAL(text.0.cast())));
        sddl
    };
    let owner = sddl
        .strip_prefix("O:")
        .and_then(|rest| rest.split_once("D:"))
        .map(|(owner, _)| owner.to_owned())
        .unwrap_or_default();
    // SDDL writes well-known accounts by alias (the built-in Administrator, which CI runners use,
    // as `LA`): compare the SIDs, not their spellings.
    assert_eq!(
        sid_text(&owner),
        security::user_sid().unwrap(),
        "the owner is this user: {sddl}"
    );
    assert!(
        sddl.contains(&format!(";;;{owner})")),
        "no grant for the user: {sddl}"
    );
    assert!(
        !sddl.contains("WD)") && !sddl.contains(";AU)"),
        "a grant for others: {sddl}"
    );
    assert!(sddl.contains("(ML;;NW;;;ME)"), "{sddl}");
    assert_eq!(security::CLIENT_ACCESS & 0x4, 0, "FILE_APPEND_DATA");
    // An unelevated primary refuses no shutdown: the guard is for an elevated one only.
    let names = names();
    let mut first = primary(&names);
    let mut commands = first.take_commands().unwrap();
    send(&names.pipe, Command::ShutdownForUpdate, WAIT).unwrap();
    assert_eq!(commands.try_recv().unwrap(), Command::ShutdownForUpdate);
}

/// A SID in SDDL text (`S-1-5-…` or an alias such as `LA`) as its `S-1-5-…` form.
fn sid_text(sid: &str) -> String {
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW};
    use windows::Win32::Security::PSID;
    use windows::core::{HSTRING, PWSTR};

    let mut psid = PSID::default();
    let mut text = PWSTR::null();
    // SAFETY: valid strings and out pointers; both buffers are freed once after reading.
    unsafe {
        ConvertStringSidToSidW(&HSTRING::from(sid), &mut psid).unwrap();
        ConvertSidToStringSidW(psid, &mut text).unwrap();
        let out = text.to_string().unwrap();
        LocalFree(Some(HLOCAL(text.0.cast())));
        LocalFree(Some(HLOCAL(psid.0)));
        out
    }
}

/// phones-a7 / b4: Windows starts a clicked link's launch unelevated. With the primary running as
/// administrator (TUN) that launch still hands its link over, but cannot make the primary quit.
#[test]
#[ignore = "needs elevation"]
fn elevated_an_unelevated_launch_hands_a_link_but_cannot_stop_the_primary() {
    assert!(crate::elevation::is_elevated(), "run elevated");
    let names = names();
    let mut first = primary(&names);
    let mut commands = first.take_commands().unwrap();
    let pipe = names.pipe.clone();
    let (linked, stopped) = std::thread::spawn(move || {
        as_unelevated(|| {
            let linked = send(&pipe, Command::OpenLink(KEY.into()), WAIT);
            (linked, send(&pipe, Command::ShutdownForUpdate, WAIT))
        })
    })
    .join()
    .unwrap();
    linked.unwrap();
    assert!(stopped.is_err());
    assert_eq!(commands.try_recv().unwrap(), Command::OpenLink(KEY.into()));
    assert!(commands.try_recv().is_err());
}

/// Runs `f` on this thread as UAC runs an unelevated launch: a medium-integrity copy of the
/// process token whose administrators group is deny-only.
fn as_unelevated<T>(f: impl FnOnce() -> T) -> T {
    use windows::Win32::Security::{
        CreateRestrictedToken, CreateWellKnownSid, DISABLE_MAX_PRIVILEGE, GetLengthSid,
        ImpersonateLoggedOnUser, PSID, RevertToSelf, SECURITY_MAX_SID_SIZE, SID_AND_ATTRIBUTES,
        SetTokenInformation, TOKEN_ADJUST_DEFAULT, TOKEN_DUPLICATE, TOKEN_IMPERSONATE,
        TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TokenIntegrityLevel, WinBuiltinAdministratorsSid,
        WinMediumLabelSid,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut admins = [0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut medium = [0u8; SECURITY_MAX_SID_SIZE as usize];
    let (admins, medium) = (
        PSID(admins.as_mut_ptr().cast()),
        PSID(medium.as_mut_ptr().cast()),
    );
    let (mut process, mut lowered) = (HANDLE::default(), HANDLE::default());
    // SAFETY: SID buffers of the maximum size; tokens opened here, closed by OwnedHandle; the
    // label struct and SID outlive SetTokenInformation; the thread reverts before returning.
    unsafe {
        let mut len = SECURITY_MAX_SID_SIZE;
        CreateWellKnownSid(WinBuiltinAdministratorsSid, None, Some(admins), &mut len).unwrap();
        let mut len = SECURITY_MAX_SID_SIZE;
        CreateWellKnownSid(WinMediumLabelSid, None, Some(medium), &mut len).unwrap();
        let rights = TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_IMPERSONATE;
        OpenProcessToken(GetCurrentProcess(), rights, &mut process).unwrap();
        let _process = OwnedHandle::from_raw_handle(process.0);
        let deny = [SID_AND_ATTRIBUTES {
            Sid: admins,
            Attributes: 0,
        }];
        CreateRestrictedToken(
            process,
            DISABLE_MAX_PRIVILEGE,
            Some(&deny),
            None,
            None,
            &mut lowered,
        )
        .unwrap();
        let lowered_owned = OwnedHandle::from_raw_handle(lowered.0);
        // 0x20 = SE_GROUP_INTEGRITY.
        let label = TOKEN_MANDATORY_LABEL {
            Label: SID_AND_ATTRIBUTES {
                Sid: medium,
                Attributes: 0x20,
            },
        };
        let size = size_of::<TOKEN_MANDATORY_LABEL>() as u32 + GetLengthSid(medium);
        SetTokenInformation(
            lowered,
            TokenIntegrityLevel,
            (&raw const label).cast(),
            size,
        )
        .unwrap();
        ImpersonateLoggedOnUser(lowered).unwrap();
        let out = f();
        RevertToSelf().unwrap();
        drop(lowered_owned);
        out
    }
}
