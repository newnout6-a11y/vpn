//! The installer gate against a fake process layer: the scenario matrix of delivery §7.3
//! (AT-11-002 / AT-11-009) plus the ownership rules of `installer/PROGRESS.md`.
use std::cell::{Cell, RefCell};
use std::rc::Rc;

use super::*;

const DIR: &str = r"C:\fixture\vpn";
const EXE: &str = r"C:\fixture\vpn\VPN Tunnel Enforcer.exe";
const RUNTIME: &str = r"C:\ProgramData\VPNTE\runtime";
const OWN_PID: u32 = 9999;
/// The Windows session the gate runs in.
const OWN_SESSION: u32 = 1;
const TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug, Clone)]
struct Proc {
    pid: u32,
    ppid: u32,
    path: &'static str,
    created: u64,
    session: Option<u32>,
}

impl Proc {
    fn new(pid: u32, ppid: u32, path: &'static str, created: u64) -> Self {
        Self {
            pid,
            ppid,
            path,
            created,
            session: Some(OWN_SESSION),
        }
    }

    fn in_session(self, session: Option<u32>) -> Self {
        Self { session, ..self }
    }
}

/// The installed client, PID 42.
fn client() -> Proc {
    Proc::new(42, 1, EXE, 100)
}

/// A process layer that plays `frames` (one per snapshot, the last one repeating) and records
/// what the gate did.
struct Fake {
    frames: Vec<Vec<Proc>>,
    fail_snapshot: bool,
    gone_once: RefCell<Vec<u32>>,
    denied: Vec<u32>,
    handle_path: &'static str,
    ends: bool,
    exit: u32,
    kill_works: bool,
    snapshots: Cell<usize>,
    spawned: RefCell<Vec<String>>,
    opened: Cell<usize>,
    closed: Rc<Cell<usize>>,
    waits: Rc<RefCell<Vec<Duration>>>,
    killed: RefCell<Vec<u32>>,
}

impl Fake {
    fn new(frames: Vec<Vec<Proc>>) -> Self {
        Self {
            frames,
            fail_snapshot: false,
            gone_once: RefCell::default(),
            denied: Vec::new(),
            handle_path: EXE,
            ends: true,
            exit: EXIT_ACK,
            kill_works: true,
            snapshots: Cell::new(0),
            spawned: RefCell::default(),
            opened: Cell::new(0),
            closed: Rc::default(),
            waits: Rc::default(),
            killed: RefCell::default(),
        }
    }

    fn find(&self, pid: u32) -> Option<Proc> {
        self.frames.iter().flatten().find(|p| p.pid == pid).cloned()
    }

    fn run(&self) -> Result<(), Refusal> {
        gate(
            self,
            &Scope::new(Path::new(DIR), Some(Path::new(RUNTIME)), OWN_PID),
            TIMEOUT,
        )
    }

    /// Asserts whether the client was signalled and its handle bound (and released).
    fn assert_signalled(&self, signalled: bool, bound: bool) {
        let expected: Vec<String> = if signalled {
            vec![format!("{EXE} {ARG_SHUTDOWN_FOR_UPDATE}")]
        } else {
            Vec::new()
        };
        assert_eq!(*self.spawned.borrow(), expected);
        assert_eq!(self.opened.get(), usize::from(bound));
        assert_eq!(
            self.closed.get(),
            usize::from(bound),
            "bound handle released"
        );
    }
}

struct Handle {
    path: &'static str,
    ends: bool,
    exit: u32,
    waits: Rc<RefCell<Vec<Duration>>>,
    closed: Rc<Cell<usize>>,
}

impl Waitable for Handle {
    fn image_path(&self) -> io::Result<PathBuf> {
        Ok(PathBuf::from(self.path))
    }
    fn wait(&self, timeout: Duration) -> io::Result<bool> {
        self.waits.borrow_mut().push(timeout);
        Ok(self.ends)
    }
    fn exit_code(&self) -> io::Result<u32> {
        Ok(self.exit)
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        self.closed.set(self.closed.get() + 1);
    }
}

impl ProcessOs for Fake {
    fn snapshot(&self) -> io::Result<Vec<ProcRow>> {
        if self.fail_snapshot {
            return Err(io::Error::from_raw_os_error(5));
        }
        let frame = &self.frames[self.snapshots.get().min(self.frames.len() - 1)];
        self.snapshots.set(self.snapshots.get() + 1);
        let killed = self.killed.borrow();
        // The helper itself (a copy of the client exe) is always listed.
        let own = ProcRow {
            pid: OWN_PID,
            ppid: 1,
            name: MAIN_EXE.to_owned(),
            session: Some(OWN_SESSION),
        };
        Ok(std::iter::once(own)
            .chain(
                frame
                    .iter()
                    .filter(|p| !(self.kill_works && killed.contains(&p.pid)))
                    .map(|p| ProcRow {
                        pid: p.pid,
                        ppid: p.ppid,
                        name: p.path.rsplit('\\').next().unwrap_or_default().to_owned(),
                        session: p.session,
                    }),
            )
            .collect())
    }
    fn image_path(&self, pid: u32) -> Result<PathBuf, ProcError> {
        let mut gone = self.gone_once.borrow_mut();
        if let Some(i) = gone.iter().position(|p| *p == pid) {
            gone.remove(i);
            return Err(ProcError::Gone);
        }
        if self.denied.contains(&pid) {
            return Err(ProcError::Denied);
        }
        self.find(pid)
            .map(|p| PathBuf::from(p.path))
            .ok_or(ProcError::Gone)
    }
    fn created(&self, pid: u32) -> Option<u64> {
        self.find(pid).map(|p| p.created)
    }
    fn open_waitable(&self, pid: u32) -> Result<Box<dyn Waitable>, ProcError> {
        assert_eq!(pid, 42, "only the primary is ever bound");
        self.opened.set(self.opened.get() + 1);
        Ok(Box::new(Handle {
            path: self.handle_path,
            ends: self.ends,
            exit: self.exit,
            waits: self.waits.clone(),
            closed: self.closed.clone(),
        }))
    }
    fn spawn_detached(&self, exe: &Path, args: &[&str]) -> io::Result<()> {
        self.spawned
            .borrow_mut()
            .push(format!("{} {}", exe.display(), args.join(" ")));
        Ok(())
    }
    fn terminate(&self, pid: u32, image: &Path, wait: Duration) -> io::Result<bool> {
        assert_eq!(wait, KILL_WAIT);
        assert_eq!(
            self.find(pid).map(|p| PathBuf::from(p.path)).as_deref(),
            Some(image)
        );
        self.killed.borrow_mut().push(pid);
        Ok(self.kill_works)
    }
    fn sleep(&self, duration: Duration) {
        assert_eq!(duration, DRAIN_STEP);
    }
}

/// AT-11-002: an acknowledged exit (73) with nothing left is the only success with a client.
#[test]
fn success_needs_the_acknowledgement() {
    let os = Fake::new(vec![vec![client()], vec![]]);
    assert!(os.run().is_ok());
    os.assert_signalled(true, true);
    assert_eq!(*os.waits.borrow(), vec![TIMEOUT]);
    assert!(os.killed.borrow().is_empty());
}

/// AT-11-009: nothing running is a quick success that signals nothing.
#[test]
fn nothing_running_passes_at_once() {
    let os = Fake::new(vec![vec![]]);
    assert!(os.run().is_ok());
    os.assert_signalled(false, false);
    assert_eq!(os.snapshots.get(), 1);
}

/// AT-11-002: timeout, a normal exit and a crash are refusals, never success.
#[test]
fn only_exit_code_73_acknowledges() {
    let mut os = Fake::new(vec![vec![client()], vec![]]);
    os.ends = false;
    assert!(matches!(os.run(), Err(Refusal::Timeout)));
    os.assert_signalled(true, true);
    for code in [0, 1] {
        let mut os = Fake::new(vec![vec![client()], vec![]]);
        os.exit = code;
        assert!(matches!(os.run(), Err(Refusal::NoAck(c)) if c == code));
        os.assert_signalled(true, true);
    }
}

/// AT-11-009: an unreadable process list refuses with the OS error, before any signal.
#[test]
fn query_error_carries_the_os_error() {
    let mut os = Fake::new(vec![vec![client()]]);
    os.fail_snapshot = true;
    let err = os.run().unwrap_err();
    assert_eq!(
        err.to_string(),
        "Cannot list processes (os error 5); update refused."
    );
    os.assert_signalled(false, false);
}

const XRAY_LEGACY: &str = r"C:\fixture\vpn\vpnte-xray.exe";

/// B-08: engines left after an acknowledged exit are terminated after the drain.
#[test]
fn leftover_engines_are_terminated_after_the_drain() {
    let engine = Proc::new(50, 42, XRAY_LEGACY, 110);
    let os = Fake::new(vec![vec![client(), engine.clone()], vec![engine]]);
    assert!(os.run().is_ok());
    assert!(os.snapshots.get() >= 4);
    assert_eq!(*os.killed.borrow(), vec![50]);
    os.assert_signalled(true, true);

    let engine = Proc::new(50, 42, XRAY_LEGACY, 110);
    let mut os = Fake::new(vec![vec![client(), engine.clone()], vec![engine]]);
    os.kill_works = false;
    assert!(matches!(os.run(), Err(Refusal::Remaining)));
}

/// A second client is never terminated; helper children of the acknowledged one are.
#[test]
fn second_client_refuses_and_helpers_are_terminated() {
    let other = Proc::new(77, 1, EXE, 200);
    let os = Fake::new(vec![vec![client()], vec![other]]);
    assert!(matches!(os.run(), Err(Refusal::Remaining)));
    assert!(os.killed.borrow().is_empty());

    let helper = Proc::new(43, 42, EXE, 150);
    let os = Fake::new(vec![vec![client(), helper.clone()], vec![helper]]);
    assert!(os.run().is_ok());
    assert_eq!(*os.killed.borrow(), vec![43]);
    os.assert_signalled(true, true);
}

/// Engines that end within the drain need no termination.
#[test]
fn released_after_polls() {
    let engine = Proc::new(50, 42, XRAY_LEGACY, 110);
    let os = Fake::new(vec![
        vec![client(), engine.clone()],
        vec![engine.clone()],
        vec![engine],
        vec![],
    ]);
    assert!(os.run().is_ok());
    assert_eq!(os.snapshots.get(), 4);
    assert!(os.killed.borrow().is_empty());
}

/// A client running from another directory is not ours: nothing is signalled or stopped.
#[test]
fn foreign_client_is_ignored() {
    let os = Fake::new(vec![vec![Proc::new(
        42,
        1,
        r"C:\foreign\VPN Tunnel Enforcer.exe",
        100,
    )]]);
    assert!(os.run().is_ok());
    os.assert_signalled(false, false);
}

/// The handle bound before the signal must still be the installed exe.
#[test]
fn identity_change_refuses_before_the_signal() {
    let mut os = Fake::new(vec![vec![client()]]);
    os.handle_path = r"C:\elsewhere\VPN Tunnel Enforcer.exe";
    assert!(matches!(os.run(), Err(Refusal::IdentityChanged)));
    os.assert_signalled(false, true);
}

/// Two primaries, or a client whose image cannot be read, cannot be addressed.
#[test]
fn unidentifiable_clients_refuse_without_killing() {
    let os = Fake::new(vec![vec![client(), Proc::new(43, 7, EXE, 90)]]);
    assert!(matches!(os.run(), Err(Refusal::CannotIdentify)));
    os.assert_signalled(false, false);

    let mut os = Fake::new(vec![vec![client()]]);
    os.denied = vec![42];
    assert!(matches!(os.run(), Err(Refusal::CannotIdentify)));
    os.assert_signalled(false, false);

    // A client elsewhere under the directory and no primary.
    let os = Fake::new(vec![vec![Proc::new(
        44,
        1,
        r"C:\fixture\vpn\old\VPN Tunnel Enforcer.exe",
        100,
    )]]);
    assert!(matches!(os.run(), Err(Refusal::CannotIdentify)));
    assert!(os.killed.borrow().is_empty());
}

/// One copy runs per Windows session (owner decision 12): another user's own client, which a
/// standard user cannot read, does not block the update of this session's copy, and the shared
/// Electron runtime engines it may use stay alone. An unreadable client of this session or of an
/// unknown session still refuses, and a readable one of ours in another session cannot be
/// reached by the signal, so it refuses before anything is signalled.
#[test]
fn clients_of_other_sessions() {
    let theirs = Proc::new(
        80,
        1,
        r"C:\Users\b\AppData\Local\VPNTE\VPN Tunnel Enforcer.exe",
        90,
    )
    .in_session(Some(2));
    let mut os = Fake::new(vec![vec![client(), theirs.clone()], vec![theirs.clone()]]);
    os.denied = vec![80];
    assert!(os.run().is_ok());
    os.assert_signalled(true, true);

    let engine = Proc::new(61, 80, r"C:\ProgramData\VPNTE\runtime\x\vpnte-xray.exe", 95);
    let mut os = Fake::new(vec![vec![theirs.clone(), engine]]);
    os.denied = vec![80];
    assert!(os.run().is_ok());
    os.assert_signalled(false, false);
    assert!(os.killed.borrow().is_empty());

    for session in [Some(OWN_SESSION), None] {
        let mut os = Fake::new(vec![vec![theirs.clone().in_session(session)]]);
        os.denied = vec![80];
        assert!(matches!(os.run(), Err(Refusal::CannotIdentify)));
        os.assert_signalled(false, false);
    }

    let os = Fake::new(vec![vec![client().in_session(Some(2))]]);
    assert!(matches!(os.run(), Err(Refusal::CannotIdentify)));
    os.assert_signalled(false, false);
    assert!(os.killed.borrow().is_empty());
}

/// Chromium-style children belong to the primary; a recycled parent PID never hides it.
#[test]
fn children_and_stale_parents_keep_one_primary() {
    let child = Proc::new(43, 42, EXE, 150);
    let os = Fake::new(vec![vec![client(), child], vec![]]);
    assert!(os.run().is_ok());
    os.assert_signalled(true, true);

    // 42's parent PID 43 was recycled by a process created after it.
    let os = Fake::new(vec![
        vec![Proc::new(42, 43, EXE, 100), Proc::new(43, 42, EXE, 150)],
        vec![],
    ]);
    assert!(os.run().is_ok());
    os.assert_signalled(true, true);
}

/// A row that exited between the snapshot and the open is simply gone.
#[test]
fn exit_race_counts_as_absent() {
    let os = Fake::new(vec![vec![Proc::new(50, 1, XRAY_LEGACY, 110)], vec![]]);
    os.gone_once.borrow_mut().push(50);
    assert!(os.run().is_ok());
    os.assert_signalled(false, false);
    assert!(os.killed.borrow().is_empty());
}

/// B-08: old engines without any client (here in the Electron runtime dir) are terminated.
#[test]
fn orphan_engines_are_terminated() {
    let orphan = Proc::new(
        60,
        1,
        r"C:\ProgramData\VPNTE\runtime\0123456789abcdef0123456789abcdef\tun-runtime\vpnte-sing-box.exe",
        100,
    );
    let os = Fake::new(vec![vec![orphan.clone()]]);
    assert!(os.run().is_ok());
    assert_eq!(*os.killed.borrow(), vec![60]);
    os.assert_signalled(false, false);

    // While an old client runs from another directory, the shared runtime engines may be its
    // own: they are left alone (and that client is not ours to stop).
    let other = Proc::new(
        80,
        1,
        r"C:\Program Files\Old VPNTE\VPN Tunnel Enforcer.exe",
        90,
    );
    let os = Fake::new(vec![vec![other, orphan]]);
    assert!(os.run().is_ok());
    assert!(os.killed.borrow().is_empty());
    os.assert_signalled(false, false);
}

/// Never by name alone: the user's own `xray.exe` / `sing-box.exe` elsewhere, a look-alike
/// directory, a new-generation name in the old runtime dir and the helper itself are not ours.
#[test]
fn ownership_is_decided_by_path() {
    let os = Fake::new(vec![vec![
        Proc::new(70, 1, r"C:\Users\u\AppData\Local\Happ\xray.exe", 100),
        Proc::new(71, 1, r"C:\fixture\vpn-evil\sing-box.exe", 100),
        Proc::new(72, 1, r"C:\ProgramData\VPNTE\runtime\x\sing-box.exe", 100),
        Proc::new(OWN_PID, 1, EXE, 100),
    ]]);
    assert!(os.run().is_ok());
    assert!(os.killed.borrow().is_empty());
    os.assert_signalled(false, false);

    // Our engines under the installation, in any letter case, are ours.
    let os = Fake::new(vec![vec![
        Proc::new(73, 1, r"c:\FIXTURE\vpn\resources\SING-BOX.exe", 100),
        Proc::new(74, 1, r"C:\fixture\vpn\vpnte-proxy.exe", 100),
    ]]);
    assert!(os.run().is_ok());
    assert_eq!(*os.killed.borrow(), vec![73, 74]);
}

/// An empty or missing `--install-dir` refuses before anything is read.
#[test]
fn missing_install_dir_refuses() {
    let os = Fake::new(vec![vec![client()]]);
    let err = await_shutdown(&os, None, None, TIMEOUT).unwrap_err();
    assert_eq!(
        err.to_string(),
        "Installation path is missing; update refused."
    );
    assert_eq!(os.snapshots.get(), 0);
}

/// The stderr lines are the installer contract's texts, plain ASCII.
#[test]
fn refusal_lines_follow_the_contract() {
    let lines = [
        (
            Refusal::CannotIdentify,
            "Cannot identify the installed primary client. Close VPNTE normally and retry; no processes were killed.",
        ),
        (
            Refusal::IdentityChanged,
            "Primary process identity changed; update refused.",
        ),
        (
            Refusal::Timeout,
            "Client cleanup timed out; update refused.",
        ),
        (
            Refusal::NoAck(0),
            "Client exited without cleanup acknowledgement; update refused.",
        ),
        (
            Refusal::Remaining,
            "VPNTE background processes remain; update refused.",
        ),
    ];
    for (refusal, line) in lines {
        assert_eq!(refusal.to_string(), line);
        assert!(line.is_ascii());
    }
    let hresult = io::Error::from_raw_os_error(0x8007_0005_u32.cast_signed());
    assert_eq!(os_code(&hresult), "0x80070005");
}
