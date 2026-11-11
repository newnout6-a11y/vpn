use std::cell::{Cell, RefCell};

use windows::Win32::Foundation::E_UNEXPECTED;
use windows::core::HRESULT;

use super::*;

const PRESENT: AutostartState = AutostartState::Present { matches_exe: true };
const STALE: AutostartState = AutostartState::Present { matches_exe: false };

/// Task Scheduler stand-in: records applies, can refuse one direction, ignore applies
/// (the read-back then disagrees) or fail every read.
struct Fake<'a> {
    state: Cell<AutostartState>,
    applied: RefCell<Vec<bool>>,
    refuse: Option<bool>,
    ignore_applies: bool,
    read_error: Option<HRESULT>,
    on_apply: Box<dyn Fn() + 'a>,
}

impl Fake<'_> {
    fn new(state: AutostartState) -> Self {
        Self {
            state: Cell::new(state),
            applied: RefCell::default(),
            refuse: None,
            ignore_applies: false,
            read_error: None,
            on_apply: Box::new(|| {}),
        }
    }
}

impl AutostartOs for Fake<'_> {
    fn apply(&self, enabled: bool) -> Result<()> {
        self.applied.borrow_mut().push(enabled);
        (self.on_apply)();
        if self.refuse == Some(enabled) {
            let what = if enabled {
                "create refused"
            } else {
                "delete refused"
            };
            return Err(windows::core::Error::new(E_ACCESSDENIED, what));
        }
        if !self.ignore_applies {
            self.state.set(wanted(enabled));
        }
        Ok(())
    }
    fn read(&self) -> Result<AutostartState> {
        match self.read_error {
            Some(code) => Err(code.into()),
            None => Ok(self.state.get()),
        }
    }
}

/// The settings document as far as these tests care: the flag plus an unrelated field.
#[derive(Default)]
struct Stored {
    autostart: bool,
    stealth_mode: bool,
}

fn save(stored: &RefCell<Stored>) -> impl FnOnce(bool) -> AppResult<()> + '_ {
    move |on| {
        stored.borrow_mut().autostart = on;
        Ok(())
    }
}

fn disk_full(_: bool) -> AppResult<()> {
    Err(AppError::internal(std::io::Error::other("Disk full")))
}

/// AT-03-002: enable, then a delete that fails leaves the flag on.
#[test]
fn a_refused_delete_keeps_the_flag() {
    let os = Fake {
        refuse: Some(false),
        ..Fake::new(AutostartState::Absent)
    };
    let stored = RefCell::new(Stored::default());
    set_checked(&os, false, true, save(&stored)).unwrap();
    assert!(stored.borrow().autostart);

    let err = set_checked(&os, true, false, save(&stored)).unwrap_err();
    assert!(
        matches!(err, AutostartError::Unchanged(Step::Os(_))),
        "{err}"
    );
    assert!(stored.borrow().autostart);
    assert_eq!(
        *os.applied.borrow(),
        [true, false],
        "no restore after a refused apply"
    );
}

/// AT-03-002: create succeeds but the read-back says absent: restored, flag unchanged.
#[test]
fn a_readback_mismatch_restores_the_previous_state() {
    let os = Fake {
        ignore_applies: true,
        ..Fake::new(AutostartState::Absent)
    };
    let stored = RefCell::new(Stored::default());
    let err = set_checked(&os, false, true, save(&stored)).unwrap_err();
    assert!(err.to_string().contains("readback"), "{err}");
    assert!(matches!(
        err,
        AutostartError::Unchanged(Step::Readback { .. })
    ));
    assert_eq!(*os.applied.borrow(), [true, false], "the delete was issued");
    assert!(!stored.borrow().autostart);
}

/// AT-03-003: a read-back that fails (access denied, anything unexpected) is an unknown
/// state, never "absent"; the flag is not touched.
#[test]
fn an_unreadable_task_is_unknown_and_keeps_the_flag() {
    for code in [E_ACCESSDENIED, E_UNEXPECTED] {
        let os = Fake {
            read_error: Some(code),
            ..Fake::new(AutostartState::Absent)
        };
        let stored = RefCell::new(Stored::default());
        let err = set_checked(&os, false, true, save(&stored)).unwrap_err();
        assert!(matches!(err, AutostartError::Unknown { .. }), "{err}");
        assert!(!stored.borrow().autostart);
    }
}

/// AT-03-003: an answer that is not the task we asked for (stale action) is not success.
#[test]
fn a_stale_task_after_create_is_a_readback_failure() {
    let os = Fake {
        ignore_applies: true,
        ..Fake::new(STALE)
    };
    let stored = RefCell::new(Stored::default());
    let err = set_checked(&os, false, true, save(&stored)).unwrap_err();
    let unknown = matches!(
        err,
        AutostartError::Unknown {
            cause: Step::Readback { .. },
            ..
        }
    );
    assert!(unknown, "the stale task also survives the delete: {err}");
    assert!(!stored.borrow().autostart);
}

#[test]
fn a_settings_save_made_during_the_create_is_kept() {
    let stored = RefCell::new(Stored::default());
    let os = Fake {
        on_apply: Box::new(|| stored.borrow_mut().stealth_mode = true),
        ..Fake::new(AutostartState::Absent)
    };
    set_checked(&os, false, true, save(&stored)).unwrap();
    assert!(stored.borrow().autostart && stored.borrow().stealth_mode);
}

/// Persisting fails after the create: the task is deleted again, the flag stays off.
#[test]
fn a_failed_persist_deletes_the_task_again() {
    let os = Fake::new(AutostartState::Absent);
    let err = set_checked(&os, false, true, disk_full).unwrap_err();
    assert!(
        matches!(err, AutostartError::Unchanged(Step::Persist(_))),
        "{err}"
    );
    assert_eq!(*os.applied.borrow(), [true, false]);
    assert_eq!(os.state.get(), AutostartState::Absent);
}

/// The restore fails too: the message names the unknown state and both causes.
#[test]
fn a_failed_restore_reports_an_unknown_state() {
    let os = Fake {
        refuse: Some(false),
        ..Fake::new(AutostartState::Absent)
    };
    let err = set_checked(&os, false, true, disk_full).unwrap_err();
    let text = err.to_string();
    for needle in ["Autostart state is unknown", "Disk full", "delete refused"] {
        assert!(text.contains(needle), "{needle:?} missing in {text}");
    }
    let AutostartError::Unknown {
        cause: Step::Persist(cause),
        restore: Step::Os(restore),
    } = &err
    else {
        panic!("both causes must be reachable: {err:?}");
    };
    assert!(cause.to_string().contains("Disk full"));
    assert_eq!(restore.code(), E_ACCESSDENIED);
    let app: AppError = err.into();
    assert_eq!(app.user_msg().key, "winnet.autostart.unknown");
}

#[test]
fn app_errors_name_the_reason() {
    let refused = AutostartError::Unchanged(Step::Os(E_ACCESSDENIED.into()));
    let app: AppError = refused.into();
    assert_eq!(
        (app.kind, app.user_msg().key.as_ref()),
        (ErrorKind::Permission, "winnet.autostart.needsAdmin")
    );
    let mismatch = AutostartError::Unchanged(Step::Readback {
        expected: PRESENT,
        found: STALE,
    });
    assert_eq!(
        AppError::from(mismatch).user_msg().key,
        "winnet.autostart.failed"
    );
}

/// Startup sync acts only on a mismatch; a stale (old exe) task is replaced or removed.
#[test]
fn sync_acts_only_on_a_mismatch() {
    for (state, enabled, acted) in [
        (AutostartState::Absent, false, false),
        (PRESENT, true, false),
        (STALE, false, true),
        (STALE, true, true),
        (AutostartState::Absent, true, true),
        (PRESENT, false, true),
    ] {
        let os = Fake::new(state);
        assert_eq!(sync(&os, enabled).unwrap(), acted, "{state:?} -> {enabled}");
        assert_eq!(
            *os.applied.borrow(),
            if acted { vec![enabled] } else { vec![] }
        );
    }
    let os = Fake {
        read_error: Some(E_ACCESSDENIED),
        ..Fake::new(PRESENT)
    };
    assert!(sync(&os, false).is_err(), "unknown state: no blind delete");
    assert!(os.applied.borrow().is_empty());
}

#[test]
fn exe_paths_compare_like_windows_paths() {
    let exe = Path::new(r"C:\Program Files\VPN Tunnel Enforcer\VPN Tunnel Enforcer.exe");
    assert!(same_exe(
        r"c:\program files\vpn tunnel enforcer\vpn tunnel enforcer.EXE",
        exe
    ));
    assert!(same_exe(
        r#""C:\Program Files\VPN Tunnel Enforcer\VPN Tunnel Enforcer.exe""#,
        exe
    ));
    assert!(same_exe(
        "C:/Program Files/VPN Tunnel Enforcer/VPN Tunnel Enforcer.exe",
        exe
    ));
    assert!(!same_exe(
        r"C:\Users\u\AppData\Local\Programs\vpn\VPN Tunnel Enforcer.exe",
        exe
    ));
    assert!(same_exe(
        r"C:\Пользователи\ВПН.exe",
        Path::new(r"c:\пользователи\впн.exe")
    ));
}

/// B12: only an enabled task whose single action is `exe --autostart` is ours; the old schtasks
/// task (no flag), another exe, extra actions or a disabled task are stale.
#[test]
fn only_an_enabled_exe_autostart_task_matches() {
    let exe = Path::new(r"C:\Program Files\VPN Tunnel Enforcer\VPN Tunnel Enforcer.exe");
    let action = |path: &str, arguments: &str| ExecAction {
        path: path.into(),
        arguments: arguments.into(),
    };
    let ours = action(
        r#""C:\Program Files\VPN Tunnel Enforcer\VPN Tunnel Enforcer.exe""#,
        "--autostart ",
    );
    let task = |enabled, exec: Vec<ExecAction>, other_actions| TaskInfo {
        user_id: r"PC\user".into(),
        enabled,
        exec,
        other_actions,
    };
    assert!(runs_exe(&task(true, vec![ours.clone()], 0), exe));
    for stale in [
        task(false, vec![ours.clone()], 0),
        task(true, vec![action(&exe.to_string_lossy(), "")], 0),
        task(
            true,
            vec![action(r"C:\old\VPN Tunnel Enforcer.exe", "--autostart")],
            0,
        ),
        task(true, vec![ours.clone(), ours.clone()], 0),
        task(true, vec![ours.clone()], 1),
        task(true, vec![], 0),
    ] {
        assert!(!runs_exe(&stale, exe), "{stale:?}");
    }
}

fn test_task_name() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    format!("VPNTE-Test-{:x}-{nanos:x}", std::process::id())
}

/// Read-only query of a name that cannot exist: "file not found" maps to `Absent`.
#[test]
fn a_missing_task_reads_as_absent() {
    let state = state_of(&test_task_name(), Path::new(r"C:\x.exe")).unwrap();
    assert_eq!(state, AutostartState::Absent);
}

/// Names that cannot exist: nothing is read or deleted, and a missing folder is "absent" too.
#[test]
fn missing_tasks_and_folders_are_absent() {
    let name = test_task_name();
    assert_eq!(read_task(&name).unwrap(), None);
    assert_eq!(read_task(&format!(r"\{name}\Task")).unwrap(), None);
    assert!(!delete_task(&name).unwrap());
    assert!(!delete_task_folder(&format!(r"\{name}")).unwrap());
}

/// B12: the definition is built and serialised, never registered.
#[test]
fn the_definition_has_no_battery_or_time_limits() {
    let _com = Com::enter(Apartment::Mta);
    let (service, _folder) = connect().unwrap();
    let user = current_user().unwrap();
    assert!(!user.is_empty());
    let exe = Path::new(r"C:\Program Files\VPN Tunnel Enforcer\VPN Tunnel Enforcer.exe");
    let definition = build_definition(&service, exe, &user).unwrap();
    let mut xml = BSTR::new();
    // SAFETY: `xml` is a valid out slot.
    unsafe { definition.XmlText(&mut xml) }.unwrap();
    let xml = xml.to_string();
    for needle in [
        "<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>",
        "<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>",
        "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>",
        "<Priority>4</Priority>",
        "<RunLevel>HighestAvailable</RunLevel>",
        "<LogonType>InteractiveToken</LogonType>",
        "<LogonTrigger>",
        &format!("<UserId>{user}</UserId>"),
        &format!("<Command>{}</Command>", exe.display()),
        "<Arguments>--autostart</Arguments>",
        r"<WorkingDirectory>C:\Program Files\VPN Tunnel Enforcer</WorkingDirectory>",
    ] {
        assert!(xml.contains(needle), "{needle} missing in\n{xml}");
    }
    let mut policy = Default::default();
    // SAFETY: `policy` is a valid out-pointer.
    unsafe {
        definition
            .Settings()
            .unwrap()
            .MultipleInstances(&mut policy)
    }
    .unwrap();
    assert_eq!(policy, TASK_INSTANCES_IGNORE_NEW);
}

/// Registers a throw-away task, reads it back and deletes it again.
#[test]
#[ignore = "needs elevation"]
fn elevated_registers_reads_back_and_deletes() {
    let name = test_task_name();
    let exe = std::env::current_exe().unwrap();
    set_task(&name, true, &exe).unwrap();
    let state = state_of(&name, &exe);
    let other = state_of(&name, Path::new(r"C:\other.exe"));
    let info = read_task(&name);
    set_task(&name, false, &exe).unwrap();
    assert_eq!(state.unwrap(), PRESENT);
    assert_eq!(other.unwrap(), STALE);
    let info = info.unwrap().unwrap();
    assert_eq!((info.exec.len(), info.other_actions), (1, 0));
    assert!(info.enabled);
    assert_eq!(info.exec[0].arguments, AUTOSTART_ARG);
    assert_eq!(state_of(&name, &exe).unwrap(), AutostartState::Absent);
    set_task(&name, false, &exe).unwrap();
}
