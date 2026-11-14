use std::cell::{Cell, RefCell};

use windows::Win32::Foundation::E_UNEXPECTED;
use windows::core::HRESULT;

use super::*;
use crate::registry::TestKey;

const PRESENT: AutostartState = AutostartState::Present { matches_exe: true };
const STALE: AutostartState = AutostartState::Present { matches_exe: false };
const OFF: AutostartState = AutostartState::DisabledByUser { matches_exe: true };
const OFF_STALE: AutostartState = AutostartState::DisabledByUser { matches_exe: false };

/// `Run` value stand-in: records applies, can refuse one direction, ignore applies (the
/// read-back then disagrees), fail every read, or play an entry switched off in Task Manager.
struct Fake<'a> {
    state: Cell<AutostartState>,
    applied: RefCell<Vec<bool>>,
    refuse: Option<bool>,
    ignore_applies: bool,
    switched_off: bool,
    read_error: Option<HRESULT>,
    legacy: Cell<Option<HRESULT>>,
    legacy_calls: Cell<usize>,
    on_apply: Box<dyn Fn() + 'a>,
}

impl Fake<'_> {
    fn new(state: AutostartState) -> Self {
        Self {
            state: Cell::new(state),
            applied: RefCell::default(),
            refuse: None,
            ignore_applies: false,
            switched_off: false,
            read_error: None,
            legacy: Cell::new(None),
            legacy_calls: Cell::new(0),
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
                "write refused"
            } else {
                "delete refused"
            };
            return Err(windows::core::Error::new(E_ACCESSDENIED, what));
        }
        if !self.ignore_applies {
            self.state.set(match (enabled, self.switched_off) {
                (true, true) => OFF,
                _ => wanted(enabled),
            });
        }
        Ok(())
    }
    fn read(&self) -> Result<AutostartState> {
        match self.read_error {
            Some(code) => Err(code.into()),
            None => Ok(self.state.get()),
        }
    }
    fn remove_legacy_task(&self) -> Result<bool> {
        self.legacy_calls.set(self.legacy_calls.get() + 1);
        match self.legacy.get() {
            Some(code) => Err(code.into()),
            None => Ok(false),
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

/// AT-03-002: the write succeeds but the read-back says absent: restored, flag unchanged.
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
fn an_unreadable_value_is_unknown_and_keeps_the_flag() {
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

/// AT-03-003: an answer that is not the value we wrote (stale command) is not success.
#[test]
fn a_stale_value_after_the_write_is_a_readback_failure() {
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
    assert!(unknown, "the stale value also survives the delete: {err}");
    assert!(!stored.borrow().autostart);
}

#[test]
fn a_settings_save_made_during_the_write_is_kept() {
    let stored = RefCell::new(Stored::default());
    let os = Fake {
        on_apply: Box::new(|| stored.borrow_mut().stealth_mode = true),
        ..Fake::new(AutostartState::Absent)
    };
    set_checked(&os, false, true, save(&stored)).unwrap();
    assert!(stored.borrow().autostart && stored.borrow().stealth_mode);
}

/// Persisting fails after the write: the value is deleted again, the flag stays off.
#[test]
fn a_failed_persist_deletes_the_value_again() {
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
    assert_eq!(app.user_msg().key, "winnet.autostart.stateUnknown");
}

#[test]
fn app_errors_name_the_reason() {
    let refused = AutostartError::Unchanged(Step::Os(E_ACCESSDENIED.into()));
    let app: AppError = refused.into();
    assert_eq!(
        (app.kind, app.user_msg().key.as_ref()),
        (ErrorKind::Permission, "winnet.autostart.denied")
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

/// NOADMIN §3: an entry the user switched off in Task Manager is the user's switch. Enabling
/// writes the value and succeeds (the hint says where to switch it on); sync never fights it.
#[test]
fn an_entry_switched_off_in_task_manager_is_never_switched_on() {
    let os = Fake {
        switched_off: true,
        ..Fake::new(AutostartState::Absent)
    };
    let stored = RefCell::new(Stored::default());
    set_checked(&os, false, true, save(&stored)).unwrap();
    assert!(stored.borrow().autostart);
    assert_eq!(os.state.get(), OFF);
    assert_eq!(
        OFF.hint().map(|m| m.key),
        Some("winnet.autostart.disabledByUser".into())
    );
    assert_eq!(
        (PRESENT.hint(), AutostartState::Absent.hint()),
        (None, None)
    );
    assert!(!sync(&os, true).unwrap(), "left as the user set it");
    assert_eq!(*os.applied.borrow(), [true]);
    os.state.set(OFF_STALE);
    assert!(sync(&os, true).unwrap(), "a stale entry is re-pointed");
    assert_eq!(os.state.get(), OFF, "and stays switched off");
    assert!(
        sync(&os, false).unwrap(),
        "turning autostart off deletes it"
    );
    assert_eq!(os.state.get(), AutostartState::Absent);
}

/// Startup sync acts only on a mismatch; a stale (old exe) value is replaced or removed.
#[test]
fn sync_acts_only_on_a_mismatch() {
    for (state, enabled, acted) in [
        (AutostartState::Absent, false, false),
        (PRESENT, true, false),
        (OFF, true, false),
        (STALE, false, true),
        (STALE, true, true),
        (OFF_STALE, true, true),
        (OFF, false, true),
        (AutostartState::Absent, true, true),
        (PRESENT, false, true),
    ] {
        let os = Fake::new(state);
        assert_eq!(sync(&os, enabled).unwrap(), acted, "{state:?} -> {enabled}");
        assert_eq!(
            *os.applied.borrow(),
            if acted { vec![enabled] } else { vec![] }
        );
        assert_eq!(os.legacy_calls.get(), 1, "the 1.x task is looked at");
    }
    let os = Fake {
        read_error: Some(E_ACCESSDENIED),
        ..Fake::new(PRESENT)
    };
    assert!(sync(&os, false).is_err(), "unknown state: no blind delete");
    assert!(os.applied.borrow().is_empty());
}

/// A failing removal of the 1.x task does not stop the sync of the value; it is reported after.
#[test]
fn a_failed_legacy_removal_is_reported_after_the_sync() {
    let os = Fake::new(AutostartState::Absent);
    os.legacy.set(Some(E_UNEXPECTED));
    assert!(sync(&os, true).is_err());
    assert_eq!(os.state.get(), PRESENT);
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

/// Only `"<this exe>" --autostart` is ours; the 1.x form (no flag), another exe or extra
/// arguments are stale.
#[test]
fn only_this_exe_with_the_flag_matches() {
    let exe = Path::new(r"C:\Program Files\VPN Tunnel Enforcer\VPN Tunnel Enforcer.exe");
    assert_eq!(
        command(exe),
        r#""C:\Program Files\VPN Tunnel Enforcer\VPN Tunnel Enforcer.exe" --autostart"#
    );
    assert!(runs_exe(&command(exe), exe));
    assert!(runs_exe(
        r#"  "c:\program files\vpn tunnel enforcer\VPN Tunnel Enforcer.exe"   --autostart "#,
        exe
    ));
    assert!(runs_exe(
        r"C:\vpn\app.exe --autostart",
        Path::new(r"C:\vpn\app.exe")
    ));
    for stale in [
        r#""C:\Program Files\VPN Tunnel Enforcer\VPN Tunnel Enforcer.exe""#,
        r#""C:\old\VPN Tunnel Enforcer.exe" --autostart"#,
        r#""C:\Program Files\VPN Tunnel Enforcer\VPN Tunnel Enforcer.exe" --autostart --x"#,
        r"C:\Program Files\VPN Tunnel Enforcer\VPN Tunnel Enforcer.exe --autostart",
        "",
    ] {
        assert!(!runs_exe(stale, exe), "{stale}");
    }
}

/// The real registry code on throw-away keys (`HKCU\Software\VPNTE-Test-*`), never the real
/// `Run` key: write, read back, Task Manager's switch, stale data, delete.
#[test]
fn the_value_round_trips_on_throw_away_keys() {
    let root = TestKey::new();
    let (run, approved) = (
        format!(r"{}\Run", root.path),
        format!(r"{}\StartupApproved\Run", root.path),
    );
    let place = Place {
        run: &run,
        approved: &approved,
        name: "VPNTE-Test",
    };
    let exe = Path::new(r"C:\Program Files\VPN Tunnel Enforcer\VPN Tunnel Enforcer.exe");
    assert_eq!(place.state(exe).unwrap(), AutostartState::Absent, "no key");
    place.set(false, exe).unwrap();
    place.set(true, exe).unwrap();
    assert_eq!(place.state(exe).unwrap(), PRESENT);
    assert_eq!(place.state(Path::new(r"C:\other.exe")).unwrap(), STALE);
    let key = Key::open(Hive::CurrentUser, &run, Access::Read, View::Native)
        .unwrap()
        .unwrap();
    assert_eq!(key.string("VPNTE-Test").unwrap(), Some(command(exe)));

    let (switch, _) = Key::create(Hive::CurrentUser, &approved, View::Native).unwrap();
    let toggle = |first: u8| {
        let mut data = vec![0u8; 12];
        data[0] = first;
        switch
            .set("VPNTE-Test", &Value::Raw { kind: 3, data })
            .unwrap();
    };
    toggle(3);
    assert_eq!(place.state(exe).unwrap(), OFF);
    toggle(2);
    assert_eq!(place.state(exe).unwrap(), PRESENT);
    toggle(7);
    assert_eq!(place.state(Path::new(r"C:\other.exe")).unwrap(), OFF_STALE);
    toggle(6);
    assert_eq!(place.state(exe).unwrap(), PRESENT);

    let (writable, _) = Key::create(Hive::CurrentUser, &run, View::Native).unwrap();
    writable.set_dword("VPNTE-Test", 1).unwrap();
    assert_eq!(place.state(exe).unwrap(), STALE, "another type is stale");
    place.set(true, exe).unwrap();
    assert_eq!(place.state(exe).unwrap(), PRESENT);
    place.set(false, exe).unwrap();
    assert_eq!(place.state(exe).unwrap(), AutostartState::Absent);
    place.set(false, exe).unwrap();
}

fn test_task_name() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    format!("VPNTE-Test-{:x}-{nanos:x}", std::process::id())
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

/// The real `Run` key, with a throw-away value name: written, read back, deleted again.
#[test]
#[ignore = "changes system state"]
fn system_run_value_round_trip() {
    let name = test_task_name();
    let place = Place {
        name: &name,
        ..REAL
    };
    let exe = std::env::current_exe().unwrap();
    let before = place.state(&exe).unwrap();
    let written = place.set(true, &exe);
    let state = place.state(&exe);
    let removed = place.set(false, &exe);
    written.unwrap();
    removed.unwrap();
    assert_eq!(before, AutostartState::Absent);
    assert_eq!(state.unwrap(), PRESENT);
    assert_eq!(place.state(&exe).unwrap(), AutostartState::Absent);
}
