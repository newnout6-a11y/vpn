use std::sync::Arc;

use vpnte_base::types::KillSwitchLevel;

use super::*;
use crate::wfp::desired::{Plan, desired};
use crate::wfp::model::Conn;

/// Provider / sublayer as they were before an elevated test; what the test created goes. Holds
/// a lock so the elevated tests never create or delete our objects under each other.
pub(crate) struct Objects {
    provider: bool,
    sublayer: bool,
    _serial: parking_lot::MutexGuard<'static, ()>,
}

impl Objects {
    pub(crate) fn before() -> Self {
        static SERIAL: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
        let serial = SERIAL.lock();
        let e = Engine::open_persistent().unwrap();
        let provider = e.provider_exists(&PROVIDER_KEY).unwrap();
        Self {
            provider,
            sublayer: e.sublayer(&SUBLAYER_KEY).unwrap().is_some(),
            _serial: serial,
        }
    }
    /// Something of ours was already there (a real installation).
    pub(crate) fn existed(&self) -> bool {
        self.provider || self.sublayer
    }
    pub(crate) fn restore(self) {
        let e = Engine::open_persistent().unwrap();
        if !self.sublayer {
            e.delete_sublayer(&SUBLAYER_KEY).unwrap();
        }
        if !self.provider {
            e.delete_provider(&PROVIDER_KEY).unwrap();
        }
    }
}

/// A filter that can never matter: permit TEST-NET-2 host 198.51.100.7, port 9 (discard).
pub(crate) fn harmless(name: &'static str) -> FilterSpec {
    FilterSpec {
        name,
        layer: Layer::Connect4,
        action: Action::Permit,
        weight: 1,
        conds: vec![
            Cond::RemoteV4("198.51.100.7/32".parse().unwrap()),
            Cond::RemotePort(9),
        ],
    }
}

/// The 8.3 alias of an existing file, `None` when the volume has no short names.
pub(crate) fn short_name(long: &Path) -> Option<std::path::PathBuf> {
    let wide = crate::win::wide_os(long);
    let mut buf = [0u16; 1024];
    // SAFETY: `wide` is NUL-terminated and outlives the call; `buf` is a valid output slice.
    let n = unsafe {
        windows::Win32::Storage::FileSystem::GetShortPathNameW(
            windows::core::PCWSTR(wide.as_ptr()),
            Some(&mut buf),
        )
    } as usize;
    let short = String::from_utf16_lossy(buf.get(..n)?);
    let differs = n > 0 && !short.eq_ignore_ascii_case(&long.to_string_lossy());
    differs.then(|| short.into())
}

fn own_id() -> Arc<AppId> {
    Arc::new(app_id(&std::env::current_exe().unwrap()).unwrap())
}

/// AT-03-003 / AT-03-012 (§7.3 flag acceptance): persistent valid {1, 65}; boot valid
/// {2, 34, 66, 98}; persistent invalid {0, 2, 9, 33, 129}.
#[test]
fn flag_acceptance() {
    let info = |flags| FilterInfo {
        id: 1,
        key: GUID::zeroed(),
        layer: Layer::Connect6.key(),
        sublayer: SUBLAYER_KEY,
        provider: Some(PROVIDER_KEY),
        flags,
        action: FWP_ACTION_PERMIT.0,
        weight: Some(15),
        name: String::new(),
    };
    assert!([1, 65].iter().all(|&f| info(f).flags_valid(false)));
    assert!([2, 34, 66, 98].iter().all(|&f| info(f).flags_valid(true)));
    assert!(
        [0, 2, 9, 33, 129]
            .iter()
            .all(|&f| !info(f).flags_valid(false))
    );
    assert!(info(65).is_persistent() && !info(0).is_persistent());
}

/// No elevation needed: the app ID is the NT device path of the file, NUL-terminated UTF-16.
#[test]
fn app_id_is_the_device_path() {
    let exe = std::env::current_exe().unwrap();
    let id = app_id(&exe).unwrap();
    let units: Vec<u16> = id
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u16::from_le_bytes(*b))
        .collect();
    let text = String::from_utf16_lossy(&units)
        .trim_end_matches('\0')
        .to_lowercase();
    assert!(text.starts_with(r"\device\"), "{text}");
    let name = exe.file_name().unwrap().to_string_lossy().to_lowercase();
    assert!(text.ends_with(&name), "{text}");
    assert!(app_id(std::path::Path::new(r"C:\no\such\program.exe")).is_err());
}

/// Read-only, any elevation: a plain session enumerates a whole layer (boot-time and
/// disabled filters included) or is refused with access denied; nothing is added.
#[test]
fn enumeration_reads_or_is_denied() {
    let engine = match Engine::open_persistent() {
        Ok(engine) => engine,
        Err(e) => return assert!(e.is_access_denied(), "{e}"),
    };
    match engine.list(&ListQuery {
        layer: Layer::Connect4,
        provider: None,
    }) {
        Ok(all) => assert!(all.iter().all(|f| f.layer == Layer::Connect4.key())),
        Err(e) => assert!(e.is_access_denied(), "{e}"),
    }
    match engine.owned_filters() {
        Ok(ours) => assert!(ours.iter().all(|f| f.provider == Some(PROVIDER_KEY))),
        Err(e) => assert!(e.is_access_denied(), "{e}"),
    }
    if let Err(e) = engine.sublayer(&SUBLAYER_KEY) {
        assert!(e.is_access_denied(), "{e}");
    }
}

/// Every condition kind of the catalogue (one standard + TUN set, actions turned into
/// permits so nothing is blocked) is accepted by BFE in one dynamic transaction, read back
/// with its weight and removed again.
#[test]
#[ignore = "needs elevation"]
fn elevated_catalogue_round_trip_in_a_dynamic_session() {
    let objects = Objects::before();
    let weight = Engine::open_persistent()
        .unwrap()
        .ensure_provider_and_sublayer()
        .unwrap();
    assert!(weight > 0);
    let me = own_id();
    let plan = Plan {
        level: KillSwitchLevel::Standard,
        armed: true,
        leak_protection: true,
        public_wifi_compat: true,
        allow_lan: true,
        // `Connecting` with a LUID: both TUN permits (LUID and the provisional addresses).
        conn: Conn::Connecting,
        tun_luid: Some(1),
        tun_addrs: vec![
            "192.0.2.77".parse().unwrap(),
            "2001:db8::77".parse().unwrap(),
        ],
        engines: vec![me.clone()],
        own: Some(me.clone()),
        session: vec![me.clone()],
        exception_apps: vec![me],
        exception_nets: vec![
            "192.0.2.0/24".parse().unwrap(),
            "2001:db8::/32".parse().unwrap(),
        ],
    };
    let specs: Vec<FilterSpec> = desired(&plan)
        .dynamic
        .into_iter()
        .map(|s| FilterSpec {
            action: Action::Permit,
            ..s
        })
        .collect();
    let kinds: std::collections::HashSet<_> = specs
        .iter()
        .flat_map(|s| s.conds.iter().map(std::mem::discriminant))
        .collect();
    assert_eq!(kinds.len(), 10, "every Cond kind is exercised");
    let engine = Engine::open_dynamic().unwrap();
    let ids = engine
        .transaction(|e| {
            specs
                .iter()
                .map(|s| e.add(s))
                .collect::<Result<Vec<_>, _>>()
        })
        .unwrap();
    let listed = engine.owned_filters().unwrap();
    for (id, spec) in ids.iter().zip(&specs) {
        let f = listed
            .iter()
            .find(|f| f.id == *id)
            .expect("filter read back");
        assert!(
            !f.is_persistent() && f.sublayer == SUBLAYER_KEY && f.provider == Some(PROVIDER_KEY)
        );
        assert_eq!(
            (f.weight, f.name.as_str()),
            (Some(spec.weight), format!("VPNTE {}", spec.name).as_str())
        );
        assert_eq!(f.layer, spec.layer.key());
    }
    engine
        .transaction(|e| ids.iter().try_for_each(|&id| e.delete(id)))
        .unwrap();
    let left = engine.owned_filters().unwrap();
    assert!(left.iter().all(|f| !ids.contains(&f.id)));
    drop(engine);
    objects.restore();
}

/// A plain session adds persistent filters (read back with the PERSISTENT flag, maybe plus
/// INDEXED) and deletes them again.
#[test]
#[ignore = "needs elevation"]
fn elevated_persistent_filter_round_trip() {
    let objects = Objects::before();
    let engine = Engine::open_persistent().unwrap();
    engine.ensure_provider_and_sublayer().unwrap();
    let id = engine
        .transaction(|e| e.add(&harmless("test-persistent")))
        .unwrap();
    let f = engine
        .owned_filters()
        .unwrap()
        .into_iter()
        .find(|f| f.id == id)
        .expect("read back");
    assert!(
        f.is_persistent() && f.flags_valid(false),
        "flags {:#x}",
        f.flags
    );
    engine.delete(id).unwrap();
    engine.delete(id).unwrap();
    assert!(engine.owned_filters().unwrap().iter().all(|f| f.id != id));
    drop(engine);
    objects.restore();
}

/// An error inside a transaction aborts it: nothing added in it survives.
#[test]
#[ignore = "needs elevation"]
fn elevated_failed_transaction_leaves_nothing() {
    let objects = Objects::before();
    Engine::open_persistent()
        .unwrap()
        .ensure_provider_and_sublayer()
        .unwrap();
    let engine = Engine::open_dynamic().unwrap();
    let before = engine.owned_filters().unwrap().len();
    let refused = WfpError {
        op: "test",
        code: 1,
    };
    let result = engine.transaction(|e| {
        e.add(&harmless("test-abort"))?;
        Err::<(), _>(refused)
    });
    assert_eq!(result, Err(refused));
    assert_eq!(engine.owned_filters().unwrap().len(), before);
    drop(engine);
    objects.restore();
}
