//! Adapter writes for the legacy restore only (spec §3.9): the `ms_tcpip6` binding through
//! INetCfg, static IPv4 DNS through `Get/SetInterfaceDnsSettings`, and the resolver cache flush.
//! The app itself never changes adapters (sing-box owns routes and DNS).
//!
//! The INetCfg interfaces are not in the `windows` crate's metadata, so they are declared here
//! from `netcfgx.h` (every method in vtable order; only some are called).
#![allow(non_snake_case, clippy::upper_case_acronyms)]

use std::ffi::c_void;
use std::net::Ipv4Addr;

use windows::Win32::Foundation::{HWND, WIN32_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceGuidToLuid, DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS_VERSION1,
    DNS_SETTING_NAMESERVER,
};
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, CoCreateInstance, CoTaskMemFree};
use windows::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};
use windows::Win32::System::Registry::HKEY;
use windows::core::{GUID, HRESULT, IUnknown, IUnknown_Vtbl, Interface, PCWSTR, PWSTR, s, w};
use windows_core::interface;

use super::com::Com;

const CLSID_CNETCFG: GUID = GUID::from_u128(0x5b035261_40f9_11d1_aaec_00805fc1270e);
const GUID_DEVCLASS_NET: GUID = GUID::from_u128(0x4d36e972_e325_11ce_bfc1_08002be10318);
const EBP_BELOW: u32 = 0x2;
const LOCK_TIMEOUT_MS: u32 = 5000;

#[interface("c0e8ae93-306e-11d1-aacf-00805fc1270e")]
unsafe trait INetCfg: IUnknown {
    fn Initialize(&self, reserved: *const c_void) -> HRESULT;
    fn Uninitialize(&self) -> HRESULT;
    fn Apply(&self) -> HRESULT;
    fn Cancel(&self) -> HRESULT;
    fn EnumComponents(&self, class: *const GUID, out: *mut *mut c_void) -> HRESULT;
    fn FindComponent(&self, inf_id: PCWSTR, out: *mut Option<INetCfgComponent>) -> HRESULT;
    fn QueryNetCfgClass(
        &self,
        class: *const GUID,
        iid: *const GUID,
        out: *mut *mut c_void,
    ) -> HRESULT;
}

#[interface("c0e8ae9f-306e-11d1-aacf-00805fc1270e")]
unsafe trait INetCfgLock: IUnknown {
    fn AcquireWriteLock(&self, timeout_ms: u32, client: PCWSTR, holder: *mut PWSTR) -> HRESULT;
    fn ReleaseWriteLock(&self) -> HRESULT;
    fn IsWriteLocked(&self, holder: *mut PWSTR) -> HRESULT;
}

#[interface("c0e8ae99-306e-11d1-aacf-00805fc1270e")]
unsafe trait INetCfgComponent: IUnknown {
    fn GetDisplayName(&self, out: *mut PWSTR) -> HRESULT;
    fn SetDisplayName(&self, name: PCWSTR) -> HRESULT;
    fn GetHelpText(&self, out: *mut PWSTR) -> HRESULT;
    fn GetId(&self, out: *mut PWSTR) -> HRESULT;
    fn GetCharacteristics(&self, out: *mut u32) -> HRESULT;
    fn GetInstanceGuid(&self, out: *mut GUID) -> HRESULT;
    fn GetPnpDevNodeId(&self, out: *mut PWSTR) -> HRESULT;
    fn GetClassGuid(&self, out: *mut GUID) -> HRESULT;
    fn GetBindName(&self, out: *mut PWSTR) -> HRESULT;
    fn GetDeviceStatus(&self, out: *mut u32) -> HRESULT;
    fn OpenParamKey(&self, out: *mut HKEY) -> HRESULT;
    fn RaisePropertyUi(&self, parent: HWND, flags: u32, context: *mut c_void) -> HRESULT;
}

#[interface("c0e8ae9e-306e-11d1-aacf-00805fc1270e")]
unsafe trait INetCfgComponentBindings: IUnknown {
    fn BindTo(&self, item: *mut c_void) -> HRESULT;
    fn UnbindFrom(&self, item: *mut c_void) -> HRESULT;
    fn SupportsBindingInterface(&self, flags: u32, name: PCWSTR) -> HRESULT;
    fn IsBoundTo(&self, item: *mut c_void) -> HRESULT;
    fn IsBindableTo(&self, item: *mut c_void) -> HRESULT;
    fn EnumBindingPaths(&self, flags: u32, out: *mut Option<IEnumNetCfgBindingPath>) -> HRESULT;
    fn MoveBefore(&self, src: *mut c_void, dest: *mut c_void) -> HRESULT;
    fn MoveAfter(&self, src: *mut c_void, dest: *mut c_void) -> HRESULT;
}

#[interface("c0e8ae91-306e-11d1-aacf-00805fc1270e")]
unsafe trait IEnumNetCfgBindingPath: IUnknown {
    fn Next(&self, count: u32, out: *mut Option<INetCfgBindingPath>, fetched: *mut u32) -> HRESULT;
    fn Skip(&self, count: u32) -> HRESULT;
    fn Reset(&self) -> HRESULT;
    fn Clone(&self, out: *mut *mut c_void) -> HRESULT;
}

#[interface("c0e8ae96-306e-11d1-aacf-00805fc1270e")]
unsafe trait INetCfgBindingPath: IUnknown {
    fn IsSamePathAs(&self, path: *mut c_void) -> HRESULT;
    fn IsSubPathOf(&self, path: *mut c_void) -> HRESULT;
    fn IsEnabled(&self) -> HRESULT;
    fn Enable(&self, enable: windows::core::BOOL) -> HRESULT;
    fn GetPathToken(&self, out: *mut PWSTR) -> HRESULT;
    fn GetOwner(&self, out: *mut Option<INetCfgComponent>) -> HRESULT;
    fn GetDepth(&self, out: *mut u32) -> HRESULT;
    fn EnumBindingInterfaces(&self, out: *mut Option<IEnumNetCfgBindingInterface>) -> HRESULT;
}

#[interface("c0e8ae90-306e-11d1-aacf-00805fc1270e")]
unsafe trait IEnumNetCfgBindingInterface: IUnknown {
    fn Next(
        &self,
        count: u32,
        out: *mut Option<INetCfgBindingInterface>,
        fetched: *mut u32,
    ) -> HRESULT;
    fn Skip(&self, count: u32) -> HRESULT;
    fn Reset(&self) -> HRESULT;
    fn Clone(&self, out: *mut *mut c_void) -> HRESULT;
}

#[interface("c0e8ae94-306e-11d1-aacf-00805fc1270e")]
unsafe trait INetCfgBindingInterface: IUnknown {
    fn GetName(&self, out: *mut PWSTR) -> HRESULT;
    fn GetUpperComponent(&self, out: *mut Option<INetCfgComponent>) -> HRESULT;
    fn GetLowerComponent(&self, out: *mut Option<INetCfgComponent>) -> HRESULT;
}

type Res<T> = Result<T, String>;

fn hr_err(op: &'static str) -> impl Fn(windows::core::Error) -> String {
    move |e| format!("{op}: {e}")
}

/// Takes a CoTaskMem string returned by INetCfg.
///
/// # Safety
/// `p` is null or a NUL-terminated string allocated with `CoTaskMemAlloc`, not used afterwards.
unsafe fn take(p: PWSTR) -> String {
    if p.is_null() {
        return String::new();
    }
    // SAFETY: per the contract above.
    let text = unsafe { p.to_string() }.unwrap_or_default();
    // SAFETY: allocated by the callee with CoTaskMemAlloc, freed once.
    unsafe { CoTaskMemFree(Some(p.0 as *const c_void)) };
    text
}

/// Runs `f` on a fresh thread in a single-threaded apartment: INetCfg is apartment-threaded and
/// must not run on a pooled thread whose apartment is unknown.
fn on_sta<T: Send + 'static>(f: impl FnOnce() -> Res<T> + Send + 'static) -> Res<T> {
    std::thread::spawn(move || {
        let _com = Com::enter(true);
        f()
    })
    .join()
    .map_err(|_| "INetCfg thread panicked".to_string())?
}

fn create() -> Res<INetCfg> {
    // SAFETY: COM is initialised on this thread (see `on_sta`).
    unsafe { CoCreateInstance(&CLSID_CNETCFG, None, CLSCTX_INPROC_SERVER) }
        .map_err(hr_err("CNetCfg"))
}

/// The direct `ms_tcpip6` → adapter binding path of `guid`: one binding interface whose upper
/// component is `ms_tcpip6` and whose lower one is the net-class adapter with that instance
/// GUID. `None` when the adapter has no such path (removed NIC); more than one is an error.
fn tcpip6_path(cfg: &INetCfg, guid: &GUID) -> Res<Option<INetCfgBindingPath>> {
    let mut tcpip6 = None;
    // SAFETY: initialised INetCfg; out-pointer to a local.
    unsafe { cfg.FindComponent(w!("ms_tcpip6"), &mut tcpip6) }
        .ok()
        .map_err(hr_err("FindComponent"))?;
    let tcpip6 = tcpip6.ok_or("ms_tcpip6 is not installed")?;
    let bindings: INetCfgComponentBindings = tcpip6.cast().map_err(hr_err("bindings"))?;
    let mut paths = None;
    // SAFETY: live interface; out-pointer to a local.
    unsafe { bindings.EnumBindingPaths(EBP_BELOW, &mut paths) }
        .ok()
        .map_err(hr_err("EnumBindingPaths"))?;
    let paths = paths.ok_or("no binding paths")?;
    let mut found = Vec::new();
    loop {
        let (mut path, mut fetched) = (None, 0u32);
        // SAFETY: one element requested into a local slot.
        unsafe { paths.Next(1, &mut path, &mut fetched) }
            .ok()
            .map_err(hr_err("binding path enumeration"))?;
        let Some(path) = path.filter(|_| fetched == 1) else {
            break;
        };
        if leads_to(&path, guid)? {
            found.push(path);
        }
    }
    match found.len() {
        0 | 1 => Ok(found.pop()),
        n => Err(format!("{n} IPv6 binding paths for one adapter")),
    }
}

fn leads_to(path: &INetCfgBindingPath, guid: &GUID) -> Res<bool> {
    let mut items = None;
    // SAFETY: live interface; out-pointer to a local.
    unsafe { path.EnumBindingInterfaces(&mut items) }
        .ok()
        .map_err(hr_err("EnumBindingInterfaces"))?;
    let items = items.ok_or("no binding interfaces")?;
    let mut interfaces = Vec::new();
    loop {
        let (mut item, mut fetched) = (None, 0u32);
        // SAFETY: one element requested into a local slot.
        unsafe { items.Next(1, &mut item, &mut fetched) }
            .ok()
            .map_err(hr_err("binding interface enumeration"))?;
        match item.filter(|_| fetched == 1) {
            Some(item) => interfaces.push(item),
            None => break,
        }
    }
    let [interface] = interfaces.as_slice() else {
        return Ok(false);
    };
    let (mut upper, mut lower) = (None, None);
    // SAFETY: live interface; out-pointers to locals.
    unsafe { interface.GetUpperComponent(&mut upper) }
        .ok()
        .map_err(hr_err("GetUpperComponent"))?;
    // SAFETY: as above.
    unsafe { interface.GetLowerComponent(&mut lower) }
        .ok()
        .map_err(hr_err("GetLowerComponent"))?;
    let (Some(upper), Some(lower)) = (upper, lower) else {
        return Ok(false);
    };
    let mut id = PWSTR::null();
    let (mut class, mut instance) = (GUID::zeroed(), GUID::zeroed());
    // SAFETY: live component; out-pointer to a local.
    unsafe { upper.GetId(&mut id) }
        .ok()
        .map_err(hr_err("GetId"))?;
    // SAFETY: the CoTaskMem string GetId just returned, taken once.
    let id = unsafe { take(id) };
    // SAFETY: live component; out-pointers to locals.
    unsafe { lower.GetClassGuid(&mut class) }
        .ok()
        .map_err(hr_err("GetClassGuid"))?;
    // SAFETY: as above.
    unsafe { lower.GetInstanceGuid(&mut instance) }
        .ok()
        .map_err(hr_err("GetInstanceGuid"))?;
    Ok(id.eq_ignore_ascii_case("ms_tcpip6") && class == GUID_DEVCLASS_NET && instance == *guid)
}

fn is_enabled(path: &INetCfgBindingPath) -> Res<bool> {
    // SAFETY: live interface.
    match unsafe { path.IsEnabled() } {
        hr if hr.0 == 0 => Ok(true),
        hr if hr.0 == 1 => Ok(false),
        hr => Err(format!(
            "IsEnabled: {}",
            windows::core::Error::from_hresult(hr)
        )),
    }
}

/// Whether `ms_tcpip6` is enabled on the adapter (`None`: no binding path). Read-only: no write
/// lock, works unelevated.
pub(crate) fn ipv6_binding(guid: GUID) -> Res<Option<bool>> {
    on_sta(move || {
        let cfg = create()?;
        // SAFETY: fresh instance; no reserved data.
        unsafe { cfg.Initialize(std::ptr::null()) }
            .ok()
            .map_err(hr_err("Initialize"))?;
        let state = tcpip6_path(&cfg, &guid).and_then(|p| p.as_ref().map(is_enabled).transpose());
        // SAFETY: initialised above.
        let _ = unsafe { cfg.Uninitialize() };
        state
    })
}

/// Re-enables `ms_tcpip6` on the adapter (needs elevation). `Ok(false)`: it already was. The
/// result is decided by a read-back through a new INetCfg instance (a staged `IsEnabled` is
/// no proof), so a successful-with-info `Apply` (`NETCFG_S_REBOOT`) counts when it took (B17).
pub(crate) fn enable_ipv6(guid: GUID) -> Res<bool> {
    let changed = on_sta(move || {
        let cfg = create()?;
        let lock: INetCfgLock = cfg.cast().map_err(hr_err("INetCfgLock"))?;
        let mut holder = PWSTR::null();
        // SAFETY: live interface; `holder` receives a CoTaskMem string only when another
        // client holds the lock.
        let hr = unsafe {
            lock.AcquireWriteLock(LOCK_TIMEOUT_MS, w!("VPNTE adapter lockdown"), &mut holder)
        };
        if hr.0 != 0 {
            // SAFETY: the out-string of the call above.
            let who = unsafe { take(holder) };
            return Err(format!(
                "INetCfg write lock not acquired ({hr:?}, held by {who:?})"
            ));
        }
        let result = apply_enable(&cfg, &guid);
        // SAFETY: the lock was acquired above.
        let _ = unsafe { lock.ReleaseWriteLock() };
        result
    })?;
    match ipv6_binding(guid)? {
        Some(true) => Ok(changed),
        Some(false) => Err("IPv6 binding still disabled after Apply".into()),
        None => Err("IPv6 binding path vanished".into()),
    }
}

fn apply_enable(cfg: &INetCfg, guid: &GUID) -> Res<bool> {
    // SAFETY: write lock held; no reserved data.
    unsafe { cfg.Initialize(std::ptr::null()) }
        .ok()
        .map_err(hr_err("Initialize"))?;
    let result = (|| {
        let path = tcpip6_path(cfg, guid)?.ok_or("no IPv6 binding path for the adapter")?;
        if is_enabled(&path)? {
            return Ok(false);
        }
        // SAFETY: live interfaces of an initialised, write-locked INetCfg.
        let applied = unsafe { path.Enable(true.into()) }
            .ok()
            .and_then(|()| unsafe { cfg.Apply() }.ok());
        if let Err(e) = applied {
            // SAFETY: as above; discards the staged change.
            let _ = unsafe { cfg.Cancel() };
            return Err(format!("enable IPv6 binding: {e}"));
        }
        Ok(true)
    })();
    // SAFETY: initialised above.
    let _ = unsafe { cfg.Uninitialize() };
    result
}

/// A system DLL export resolved at run time (the DNS settings API exists only since
/// Windows 10 2004; `DnsFlushResolverCache` is undocumented).
fn export(dll: PCWSTR, name: windows::core::PCSTR) -> Option<RawProc> {
    // SAFETY: loads only from System32; the module stays loaded for the process lifetime.
    let module = unsafe { LoadLibraryExW(dll, None, LOAD_LIBRARY_SEARCH_SYSTEM32) }.ok()?;
    // SAFETY: valid module handle and NUL-terminated export name.
    unsafe { GetProcAddress(module, name) }
}

/// What `GetProcAddress` returns.
type RawProc = unsafe extern "system" fn() -> isize;
type GetDns = unsafe extern "system" fn(GUID, *mut DNS_INTERFACE_SETTINGS) -> WIN32_ERROR;
type SetDns = unsafe extern "system" fn(GUID, *const DNS_INTERFACE_SETTINGS) -> WIN32_ERROR;
type FreeDns = unsafe extern "system" fn(*mut DNS_INTERFACE_SETTINGS);
type FlushDns = unsafe extern "system" fn() -> i32;

/// The adapter's static IPv4 DNS servers (`NameServer`; empty = DHCP).
pub(crate) fn static_dns(guid: GUID) -> Res<Vec<Ipv4Addr>> {
    let (Some(get), Some(free)) = (
        export(w!("iphlpapi.dll"), s!("GetInterfaceDnsSettings")),
        export(w!("iphlpapi.dll"), s!("FreeInterfaceDnsSettings")),
    ) else {
        return Err("DNS settings API not available (Windows 10 2004+)".into());
    };
    // SAFETY: the exports have exactly these documented signatures.
    let get = unsafe { std::mem::transmute::<RawProc, GetDns>(get) };
    // SAFETY: as above.
    let free = unsafe { std::mem::transmute::<RawProc, FreeDns>(free) };
    let mut settings = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        ..Default::default()
    };
    // SAFETY: versioned structure owned here; its strings are released with `free`.
    let code = unsafe { get(guid, &mut settings) };
    if code.0 != 0 {
        return Err(format!(
            "GetInterfaceDnsSettings: {}",
            windows::core::Error::from(code)
        ));
    }
    // SAFETY: NameServer is null or a NUL-terminated string owned by `settings`.
    let text = match settings.NameServer.is_null() {
        true => String::new(),
        false => unsafe { settings.NameServer.to_string() }.unwrap_or_default(),
    };
    // SAFETY: filled by GetInterfaceDnsSettings, freed once.
    unsafe { free(&mut settings) };
    parse_name_servers(&text)
}

/// `NameServer` lists are separated by commas, semicolons or blanks.
pub(crate) fn parse_name_servers(text: &str) -> Res<Vec<Ipv4Addr>> {
    text.split([',', ';', ' ', '\t'])
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse()
                .map_err(|_| format!("unexpected NameServer entry {s:?}"))
        })
        .collect()
}

/// Sets the static IPv4 DNS servers (`[]` = back to DHCP) and reads them back.
pub(crate) fn set_static_dns(guid: GUID, servers: &[Ipv4Addr]) -> Res<()> {
    let set = export(w!("iphlpapi.dll"), s!("SetInterfaceDnsSettings"))
        .ok_or("DNS settings API not available (Windows 10 2004+)")?;
    // SAFETY: the export has exactly this documented signature.
    let set = unsafe { std::mem::transmute::<RawProc, SetDns>(set) };
    let list: Vec<String> = servers.iter().map(Ipv4Addr::to_string).collect();
    let mut text: Vec<u16> = list.join(",").encode_utf16().chain([0]).collect();
    let settings = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        Flags: u64::from(DNS_SETTING_NAMESERVER),
        NameServer: PWSTR(text.as_mut_ptr()),
        ..Default::default()
    };
    // SAFETY: `settings` and the string it points to outlive the call.
    let code = unsafe { set(guid, &settings) };
    if code.0 != 0 {
        return Err(format!(
            "SetInterfaceDnsSettings: {}",
            windows::core::Error::from(code)
        ));
    }
    match static_dns(guid)? {
        read if read == servers => Ok(()),
        read => Err(format!("DNS reads back {read:?}")),
    }
}

/// Flushes the DNS client cache; best effort (sing-tun calls the same export).
pub(crate) fn flush_resolver_cache() {
    if let Some(flush) = export(w!("dnsapi.dll"), s!("DnsFlushResolverCache")) {
        // SAFETY: the export takes no arguments and returns a BOOL.
        let flush = unsafe { std::mem::transmute::<RawProc, FlushDns>(flush) };
        // SAFETY: as above.
        let _ = unsafe { flush() };
    }
}

/// The adapter still exists: its GUID maps to a LUID whose interface row carries that GUID.
pub(crate) fn present(guid: GUID) -> bool {
    let mut luid = NET_LUID_LH::default();
    // SAFETY: valid in / out pointers.
    if unsafe { ConvertInterfaceGuidToLuid(&guid, &mut luid) }.0 != 0 {
        return false;
    }
    // SAFETY: plain integer view of the LUID union.
    let value = unsafe { luid.Value };
    matches!(vpnte_winnet::counters::read(value), Ok(Some(row)) if row.guid == guid.to_u128())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_server_lists() {
        let a: Ipv4Addr = "192.0.2.1".parse().unwrap();
        let b: Ipv4Addr = "198.51.100.2".parse().unwrap();
        assert_eq!(parse_name_servers(""), Ok(vec![]));
        assert_eq!(parse_name_servers("192.0.2.1"), Ok(vec![a]));
        assert_eq!(parse_name_servers("192.0.2.1,198.51.100.2"), Ok(vec![a, b]));
        assert_eq!(
            parse_name_servers(" 192.0.2.1; 198.51.100.2\t"),
            Ok(vec![a, b])
        );
        assert!(parse_name_servers("192.0.2.1,fe80::1").is_err());
    }

    /// Read-only, unelevated: the hand-declared INetCfg vtables walk this machine's real
    /// bindings and agree with `GetAdaptersAddresses` about IPv6 on every physical adapter.
    #[test]
    fn reads_real_bindings_and_dns() {
        let adapters = vpnte_winnet::adapters::inventory().expect("adapter inventory");
        let mut checked = 0;
        for adapter in adapters.iter().filter(|a| a.physical) {
            assert!(present(adapter.guid), "{} not present", adapter.alias);
            match ipv6_binding(adapter.guid) {
                Ok(state) => {
                    assert_eq!(state, Some(adapter.ipv6_enabled), "{}", adapter.alias);
                    checked += 1;
                }
                Err(e) => panic!("INetCfg read failed for {}: {e}", adapter.alias),
            }
            if adapter.ipv4_enabled {
                static_dns(adapter.guid).expect("static DNS read");
            }
        }
        assert!(!present(GUID::from_u128(
            0x0bad0bad_0000_4000_8000_000000000001
        )));
        assert_eq!(
            ipv6_binding(GUID::from_u128(0x0bad0bad_0000_4000_8000_000000000001)),
            Ok(None)
        );
        eprintln!("INetCfg checked {checked} physical adapters");
    }

    /// Acts on this machine without changing it: takes the INetCfg write lock and finds IPv6
    /// already enabled on each physical adapter that has it, so nothing is applied.
    #[test]
    #[ignore = "needs elevation"]
    fn elevated_write_lock_path_is_a_no_op_when_enabled() {
        let adapters = vpnte_winnet::adapters::inventory().expect("adapter inventory");
        for adapter in adapters.iter().filter(|a| a.physical && a.ipv6_enabled) {
            assert_eq!(enable_ipv6(adapter.guid), Ok(false), "{}", adapter.alias);
        }
    }
}
