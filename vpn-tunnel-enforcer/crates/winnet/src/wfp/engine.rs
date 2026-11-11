//! The `windows` crate calls: engine sessions, transactions, filters, provider and sublayer.
//! Every function returns the raw WFP status in [`WfpError`]; [`super::protection`] maps it.
use std::ffi::c_void;
use std::ptr;

use windows::Win32::Foundation::{
    ERROR_ACCESS_DENIED, FWP_E_ALREADY_EXISTS, FWP_E_FILTER_NOT_FOUND, FWP_E_NO_TXN_IN_PROGRESS,
    FWP_E_PROVIDER_NOT_FOUND, FWP_E_SESSION_ABORTED, FWP_E_SUBLAYER_NOT_FOUND, HANDLE,
};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWPM_DISPLAY_DATA0, FWPM_PROVIDER_FLAG_PERSISTENT, FWPM_PROVIDER0, FWPM_SESSION_FLAG_DYNAMIC,
    FWPM_SESSION0, FWPM_SUBLAYER_FLAG_PERSISTENT, FWPM_SUBLAYER0, FwpmEngineClose0,
    FwpmEngineOpen0, FwpmFilterDeleteById0, FwpmFreeMemory0, FwpmProviderAdd0,
    FwpmProviderDeleteByKey0, FwpmProviderGetByKey0, FwpmSubLayerAdd0, FwpmSubLayerDeleteByKey0,
    FwpmSubLayerGetByKey0, FwpmTransactionAbort0, FwpmTransactionBegin0, FwpmTransactionCommit0,
};
use windows::Win32::System::Rpc::{
    EPT_S_NOT_REGISTERED, RPC_C_AUTHN_WINNT, RPC_S_CALL_FAILED, RPC_S_SERVER_UNAVAILABLE,
    RPC_S_UNKNOWN_IF,
};
use windows::core::{GUID, HRESULT, PCWSTR, PWSTR};

use super::{PROVIDER_KEY, SUBLAYER_KEY};
use crate::win::{read_wide, wide};

/// How long a call waits for BFE's write lock; a stuck lock must fail the call, not hang
/// Stop or shutdown.
const TXN_WAIT_MS: u32 = 5_000;
const PROVIDER_NAME: &str = "VPN Tunnel Enforcer";
const SUBLAYER_NAME: &str = "VPNTE protection";
pub(crate) const DESCRIPTION: &str = "VPNTE network protection";

/// A failed WFP call: the operation and its raw status (Win32 error or `FWP_E_*` HRESULT).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{op} failed with {code:#010x}")]
pub struct WfpError {
    pub op: &'static str,
    pub code: u32,
}

impl WfpError {
    /// The status equals this HRESULT (`FWP_E_*`).
    pub fn is(&self, hr: HRESULT) -> bool {
        self.code == hr.0 as u32
    }

    /// Not elevated, or BFE refused the object access.
    pub fn is_access_denied(&self) -> bool {
        self.code == ERROR_ACCESS_DENIED.0
    }

    /// The RPC link to BFE is gone (service stopped or restarted).
    pub fn is_rpc_failure(&self) -> bool {
        [
            RPC_S_UNKNOWN_IF,
            RPC_S_SERVER_UNAVAILABLE,
            RPC_S_CALL_FAILED,
            EPT_S_NOT_REGISTERED,
        ]
        .iter()
        .any(|s| self.code == s.0 as u32)
    }

    /// The session is unusable and must be reopened (a dynamic one has lost its filters).
    pub fn engine_lost(&self) -> bool {
        self.is_rpc_failure() || self.is(FWP_E_SESSION_ABORTED)
    }
}

pub(crate) fn check(op: &'static str, code: u32) -> Result<(), WfpError> {
    match code {
        0 => Ok(()),
        code => Err(WfpError { op, code }),
    }
}

/// Display data borrowing two UTF-16 buffers that must outlive the call.
pub(crate) fn display(name: &mut [u16], description: &mut [u16]) -> FWPM_DISPLAY_DATA0 {
    FWPM_DISPLAY_DATA0 {
        name: PWSTR(name.as_mut_ptr()),
        description: PWSTR(description.as_mut_ptr()),
    }
}

/// A block of memory WFP allocated for us; freed with `FwpmFreeMemory0`.
pub(crate) struct WfpMem(pub *mut c_void);

impl Drop for WfpMem {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from a WFP call and is freed exactly once.
            unsafe { FwpmFreeMemory0(&mut self.0) }
        }
    }
}

/// Our sublayer (or any other) as BFE reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SublayerInfo {
    pub key: GUID,
    /// Actual weight; BFE may assign less than requested (65533 for 65535 was seen in the field).
    pub weight: u16,
    pub flags: u32,
    pub provider: Option<GUID>,
    pub name: String,
}

/// An open WFP engine session; closed on drop (a dynamic session takes its objects with it).
pub struct Engine {
    handle: HANDLE,
    dynamic: bool,
}

// SAFETY: the handle is an RPC binding to BFE, usable from any thread; the owner serialises
// all use (Protection keeps it behind one mutex), so only `Send` is claimed.
unsafe impl Send for Engine {}

impl Drop for Engine {
    fn drop(&mut self) {
        // SAFETY: the handle came from FwpmEngineOpen0 and is closed exactly once.
        let code = unsafe { FwpmEngineClose0(self.handle) };
        if code != 0 {
            tracing::warn!(
                code = format_args!("{code:#010x}"),
                "FwpmEngineClose0 failed"
            );
        }
    }
}

impl Engine {
    /// Opens a dynamic session: BFE removes everything it adds when the handle closes or the
    /// process dies, so a crash in `standard` never leaves the user offline.
    pub fn open_dynamic() -> Result<Self, WfpError> {
        Self::open(FWPM_SESSION_FLAG_DYNAMIC, "VPNTE dynamic")
    }

    /// Opens a plain session for persistent objects (a dynamic session cannot add them).
    pub fn open_persistent() -> Result<Self, WfpError> {
        Self::open(0, "VPNTE persistent")
    }

    fn open(flags: u32, name: &str) -> Result<Self, WfpError> {
        let mut name = wide(name);
        let mut description = wide(DESCRIPTION);
        let session = FWPM_SESSION0 {
            displayData: display(&mut name, &mut description),
            flags,
            txnWaitTimeoutInMSec: TXN_WAIT_MS,
            ..Default::default()
        };
        let mut handle = HANDLE::default();
        // SAFETY: `session` and its strings outlive the call; `handle` is a valid out pointer.
        let code = unsafe {
            FwpmEngineOpen0(
                PCWSTR::null(),
                RPC_C_AUTHN_WINNT,
                None,
                Some(&raw const session),
                &mut handle,
            )
        };
        check("FwpmEngineOpen0", code)?;
        Ok(Self {
            handle,
            dynamic: flags & FWPM_SESSION_FLAG_DYNAMIC != 0,
        })
    }

    /// Whether objects added through this session vanish with it.
    pub fn is_dynamic(&self) -> bool {
        self.dynamic
    }

    pub(crate) fn handle(&self) -> HANDLE {
        self.handle
    }

    /// Runs `f` in one BFE transaction: committed on `Ok`, aborted on `Err`, so a change is
    /// all or nothing (blocks are never in place without their permits).
    pub fn transaction<R>(
        &self,
        f: impl FnOnce(&Self) -> Result<R, WfpError>,
    ) -> Result<R, WfpError> {
        // SAFETY: valid engine handle.
        check("FwpmTransactionBegin0", unsafe {
            FwpmTransactionBegin0(self.handle, 0)
        })?;
        let result = f(self).and_then(|r| {
            // SAFETY: valid engine handle with a transaction in progress.
            check("FwpmTransactionCommit0", unsafe {
                FwpmTransactionCommit0(self.handle)
            })
            .map(|()| r)
        });
        if result.is_err() {
            // SAFETY: valid engine handle; BFE may already have ended the transaction.
            let code = unsafe { FwpmTransactionAbort0(self.handle) };
            if code != 0 && code != FWP_E_NO_TXN_IN_PROGRESS.0 as u32 {
                tracing::warn!(
                    code = format_args!("{code:#010x}"),
                    "FwpmTransactionAbort0 failed"
                );
            }
        }
        result
    }

    /// Creates our provider and sublayer when missing (needs a persistent session) and returns
    /// the sublayer weight BFE actually assigned; it is logged, never asserted.
    pub fn ensure_provider_and_sublayer(&self) -> Result<u16, WfpError> {
        if !self.provider_exists(&PROVIDER_KEY)? {
            let mut name = wide(PROVIDER_NAME);
            let mut description = wide(DESCRIPTION);
            // No `serviceName`: BFE loads a provider's persistent filters at boot only when it
            // has none (or its service is auto-start), and strict must hold from boot on.
            let provider = FWPM_PROVIDER0 {
                providerKey: PROVIDER_KEY,
                displayData: display(&mut name, &mut description),
                flags: FWPM_PROVIDER_FLAG_PERSISTENT,
                ..Default::default()
            };
            // SAFETY: `provider` and its strings outlive the call.
            let code = unsafe { FwpmProviderAdd0(self.handle, &provider, None) };
            if code != FWP_E_ALREADY_EXISTS.0 as u32 {
                check("FwpmProviderAdd0", code)?;
            }
        }
        if let Some(info) = self.sublayer(&SUBLAYER_KEY)? {
            return Ok(info.weight);
        }
        let mut name = wide(SUBLAYER_NAME);
        let mut description = wide(DESCRIPTION);
        let mut provider = PROVIDER_KEY;
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: SUBLAYER_KEY,
            displayData: display(&mut name, &mut description),
            flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
            providerKey: &mut provider,
            weight: u16::MAX,
            ..Default::default()
        };
        // SAFETY: `sublayer`, its strings and the provider key outlive the call.
        let code = unsafe { FwpmSubLayerAdd0(self.handle, &sublayer, None) };
        if code != FWP_E_ALREADY_EXISTS.0 as u32 {
            check("FwpmSubLayerAdd0", code)?;
        }
        let info = self.sublayer(&SUBLAYER_KEY)?;
        let not_found = WfpError {
            op: "FwpmSubLayerGetByKey0",
            code: FWP_E_SUBLAYER_NOT_FOUND.0 as u32,
        };
        let weight = info.ok_or(not_found)?.weight;
        tracing::info!(weight, "WFP sublayer ready");
        Ok(weight)
    }

    pub(crate) fn provider_exists(&self, key: &GUID) -> Result<bool, WfpError> {
        let mut out: *mut FWPM_PROVIDER0 = ptr::null_mut();
        // SAFETY: valid handle, key and out pointer; the result is freed by `WfpMem`.
        let code = unsafe { FwpmProviderGetByKey0(self.handle, key, &mut out) };
        let _mem = WfpMem(out.cast());
        if code == FWP_E_PROVIDER_NOT_FOUND.0 as u32 {
            return Ok(false);
        }
        check("FwpmProviderGetByKey0", code).map(|()| true)
    }

    /// The sublayer with this key, `None` when absent.
    pub fn sublayer(&self, key: &GUID) -> Result<Option<SublayerInfo>, WfpError> {
        let mut out: *mut FWPM_SUBLAYER0 = ptr::null_mut();
        // SAFETY: valid handle, key and out pointer; the result is freed by `WfpMem`.
        let code = unsafe { FwpmSubLayerGetByKey0(self.handle, key, &mut out) };
        let _mem = WfpMem(out.cast());
        if code == FWP_E_SUBLAYER_NOT_FOUND.0 as u32 {
            return Ok(None);
        }
        check("FwpmSubLayerGetByKey0", code)?;
        // SAFETY: on success `out` points to a valid FWPM_SUBLAYER0 until `_mem` drops.
        let s = unsafe { &*out };
        // SAFETY: a non-null provider key points into the same block.
        let provider = (!s.providerKey.is_null()).then(|| unsafe { *s.providerKey });
        Ok(Some(SublayerInfo {
            key: s.subLayerKey,
            weight: s.weight,
            flags: s.flags,
            provider,
            // SAFETY: WFP strings are NUL-terminated inside the block `_mem` still holds.
            name: unsafe { read_wide(s.displayData.name.0) },
        }))
    }

    /// Deletes a sublayer; absent counts as done. Fails with `FWP_E_IN_USE` while filters use it.
    pub fn delete_sublayer(&self, key: &GUID) -> Result<(), WfpError> {
        // SAFETY: valid handle and key.
        let code = unsafe { FwpmSubLayerDeleteByKey0(self.handle, key) };
        match code == FWP_E_SUBLAYER_NOT_FOUND.0 as u32 {
            true => Ok(()),
            false => check("FwpmSubLayerDeleteByKey0", code),
        }
    }

    /// Deletes a provider; absent counts as done.
    pub fn delete_provider(&self, key: &GUID) -> Result<(), WfpError> {
        // SAFETY: valid handle and key.
        let code = unsafe { FwpmProviderDeleteByKey0(self.handle, key) };
        match code == FWP_E_PROVIDER_NOT_FOUND.0 as u32 {
            true => Ok(()),
            false => check("FwpmProviderDeleteByKey0", code),
        }
    }

    /// Deletes a filter by runtime ID; absent counts as done.
    pub fn delete(&self, id: u64) -> Result<(), WfpError> {
        // SAFETY: valid handle.
        let code = unsafe { FwpmFilterDeleteById0(self.handle, id) };
        match code == FWP_E_FILTER_NOT_FOUND.0 as u32 {
            true => Ok(()),
            false => check("FwpmFilterDeleteById0", code),
        }
    }
}
