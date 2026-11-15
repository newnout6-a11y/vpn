//! Filters: [`FilterSpec`] to `FWPM_FILTER0`, add, enumerate, and application IDs.
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::ptr;

use ipnet::{Ipv4Net, Ipv6Net};
use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, HANDLE};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE,
    FWP_CONDITION_FLAG_IS_LOOPBACK, FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0,
    FWP_FILTER_ENUM_FLAG_INCLUDE_BOOTTIME, FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED,
    FWP_FILTER_ENUM_FULLY_CONTAINED, FWP_MATCH_EQUAL, FWP_MATCH_FLAGS_ALL_SET, FWP_UINT8,
    FWP_UINT16, FWP_UINT32, FWP_UINT64, FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK,
    FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK, FWP_VALUE0, FWP_VALUE0_0, FWPM_ACTION0,
    FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_FLAGS, FWPM_CONDITION_IP_LOCAL_ADDRESS,
    FWPM_CONDITION_IP_LOCAL_INTERFACE, FWPM_CONDITION_IP_LOCAL_PORT, FWPM_CONDITION_IP_PROTOCOL,
    FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_CONDITION_IP_REMOTE_PORT, FWPM_FILTER_CONDITION0,
    FWPM_FILTER_ENUM_TEMPLATE0, FWPM_FILTER_FLAG_BOOTTIME, FWPM_FILTER_FLAG_DISABLED,
    FWPM_FILTER_FLAG_INDEXED, FWPM_FILTER_FLAG_NONE, FWPM_FILTER_FLAG_PERSISTENT, FWPM_FILTER0,
    FwpmFilterAdd0, FwpmFilterCreateEnumHandle0, FwpmFilterDestroyEnumHandle0, FwpmFilterEnum0,
    FwpmGetAppIdFromFileName0,
};
use windows::core::{GUID, PCWSTR};

use super::engine::{Engine, Lifetime, WfpError, WfpMem, check, display};
use super::spec::{Action, AppId, Cond, FilterSpec, Layer};
use super::{PROVIDER_KEY, SUBLAYER_KEY};
use crate::win::{read_wide, wide, wide_os};

/// Filters returned per `FwpmFilterEnum0` call.
const BATCH: u32 = 256;

/// What to enumerate: one layer, optionally only one provider's filters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListQuery {
    pub layer: Layer,
    pub provider: Option<GUID>,
}

/// A filter as BFE reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterInfo {
    pub id: u64,
    pub key: GUID,
    pub layer: GUID,
    pub sublayer: GUID,
    pub provider: Option<GUID>,
    /// `FWPM_FILTER_FLAG_*`; BFE adds `INDEXED` (0x40) to persistent filters on read-back.
    pub flags: u32,
    /// `FWP_ACTION_TYPE` value.
    pub action: u32,
    /// `FWP_UINT8` weight, `None` for other weight types.
    pub weight: Option<u8>,
    pub name: String,
}

impl FilterInfo {
    /// Survives reboots (strict).
    pub fn is_persistent(&self) -> bool {
        self.flags & FWPM_FILTER_FLAG_PERSISTENT.0 != 0
    }

    /// The flags are exactly what an intact persistent (or, with `boot`, boot-time) filter
    /// reads back with: Windows adds INDEXED (0x40) to persistent filters, and boot-time ones
    /// read back as DISABLED (0x20) after BFE switched to the persistent policy. Anything else
    /// (disabled, CLEAR_ACTION_RIGHT, ...) is not intact.
    pub fn flags_valid(&self, boot: bool) -> bool {
        let indexed = FWPM_FILTER_FLAG_INDEXED.0;
        match boot {
            true => {
                self.flags & !(indexed | FWPM_FILTER_FLAG_DISABLED.0) == FWPM_FILTER_FLAG_BOOTTIME.0
            }
            false => self.flags & !indexed == FWPM_FILTER_FLAG_PERSISTENT.0,
        }
    }
}

/// The WFP application ID of an existing executable (`FwpmGetAppIdFromFileName0`): the NT
/// device path of its canonical path. WFP keeps an 8.3 spelling as given, so a short name would
/// give another ID than the process launched from the long path (review D6).
pub fn app_id(exe: &Path) -> Result<AppId, WfpError> {
    app_id_of(&canonical(exe)?)
}

/// `exe` with 8.3 names, symbolic links and junctions resolved (verbatim `\\?\` form, which
/// `FwpmGetAppIdFromFileName0` accepts); a missing file or a directory is `ERROR_FILE_NOT_FOUND`.
pub(crate) fn canonical(exe: &Path) -> Result<PathBuf, WfpError> {
    let failed = |code| WfpError {
        op: "canonicalize",
        code,
    };
    let path = std::fs::canonicalize(exe).map_err(|e| {
        failed(
            e.raw_os_error()
                .map_or(ERROR_FILE_NOT_FOUND.0, |c| c as u32),
        )
    })?;
    match path.is_file() {
        true => Ok(path),
        false => Err(failed(ERROR_FILE_NOT_FOUND.0)),
    }
}

/// [`app_id`] of a path that is already canonical.
pub(crate) fn app_id_of(canonical: &Path) -> Result<AppId, WfpError> {
    let path = wide_os(canonical);
    let mut blob: *mut FWP_BYTE_BLOB = ptr::null_mut();
    // SAFETY: `path` is NUL-terminated and outlives the call; the blob is freed by `WfpMem`.
    let code = unsafe { FwpmGetAppIdFromFileName0(PCWSTR(path.as_ptr()), &mut blob) };
    let _mem = WfpMem(blob.cast());
    check("FwpmGetAppIdFromFileName0", code)?;
    // SAFETY: on success `blob` points to a valid FWP_BYTE_BLOB of `size` bytes.
    let bytes = unsafe { std::slice::from_raw_parts((*blob).data, (*blob).size as usize) };
    Ok(AppId::from_bytes(bytes.to_vec()))
}

/// Condition array plus the values its pointers refer to; must outlive `FwpmFilterAdd0`.
/// The value vectors are filled completely before any pointer into them is taken, so their
/// buffers never move afterwards (moving the struct does not move them either).
struct Conditions {
    conds: Vec<FWPM_FILTER_CONDITION0>,
    _u64s: Vec<u64>,
    _v4: Vec<FWP_V4_ADDR_AND_MASK>,
    _v6: Vec<FWP_V6_ADDR_AND_MASK>,
    _blobs: Vec<FWP_BYTE_BLOB>,
}

impl Conditions {
    fn new(spec: &FilterSpec) -> Self {
        let (mut u64s, mut v4, mut v6, mut blobs) =
            (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        // Host byte order for IPv4: the numeric value of the address.
        let mut push_v4 = |net: Ipv4Net| {
            v4.push(FWP_V4_ADDR_AND_MASK {
                addr: u32::from(net.network()),
                mask: u32::from(net.netmask()),
            })
        };
        let mut push_v6 = |net: Ipv6Net| {
            v6.push(FWP_V6_ADDR_AND_MASK {
                addr: net.network().octets(),
                prefixLength: net.prefix_len(),
            })
        };
        for cond in &spec.conds {
            match cond {
                // WFP only reads the blob; the mutable pointer is what the struct declares.
                Cond::AppId(id) => blobs.push(FWP_BYTE_BLOB {
                    size: id.as_bytes().len() as u32,
                    data: id.as_bytes().as_ptr().cast_mut(),
                }),
                Cond::LocalInterface(luid) => u64s.push(*luid),
                Cond::RemoteV4(net) => push_v4(*net),
                Cond::RemoteV6(net) => push_v6(*net),
                Cond::LocalAddr(IpAddr::V4(a)) => push_v4(Ipv4Net::from(*a)),
                Cond::LocalAddr(IpAddr::V6(a)) => push_v6(Ipv6Net::from(*a)),
                _ => {}
            }
        }
        let (mut iu, mut i4, mut i6, mut ib) = (0, 0, 0, 0);
        let mut conds = Vec::with_capacity(spec.conds.len());
        for cond in &spec.conds {
            type V = FWP_CONDITION_VALUE0_0;
            let (field, matching, value) = match cond {
                Cond::AppId(_) => {
                    ib += 1;
                    let v = V {
                        byteBlob: ptr::from_mut(&mut blobs[ib - 1]),
                    };
                    (
                        FWPM_CONDITION_ALE_APP_ID,
                        FWP_MATCH_EQUAL,
                        value(FWP_BYTE_BLOB_TYPE, v),
                    )
                }
                Cond::LocalInterface(_) => {
                    iu += 1;
                    let v = V {
                        uint64: ptr::from_mut(&mut u64s[iu - 1]),
                    };
                    (
                        FWPM_CONDITION_IP_LOCAL_INTERFACE,
                        FWP_MATCH_EQUAL,
                        value(FWP_UINT64, v),
                    )
                }
                Cond::Loopback => {
                    let v = V {
                        uint32: FWP_CONDITION_FLAG_IS_LOOPBACK,
                    };
                    (
                        FWPM_CONDITION_FLAGS,
                        FWP_MATCH_FLAGS_ALL_SET,
                        value(FWP_UINT32, v),
                    )
                }
                Cond::Protocol(p) => (
                    FWPM_CONDITION_IP_PROTOCOL,
                    FWP_MATCH_EQUAL,
                    value(FWP_UINT8, V { uint8: *p }),
                ),
                Cond::LocalPort(p) | Cond::IcmpType(p) => (
                    FWPM_CONDITION_IP_LOCAL_PORT,
                    FWP_MATCH_EQUAL,
                    value(FWP_UINT16, V { uint16: *p }),
                ),
                Cond::RemotePort(p) => (
                    FWPM_CONDITION_IP_REMOTE_PORT,
                    FWP_MATCH_EQUAL,
                    value(FWP_UINT16, V { uint16: *p }),
                ),
                Cond::RemoteV4(_) | Cond::LocalAddr(IpAddr::V4(_)) => {
                    i4 += 1;
                    let v = V {
                        v4AddrMask: ptr::from_mut(&mut v4[i4 - 1]),
                    };
                    (
                        address_field(cond),
                        FWP_MATCH_EQUAL,
                        value(FWP_V4_ADDR_MASK, v),
                    )
                }
                Cond::RemoteV6(_) | Cond::LocalAddr(IpAddr::V6(_)) => {
                    i6 += 1;
                    let v = V {
                        v6AddrMask: ptr::from_mut(&mut v6[i6 - 1]),
                    };
                    (
                        address_field(cond),
                        FWP_MATCH_EQUAL,
                        value(FWP_V6_ADDR_MASK, v),
                    )
                }
            };
            conds.push(condition(field, matching, value));
        }
        Self {
            conds,
            _u64s: u64s,
            _v4: v4,
            _v6: v6,
            _blobs: blobs,
        }
    }
}

fn address_field(cond: &Cond) -> GUID {
    match cond {
        Cond::LocalAddr(_) => FWPM_CONDITION_IP_LOCAL_ADDRESS,
        _ => FWPM_CONDITION_IP_REMOTE_ADDRESS,
    }
}

fn value(
    kind: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_DATA_TYPE,
    anonymous: FWP_CONDITION_VALUE0_0,
) -> FWP_CONDITION_VALUE0 {
    FWP_CONDITION_VALUE0 {
        r#type: kind,
        Anonymous: anonymous,
    }
}

fn condition(
    field: GUID,
    match_type: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_MATCH_TYPE,
    value: FWP_CONDITION_VALUE0,
) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field,
        matchType: match_type,
        conditionValue: value,
    }
}

/// Destroys an enumeration handle on drop.
struct EnumHandle<'a> {
    engine: &'a Engine,
    handle: HANDLE,
}

impl Drop for EnumHandle<'_> {
    fn drop(&mut self) {
        // SAFETY: both handles are valid and the enumeration handle is destroyed once.
        let code = unsafe { FwpmFilterDestroyEnumHandle0(self.engine.handle(), self.handle) };
        if code != 0 {
            tracing::warn!(
                code = format_args!("{code:#010x}"),
                "FwpmFilterDestroyEnumHandle0 failed"
            );
        }
    }
}

impl Engine {
    /// Adds one filter to our provider and sublayer and returns its runtime ID, with this
    /// session's [`Lifetime`]: dynamic (gone with the process), static (survives the process,
    /// gone at reboot: only the helper service, which Windows restarts after a crash, opens
    /// such a session) or persistent ("Always").
    pub fn add(&self, spec: &FilterSpec) -> Result<u64, WfpError> {
        let mut conds = Conditions::new(spec);
        let mut name = wide(&format!("VPNTE {}", spec.name));
        let mut description = wide(super::engine::DESCRIPTION);
        let mut provider = PROVIDER_KEY;
        let action = match spec.action {
            Action::Permit => FWP_ACTION_PERMIT,
            Action::Block => FWP_ACTION_BLOCK,
        };
        let filter = FWPM_FILTER0 {
            displayData: display(&mut name, &mut description),
            flags: match self.lifetime() {
                Lifetime::Dynamic | Lifetime::Static => FWPM_FILTER_FLAG_NONE,
                Lifetime::Persistent => FWPM_FILTER_FLAG_PERSISTENT,
            },
            providerKey: &mut provider,
            layerKey: spec.layer.key(),
            subLayerKey: SUBLAYER_KEY,
            weight: FWP_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_VALUE0_0 { uint8: spec.weight },
            },
            numFilterConditions: conds.conds.len() as u32,
            filterCondition: match conds.conds.is_empty() {
                true => ptr::null_mut(),
                false => conds.conds.as_mut_ptr(),
            },
            action: FWPM_ACTION0 {
                r#type: action,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut id = 0u64;
        // SAFETY: `filter` and everything it points to (`conds`, strings, provider key, the app
        // ID bytes borrowed from `spec`) outlive the call; `id` is a valid out pointer.
        let code = unsafe { FwpmFilterAdd0(self.handle(), &filter, None, Some(&mut id)) };
        check("FwpmFilterAdd0", code)?;
        Ok(id)
    }

    /// Fresh enumeration of one layer, boot-time and disabled filters included (the default
    /// enumeration hides them, and cleanup or verification must not read that as "none").
    pub fn list(&self, q: &ListQuery) -> Result<Vec<FilterInfo>, WfpError> {
        let mut provider = q.provider.unwrap_or_default();
        let template = FWPM_FILTER_ENUM_TEMPLATE0 {
            providerKey: match q.provider {
                Some(_) => &mut provider,
                None => ptr::null_mut(),
            },
            // A template must name a real layer: a zero layer fails with FWP_E_LAYER_NOT_FOUND.
            layerKey: q.layer.key(),
            enumType: FWP_FILTER_ENUM_FULLY_CONTAINED,
            flags: FWP_FILTER_ENUM_FLAG_INCLUDE_BOOTTIME | FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED,
            actionMask: u32::MAX,
            ..Default::default()
        };
        let mut handle = HANDLE::default();
        // SAFETY: `template` (and the provider key it points to) outlive the call.
        let code = unsafe {
            FwpmFilterCreateEnumHandle0(self.handle(), Some(&raw const template), &mut handle)
        };
        check("FwpmFilterCreateEnumHandle0", code)?;
        let guard = EnumHandle {
            engine: self,
            handle,
        };
        let mut out = Vec::new();
        loop {
            let mut entries: *mut *mut FWPM_FILTER0 = ptr::null_mut();
            let mut n = 0u32;
            // SAFETY: valid handles and out pointers; the entry array is freed by `WfpMem`.
            let code = unsafe {
                FwpmFilterEnum0(self.handle(), guard.handle, BATCH, &mut entries, &mut n)
            };
            let _mem = WfpMem(entries.cast());
            check("FwpmFilterEnum0", code)?;
            for i in 0..n as usize {
                // SAFETY: `entries` holds `n` valid filter pointers until `_mem` drops.
                let f = unsafe { &**entries.add(i) };
                out.push(info(f));
            }
            if n < BATCH {
                return Ok(out);
            }
        }
    }

    /// Every filter of our provider on our four layers.
    pub fn owned_filters(&self) -> Result<Vec<FilterInfo>, WfpError> {
        let mut out = Vec::new();
        for layer in Layer::OURS {
            out.extend(self.list(&ListQuery {
                layer,
                provider: Some(PROVIDER_KEY),
            })?);
        }
        Ok(out)
    }
}

fn info(f: &FWPM_FILTER0) -> FilterInfo {
    // SAFETY: for an FWP_UINT8 weight the `uint8` member is the active one.
    let weight = if f.weight.r#type == FWP_UINT8 {
        Some(unsafe { f.weight.Anonymous.uint8 })
    } else {
        None
    };
    // SAFETY: a non-null provider key points into the enumeration block, alive for this call.
    let provider = (!f.providerKey.is_null()).then(|| unsafe { *f.providerKey });
    FilterInfo {
        id: f.filterId,
        key: f.filterKey,
        layer: f.layerKey,
        sublayer: f.subLayerKey,
        provider,
        flags: f.flags.0,
        action: f.action.r#type.0,
        weight,
        // SAFETY: WFP strings are NUL-terminated inside the enumeration block, alive for this call.
        name: unsafe { read_wide(f.displayData.name.0) },
    }
}

#[cfg(test)]
pub(crate) mod tests;
