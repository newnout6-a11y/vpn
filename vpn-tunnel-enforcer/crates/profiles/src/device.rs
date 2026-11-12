//! The device a subscription server should believe it talks to: User-Agents, device headers and
//! the legacy HWID. Panels bind subscriptions to the HWID ("Sosa Connect and similar panels return
//! an EMPTY 200 OK when the header is missing"), so the Electron value is reproduced bit for bit:
//! a changed value consumes a new device slot on HWID-limited plans.
use sha2::{Digest, Sha256};
use vpnte_base::types::ClientDevice;

/// Happ version announced in the User-Agent.
pub const HAPP_VERSION: &str = "3.22.1";
/// Clients tried after the Happ User-Agent, in order.
const EXTRA_AGENTS: [&str; 3] = ["sing-box/1.13.8", "v2RayTun/1.0", "v2rayN/7.0"];
/// Environment override of the HWID (development and tests).
pub const HWID_ENV: &str = "VPNTE_SUBSCRIPTION_HWID";

/// Operating system and model a device claims in the identity headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceProfile {
    /// `x-device-os` (`Windows`).
    pub os: &'static str,
    /// `x-ver-os` (`11`).
    pub os_version: &'static str,
    /// `x-device-model` (`Windows PC`).
    pub model: &'static str,
}

/// The identity headers' values for `device`.
pub fn device_profile(device: ClientDevice) -> DeviceProfile {
    let (os, os_version, model) = match device {
        ClientDevice::Pc => ("Windows", "11", "Windows PC"),
        ClientDevice::Android => ("Android", "15", "SM-A556B"),
        ClientDevice::Ios => ("iOS", "18.3", "iPhone 15 Pro"),
        ClientDevice::Mac => ("macOS", "15.3", "MacBookPro18,3"),
    };
    DeviceProfile {
        os,
        os_version,
        model,
    }
}

/// uTLS fingerprint that matches `device` (the emitter's default when the provider gave none).
pub use crate::common::fields::utls_fingerprint;

/// User-Agents to try for `device`, in order, without repeats (the old mac list sent
/// `sing-box/1.13.8` twice). The Happ agent carries the same `hwid` as the `x-hwid` header; the
/// old app put the computed hash there even when the environment override was set (P-38).
/// `None` (the group does not send its HWID) leaves the HWID segment out of the Happ agent.
pub fn user_agents(device: ClientDevice, hwid: Option<&str>) -> Vec<String> {
    let second = match device {
        ClientDevice::Pc => None,
        ClientDevice::Android => Some("v2RayTun/1.0/android"),
        ClientDevice::Ios => Some("v2RayTun/1.0/ios"),
        ClientDevice::Mac => Some("sing-box/1.13.8"),
    };
    let os = device_profile(device).os;
    let happ = match hwid {
        Some(hwid) => format!("Happ/{HAPP_VERSION}/{os}/{hwid}"),
        None => format!("Happ/{HAPP_VERSION}/{os}"),
    };
    let mut agents = vec![happ];
    for agent in second.into_iter().chain(EXTRA_AGENTS) {
        if !agents.iter().any(|a| a == agent) {
            agents.push(agent.to_owned());
        }
    }
    agents
}

/// Identity headers sent with the HWID set: `x-hwid`, `x-device-os`, `x-ver-os`, `x-device-model`.
pub fn device_headers(device: ClientDevice, hwid: &str) -> [(&'static str, String); 4] {
    let p = device_profile(device);
    [
        ("x-hwid", hwid.to_owned()),
        ("x-device-os", p.os.to_owned()),
        ("x-ver-os", p.os_version.to_owned()),
        ("x-device-model", p.model.to_owned()),
    ]
}

/// The machine facts the legacy HWID was hashed from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MachineIdentity {
    /// Winsock host name (`GetHostNameW`, what Node's `os.hostname()` returned), not the
    /// upper-cased NetBIOS name.
    pub host_name: String,
    /// `GetUserNameW`, as Node's `os.userInfo().username`.
    pub user_name: String,
    /// `%USERDOMAIN%`, empty when unset.
    pub user_domain: String,
}

/// HWID of the Electron app for `device`:
/// `hex(sha256("happ-compatible-mobile-hwid|<device>|<host>|<user>|<domain>|x64|win32"))[..16]`.
/// `x64|win32` is fixed: the old installer shipped x64 only, so even Windows on ARM hashed `x64`.
pub fn legacy_hwid(device: ClientDevice, id: &MachineIdentity) -> String {
    let device = match device {
        ClientDevice::Pc => "pc",
        ClientDevice::Android => "android",
        ClientDevice::Ios => "ios",
        ClientDevice::Mac => "mac",
    };
    let seed = format!(
        "happ-compatible-mobile-hwid|{device}|{}|{}|{}|x64|win32",
        id.host_name, id.user_name, id.user_domain
    );
    let mut hex = hex::encode(Sha256::digest(seed.as_bytes()));
    hex.truncate(16);
    hex
}

/// `VPNTE_SUBSCRIPTION_HWID`, trimmed, when set and not blank. It replaces the HWID in the header
/// and in the User-Agent alike.
pub fn hwid_override() -> Option<String> {
    std::env::var(HWID_ENV)
        .ok()
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
}

impl MachineIdentity {
    /// This machine's identity, read the way Node read it. Node fell back to `%USERNAME%` only when
    /// the user lookup failed; a host name it could not read made the old fetch fail, so the
    /// NetBIOS name is a stand-in that at least stays stable.
    pub fn current() -> Self {
        let env = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
        Self {
            host_name: winsock_host_name()
                .or_else(|| env("COMPUTERNAME"))
                .unwrap_or_default(),
            user_name: user_name().or_else(|| env("USERNAME")).unwrap_or_default(),
            user_domain: env("USERDOMAIN").unwrap_or_default(),
        }
    }
}

/// `GetHostNameW` after `WSAStartup`, as libuv's `uv_os_gethostname` does.
fn winsock_host_name() -> Option<String> {
    use windows::Win32::Networking::WinSock::{GetHostNameW, WSACleanup, WSADATA, WSAStartup};

    let mut data = WSADATA::default();
    // SAFETY: `data` is a valid, writable WSADATA for the duration of the call.
    if unsafe { WSAStartup(0x0202, &mut data) } != 0 {
        return None;
    }
    let mut buf = [0u16; 257];
    // SAFETY: the slice is valid for writes of its whole length, which the binding passes along.
    let rc = unsafe { GetHostNameW(&mut buf) };
    // SAFETY: balances the successful WSAStartup above.
    unsafe { WSACleanup() };
    (rc == 0)
        .then(|| utf16_until_nul(&buf))
        .filter(|name| !name.is_empty())
}

/// `GetUserNameW`, as libuv's `uv_os_get_passwd` does.
fn user_name() -> Option<String> {
    use windows::Win32::System::WindowsProgramming::GetUserNameW;
    use windows::core::PWSTR;

    let mut buf = [0u16; 257];
    let mut len = buf.len() as u32;
    // SAFETY: `buf` holds `len` writable UTF-16 units and `len` is a valid in/out pointer.
    unsafe { GetUserNameW(Some(PWSTR(buf.as_mut_ptr())), &mut len) }.ok()?;
    Some(utf16_until_nul(&buf))
}

fn utf16_until_nul(buf: &[u16]) -> String {
    let end = buf.iter().position(|&u| u == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [ClientDevice; 4] = [
        ClientDevice::Pc,
        ClientDevice::Android,
        ClientDevice::Ios,
        ClientDevice::Mac,
    ];

    fn id(host: &str, user: &str, domain: &str) -> MachineIdentity {
        MachineIdentity {
            host_name: host.into(),
            user_name: user.into(),
            user_domain: domain.into(),
        }
    }

    /// profiles §7.2 "HWID" and servers §7: synthetic seeds, values recomputed with sha256sum.
    #[test]
    fn legacy_hwid_is_bit_exact() {
        let test = id("TESTHOST", "tester", "TESTDOMAIN");
        assert_eq!(legacy_hwid(ClientDevice::Pc, &test), "a7d341199a33fa78");
        assert_eq!(
            legacy_hwid(ClientDevice::Android, &test),
            "4f6dd4aa1d91b4cb"
        );
        let host1 = id("HOST-1", "alice", "WORKGROUP");
        let got: Vec<String> = ALL.iter().map(|d| legacy_hwid(*d, &host1)).collect();
        assert_eq!(
            got,
            [
                "99c6d48e9a5a5e32",
                "2ed2387177b3e714",
                "00ba16f6d8390831",
                "887fdec7a9d12def"
            ]
        );
    }

    /// §7.2 "UA format": the Happ agent first, per device.
    #[test]
    fn happ_agent_comes_first() {
        let hwid = legacy_hwid(ClientDevice::Pc, &id("HOST-1", "alice", "WORKGROUP"));
        assert_eq!(
            user_agents(ClientDevice::Pc, Some(&hwid))[0],
            "Happ/3.22.1/Windows/99c6d48e9a5a5e32"
        );
        let re =
            regex::Regex::new(r"^Happ/3\.22\.1/(Windows|Android|iOS|macOS)/[a-f0-9]{16}$").unwrap();
        let oses: Vec<String> = ALL
            .iter()
            .map(|d| {
                let hwid = legacy_hwid(*d, &MachineIdentity::default());
                let first = user_agents(*d, Some(&hwid)).remove(0);
                re.captures(&first).unwrap()[1].to_owned()
            })
            .collect();
        assert_eq!(oses, ["Windows", "Android", "iOS", "macOS"]);
        // The override reaches the User-Agent too (P-38).
        assert_eq!(
            user_agents(ClientDevice::Pc, Some("abc"))[0],
            "Happ/3.22.1/Windows/abc"
        );
    }

    /// ru-2026 item 1: a group that does not send its HWID keeps the Happ agent without it.
    #[test]
    fn happ_agent_without_the_hwid() {
        assert_eq!(
            user_agents(ClientDevice::Pc, None)[0],
            "Happ/3.22.1/Windows"
        );
        assert_eq!(user_agents(ClientDevice::Ios, None)[0], "Happ/3.22.1/iOS");
        assert_eq!(
            user_agents(ClientDevice::Pc, None)[1..],
            user_agents(ClientDevice::Pc, Some("h"))[1..]
        );
    }

    #[test]
    fn agent_lists_per_device_without_repeats() {
        let h = Some("h");
        assert_eq!(
            user_agents(ClientDevice::Pc, h)[1..],
            ["sing-box/1.13.8", "v2RayTun/1.0", "v2rayN/7.0"]
        );
        assert_eq!(
            user_agents(ClientDevice::Android, h)[1..],
            [
                "v2RayTun/1.0/android",
                "sing-box/1.13.8",
                "v2RayTun/1.0",
                "v2rayN/7.0"
            ]
        );
        assert_eq!(user_agents(ClientDevice::Ios, h)[1], "v2RayTun/1.0/ios");
        assert_eq!(
            user_agents(ClientDevice::Mac, h)[1..],
            ["sing-box/1.13.8", "v2RayTun/1.0", "v2rayN/7.0"]
        );
    }

    #[test]
    fn headers_and_fingerprints_per_device() {
        assert_eq!(
            device_headers(ClientDevice::Mac, "abc"),
            [
                ("x-hwid", "abc".to_owned()),
                ("x-device-os", "macOS".to_owned()),
                ("x-ver-os", "15.3".to_owned()),
                ("x-device-model", "MacBookPro18,3".to_owned()),
            ]
        );
        assert_eq!(device_profile(ClientDevice::Android).model, "SM-A556B");
        let fps: Vec<&str> = ALL.iter().map(|d| utls_fingerprint(*d)).collect();
        assert_eq!(fps, ["chrome", "android", "ios", "safari"]);
    }

    /// Reads the real machine: values exist and give four distinct, stable HWIDs.
    #[test]
    fn current_machine_identity() {
        let me = MachineIdentity::current();
        assert!(!me.host_name.is_empty() && !me.user_name.is_empty());
        assert_eq!(me, MachineIdentity::current());
        let mut hwids: Vec<String> = ALL.iter().map(|d| legacy_hwid(*d, &me)).collect();
        hwids.sort();
        hwids.dedup();
        assert_eq!(hwids.len(), 4);
    }
}
