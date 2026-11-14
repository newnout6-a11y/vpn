//! The device a subscription server should believe it talks to: User-Agents, device headers and
//! the legacy HWID. Panels bind subscriptions to the HWID ("Sosa Connect and similar panels return
//! an EMPTY 200 OK when the header is missing"), so the Electron value is reproduced bit for bit:
//! a changed value consumes a new device slot on HWID-limited plans.
use sha2::{Digest, Sha256};
use vpnte_base::types::ClientDevice;

/// Happ version announced in the User-Agent of a PC or a Mac (Happ desktop 4.7.2, GitHub release
/// of 2026-10-30): panels gate old clients with an "update the app" placeholder.
pub const HAPP_VERSION: &str = "4.7.2";
/// Happ for Android (GitHub release 4.10.1, 2026-11-04) and iOS (App Store 6.4.0, 2026-11-11).
const HAPP_ANDROID: &str = "4.10.1";
const HAPP_IOS: &str = "6.4.0";
/// Clients tried after the device's own, in order, each one whose answer the parser reads:
/// v2rayN 7.25.6 (`v2rayN/x.y.z`: Remnawave and Marzban want three parts before they serve Xray
/// JSON), Clash Verge Rev 2.5.10 (Mihomo YAML), sing-box 1.14.4, v2RayTun 5.26.83 (research in
/// `crates/servers/progress/p-live-fix.md`, 14.11.2026).
const EXTRA_AGENTS: [&str; 4] = [
    "v2rayN/7.25.6",
    "clash-verge/v2.5.10",
    "sing-box/1.14.4",
    "v2RayTun/5.26.83",
];
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

/// User-Agents to try for `device`, in order, without repeats: Happ first (the client panels
/// serve most), then the device's own second client, then [`EXTRA_AGENTS`]. The Happ agent
/// carries the same `hwid` as the `x-hwid` header; the old app put the computed hash there even
/// when the environment override was set (P-38). `None` (the group does not send its HWID) leaves
/// the HWID segment out of the Happ agent.
pub fn user_agents(device: ClientDevice, hwid: Option<&str>) -> Vec<String> {
    let (happ, second) = match device {
        ClientDevice::Pc | ClientDevice::Mac => (HAPP_VERSION, None),
        ClientDevice::Android => (HAPP_ANDROID, Some("v2RayTun/5.26.83/android")),
        ClientDevice::Ios => (HAPP_IOS, Some("Streisand/1.7.1")),
    };
    let os = device_profile(device).os;
    let happ = match hwid {
        Some(hwid) => format!("Happ/{happ}/{os}/{hwid}"),
        None => format!("Happ/{happ}/{os}"),
    };
    let mut agents = vec![happ];
    for agent in second.into_iter().chain(EXTRA_AGENTS) {
        if !agents.iter().any(|a| a == agent) {
            agents.push(agent.to_owned());
        }
    }
    agents
}

/// The family of a User-Agent (`Happ`, `v2rayN`, `clash-verge`): what a log line and a group's
/// remembered identity name, never the version or the HWID it may carry.
pub fn agent_family(agent: &str) -> &str {
    agent.split('/').next().unwrap_or_default().trim()
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

/// Remnawave's HWID rule (panel v3.0.0): 10 to 64 of `[a-zA-Z0-9=-]`. A panel ignores any other
/// value as if no HWID had been sent, which on a device-limited plan reads as "not supported".
pub fn is_valid_hwid(hwid: &str) -> bool {
    (10..=64).contains(&hwid.len())
        && hwid
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'=' | b'-'))
}

/// A fresh random HWID in the legacy shape (16 lowercase hex digits, as Android IDs and the old
/// app's hash look): what a panel sees as a new device after the user resets the ID.
pub fn random_hwid() -> String {
    // The last 8 bytes of a v4 UUID: 62 random bits (only the variant bits are fixed).
    hex::encode(&uuid::Uuid::new_v4().as_bytes()[8..])
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

    /// p-subs (Remnawave v3.0.0 HWID rule): the legacy hash and a reset ID pass; other values a
    /// panel would ignore do not.
    #[test]
    fn hwids_follow_the_remnawave_rule() {
        for d in ALL {
            assert!(is_valid_hwid(&legacy_hwid(
                d,
                &id("HOST-1", "alice", "WORKGROUP")
            )));
        }
        let fresh = random_hwid();
        assert!(is_valid_hwid(&fresh), "{fresh}");
        assert_eq!(fresh.len(), 16);
        assert_ne!(fresh, random_hwid());
        assert!(is_valid_hwid("Ab-0=Ab-0="));
        assert!(is_valid_hwid(&"a".repeat(64)));
        for bad in ["short1234", "", "has space1", "under_score1", "кириллица12"] {
            assert!(!is_valid_hwid(bad), "{bad}");
        }
        assert!(!is_valid_hwid(&"a".repeat(65)));
    }

    /// §7.2 "UA format": the Happ agent first, per device, with the current Happ of each OS
    /// (p-live-fix 1b).
    #[test]
    fn happ_agent_comes_first() {
        let hwid = legacy_hwid(ClientDevice::Pc, &id("HOST-1", "alice", "WORKGROUP"));
        assert_eq!(
            user_agents(ClientDevice::Pc, Some(&hwid))[0],
            "Happ/4.7.2/Windows/99c6d48e9a5a5e32"
        );
        let re = regex::Regex::new(
            r"^Happ/(4\.7\.2|4\.10\.1|6\.4\.0)/(Windows|Android|iOS|macOS)/[a-f0-9]{16}$",
        )
        .unwrap();
        let oses: Vec<String> = ALL
            .iter()
            .map(|d| {
                let hwid = legacy_hwid(*d, &MachineIdentity::default());
                let first = user_agents(*d, Some(&hwid)).remove(0);
                let caps = re.captures(&first).unwrap();
                format!("{} {}", &caps[2], &caps[1])
            })
            .collect();
        assert_eq!(
            oses,
            [
                "Windows 4.7.2",
                "Android 4.10.1",
                "iOS 6.4.0",
                "macOS 4.7.2"
            ]
        );
        // The override reaches the User-Agent too (P-38).
        assert_eq!(
            user_agents(ClientDevice::Pc, Some("abc"))[0],
            "Happ/4.7.2/Windows/abc"
        );
    }

    /// ru-2026 item 1: a group that does not send its HWID keeps the Happ agent without it.
    #[test]
    fn happ_agent_without_the_hwid() {
        assert_eq!(user_agents(ClientDevice::Pc, None)[0], "Happ/4.7.2/Windows");
        assert_eq!(user_agents(ClientDevice::Ios, None)[0], "Happ/6.4.0/iOS");
        assert_eq!(
            user_agents(ClientDevice::Pc, None)[1..],
            user_agents(ClientDevice::Pc, Some("h"))[1..]
        );
    }

    /// p-live-fix 1b: then clients whose answers the parser reads, current versions.
    #[test]
    fn agent_lists_per_device_without_repeats() {
        let h = Some("h");
        let tail = [
            "v2rayN/7.25.6",
            "clash-verge/v2.5.10",
            "sing-box/1.14.4",
            "v2RayTun/5.26.83",
        ];
        assert_eq!(user_agents(ClientDevice::Pc, h)[1..], tail);
        assert_eq!(user_agents(ClientDevice::Mac, h)[1..], tail);
        assert_eq!(
            user_agents(ClientDevice::Android, h)[1..],
            [
                "v2RayTun/5.26.83/android",
                "v2rayN/7.25.6",
                "clash-verge/v2.5.10",
                "sing-box/1.14.4",
                "v2RayTun/5.26.83"
            ]
        );
        assert_eq!(user_agents(ClientDevice::Ios, h)[1], "Streisand/1.7.1");
        for d in ALL {
            let mut agents = user_agents(d, h);
            let n = agents.len();
            agents.sort();
            agents.dedup();
            assert_eq!(agents.len(), n, "{d:?}");
        }
    }

    #[test]
    fn families_carry_no_version_or_hwid() {
        assert_eq!(agent_family("Happ/4.7.2/Windows/99c6d48e9a5a5e32"), "Happ");
        assert_eq!(agent_family("clash-verge/v2.5.10"), "clash-verge");
        assert_eq!(agent_family("Streisand"), "Streisand");
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
