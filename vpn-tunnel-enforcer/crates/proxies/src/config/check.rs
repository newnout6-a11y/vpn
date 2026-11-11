//! AT-02-008 (sing-box 1.14 compatibility): every config shape `build` produces passes the real
//! `sing-box check -c stdin` (the bundled 1.14 binary rejects unknown keys and refused
//! combinations; `check` neither listens nor dials). Skipped quietly when the binary is absent.
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use serde_json::{Value, json};
use vpnte_base::types::Creds;
use vpnte_profiles::emit_singbox::{EmitPolicy, emit_singbox};
use vpnte_profiles::model::{Host, Kind, Tls};

use super::tests::{hostname, profile, sample, shadowtls_chain, wireguard};
use super::{build, pin, xray_bridge};

fn sing_box() -> Option<PathBuf> {
    let exe = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../resources/sing-box.exe"
    ));
    exe.is_file().then_some(exe)
}

/// Runs `sing-box check` on `config`; the error carries the engine's message.
fn check(exe: &PathBuf, config: &Value) -> Result<(), String> {
    let mut cmd = Command::new(exe);
    cmd.args(["check", "-c", "stdin", "--disable-color"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    let mut child = cmd.spawn().map_err(|e| e.to_string())?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(config.to_string().as_bytes())
            .map_err(|e| e.to_string())?;
    }
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).into_owned())
    }
}

#[test]
fn every_config_shape_passes_sing_box_check() {
    let Some(exe) = sing_box() else {
        return;
    };
    // Negative control: the checker really rejects what sing-box does not know.
    let mut bogus = build(&sample(), 17990).unwrap();
    bogus["route"]["no_such_option"] = json!(true);
    assert!(check(&exe, &bogus).is_err());
    let ip = "203.0.113.5".parse().unwrap();
    let mut ws = hostname(json!({
        "tls": { "enabled": true },
        "transport": { "type": "ws", "path": "/x" },
    }));
    pin(&mut ws, "vpn.example.test", ip);
    let mut upgrade = hostname(json!({ "transport": { "type": "httpupgrade", "path": "/u" } }));
    pin(&mut upgrade, "vpn.example.test", ip);
    let mut chain = shadowtls_chain();
    pin(&mut chain, "vpn.example.test", ip);
    let mut trojan = profile(
        Host::Domain("vpn.example.test".into()),
        443,
        Kind::Trojan {
            password: "fake-password".into(),
        },
    );
    trojan.tls = Some(Tls::default());
    let mut trojan = emit_singbox(&trojan, super::PROXY_OUT_TAG, &EmitPolicy::default()).unwrap();
    pin(&mut trojan, "vpn.example.test", ip);
    let creds = Creds {
        user: "fake-user".into(),
        pass: "fake-pass".into(),
    };
    let cases = [
        ("vless ip", sample()),
        ("vless ws pinned", ws),
        ("vless httpupgrade pinned", upgrade),
        // Not pinned: sing-box falls back to the system resolver (no DNS block needed).
        ("vless hostname", hostname(json!({}))),
        ("trojan emitted + pinned", trojan),
        ("shadowtls chain pinned", chain),
        ("wireguard endpoint", wireguard(Host::Ip(ip))),
        ("xray bridge", xray_bridge(41234, &creds).unwrap()),
    ];
    for (name, upstream) in cases {
        let config = build(&upstream, 17990).unwrap();
        if let Err(e) = check(&exe, &config) {
            panic!("{name}: sing-box check failed: {e}");
        }
    }
}
