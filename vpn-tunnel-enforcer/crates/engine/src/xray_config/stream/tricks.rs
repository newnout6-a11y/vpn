//! Item 18 on Xray 26.11.9: a key's TLS tricks as `streamSettings.finalmask.tcp` `fragment`.
//! The freedom outbound's `fragment` is deprecated there (it prints "use
//! streamSettings.finalmask.tcp") and would cut every direct connection's hello as well.
use serde_json::{Value, json};
use vpnte_profiles::model::{HelloSplit, Profile, Span, Tls, TlsTricks};

/// `finalmask` for a TCP stream under TLS; `None` when the key runs without tricks. The app's
/// default needs the caller's stealth flag, which `translate` does not get: the tunnel resolves
/// it into the profile first ([`Profile::tls_tricks_for`]).
///
/// Xray's `fragment` mask: `packets: "tlshello"` cuts the hello into TLS records of `length`
/// bytes, each written `delay` ms after the last (`delay` 0: all records in one write, so a
/// record split only); numeric packets (`"1-1"`) cut the first write, the hello, into raw TCP
/// pieces. Never REALITY (as on sing-box: `tls_tricks_for` gives it none); XHTTP over HTTP/3
/// dials QUIC, where TCP masks mean nothing.
pub(super) fn finalmask(p: &Profile, tls: &Tls, network: &str) -> Option<Value> {
    let h3 = matches!(tls.alpn.as_slice(), [only] if only.eq_ignore_ascii_case("h3"));
    if network == "xhttp" && h3 {
        return None;
    }
    let (packets, split) = match p.tls_tricks_for(false) {
        TlsTricks::Off => return None,
        TlsTricks::Record => (
            "tlshello",
            HelloSplit {
                interval_ms: Span::new(0, 0),
                ..HelloSplit::PRESET
            },
        ),
        TlsTricks::Hello(split) => ("1-1", split),
        TlsTricks::Both(split) => ("tlshello", split),
    };
    let settings = json!({
        "packets": packets,
        "length": split.len.to_string(),
        "delay": split.interval_ms.to_string(),
    });
    Some(json!({ "tcp": [{ "type": "fragment", "settings": settings }] }))
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::process::{Command, Stdio};

    use serde_json::{Value, json};
    use vpnte_base::types::{ClientDevice, Creds};
    use vpnte_profiles::uri::parse_uri;

    use crate::slot::SlotEndpoint;
    use crate::test_support::{hidden, xray_exe};
    use crate::xray_config::{build_config, proxy_graph};

    const ID: &str = "00000000-0000-4000-8000-000000000001";
    /// Public sample key from the sing-box docs (not a credential).
    const PBK: &str = "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0";

    /// The slot config Xray would get for `link`.
    fn slot_config(link: &str) -> Value {
        let p = parse_uri(link).unwrap_or_else(|e| panic!("{link}: {e:?}"));
        let graph = proxy_graph(&p, ClientDevice::Pc).unwrap_or_else(|e| panic!("{link}: {e}"));
        let creds = Creds {
            user: "slot-user".into(),
            pass: "slot-password".into(),
        };
        let ep = SlotEndpoint::new(20090, creds).expect("endpoint");
        build_config(&graph, &ep)
    }

    fn mask(config: &Value) -> &Value {
        &config["outbounds"][0]["streamSettings"]["finalmask"]
    }

    /// `xray run -test` output when Xray accepted the config, else the panic with its output.
    fn xray_test(config: &Value) -> Option<String> {
        let exe = xray_exe()?;
        // No console of its own: other tests detach this process from its console, and a
        // console child would then open a window and lose its output.
        let mut child = hidden(Command::new(exe).args(["run", "-test", "-config", "stdin:"]))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("xray starts");
        let mut stdin = child.stdin.take().expect("stdin");
        stdin
            .write_all(config.to_string().as_bytes())
            .expect("config written");
        drop(stdin);
        let out = child.wait_with_output().expect("xray ends");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(text.contains("Configuration OK."), "{text}\n{config:#}");
        Some(text)
    }

    /// Item 18: every TCP stream under TLS carries the key's tricks as a finalmask fragment that
    /// the bundled Xray accepts without a deprecation; REALITY and XHTTP over HTTP/3 do not.
    #[test]
    fn tricks_reach_finalmask_and_pass_xray_test() {
        let fragment = |packets: &str, length: &str, delay: &str| {
            json!({ "tcp": [{ "type": "fragment",
                "settings": { "packets": packets, "length": length, "delay": delay } }] })
        };
        let base = format!("vless://{ID}@nl.example:443?security=tls&sni=nl.example");
        let reality = format!(
            "vless://{ID}@nl.example:443?security=reality&pbk={PBK}&sid=1234&sni=www.example.com&flow=xtls-rprx-vision"
        );
        let cases = [
            (
                format!("{base}&fragment=tlshello,100-200,10-20#both"),
                fragment("tlshello", "100-200", "10-20"),
            ),
            (
                format!("{base}&type=tcp&fragment=1,40-60,30-50#hello"),
                fragment("1-1", "40-60", "30-50"),
            ),
            (
                "trojan://fake-pass@nl.example:443?security=tls&type=ws&path=/ws&host=cdn.example&fragment=tlshello,100-200,0#record".into(),
                fragment("tlshello", "100-200", "0"),
            ),
            (
                format!("{base}&type=xhttp&path=/x&fragment=tlshello,150,15#xhttp"),
                fragment("tlshello", "150", "15"),
            ),
            (
                format!("{base}&type=grpc&serviceName=svc&fgsize=100-200&fgsleep=10-20#grpc"),
                fragment("1-1", "100-200", "10-20"),
            ),
        ];
        for (link, expected) in cases {
            let config = slot_config(&link);
            assert_eq!(mask(&config), &expected, "{link}");
            // ws and Trojan draw their own deprecation notes on 26.11.9; none may be ours.
            if let Some(out) = xray_test(&config) {
                let ours = |line: &&str| line.contains("deprecated") && line.contains("fragment");
                assert!(!out.lines().any(|line| ours(&line)), "{out}");
            }
        }
        // REALITY never (review a4 / b1, as sing-box): its hello names a camouflage site.
        let untouched = [
            format!("{base}&type=xhttp&alpn=h3&path=/x&fragment=tlshello,100-200,10-20#h3"),
            format!("{reality}&fragment=1,40-60,30-50#reality"),
            format!("{base}#none"),
        ];
        for link in untouched {
            let config = slot_config(&link);
            assert_eq!(mask(&config), &Value::Null, "{link}");
            xray_test(&config);
        }
    }

    /// Why finalmask: Xray 26.11.9 still reads the freedom `fragment` (checked here) but marks it
    /// deprecated in favour of `streamSettings.finalmask.tcp` (its source at tag v26.11.9). The
    /// deprecation line itself is not asserted: Xray prints it from its log goroutine, and in CI
    /// `run -test` exits before it shows (5 runs out of 5 on 4af7b12), so it proves nothing here.
    #[test]
    fn freedom_fragment_is_still_read_here() {
        let config = json!({ "outbounds": [{ "protocol": "freedom", "settings": {
            "fragment": { "packets": "tlshello", "length": "100-200", "interval": "10-20" } } }] });
        // `xray_test` asserts «Configuration OK.»; `None` = no bundled Xray here.
        xray_test(&config);
    }

    /// A key with tricks of its own keeps them on Xray: no "stealth does not apply" warning,
    /// and pasted trick keys are not "lost sing-box options"; without them both stay.
    #[test]
    fn own_tricks_silence_the_stealth_warning() {
        let keys = |link: &str| {
            let p = parse_uri(link).expect("link");
            crate::xray_config::warnings(&p, true)
                .into_iter()
                .map(|m| m.key)
                .collect::<Vec<_>>()
        };
        let base = format!("vless://{ID}@nl.example:443?security=tls&sni=nl.example");
        assert!(keys(&format!("{base}&fragment=tlshello,100-200,10-20#own")).is_empty());
        assert_eq!(
            keys(&format!("{base}#default")),
            ["engine.xray.warn.stealth"]
        );
        let mut pasted = parse_uri(&format!("{base}#pasted")).expect("link");
        pasted
            .singbox_extra
            .insert("tls.record_fragment".into(), json!(true));
        // Pasted keys add to the default: until the caller resolves it, stealth is not whole.
        let msgs = crate::xray_config::warnings(&pasted, true);
        assert_eq!(msgs.len(), 1, "{msgs:?}");
        assert_eq!(msgs[0].key, "engine.xray.warn.stealth");
        let mut resolved = pasted.clone();
        resolved.tls.as_mut().expect("tls").tricks = Some(pasted.tls_tricks_for(true));
        let msgs = crate::xray_config::warnings(&resolved, true);
        assert!(msgs.is_empty(), "{msgs:?}");
        assert_eq!(
            mask(&build_config(
                &proxy_graph(&pasted, ClientDevice::Pc).expect("graph"),
                &SlotEndpoint::new(
                    20091,
                    Creds {
                        user: "u".into(),
                        pass: "p".into()
                    }
                )
                .expect("endpoint"),
            ))["tcp"][0]["settings"]["packets"],
            "tlshello"
        );
    }

    /// Xray applies pasted trick keys, so the "lost sing-box options" text names none (review a6).
    #[test]
    fn lost_options_text_names_no_fragmentation() {
        let texts = [
            include_str!("../../../locales/engine-xray-config.en.json"),
            include_str!("../../../locales/engine-xray-config.ru.json"),
        ];
        for json in texts {
            let text = &crate::test_locales::flatten(json)["engine.xray.warn.singboxExtra"];
            let lower = text.to_lowercase();
            assert!(
                !lower.contains("fragment") && !lower.contains("фрагмент"),
                "{text}"
            );
        }
    }
}
