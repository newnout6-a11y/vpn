use super::redaction::{Policy, Redactor, USER};

/// Forensics-policy text through a fresh redactor.
fn forensic(s: &str) -> String {
    Redactor::new(None).text(s, Policy::Forensics)
}

/// The `ip_xxxxxxxx` pseudonyms in a text, in order.
fn pseudonyms(s: &str) -> Vec<String> {
    let re = regex::Regex::new(r"ip_[0-9a-f]{8}").unwrap();
    re.find_iter(s).map(|m| m.as_str().to_string()).collect()
}

/// FR vectors, IP part. Changed by the app's one policy (vpnte_core::redact): public addresses
/// become the logger's `ip_xxxxxxxx` pseudonyms (same in logs and forensics), private,
/// CGNAT, link-local and ULA addresses are kept as they are.
#[test]
fn ip_pseudonyms_are_stable_and_keep_the_class() {
    let out = forensic("connect to 203.0.113.7:443");
    assert!(!out.contains("203.0.113.7"), "{out}");
    assert!(out.contains(":443"));
    let mut r = Redactor::new(None);
    let a = r.text("a.example.com -> 203.0.113.7", Policy::Forensics);
    let b = r.text("flow 203.0.113.7:443 reset", Policy::Forensics);
    assert_eq!(pseudonyms(&a), pseudonyms(&b));
    let two = pseudonyms(&forensic("203.0.113.7 talked to 198.51.100.9"));
    assert_eq!(two.len(), 2);
    assert_ne!(two[0], two[1]);
    let mixed = forensic("10.0.0.5 192.168.1.1 172.16.3.4 100.64.0.1 169.254.1.2 8.8.8.8");
    assert!(mixed.starts_with("10.0.0.5 192.168.1.1 172.16.3.4 100.64.0.1 169.254.1.2 ip_"));
    let v6 = forensic("remote 2001:db8::dead:beef port 443");
    assert!(
        !v6.contains("dead:beef") && pseudonyms(&v6).len() == 1,
        "{v6}"
    );
    // IPv4-mapped IPv6 is the same address (B-18): same pseudonym, no octets left.
    let mapped = forensic("::ffff:203.0.113.77 and 203.0.113.77");
    let p = pseudonyms(&mapped);
    assert_eq!(p.len(), 2, "{mapped}");
    assert_eq!(p[0], p[1]);
    assert!(!mapped.contains("113.77"));
}

/// Loopback, the own TUN, private v6, versions, `localhost` and artefact file names pass through.
#[test]
fn constants_pass_through() {
    for s in [
        "proxy on 127.0.0.1:10808, bound 0.0.0.0",
        "gw 192.168.250.253 resolver 192.168.250.254",
        "sing-box version 1.9.3 build ok",
        "bound ::1",
        "fe80::1%eth0 and fd00::abcd",
        "via localhost and localhost.localdomain",
        "missing expected artifact: wfp-state.xml, summary.json, pktmon-trace.txt",
        "events.prev.ndjson pktmon.etl svchost.exe",
    ] {
        assert_eq!(forensic(s), s);
    }
}

/// MACs: the app policy masks them by type (`<redacted-mac>`, case-insensitive, both separators).
#[test]
fn macs_are_masked() {
    let out = forensic("nic aa:bb:cc:dd:ee:ff peer 00-11-22-33-44-55");
    assert_eq!(out, "nic <redacted-mac> peer <redacted-mac>");
    assert_eq!(forensic("AA:BB:CC:DD:EE:FF"), "<redacted-mac>");
}

/// FR host vectors: registrable domain tokens shared by subdomains, public suffix kept, depth
/// as `<subK>`; ICANN-only suffixes (s3.amazonaws.com → .com), unknown TLDs as one label,
/// public suffixes themselves as `<host-N>`.
#[test]
fn host_pseudonyms() {
    let out = forensic("query for secret-service.example.com");
    assert_eq!(out, "query for <sub1>.<domain-1>.com");
    let out = forensic("gosuslugi.ru and foreign.com");
    assert_eq!(out, "<domain-1>.ru and <domain-2>.com");
    let out = forensic("a.example.com b.example.com other.net");
    assert_eq!(
        out,
        "<sub1>.<domain-1>.com <sub1>.<domain-1>.com <domain-2>.net"
    );
    assert_eq!(forensic("deep.cdn.example.com"), "<sub2>.<domain-1>.com");
    assert_eq!(
        forensic("server.internal-corp-tld"),
        "<domain-1>.internal-corp-tld"
    );
    assert_eq!(forensic("s3.amazonaws.com"), "<sub1>.<domain-1>.com");
    assert_eq!(forensic("printer.corp"), "<domain-1>.corp");
    assert_eq!(forensic("co.uk"), "<host-1>");
    // New vectors (B-18): `.md` is a ccTLD, Unicode names are hosts too.
    assert_eq!(forensic("site.md"), "<domain-1>.md");
    assert_eq!(forensic("пример.рф"), "<domain-1>.рф");
    assert_eq!(
        forensic("Пример.РФ и www.пример.рф"),
        "<domain-1>.РФ и <sub1>.<domain-1>.рф"
    );
}

/// Tokens live in one redactor: two exports never share a table; counts per archive.
#[test]
fn host_tables_are_per_redactor() {
    let mut a = Redactor::new(None);
    let mut b = Redactor::new(None);
    assert_eq!(a.text("x.org", Policy::Forensics), "<domain-1>.org");
    assert_eq!(a.text("y.org", Policy::Forensics), "<domain-2>.org");
    assert_eq!(b.text("y.org", Policy::Forensics), "<domain-1>.org");
    let mut s = Redactor::new(None);
    s.text(
        "203.0.113.7 203.0.113.7 198.51.100.9 a.example.com b.example.com",
        Policy::Forensics,
    );
    assert_eq!(s.hosts_replaced(), 1);
    let mut z = Redactor::new(None);
    z.text("127.0.0.1 ::1 192.168.250.254 localhost", Policy::Forensics);
    assert_eq!(z.hosts_replaced(), 0);
    // Other policies never pseudonymize hosts.
    assert_eq!(z.text("a.example.com", Policy::Data), "a.example.com");
    assert_eq!(z.text("a.example.com", Policy::Log), "a.example.com");
}

/// New vectors (B-18): user names in escaped, NT and account forms.
#[test]
fn user_names_are_masked() {
    let mut r = Redactor::new(Some("alice"));
    for policy in [Policy::Data, Policy::Forensics, Policy::Log, Policy::Config] {
        let out = r.text(r#""path":"C:\\Users\\alice\\AppData""#, policy);
        assert!(!out.contains("alice"), "{out}");
        let out = r.text(r"\device\harddiskvolume3\users\alice\app.exe", policy);
        assert_eq!(
            out,
            format!(r"\device\harddiskvolume3\users\{USER}\app.exe")
        );
        assert_eq!(
            r.text(r"DESKTOP-1\Alice", policy),
            format!(r"DESKTOP-1\{USER}")
        );
    }
    // Names shorter than 3 characters are not masked literally (too many false hits).
    assert_eq!(Redactor::new(Some("al")).text("al", Policy::Data), "al");
    // An account literally named "User" (a common default) masks once, not `<<user>>`.
    let out = Redactor::new(Some("User")).text(r"\device\hdv3\users\User\x", Policy::Data);
    assert_eq!(out, format!(r"\device\hdv3\users\{USER}\x"));
}

/// JSON: keys never change, numbers and booleans stay, string values are redacted; NDJSON lines
/// are walked, a truncated line is scrubbed as text (FR:219-265).
#[test]
fn json_and_ndjson() {
    let mut r = Redactor::new(None);
    let mut v = serde_json::json!({"remoteAddress":"203.0.113.7","remotePort":443,
        "queryName":"tracker.example.org","verdict":false});
    r.json(&mut v, Policy::Forensics);
    let keys: Vec<&String> = v.as_object().unwrap().keys().collect();
    assert_eq!(
        keys,
        ["remoteAddress", "remotePort", "queryName", "verdict"]
    );
    assert!(v["remoteAddress"].as_str().unwrap().starts_with("ip_"));
    assert_eq!(v["remotePort"], 443);
    assert_eq!(v["verdict"], false);
    assert_eq!(v["queryName"], "<sub1>.<domain-1>.org");
    let line = r.ndjson_line(r#"{"ts":1,"peer":"203.0.113.7"}"#, Policy::Forensics);
    let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(parsed["ts"], 1);
    assert_eq!(parsed["peer"], v["remoteAddress"]);
    let torn = r.ndjson_line(r#"{"ts":2,"peer":"198.51.100.9"#, Policy::Forensics);
    assert!(!torn.contains("198.51.100.9"), "{torn}");
    // Secret-named keys are masked in every policy; the broad config key rule only for configs
    // (B-19: addresses in snapshots and diagnostics stay readable).
    let mut data =
        serde_json::json!({"password":"FAKE-SECRET","address":"10.0.0.1","owner":"VPNTE"});
    let mut config = data.clone();
    r.json(&mut data, Policy::Data);
    assert_eq!(
        data,
        serde_json::json!({"password":"<redacted>","address":"10.0.0.1","owner":"VPNTE"})
    );
    r.json(&mut config, Policy::Config);
    assert_eq!(config["address"], "<redacted>");
}

/// VP secret vectors through every policy.
#[test]
fn secrets_are_scrubbed() {
    let key = "A".repeat(20) + &"b".repeat(20) + "123=";
    let cases = [
        ("password=FAKE-SECRET", "<redacted-credential>"),
        ("Bearer abc.def", "Bearer <redacted-token>"),
        (key.as_str(), "<redacted-key>"),
        (
            "vless://11111111-1111-4111-8111-111111111111@h:443",
            "<redacted-vpn-uri>",
        ),
        ("https://example.com/sub/xyz", "<redacted-url>"),
        (r"C:\Users\alice\x", "<redacted-user-path>"),
        ("11111111-1111-4111-8111-111111111111", "<redacted-uuid>"),
    ];
    for policy in [Policy::Data, Policy::Config, Policy::Log, Policy::Forensics] {
        for (input, expected) in &cases {
            let out = Redactor::new(None).text(input, policy);
            assert!(out.contains(expected), "{policy:?} {input} -> {out}");
            assert!(
                !out.contains("FAKE-SECRET") && !out.contains("alice"),
                "{out}"
            );
        }
    }
}

/// Snapshot selection (DX:270-312): 2 h window after the last app start, ≤ 40, else newest 12,
/// oldest first; name time wins over mtime.
#[test]
fn snapshot_selection() {
    use super::build::select_snapshots;
    let at = |s: &str| s.parse::<jiff::Timestamp>().unwrap().as_millisecond();
    let now = at("2026-11-11T12:00:00Z");
    let files = vec![
        (
            "snapshot-2026-11-11T08-00-00-000Z-old.json".to_string(),
            None,
        ),
        (
            "snapshot-2026-11-11T10-30-00-000Z-app-start.json".to_string(),
            None,
        ),
        (
            "snapshot-2026-11-11T10-00-00-000Z-before-start.json".to_string(),
            None,
        ),
        (
            "snapshot-2026-11-11T11-00-00-000Z-manual.json".to_string(),
            Some(0),
        ),
        ("custom.json".to_string(), Some(at("2026-11-11T11:30:00Z"))),
    ];
    assert_eq!(
        select_snapshots(&files, now),
        [
            "snapshot-2026-11-11T10-30-00-000Z-app-start.json",
            "snapshot-2026-11-11T11-00-00-000Z-manual.json",
            "custom.json",
        ]
    );
    // Nothing recent: the newest 12, oldest first.
    let old: Vec<(String, Option<i64>)> = (0..20)
        .map(|i| {
            (
                format!("s{i:02}.json"),
                Some(at("2026-11-01T00:00:00Z") + i),
            )
        })
        .collect();
    let picked = select_snapshots(&old, now);
    assert_eq!(picked.len(), 12);
    assert_eq!(picked.first().unwrap(), "s08.json");
    assert_eq!(picked.last().unwrap(), "s19.json");
    let many: Vec<(String, Option<i64>)> = (0..50)
        .map(|i| (format!("m{i:02}.json"), Some(now - 1000 * i)))
        .collect();
    assert_eq!(select_snapshots(&many, now).len(), 40);
}

#[test]
fn default_file_name_format() {
    let ms = "2026-11-11T07:20:30.123Z"
        .parse::<jiff::Timestamp>()
        .unwrap()
        .as_millisecond();
    assert_eq!(
        super::default_file_name(ms),
        "vpn-tunnel-enforcer-diagnostics-2026-11-11T07-20-30-123Z.zip"
    );
}

mod archive {
    use std::io::Read;
    use std::path::Path;
    use std::sync::Arc;

    use serde_json::{Value, json};
    use tokio::sync::watch;
    use tokio_util::sync::CancellationToken;
    use vpnte_base::{AppResult, ErrorKind};

    use super::super::build;
    use super::super::{
        ExportInputs, ExportProgress, ExportResult, RecoveryArtifact, RecoveryRead,
    };
    use super::pseudonyms;
    use crate::capture::{Capture, CaptureConfig, WindowsSystem};
    use crate::test_support::TempDir;

    /// Every entry of a ZIP as `(name, text)`.
    pub(super) fn read_zip(path: &Path) -> Vec<(String, String)> {
        let mut zip = zip::ZipArchive::new(std::fs::File::open(path).unwrap()).unwrap();
        (0..zip.len())
            .map(|i| {
                let mut entry = zip.by_index(i).unwrap();
                let mut text = String::new();
                entry.read_to_string(&mut text).unwrap();
                (entry.name().unwrap().to_string(), text)
            })
            .collect()
    }

    pub(super) fn entry<'a>(entries: &'a [(String, String)], name: &str) -> &'a str {
        let found = entries.iter().find(|(n, _)| n == name);
        &found.unwrap_or_else(|| panic!("no entry {name}")).1
    }

    pub(super) fn partials(dir: &Path) -> usize {
        std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".partial"))
            .count()
    }

    fn capture_at(root: &Path) -> Capture {
        let cfg = watch::channel(CaptureConfig::default()).1;
        Capture::new(root.to_path_buf(), cfg, Arc::new(WindowsSystem))
    }

    fn build_into(dest: &Path, inputs: ExportInputs) -> AppResult<ExportResult> {
        let progress = watch::channel(ExportProgress::default()).0;
        let token = CancellationToken::new();
        let (partial, result) = build::write(dest, inputs, None, progress, None, token)?;
        partial.commit(dest)?;
        Ok(result)
    }

    const ID: &str = "2026-11-11T07-20-30-123Z";

    /// A stopped session with DNS / socket / cache artefacts, raw captures and a binary file.
    fn forensic_root(tag: &str) -> TempDir {
        let root = TempDir::new(tag);
        let dir = root.path().join("sessions").join(ID);
        std::fs::create_dir_all(&dir).unwrap();
        let manifest = json!({"schemaVersion":2,"appVersion":"2.0.0","sessionId":ID,"running":false,
            "engine":"pktmon","startedAt":1,"stoppedAt":2,"maxSizeMb":512,"stopReason":"vpn-stop",
            "pktmon":{"state":"stopped"},"etw":{"state":"stopped"}});
        std::fs::write(dir.join("session-manifest.json"), manifest.to_string()).unwrap();
        let events = format!(
            "{}\n\n{}\n",
            json!({"category":"dns","queryName":"private-tracker.example.com","remoteAddress":"93.184.216.34"}),
            json!({"category":"tcp","remoteAddress":"93.184.216.34","remotePort":443,"reason":"reset-observed"})
        );
        std::fs::write(dir.join("events.ndjson"), events).unwrap();
        let sockets = json!({"takenAt":1,"sockets":[{"transport":"tcp","local":"192.168.1.20:50123",
            "remote":"93.184.216.34:443","pid":4242,"image":"chrome.exe"}]});
        std::fs::write(dir.join("sockets-stop.json"), sockets.to_string()).unwrap();
        std::fs::write(
            dir.join("dns-cache.txt"),
            "Entry: private-tracker.example.com  Data: 93.184.216.34\r\nEntry: bank.ru  Data: 77.88.55.66\r\n",
        )
        .unwrap();
        for raw in ["pktmon.etl", "pktmon.pcapng", "pktmon-trace.txt"] {
            std::fs::write(dir.join(raw), "raw payload 93.184.216.34").unwrap();
        }
        let mut bin = b"peer 93.184.216.34 ".to_vec();
        bin.extend_from_slice(&[0xff, 0xfe, 0x00, 0x81]);
        std::fs::write(dir.join("future-artifact.bin"), bin).unwrap();
        std::fs::write(dir.join("broken.json"), "{ this is not json 203.0.113.7").unwrap();
        root
    }

    /// Staged-forensics vectors ('pseudonymizes staged forensics artifacts…', 'never exports raw
    /// packet captures…', 'never copies bytes through verbatim…'; AT-08-010 fail-closed,
    /// AT-00-003: nothing is written into the retained session).
    #[test]
    fn forensics_are_pseudonymized_and_captures_excluded() {
        let root = forensic_root("exp-fx");
        let out = TempDir::new("exp-fx-out");
        let dest = out.path().join("diag.zip");
        let session_dir = root.path().join("sessions").join(ID);
        let before = crate::capture::store::list_artifacts(&session_dir);
        let inputs = ExportInputs {
            app_version: "2.0.0".into(),
            capture: Some(capture_at(root.path())),
            ..Default::default()
        };
        let result = build_into(&dest, inputs).unwrap();
        let entries = read_zip(&dest);
        let all: String = entries.iter().map(|(n, t)| format!("{n}\n{t}\n")).collect();
        for leaked in [
            "93.184.216.34",
            "private-tracker",
            "77.88.55.66",
            "bank.ru",
            "203.0.113.7",
        ] {
            assert!(!all.contains(leaked), "{leaked} leaked");
        }
        let base = format!("traffic-forensics/sessions/{ID}/");
        let file = |name: &str| entry(&entries, &format!("{base}{name}")).to_string();
        let cache = file("dns-cache.txt");
        assert_eq!(cache.lines().count(), 2);
        assert!(!cache.contains('\r'));
        assert!(cache.contains("<sub1>.<domain-1>.com"), "{cache}");
        assert!(cache.contains("<domain-2>.ru"), "{cache}");
        let ip = pseudonyms(&cache)[0].clone();
        assert!(pseudonyms(&file("events.ndjson")).iter().all(|p| *p == ip));
        assert_eq!(pseudonyms(&file("sockets-stop.json")), [ip]);
        let events = file("events.ndjson");
        let lines: Vec<&str> = events.split('\n').collect();
        assert_eq!(lines.len(), 4, "{events}");
        assert_eq!(lines[1], "");
        let first: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["queryName"], "<sub1>.<domain-1>.com");
        assert!(file("broken.json").contains("ip_"));
        let redaction = entry(&entries, "traffic-forensics/REDACTION.txt");
        assert!(redaction.contains("ip_") && redaction.contains("*.etl"));
        assert!(redaction.contains("Сохранены как есть"));
        // Raw captures and the binary never enter the archive; the binary gets a note.
        for raw in [
            "pktmon.etl",
            "pktmon.pcapng",
            "pktmon-trace.txt",
            "future-artifact.bin",
        ] {
            assert!(
                entries.iter().all(|(n, _)| *n != format!("{base}{raw}")),
                "{raw}"
            );
        }
        assert!(file("future-artifact.bin.excluded.txt").contains("not-utf8"));
        assert_eq!(result.excluded.len(), 4);
        assert_eq!(result.forensics_session.as_deref(), Some(ID));
        let summary: Value = serde_json::from_str(&file("summary.json")).unwrap();
        assert_eq!(summary["schemaVersion"], 2);
        assert_eq!(summary["sessionId"], ID);
        let latest = entry(&entries, "traffic-forensics/latest-session.json");
        let latest: Value = serde_json::from_str(latest).unwrap();
        assert_eq!(latest["sessionId"], ID);
        let manifest = entry(&entries, "diagnostics-manifest.json");
        let manifest: Value = serde_json::from_str(manifest).unwrap();
        assert_eq!(manifest["excluded"].as_array().unwrap().len(), 4);
        // The local session keeps its real data and gains nothing.
        assert_eq!(crate::capture::store::list_artifacts(&session_dir), before);
        let local = std::fs::read_to_string(session_dir.join("dns-cache.txt")).unwrap();
        assert!(local.contains("bank.ru"));
    }

    /// AT-01-002 (`diagnosticsExportRedaction.test.ts`): recovery documents, settings, engine
    /// configs and logs are scrubbed; addresses in diagnostics stay (B-19).
    #[test]
    fn recovery_settings_runtime_and_logs_are_scrubbed() {
        let tmp = TempDir::new("exp-rec");
        let logs = tmp.path().join("logs");
        std::fs::create_dir_all(&logs).unwrap();
        let log = "argv contained password=FAKE-SECRET\n";
        std::fs::write(logs.join("sing-box.log"), log).unwrap();
        std::fs::write(logs.join("app.log"), "{\"msg\":\"started\"}\n").unwrap();
        let mut settings = vpnte_core::settings::Settings::default();
        let proxy = "socks5://user:FAKE-SECRET@203.0.113.5:1080";
        let proxy = vpnte_core::settings::ProxyOverride::parse(proxy).unwrap().0;
        settings.proxy_override = Some(proxy);
        let config = json!({"outbounds":[{"server":"203.0.113.5","password":"FAKE-SECRET"}]});
        let inputs = ExportInputs {
            app_version: "2.0.0".into(),
            settings,
            logs_dir: Some(logs),
            system_diagnostics: Some(json!({"dns":["192.168.1.1"],"token":"FAKE-SECRET"})),
            engine_configs: vec![("sing-box".into(), config)],
            recovery: vec![RecoveryArtifact {
                artifact: "firewall.json".into(),
                file: "killswitch-manifest.json".into(),
                read: RecoveryRead::Trusted(json!({"password":"FAKE-SECRET","owner":"VPNTE"})),
            }],
            ..Default::default()
        };
        let dest = tmp.path().join("diag.zip");
        build_into(&dest, inputs).unwrap();
        let entries = read_zip(&dest);
        assert!(
            entries.iter().all(|(_, t)| !t.contains("FAKE-SECRET")),
            "secret leaked"
        );
        let ks = entry(&entries, "killswitch-manifest.json");
        assert!(ks.contains("<redacted>") && ks.contains("VPNTE"));
        let status = entry(&entries, "recovery-artifacts-status.json");
        let status: Value = serde_json::from_str(status).unwrap();
        let expected = json!([{"artifact":"firewall.json","status":"trusted-and-redacted"}]);
        assert_eq!(status, expected);
        let s: Value = serde_json::from_str(entry(&entries, "settings.json")).unwrap();
        assert_eq!(s["proxyOverride"]["host"], "<redacted>");
        assert_eq!(s["proxyOverride"]["credentials"], "<redacted>");
        assert!(s.get("logKey").is_none());
        let rt: Value = serde_json::from_str(entry(&entries, "runtime-sing-box.json")).unwrap();
        assert_eq!(rt["outbounds"][0]["server"], "<redacted>");
        assert!(entry(&entries, "runtime-sing-box.log").contains("<redacted-credential>"));
        let app_log: Value = serde_json::from_str(entry(&entries, "app-log.json")).unwrap();
        let files = app_log["files"].as_array().unwrap();
        let names: Vec<&str> = files.iter().map(|f| f["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["app.log", "sing-box.log"]);
        let diag = entry(&entries, "system-diagnostics.json");
        let diag: Value = serde_json::from_str(diag).unwrap();
        assert_eq!(diag, json!({"dns":["192.168.1.1"],"token":"<redacted>"}));
        let info: Value = serde_json::from_str(entry(&entries, "system-info.json")).unwrap();
        assert_eq!(info["appVersion"], "2.0.0");
        assert!(info["cpuCount"].as_u64().is_some());
        let manifest = entry(&entries, "diagnostics-manifest.json");
        let manifest: Value = serde_json::from_str(manifest).unwrap();
        assert_eq!(manifest["schemaVersion"], 3);
        let forensics = &manifest["redaction"]["trafficForensics"];
        assert_eq!(forensics, "not included in this bundle");
        let listed = manifest["entries"].as_array().unwrap();
        assert!(listed.iter().any(|e| e == "README.txt"));
        assert!(listed.iter().all(|e| e != "diagnostics-manifest.json"));
        assert!(entry(&entries, "README.txt").starts_with("Диагностика VPN Tunnel Enforcer"));
    }

    /// AT-01-002, failing reader: nothing of an untrusted document is exported, only its status.
    #[test]
    fn untrusted_recovery_documents_are_only_listed() {
        let tmp = TempDir::new("exp-untrusted");
        let names = [
            "latest-tun-network-baseline.json",
            "firewall.json",
            "recovery-result.json",
        ];
        let recovery = names
            .iter()
            .enumerate()
            .map(|(i, name)| RecoveryArtifact {
                artifact: (*name).into(),
                file: format!("doc-{i}.json"),
                read: if i == 0 {
                    RecoveryRead::Untrusted
                } else {
                    RecoveryRead::Absent
                },
            })
            .collect();
        let dest = tmp.path().join("diag.zip");
        let inputs = ExportInputs {
            recovery,
            ..Default::default()
        };
        build_into(&dest, inputs).unwrap();
        let entries = read_zip(&dest);
        assert!(entries.iter().all(|(n, _)| !n.starts_with("doc-")));
        let status = entry(&entries, "recovery-artifacts-status.json");
        let status: Value = serde_json::from_str(status).unwrap();
        let first = json!({"artifact":"latest-tun-network-baseline.json",
                           "status":"unavailable-or-untrusted"});
        assert_eq!(status[0], first);
        assert_eq!(status[1]["status"], "absent");
        assert_eq!(status[2]["status"], "absent");
    }

    /// A cancelled build removes its partial file and leaves the destination as it was.
    #[test]
    fn cancelled_build_leaves_the_destination() {
        let tmp = TempDir::new("exp-cancel");
        let dest = tmp.path().join("diag.zip");
        std::fs::write(&dest, "old archive").unwrap();
        let token = CancellationToken::new();
        token.cancel();
        let progress = watch::channel(ExportProgress::default()).0;
        let inputs = ExportInputs::default();
        let err = build::write(&dest, inputs, None, progress, None, token).err();
        assert_eq!(err.map(|e| e.kind), Some(ErrorKind::Cancelled));
        assert_eq!(std::fs::read_to_string(&dest).unwrap(), "old archive");
        assert_eq!(partials(tmp.path()), 0);
        // A destination directory that does not exist fails before anything is written.
        let missing = tmp.path().join("no-such-dir").join("diag.zip");
        assert!(build_into(&missing, ExportInputs::default()).is_err());
        assert!(!missing.exists());
    }
}

mod ops {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use tokio::sync::watch;
    use vpnte_base::types::Notice;
    use vpnte_base::{ErrorKind, Msg};
    use vpnte_core::ops::{OpStatus, OperationRegistry, Source};

    use super::super::archive::Partial;
    use super::super::{
        ExportInputs, ExportProgress, ExportRequest, ExportStage, NoticeSink, RESOURCE, export,
    };
    use super::archive::{partials, read_zip};
    use crate::test_support::TempDir;

    fn request(
        dest: &std::path::Path,
        inputs: ExportInputs,
    ) -> (ExportRequest, watch::Receiver<ExportProgress>) {
        let (progress, rx) = watch::channel(ExportProgress::default());
        let req = ExportRequest {
            dest: dest.to_path_buf(),
            inputs,
            source: Source::Ui,
            progress,
            notices: None,
        };
        (req, rx)
    }

    /// AT-00-003 success path: the archive replaces the destination whole, progress reaches the
    /// last stage, no partial file remains.
    #[tokio::test]
    async fn export_commits_the_archive() {
        let tmp = TempDir::new("exp-ok");
        let dest = tmp.path().join("diag.zip");
        std::fs::write(&dest, "old archive").unwrap();
        let ops = OperationRegistry::new();
        let inputs = ExportInputs {
            app_version: "2.0.0".into(),
            ..Default::default()
        };
        let (req, rx) = request(&dest, inputs);
        let result = export(&ops, req).await.unwrap();
        assert_eq!(result.path, dest);
        let entries = read_zip(&dest);
        assert_eq!(result.entries, entries.len());
        for name in [
            "settings.json",
            "system-info.json",
            "README.txt",
            "diagnostics-manifest.json",
        ] {
            assert!(entries.iter().any(|(n, _)| n == name), "{name}");
        }
        let progress = *rx.borrow();
        assert_eq!(progress.stage, ExportStage::Finishing);
        assert_eq!(progress.entries as usize, entries.len());
        assert!(progress.bytes > 0);
        assert_eq!(partials(tmp.path()), 0);
        let saved = Msg::new("forensics.export.saved").arg("name", "diag.zip");
        assert_eq!(result.saved_msg(), saved);
        assert!(!ops.is_busy(RESOURCE));
    }

    /// AT-00-004 / AT-00-005: a second export while one runs is a conflict; cancelling through
    /// the registry leaves the destination as it was and removes the partial file.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn conflict_and_cancel_keep_the_destination() {
        let tmp = TempDir::new("exp-ops");
        let logs = tmp.path().join("logs");
        std::fs::create_dir_all(&logs).unwrap();
        let line = "+0300 2026-11-11 10:00:00 INFO dns: exchanged A example.com 93.184.216.34\n";
        std::fs::write(logs.join("sing-box.log"), line.repeat(300_000)).unwrap();
        let dest = tmp.path().join("diag.zip");
        std::fs::write(&dest, "old archive").unwrap();
        let ops = OperationRegistry::new();
        let inputs = ExportInputs {
            logs_dir: Some(logs),
            ..Default::default()
        };
        let (req, mut rx) = request(&dest, inputs);
        let runner = ops.clone();
        let first = tokio::spawn(async move { export(&runner, req).await });
        // Monotonic condition (a stage could be missed); the big log keeps the export busy.
        rx.wait_for(|p| p.entries >= 1).await.unwrap();

        let other = tmp.path().join("other.zip");
        let (req, _rx) = request(&other, ExportInputs::default());
        let second = export(&ops, req).await.err().map(|e| e.kind);
        assert_eq!(second, Some(ErrorKind::Conflict));

        let running = ops
            .list()
            .into_iter()
            .find(|m| m.status == OpStatus::Running);
        assert!(ops.cancel(running.unwrap().id));
        let err = first.await.unwrap().err().map(|e| e.kind);
        assert_eq!(err, Some(ErrorKind::Cancelled));
        for _ in 0..500 {
            if !ops.is_busy(RESOURCE) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(!ops.is_busy(RESOURCE));
        assert_eq!(std::fs::read_to_string(&dest).unwrap(), "old archive");
        assert_eq!(partials(tmp.path()), 0);
        assert!(!other.exists());
    }

    /// F-178: a failed or cancelled export whose partial file cannot be removed sends exactly
    /// one «Очистка диагностики не завершена» notice.
    #[test]
    fn undeletable_partial_sends_one_notice() {
        use std::os::windows::fs::OpenOptionsExt;
        let tmp = TempDir::new("exp-cleanup");
        let count = Arc::new(AtomicUsize::new(0));
        let seen = count.clone();
        let sink: NoticeSink = Arc::new(move |n: Notice| {
            assert_eq!(n.title, Msg::new("forensics.export.cleanupFailed.title"));
            seen.fetch_add(1, Ordering::SeqCst);
        });
        let (partial, file) = Partial::create(&tmp.path().join("diag.zip"), Some(sink)).unwrap();
        drop(file);
        let path = std::fs::read_dir(tmp.path())
            .unwrap()
            .flatten()
            .next()
            .unwrap()
            .path();
        // Held without FILE_SHARE_DELETE: the removal fails like a scanner holding the file.
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&path)
            .unwrap();
        drop(partial);
        assert_eq!(count.load(Ordering::SeqCst), 1);
        drop(lock);
        std::fs::remove_file(&path).unwrap();
    }
}
