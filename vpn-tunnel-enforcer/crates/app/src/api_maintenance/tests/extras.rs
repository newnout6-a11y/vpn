//! The support archive's own entries (p-noadmin-ui): the event journal and this user's helper
//! service lines, scrubbed and appended to a finished pack before it takes its place. Temp
//! folders only; no real service is asked (the answer is made here).
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use vpnte_service::proto::{ServiceLogLine, ServiceLogWire};

use crate::api_logs::ServiceAnswer;
use crate::api_maintenance::export::place;
use crate::api_maintenance::extras::{SERVICE_LOG, gather};
use crate::api_settings::test_support::TempDir;

const USER: &str = "Tester";
const PUBLIC_IP: &str = "93.184.216.34";

/// A finished pack with one entry, as the forensics export leaves it.
fn pack(path: &Path) {
    let mut zip = zip::ZipWriter::new(File::create(path).expect("pack"));
    zip.start_file("settings.json", zip::write::SimpleFileOptions::default())
        .expect("entry");
    zip.write_all(b"{}").expect("body");
    zip.finish().expect("finish");
}

fn entries(path: &Path) -> Vec<(String, String)> {
    let mut zip = zip::ZipArchive::new(File::open(path).expect("archive")).expect("zip");
    (0..zip.len())
        .map(|i| {
            let mut file = zip.by_index(i).expect("entry");
            let mut body = String::new();
            file.read_to_string(&mut body).expect("utf-8");
            (file.name().expect("name").into_owned(), body)
        })
        .collect()
}

fn journal(root: &Path) {
    let current = format!(
        concat!(
            r#"{{"seq":2,"at":2,"topic":"session","tone":"info","title":{{"key":"a","args":{{"ip":"{ip}","who":"C:\\Users\\{user}\\x","token":"abc"}}}}}}"#,
            "\n",
            r#"{{"seq":3,"at":3,"top"#,
            "\n"
        ),
        ip = PUBLIC_IP,
        user = USER,
    );
    std::fs::write(root.join("events.jsonl"), current).expect("current");
    let previous = r#"{"seq":1,"at":1,"topic":"app","tone":"info","title":{"key":"b"}}"#;
    std::fs::write(root.join("events.1.jsonl"), format!("{previous}\n")).expect("previous");
}

fn service(truncated: bool) -> ServiceAnswer {
    let line = |offset, text: String| ServiceLogLine { offset, text };
    ServiceAnswer::Lines(ServiceLogWire {
        lines: vec![
            line(0, format!("INFO tunnel up for {USER} via {PUBLIC_IP}")),
            line(40, "INFO kill switch standard".into()),
        ],
        truncated,
    })
}

/// The journal (older file first) and the service's lines join the pack's own entries; the
/// user name, public addresses and secret-named fields are masked, a cut-off record is left
/// out, and the staging file is gone.
#[tokio::test]
async fn the_archive_gets_the_journal_and_the_service_lines() {
    let dir = TempDir::new("support-extras");
    journal(&dir.0);
    let staging = dir.0.join(".diag.zip.pack");
    let dest = dir.0.join("diag.zip");
    pack(&staging);
    let added = place(
        staging.clone(),
        dest.clone(),
        dir.0.clone(),
        Some(service(true)),
        Some(USER.into()),
    );
    assert_eq!(added.await.ok(), Some(3));
    assert!(
        !staging.exists(),
        "the staging file took the destination's place"
    );

    let entries = entries(&dest);
    let names: Vec<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        [
            "settings.json",
            "events.1.jsonl",
            "events.jsonl",
            SERVICE_LOG
        ]
    );
    let all: String = entries.iter().map(|(_, b)| b.as_str()).collect();
    assert!(!all.contains(USER), "{all}");
    assert!(!all.contains(PUBLIC_IP), "{all}");
    let current = &entries[2].1;
    assert_eq!(current.lines().count(), 1, "the cut-off record is left out");
    let record: serde_json::Value = serde_json::from_str(current.trim()).expect("still JSON");
    assert_eq!(record["title"]["args"]["token"], "<redacted>");
    let log = &entries[3].1;
    assert!(log.starts_with("[older lines not included]\n"), "{log}");
    assert!(log.contains("<user>"), "{log}");
    assert!(log.contains("INFO kill switch standard\n"), "{log}");
}

/// No service lines unless the service answered with them; no journal files, no entries.
#[test]
fn without_the_service_there_is_no_service_entry() {
    let dir = TempDir::new("support-extras-none");
    assert!(gather(&dir.0, None, Some(USER)).is_empty());
    for answer in [ServiceAnswer::NotInstalled, ServiceAnswer::Old] {
        assert!(gather(&dir.0, Some(answer), Some(USER)).is_empty());
    }
    journal(&dir.0);
    let names: Vec<&str> = gather(&dir.0, Some(ServiceAnswer::Old), Some(USER))
        .iter()
        .map(|e| e.name)
        .collect();
    assert_eq!(names, ["events.1.jsonl", "events.jsonl"]);
}

/// A pack that cannot take the entries leaves the destination as it was and no staging file.
#[tokio::test]
async fn a_failed_append_keeps_the_previous_file() {
    let dir = TempDir::new("support-extras-fail");
    journal(&dir.0);
    let staging = dir.0.join(".diag.zip.pack");
    let dest = dir.0.join("diag.zip");
    std::fs::write(&staging, b"not a zip").expect("staging");
    std::fs::write(&dest, b"previous").expect("dest");
    let placed = place(
        staging.clone(),
        dest.clone(),
        dir.0.clone(),
        None,
        Some(USER.into()),
    );
    assert!(placed.await.is_err());
    assert!(!staging.exists());
    assert_eq!(std::fs::read(&dest).expect("dest"), b"previous");
}
