//! Network and socket snapshots of a session (`network-<phase>.json`, `sockets-<phase>.json`):
//! typed winnet reads replace the old 18-cmdlet PowerShell telemetry. Best effort: a failed read
//! is recorded in the file, never fails the capture.
use std::collections::HashMap;
use std::path::Path;

use serde::Serialize;
use vpnte_base::types::{UnixMs, now_ms};
use vpnte_winnet::adapters::{self, Family};
use vpnte_winnet::process::{self, SocketRow};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AdapterOut {
    if_index: u32,
    luid: u64,
    alias: String,
    description: String,
    status: String,
    physical: bool,
    hardware: bool,
    hidden: bool,
    /// `ip/prefix`.
    addresses: Vec<String>,
    gateways: Vec<String>,
    dns: Vec<String>,
    link_speed_bps: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RouteOut {
    if_index: u32,
    destination: String,
    next_hop: Option<String>,
    metric: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Network {
    taken_at: UnixMs,
    adapters: Vec<AdapterOut>,
    routes: Vec<RouteOut>,
    errors: Vec<String>,
}

#[derive(Serialize)]
struct SocketOut<'a> {
    #[serde(flatten)]
    row: &'a SocketRow,
    /// Executable file name of the owner (attribution the ETW header PID cannot give, B-08).
    image: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Sockets<'a> {
    taken_at: UnixMs,
    sockets: Vec<SocketOut<'a>>,
    error: Option<String>,
}

/// Writes both snapshot files of `phase` (`start` / `stop`) into `dir`. Blocking.
pub fn write(dir: &Path, phase: &str) {
    let net = network();
    write_json(&dir.join(format!("network-{phase}.json")), &net);
    let (rows, error) = match process::socket_table() {
        Ok(rows) => (rows, None),
        Err(e) => (Vec::new(), Some(e.to_string())),
    };
    let mut images: HashMap<u32, Option<String>> = HashMap::new();
    let sockets = rows
        .iter()
        .map(|row| SocketOut {
            image: images
                .entry(row.pid)
                .or_insert_with(|| {
                    process::image_path(row.pid)
                        .ok()
                        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
                })
                .clone(),
            row,
        })
        .collect();
    let out = Sockets {
        taken_at: now_ms(),
        sockets,
        error,
    };
    write_json(&dir.join(format!("sockets-{phase}.json")), &out);
}

fn network() -> Network {
    let mut errors = Vec::new();
    let adapters = match adapters::inventory() {
        Ok(list) => list
            .into_iter()
            .map(|a| AdapterOut {
                if_index: a.if_index,
                luid: a.luid,
                alias: a.alias,
                description: a.description,
                status: format!("{:?}", a.status).to_lowercase(),
                physical: a.physical,
                hardware: a.hardware,
                hidden: a.hidden,
                addresses: a
                    .addresses
                    .iter()
                    .map(|u| format!("{}/{}", u.ip, u.prefix_len))
                    .collect(),
                gateways: a.gateways.iter().map(ToString::to_string).collect(),
                dns: a.dns.iter().map(ToString::to_string).collect(),
                link_speed_bps: a.link_speed_bps,
            })
            .collect(),
        Err(e) => {
            errors.push(format!("adapters: {e}"));
            Vec::new()
        }
    };
    let mut routes = Vec::new();
    for family in [Family::V4, Family::V6] {
        match adapters::routes(family) {
            Ok(list) => routes.extend(list.into_iter().map(|r| RouteOut {
                if_index: r.if_index,
                destination: r.destination.to_string(),
                next_hop: r.next_hop.map(|ip| ip.to_string()),
                metric: r.metric,
            })),
            Err(e) => errors.push(format!("routes {family:?}: {e}")),
        }
    }
    Network {
        taken_at: now_ms(),
        adapters,
        routes,
        errors,
    }
}

fn write_json<T: Serialize>(path: &Path, value: &T) {
    let result = crate::pretty_json(value)
        .map_err(std::io::Error::other)
        .and_then(|bytes| vpnte_core::store::write_atomic(path, &bytes));
    if let Err(e) = result {
        tracing::warn!("forensics snapshot {} failed: {e}", path.display());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempDir;

    /// Unelevated reads work (winnet API): both files appear and parse.
    #[test]
    fn writes_both_snapshot_files() {
        let dir = TempDir::new("snapshot");
        write(dir.path(), "start");
        for name in ["network-start.json", "sockets-start.json"] {
            let text = std::fs::read_to_string(dir.path().join(name)).unwrap();
            let v: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert!(v["takenAt"].as_i64().is_some(), "{name}");
        }
    }
}
