//! pktmon counters (`pktmon counters --json` output, layout not lab-verified): flattened into
//! packet metrics and searched for packets on the TUN component.
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// What a counter measures, decided by its key name and then its parent keys (never by the file
/// name: the old `${artifact} ${name}` test made every drop-file value a drop and no
/// `pktmon-counters.json` value an error, B-32).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MetricCategory {
    Drop,
    Byte,
    Packet,
    Error,
    Counter,
}

impl MetricCategory {
    /// First match wins: drop, byte, packet, error (TFS:569-576 order).
    fn of(key: &str) -> Self {
        let k = key.to_ascii_lowercase();
        let any = |words: &[&str]| words.iter().any(|w| k.contains(w));
        if any(&["drop", "discard"]) {
            MetricCategory::Drop
        } else if any(&["byte", "octet"]) {
            MetricCategory::Byte
        } else if any(&["packet", "frame", "pkt"]) {
            MetricCategory::Packet
        } else if any(&["error", "fail", "lost", "loss"]) {
            MetricCategory::Error
        } else {
            MetricCategory::Counter
        }
    }
}

/// One finite number of a counters file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PacketMetric {
    pub artifact: String,
    /// Dot-joined key path, array indices included (`adapters.0.packets`).
    pub path: String,
    /// Last key, `value` for a bare array element.
    pub name: String,
    pub value: f64,
    pub category: MetricCategory,
}

/// Every finite number in the JSON tree of `artifact`, in document order.
pub fn flatten_counters(root: &Value, artifact: &str) -> Vec<PacketMetric> {
    let mut out = Vec::new();
    walk(root, artifact, &mut Vec::new(), &mut out);
    out
}

fn walk(v: &Value, artifact: &str, path: &mut Vec<String>, out: &mut Vec<PacketMetric>) {
    match v {
        Value::Number(n) => {
            let Some(value) = n.as_f64().filter(|f| f.is_finite()) else {
                return;
            };
            let name = path
                .last()
                .filter(|k| k.parse::<usize>().is_err())
                .map_or_else(|| "value".to_string(), Clone::clone);
            let category = path
                .iter()
                .rev()
                .map(|k| MetricCategory::of(k))
                .find(|c| *c != MetricCategory::Counter)
                .unwrap_or(MetricCategory::Counter);
            out.push(PacketMetric {
                artifact: artifact.to_string(),
                path: path.join("."),
                name,
                value,
                category,
            });
        }
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                path.push(i.to_string());
                walk(item, artifact, path, out);
                path.pop();
            }
        }
        Value::Object(map) => {
            for (key, item) in map {
                path.push(key.clone());
                walk(item, artifact, path, out);
                path.pop();
            }
        }
        Value::Null | Value::Bool(_) | Value::String(_) => {}
    }
}

/// Packets counted on the TUN component: the first object whose name / description / alias
/// equals `tun_alias` or contains `Wintun` and whose subtree counts packets. Returns the
/// component name and the packet total.
pub(super) fn tun_packets(root: &Value, tun_alias: Option<&str>) -> Option<(String, f64)> {
    match root {
        Value::Object(map) => {
            let name = map.iter().find_map(|(k, v)| {
                let k = k.to_ascii_lowercase();
                let label = k.contains("name") || k.contains("description") || k == "alias";
                v.as_str().filter(|s| label && is_tun_name(s, tun_alias))
            });
            if let Some(name) = name {
                let total: f64 = flatten_counters(root, "")
                    .iter()
                    .filter(|m| m.category == MetricCategory::Packet)
                    .map(|m| m.value)
                    .sum();
                if total > 0.0 {
                    return Some((name.to_string(), total));
                }
            }
            map.values().find_map(|v| tun_packets(v, tun_alias))
        }
        Value::Array(items) => items.iter().find_map(|v| tun_packets(v, tun_alias)),
        _ => None,
    }
}

fn is_tun_name(name: &str, tun_alias: Option<&str>) -> bool {
    let name = name.trim();
    name.to_ascii_lowercase().contains("wintun")
        || tun_alias.is_some_and(|a| !a.trim().is_empty() && name.eq_ignore_ascii_case(a.trim()))
}
