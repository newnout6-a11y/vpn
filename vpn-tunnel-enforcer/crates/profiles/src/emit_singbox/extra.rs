//! Re-emits the allow-listed sing-box keys a pasted config carried (`Profile::singbox_extra`).
//!
//! A key is a dotted path (`tls.fragment`, `multiplex.min_streams`) or a top-level key whose
//! object value is merged into the emitted object. Typed fields and the tunnel policy win on
//! conflict; nested paths apply only where the emitter produced the parent object.
use serde_json::{Map, Value};

type Obj = Map<String, Value>;

/// Never re-emitted at any depth, whatever the importer let through: these would redirect or
/// bind the dialer, override what the emitter decides, or make the core read local files.
fn denied(key: &str) -> bool {
    key.ends_with("_path")
        || matches!(
            key,
            "type"
                | "tag"
                | "detour"
                | "bind_interface"
                | "inet4_bind_address"
                | "inet6_bind_address"
                | "bind_address_no_port"
                | "routing_mark"
                | "reuse_addr"
                | "netns"
                | "domain_resolver"
                | "domain_strategy"
        )
}

/// Merges `extra` into `target`; `allow` sees each full key path and may veto it.
pub(super) fn merge(target: &mut Obj, extra: &Obj, allow: impl Fn(&[&str]) -> bool) {
    for (key, value) in extra {
        let path: Vec<&str> = key.split('.').collect();
        if path.iter().any(|segment| segment.trim().is_empty()) {
            continue;
        }
        descend(target, &path, 0, value, &allow);
    }
}

/// Walks the parent objects of `path` (each must already be emitted), then places the value.
fn descend<'a>(
    target: &mut Obj,
    path: &[&'a str],
    depth: usize,
    value: &'a Value,
    allow: &dyn Fn(&[&str]) -> bool,
) {
    if depth + 1 >= path.len() {
        return put(target, path, value, allow);
    }
    let segment = path[depth];
    if denied(segment) || !allow(&path[..=depth]) {
        return;
    }
    if let Some(Value::Object(next)) = target.get_mut(segment) {
        descend(next, path, depth + 1, value, allow);
    }
}

/// Places `value` at the last segment of `path` inside `target` (the parent object).
fn put<'a>(target: &mut Obj, path: &[&'a str], value: &'a Value, allow: &dyn Fn(&[&str]) -> bool) {
    let Some(&key) = path.last() else { return };
    if denied(key) || !allow(path) {
        return;
    }
    match (target.get_mut(key), value) {
        (Some(Value::Object(existing)), Value::Object(incoming)) => {
            for (k, v) in incoming {
                put(existing, &[path, &[k.as_str()]].concat(), v, allow);
            }
        }
        (Some(_), _) => {}
        (None, Value::Object(incoming)) => {
            let mut fresh = Obj::new();
            for (k, v) in incoming {
                put(&mut fresh, &[path, &[k.as_str()]].concat(), v, allow);
            }
            if !fresh.is_empty() {
                target.insert(key.to_owned(), Value::Object(fresh));
            }
        }
        (None, v) => {
            target.insert(key.to_owned(), v.clone());
        }
    }
}
