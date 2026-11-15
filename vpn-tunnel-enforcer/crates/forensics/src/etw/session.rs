//! Everything that touches ferrisetw / the ETW API, kept in one place so a direct `windows`-crate
//! consumer can replace it (spec §6.3).
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::trace::{TraceTrait, UserTrace, stop_trace_by_name};
use ferrisetw::{EventRecord, GUID, SchemaLocator};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::digest::LiveDigest;
use super::writer::{RowSender, rfc3339_ms};
use super::{classify, fields};

/// Name of our real-time session (single-instance app: at most one).
pub const SESSION_NAME: &str = "VPNTE-ETW";

/// Providers and their manifest GUIDs (fixed by the manifests; enabling by GUID needs no PLA /
/// COM lookup and also works before a provider registers).
pub const PROVIDERS: [(&str, u128); 5] = [
    (
        "Microsoft-Windows-TCPIP",
        0x2F07E2EE_15DB_40F1_90EF_9D7BA282188A,
    ),
    (
        "Microsoft-Windows-DNS-Client",
        0x1C95126E_7EEA_49A9_A3FE_A378B03DDB4D,
    ),
    (
        "Microsoft-Windows-WFP",
        0x0C478C5B_0351_41B1_8C58_4A6737DA32E3,
    ),
    (
        "Microsoft-Windows-Winsock-AFD",
        0xE53C6823_7BB8_44BB_90DC_3F86090D48A6,
    ),
    (
        "Microsoft-Windows-WebIO",
        0x50B3E73C_9370_461D_BB9F_26F32D68887D,
    ),
];

/// Seconds between the 1601 FILETIME epoch and the Unix epoch, in milliseconds.
const FILETIME_UNIX_MS: i64 = 11_644_473_600_000;

/// Loss counters of the ETW session (`ControlTraceW` QUERY).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LossStats {
    pub events_lost: u32,
    pub buffers_lost: u32,
}

/// Stops a session named [`SESSION_NAME`] left behind by a crash or a killed old sidecar;
/// `true` when one existed.
pub fn reclaim_orphan() -> bool {
    stop_trace_by_name(SESSION_NAME).is_ok()
}

/// A started trace and the thread that runs `ProcessTrace` for it.
pub struct Running {
    trace: UserTrace,
    processor: JoinHandle<Result<(), String>>,
}

/// Enables every provider and starts processing on an owned thread.
pub fn start(sender: &RowSender, digest: &Arc<LiveDigest>) -> Result<Running, String> {
    let mut builder = UserTrace::new().named(SESSION_NAME.to_string());
    for (name, guid) in PROVIDERS {
        let category = classify::provider_category(name);
        let label = classify::canonical_provider(name);
        let callback = make_callback(sender.clone(), digest.clone(), label, category);
        let provider = Provider::by_guid(GUID::from_u128(guid))
            .any(u64::MAX)
            .level(0xFF)
            .add_callback(callback)
            .build();
        builder = builder.enable(provider);
    }
    let (trace, handle) = builder.start().map_err(|e| format!("{e:?}"))?;
    let processor = std::thread::Builder::new()
        .name("vpnte-etw-process".into())
        .spawn(move || UserTrace::process_from_handle(handle).map_err(|e| format!("{e:?}")))
        .map_err(|e| e.to_string())?;
    Ok(Running { trace, processor })
}

impl Running {
    /// `true` while `ProcessTrace` still runs (it returns when the session ends).
    pub fn is_processing(&self) -> bool {
        !self.processor.is_finished()
    }

    /// Stops the trace and waits up to `timeout` for the processing thread; `false` when it had to
    /// fall back to a stop by name and leave the thread behind.
    pub fn stop(self, timeout: Duration) -> bool {
        // ferrisetw closes the consumer first (callbacks stop at once; events still in ETW
        // buffers are discarded), then stops the controller session.
        if let Err(e) = self.trace.stop() {
            tracing::warn!("etw trace stop failed: {e:?}");
        }
        let deadline = Instant::now() + timeout;
        while !self.processor.is_finished() {
            if Instant::now() >= deadline {
                tracing::warn!("etw processing thread did not end; stopping the session by name");
                let _ = stop_trace_by_name(SESSION_NAME);
                return false;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        match self.processor.join() {
            Ok(Ok(())) => true,
            Ok(Err(e)) => {
                tracing::warn!("etw ProcessTrace ended with an error: {e}");
                true
            }
            Err(_) => false,
        }
    }
}

/// Event time as [`rfc3339_ms`]; the header holds a FILETIME (100 ns since 1601) unless a raw
/// timestamp mode was requested, which we never do.
fn event_time(record: &EventRecord) -> String {
    let raw = record.raw_timestamp();
    let ms = if raw > 0 {
        raw / 10_000 - FILETIME_UNIX_MS
    } else {
        vpnte_base::types::now_ms()
    };
    rfc3339_ms(ms)
}

fn make_callback(
    sender: RowSender,
    digest: Arc<LiveDigest>,
    label: &'static str,
    category: &'static str,
) -> impl FnMut(&EventRecord, &SchemaLocator) + Send + Sync + 'static {
    move |record: &EventRecord, locator: &SchemaLocator| {
        digest.note_observed();
        // ferrisetw answers a panicking callback with `process::exit(1)`, which in-process ends
        // the whole app (its own parser still has an `unimplemented!()` for MOF counted
        // strings). Such an event counts as unparsed instead.
        let handled = std::panic::catch_unwind(AssertUnwindSafe(|| {
            on_event(record, locator, &sender, &digest, label, category);
        }));
        if handled.is_err() {
            digest.note_unparsed();
        }
    }
}

/// One ETW event: an `unparsed` row, nothing (filtered noise) or a classified data row.
fn on_event(
    record: &EventRecord,
    locator: &SchemaLocator,
    sender: &RowSender,
    digest: &LiveDigest,
    label: &'static str,
    category: &'static str,
) {
    let Ok(schema) = locator.event_schema(record) else {
        // Unknown schemas are kept as rows (owner decision §10.6 «A»), counted for the summary.
        digest.note_unparsed();
        let mut row = Map::new();
        row.insert("provider".into(), label.into());
        row.insert("category".into(), category.into());
        row.insert("event".into(), "unparsed".into());
        row.insert("eventId".into(), record.event_id().into());
        row.insert("opcode".into(), record.opcode().into());
        row.insert("version".into(), record.version().into());
        row.insert("level".into(), record.level().into());
        row.insert("ts".into(), event_time(record).into());
        sender.send(row);
        return;
    };
    let task = schema.task_name();
    // TDH opcode names are localized and padded (observed on ru-RU Windows: "Сведения " for
    // win:Info), so the classifier's "info" check would miss them; opcode code 0 is win:Info.
    let opcode = schema.opcode_name().trim().to_string();
    let event_opcode = if record.opcode() == 0 {
        ""
    } else {
        opcode.as_str()
    };
    // Before property parsing, so the dropped firehose costs almost nothing.
    if !classify::is_significant(category, &task.to_lowercase()) {
        digest.note_filtered();
        return;
    }
    let kind = format!("{label} {task} {opcode}").to_lowercase();
    let (event, reason) = classify::derive_event_and_reason(category, &kind, event_opcode);
    let mut extracted = Map::new();
    fields::extract(&Parser::create(record, &schema), category, &mut extracted);

    let mut row = Map::new();
    row.insert("provider".into(), label.into());
    row.insert("category".into(), category.into());
    row.insert("event".into(), event.into());
    row.insert("reason".into(), reason.map_or(Value::Null, Value::from));
    // Always present (null when unknown): readers expect a stable shape.
    row.insert("remoteAddress".into(), Value::Null);
    row.insert("queryName".into(), Value::Null);
    row.extend(extracted);
    row.insert("eventId".into(), record.event_id().into());
    row.insert("level".into(), record.level().into());
    // The event-header PID is not an attribution (DNS-Client reports the Dnscache service).
    if record.process_id() != 0 {
        row.insert("processId".into(), record.process_id().into());
    }
    if !task.is_empty() {
        row.insert("taskName".into(), task.into());
    }
    if !opcode.is_empty() {
        row.insert("opcodeName".into(), opcode.into());
    }
    row.insert("ts".into(), event_time(record).into());
    sender.send(row);
}

/// Loss counters of the running [`SESSION_NAME`] session; `None` when it is not running or the
/// query is refused.
pub fn query_loss() -> Option<LossStats> {
    query_loss_of(SESSION_NAME)
}

fn query_loss_of(session: &str) -> Option<LossStats> {
    use windows_etw::Win32::Foundation::ERROR_SUCCESS;
    use windows_etw::Win32::System::Diagnostics::Etw::{
        CONTROLTRACE_HANDLE, ControlTraceW, EVENT_TRACE_CONTROL_QUERY, EVENT_TRACE_PROPERTIES,
        WNODE_FLAG_TRACED_GUID,
    };
    use windows_etw::core::PCWSTR;

    // Properties followed by room for the logger and log-file names (1024 UTF-16 units each),
    // in `u64`s so the struct is aligned.
    const NAME_BYTES: usize = 1024 * 2;
    let props_size = size_of::<EVENT_TRACE_PROPERTIES>();
    let total = props_size + 2 * NAME_BYTES;
    let mut buf = vec![0u64; total.div_ceil(8)];
    let props = buf.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>();
    let name: Vec<u16> = session.encode_utf16().chain([0]).collect();
    // SAFETY: `buf` is zeroed, 8-byte aligned and holds the struct plus both name areas, whose
    // offsets and total size are declared in the header as ControlTraceW requires.
    let status = unsafe {
        (*props).Wnode.BufferSize = total as u32;
        (*props).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        (*props).LoggerNameOffset = props_size as u32;
        (*props).LogFileNameOffset = (props_size + NAME_BYTES) as u32;
        ControlTraceW(
            CONTROLTRACE_HANDLE { Value: 0 },
            PCWSTR(name.as_ptr()),
            props,
            EVENT_TRACE_CONTROL_QUERY,
        )
    };
    if status != ERROR_SUCCESS {
        return None;
    }
    // SAFETY: ControlTraceW succeeded and filled the struct inside `buf`.
    let p = unsafe { &*props };
    Some(LossStats {
        events_lost: p.EventsLost,
        buffers_lost: p.RealTimeBuffersLost,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_table_matches_the_classifier() {
        for (name, guid) in PROVIDERS {
            assert_eq!(classify::known_guid(name), Some(guid), "{name}");
            assert_eq!(classify::canonical_provider(name), name);
        }
    }

    /// A session that does not exist reports nothing instead of zeros.
    #[test]
    fn loss_query_without_a_session_is_none() {
        let name = format!("VPNTE-ETW-test-absent-{}", std::process::id());
        assert_eq!(query_loss_of(&name), None);
    }
}
