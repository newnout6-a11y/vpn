//! The two DNS client policy values the old lockdown set to 1 (spec §3.10): restored exactly
//! from the adapter journal (`exists:false` → value deleted), and only while they still read
//! 1, so a value changed since is left alone. No journal → nothing is touched.
use vpnte_winnet::registry::{Access, Hive, Key, View};

use super::journal::{Journals, PolicyValue, Slot};
use super::report::{Outcome, StepId, StepRecord};

/// `(key under HKLM, value)` of `smartNameResolution` and `parallelAandAAAA`.
pub(crate) const SMART_NAME_RESOLUTION: (&str, &str) = (
    r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
    "DisableSmartNameResolution",
);
pub(crate) const PARALLEL_A_AAAA: (&str, &str) = (
    r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters",
    "DisableParallelAandAAAA",
);
/// What the old lockdown wrote to both.
const LOCKDOWN_VALUE: u32 = 1;

/// Registry access, faked in tests.
pub(crate) trait PolicyRegistry {
    /// `Ok(None)`: value or key absent; a non-DWORD value is an error.
    fn read(&self, key: &str, value: &str) -> Result<Option<u32>, String>;
    fn write(&self, key: &str, value: &str, data: u32) -> Result<(), String>;
    fn delete(&self, key: &str, value: &str) -> Result<(), String>;
}

/// HKLM, native (64-bit) view: where the old 64-bit app wrote.
pub(crate) struct Hklm;

impl Hklm {
    fn open(key: &str) -> Result<Option<Key>, String> {
        Key::open(Hive::LocalMachine, key, Access::ReadWrite, View::Native)
            .map_err(|e| e.to_string())
    }
}

impl PolicyRegistry for Hklm {
    fn read(&self, key: &str, value: &str) -> Result<Option<u32>, String> {
        let read = Key::open(Hive::LocalMachine, key, Access::Read, View::Native)
            .and_then(|k| k.map(|k| k.dword(value)).transpose());
        read.map(Option::flatten).map_err(|e| e.to_string())
    }
    fn write(&self, key: &str, value: &str, data: u32) -> Result<(), String> {
        let key = Self::open(key)?.ok_or("key vanished")?;
        key.set_dword(value, data).map_err(|e| e.to_string())
    }
    fn delete(&self, key: &str, value: &str) -> Result<(), String> {
        match Self::open(key)? {
            Some(key) => key.delete_value(value).map(drop).map_err(|e| e.to_string()),
            None => Ok(()),
        }
    }
}

/// Step 5, registry part (writes need elevation). Values are handled independently, in order.
pub(crate) fn restore(journals: &Journals, reg: &dyn PolicyRegistry) -> StepRecord {
    let step = StepId::DnsPolicy;
    let Slot::Valid(journal) = &journals.adapters else {
        // Without a journal the original values are unknown: report only (spec §6.6).
        return StepRecord::new(
            step,
            Outcome::Done,
            "no adapter journal: policy values not touched",
        );
    };
    let mut lines = Vec::new();
    let (mut changed, mut failed, mut skipped) = (false, false, false);
    for ((key, value), recorded) in [
        (SMART_NAME_RESOLUTION, journal.smart_name_resolution),
        (PARALLEL_A_AAAA, journal.parallel_a_aaaa),
    ] {
        match restore_one(reg, key, value, recorded) {
            Ok((line, acted)) => {
                changed |= acted;
                lines.push(format!("{value}: {line}"));
            }
            Err(Problem::Skipped(line)) => {
                skipped = true;
                lines.push(format!("{value}: {line}"));
            }
            Err(Problem::Failed(line)) => {
                failed = true;
                lines.push(format!("{value}: {line}"));
            }
        }
    }
    let outcome = match (failed, skipped) {
        (true, _) => Outcome::Failed,
        (false, true) => Outcome::Skipped,
        (false, false) => Outcome::Done,
    };
    StepRecord::new(step, outcome, lines.join("; ")).changed(changed)
}

enum Problem {
    Skipped(String),
    Failed(String),
}

fn restore_one(
    reg: &dyn PolicyRegistry,
    key: &str,
    value: &str,
    recorded: Option<PolicyValue>,
) -> Result<(&'static str, bool), Problem> {
    let recorded =
        recorded.ok_or_else(|| Problem::Skipped("no valid snapshot, not touched".into()))?;
    let wanted = recorded.exists.then_some(recorded.data);
    let current = reg
        .read(key, value)
        .map_err(|e| Problem::Skipped(format!("unreadable ({e}), not touched")))?;
    if current == wanted {
        return Ok(("already as recorded", false));
    }
    if current != Some(LOCKDOWN_VALUE) {
        return Ok(("changed since, left as is", false));
    }
    let written = match wanted {
        Some(data) => reg.write(key, value, data),
        None => reg.delete(key, value),
    };
    written.map_err(|e| Problem::Failed(format!("restore failed: {e}")))?;
    match reg.read(key, value) {
        Ok(read) if read == wanted => Ok(("restored", true)),
        Ok(_) => Err(Problem::Failed("reads back a different value".into())),
        Err(e) => Err(Problem::Failed(format!("read-back failed: {e}"))),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::HashMap;

    use super::super::journal::{AdapterJournal, Transition};
    use super::*;

    /// In-memory registry; `fail_delete` makes deletes fail.
    #[derive(Default)]
    struct Fake {
        values: RefCell<HashMap<String, u32>>,
        writes: RefCell<Vec<String>>,
        fail_delete: bool,
    }

    impl PolicyRegistry for Fake {
        fn read(&self, _key: &str, value: &str) -> Result<Option<u32>, String> {
            Ok(self.values.borrow().get(value).copied())
        }
        fn write(&self, _key: &str, value: &str, data: u32) -> Result<(), String> {
            self.writes.borrow_mut().push(format!("{value}={data}"));
            self.values.borrow_mut().insert(value.into(), data);
            Ok(())
        }
        fn delete(&self, _key: &str, value: &str) -> Result<(), String> {
            if self.fail_delete {
                return Err("access denied".into());
            }
            self.writes.borrow_mut().push(format!("{value} deleted"));
            self.values.borrow_mut().remove(value);
            Ok(())
        }
    }

    fn journals(smart: Option<PolicyValue>, parallel: Option<PolicyValue>) -> Journals {
        Journals {
            dir_problem: None,
            firewall: Slot::Absent,
            adapters: Slot::Valid(AdapterJournal {
                adapters: Vec::new(),
                transition: Transition::default(),
                smart_name_resolution: smart,
                parallel_a_aaaa: parallel,
                skipped: Vec::new(),
            }),
            policy: Slot::Absent,
            tun_owner: Slot::Absent,
        }
    }

    const ABSENT: PolicyValue = PolicyValue {
        exists: false,
        data: 0,
    };
    const ZERO: PolicyValue = PolicyValue {
        exists: true,
        data: 0,
    };

    fn locked_down() -> Fake {
        let fake = Fake::default();
        fake.values
            .borrow_mut()
            .insert("DisableSmartNameResolution".into(), 1);
        fake.values
            .borrow_mut()
            .insert("DisableParallelAandAAAA".into(), 1);
        fake
    }

    /// AT-03-012 (`physicalAdapterLockdownSource.test.ts`): `exists:true, data 0` writes 0;
    /// `exists:false` deletes; both read back.
    #[test]
    fn restores_exact_values() {
        let reg = locked_down();
        let record = restore(&journals(Some(ABSENT), Some(ZERO)), &reg);
        assert_eq!(record.outcome, Outcome::Done, "{}", record.detail);
        assert!(record.changed);
        assert_eq!(
            *reg.writes.borrow(),
            [
                "DisableSmartNameResolution deleted",
                "DisableParallelAandAAAA=0"
            ]
        );
    }

    /// `exists:false` with a failing delete is a failure (retried), not a success.
    #[test]
    fn failing_delete_is_reported() {
        let reg = Fake {
            fail_delete: true,
            ..locked_down()
        };
        let record = restore(&journals(Some(ABSENT), Some(ZERO)), &reg);
        assert_eq!(record.outcome, Outcome::Failed);
        assert!(
            record
                .detail
                .starts_with("DisableSmartNameResolution: restore failed")
        );
        assert_eq!(*reg.writes.borrow(), ["DisableParallelAandAAAA=0"]);
    }

    /// A missing or invalid snapshot writes nothing while the valid neighbour is restored, in
    /// order; values changed since the lockdown are left alone.
    #[test]
    fn invalid_neighbour_and_changed_values() {
        let reg = locked_down();
        let record = restore(&journals(None, Some(ZERO)), &reg);
        assert_eq!(record.outcome, Outcome::Skipped);
        assert_eq!(
            record.detail,
            "DisableSmartNameResolution: no valid snapshot, not touched; DisableParallelAandAAAA: restored"
        );
        assert_eq!(*reg.writes.borrow(), ["DisableParallelAandAAAA=0"]);

        let reg = Fake::default();
        reg.values
            .borrow_mut()
            .insert("DisableParallelAandAAAA".into(), 7);
        let record = restore(&journals(Some(ABSENT), Some(ZERO)), &reg);
        assert_eq!(record.outcome, Outcome::Done);
        assert!(!record.changed);
        assert!(reg.writes.borrow().is_empty());
        assert!(record.detail.contains("already as recorded"));
        assert!(record.detail.contains("changed since"));

        let mut none = journals(None, None);
        none.adapters = Slot::Absent;
        let record = restore(&none, &reg);
        assert_eq!(record.outcome, Outcome::Done);
        assert!(reg.writes.borrow().is_empty());
    }

    /// Read-only against the real registry (works unelevated).
    #[test]
    fn reads_the_real_values() {
        for (key, value) in [SMART_NAME_RESOLUTION, PARALLEL_A_AAAA] {
            Hklm.read(key, value).expect("policy value readable");
        }
    }
}
