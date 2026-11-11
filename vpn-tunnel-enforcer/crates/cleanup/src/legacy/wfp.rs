//! The old app's persistent WFP IPv6 policy (spec §2.4, §6.6 step 4): every filter in the
//! legacy sublayer on its three layers, whatever its shape (the old helper refused to touch
//! filters it did not recognise, so a damaged policy could never be removed before), then the
//! sublayer itself when it carries the old display name.
use vpnte_winnet::wfp::{Engine, LEGACY_IPV6_SUBLAYER, Layer, ListQuery};

use super::report::{Outcome, StepId, StepRecord};

/// Display name the old helper gave its sublayer.
pub(crate) const LEGACY_SUBLAYER_NAME: &str = "VPNTE.IPv6.v1";
const LAYERS: [Layer; 3] = [Layer::Connect6, Layer::Accept6, Layer::OutboundIpPacket6];

/// Step 4 (needs elevation). Filters go in one transaction; the sublayer separately, so a
/// sublayer still referenced elsewhere does not keep the filters alive.
pub(crate) fn clean() -> StepRecord {
    let step = StepId::LegacyWfp;
    let engine = match Engine::open_persistent() {
        Ok(engine) => engine,
        Err(e) => return StepRecord::new(step, Outcome::Failed, format!("BFE unavailable: {e}")),
    };
    let filters = engine.transaction(|e| {
        let mut deleted = 0usize;
        for layer in LAYERS {
            for filter in e.list(&ListQuery {
                layer,
                provider: None,
            })? {
                if filter.sublayer == LEGACY_IPV6_SUBLAYER {
                    e.delete(filter.id)?;
                    deleted += 1;
                }
            }
        }
        Ok(deleted)
    });
    let deleted = match filters {
        Ok(n) => n,
        Err(e) => {
            return StepRecord::new(step, Outcome::Failed, format!("filters not removed: {e}"));
        }
    };
    let sublayer = engine
        .sublayer(&LEGACY_IPV6_SUBLAYER)
        .and_then(|s| match s {
            Some(s) if s.name == LEGACY_SUBLAYER_NAME => engine
                .delete_sublayer(&LEGACY_IPV6_SUBLAYER)
                .map(|()| Some(true)),
            Some(s) => {
                tracing::warn!(name = %s.name, "legacy WFP sublayer key with a foreign name kept");
                Ok(Some(false))
            }
            None => Ok(None),
        });
    let filters = format!("{deleted} legacy IPv6 filters removed");
    match sublayer {
        Ok(None) => StepRecord::new(
            step,
            Outcome::Done,
            format!("{filters}; no legacy sublayer"),
        )
        .changed(deleted > 0),
        Ok(Some(true)) => {
            StepRecord::new(step, Outcome::Done, format!("{filters}; sublayer removed"))
                .changed(true)
        }
        Ok(Some(false)) => {
            let detail = format!("{filters}; sublayer with a foreign name kept");
            StepRecord::new(step, Outcome::Skipped, detail).changed(deleted > 0)
        }
        Err(e) => StepRecord::new(step, Outcome::Failed, format!("{filters}; sublayer: {e}"))
            .changed(deleted > 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Acts on this machine: deletes only objects in the old app's sublayer (normally none).
    #[test]
    #[ignore = "needs elevation"]
    fn elevated_removes_the_legacy_policy() {
        let record = clean();
        assert_ne!(record.outcome, Outcome::Failed, "{}", record.detail);
    }
}
