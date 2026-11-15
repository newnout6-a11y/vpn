//! Routing and DNS policy: the user's rules document (`rules.json`), the validated pattern and
//! address types, the Smart RU lists, the pure [`build`] that turns them into sing-box route /
//! DNS fragments in the owner's fixed order, domain-rule hit counting, and the managed Smart RU
//! rule-set refresh.
//!
//! Nothing here starts engines or touches the network stack; `rulesets` downloads files and runs
//! `sing-box rule-set match` for validation, everything else is pure data.

pub mod bypass;
pub mod dns;
pub mod doc;
pub mod domain;
pub mod hits;
mod matcher;
pub mod plan;
pub mod process;
pub mod rulesets;
pub mod smart_ru;

pub use doc::RulesDoc;
pub use plan::{RoutingFragments, RoutingInputs, RoutingWarning, build};
