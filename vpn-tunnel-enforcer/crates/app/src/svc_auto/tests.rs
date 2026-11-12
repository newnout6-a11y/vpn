//! Automation wiring against fakes: the coordinator's owner rules over a fake lane, the session
//! and stop mapping, the verdict feed's mapping, the failover pick. Nothing here touches the
//! system (no registry, no proxy, no engine).
mod coord;
mod feed;
mod pure;
