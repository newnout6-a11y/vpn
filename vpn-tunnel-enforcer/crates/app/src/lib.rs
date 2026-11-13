//! VPN Tunnel Enforcer application: builds the backend out of the library crates, implements the
//! UI's API traits over it and runs the Dioxus shell.

pub mod api_dashboard;
pub mod api_lists;
pub mod api_logs;
pub mod api_maintenance;
pub mod api_servers;
pub mod api_settings;
pub mod api_tools;
pub mod args;
pub mod boot;
pub mod crash_watch;
pub mod import;
pub mod restore;
pub mod root;
pub mod services;
pub mod setup;
pub mod support;
pub mod svc_auto;
pub mod svc_core;
pub mod svc_live;
pub mod svc_proxies;
pub mod svc_tunnel;
