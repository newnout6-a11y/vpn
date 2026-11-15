//! Small readers shared by several work packages (one helper per concept): strict base64,
//! display names, server addresses and ports, WireGuard field values, uTLS names.
//! Crate-private; public paths that expose one of them re-export it (`text::decode_base64_layer`).
pub mod b64;
pub mod fields;
pub mod wg;
