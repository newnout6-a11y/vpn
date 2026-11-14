//! Update channel for the app, its engines and the helper service: one feed (`update.json`)
//! signed with our own Ed25519 key in the minisign format, verified against the keys compiled
//! in here, the downloader that fetches what the feed lists (through the running session first),
//! and the store of downloaded engines. The app wires it (`vpnte-app::svc_update`); the elevated
//! pin check of `vpnte-engine` and the helper service use the same verification. No user-facing
//! text is formatted here: the app maps the outcomes to its own messages.

pub mod check;
pub mod dirs;
pub mod download;
pub mod feed;
pub mod fetch;
pub mod net;
pub mod pending;
pub mod policy;
pub mod store;
pub mod version;

#[cfg(test)]
mod test_support;
