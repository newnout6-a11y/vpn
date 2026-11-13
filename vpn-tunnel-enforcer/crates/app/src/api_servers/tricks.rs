//! The detail editor's TLS tricks (item 18): what the key runs with, as the editor's choice, and
//! the user's pick stored on the row ([`RowTricks`]). Keys that cannot take tricks on both engines
//! (no TLS over TCP, REALITY, QUIC, naive, ShadowTLS, a provider Xray graph, no server name in
//! the hello) get no editor.
use std::sync::Arc;

use vpnte_base::AppResult;
use vpnte_base::types::AdaptiveMode;
use vpnte_profiles::model::{HelloSplit, Profile, Span, TlsTricks};
use vpnte_servers::model::{ProfileId, RowTricks};
use vpnte_ui::servers::{TricksChoice, TricksSplit, TricksView};

use super::{Shared, reconnect_live, server_not_found};
use crate::support::blocking;

/// The editor's view of `id`; `None` when the key takes no tricks.
pub(super) async fn view(shared: Arc<Shared>, id: ProfileId) -> AppResult<Option<TricksView>> {
    let row = shared
        .backend
        .servers
        .get(&id)
        .ok_or_else(server_not_found)?;
    let profile = blocking(move || row.profile().map(|p| (row, p))).await;
    let (row, profile) = profile?;
    if !profile.takes_tls_tricks() {
        return Ok(None);
    }
    let tls_compat = tls_compat(&shared);
    let choice = match row.tls_tricks {
        None => key_choice(&profile, tls_compat),
        Some(RowTricks::Default) => TricksChoice::Default,
        Some(RowTricks::Set(tricks)) => choice_of(tricks),
    };
    Ok(Some(TricksView {
        choice,
        default_strong: tls_compat,
    }))
}

/// Stores the user's pick; the pick that equals what the key brings itself stores nothing, so the
/// key keeps following its provider. The connected server reconnects with it.
pub(super) async fn set(shared: Arc<Shared>, id: ProfileId, choice: TricksChoice) -> AppResult<()> {
    let servers = shared.backend.servers.clone();
    let row = servers.get(&id).ok_or_else(server_not_found)?;
    let profile = blocking(move || row.profile()).await?;
    let own = key_choice(&profile, tls_compat(&shared));
    let stored = (choice != own).then(|| row_tricks(choice));
    let target = id.clone();
    blocking(move || servers.set_tls_tricks(&target, stored)).await?;
    shared.publish();
    reconnect_live(&shared, id).await
}

/// Stealth or the session's adaptive TLS compatibility: the app default is «Сильно».
fn tls_compat(shared: &Shared) -> bool {
    let stealth = shared.backend.settings.read(|s| s.stealth_mode);
    let adaptive = shared.backend.tunnel().ok().and_then(|t| {
        let session = t.session().borrow().clone();
        session.map(|s| s.adaptive == AdaptiveMode::TlsCompatibility)
    });
    stealth || adaptive == Some(true)
}

/// What the key brings itself, as the editor shows it: a link's value as given; pasted sing-box
/// keys add to the default, so they show as what they run with.
fn key_choice(profile: &Profile, tls_compat: bool) -> TricksChoice {
    if let Some(typed) = profile.tls.as_ref().and_then(|t| t.tricks) {
        return choice_of(typed);
    }
    match profile.own_tls_tricks() {
        Some(_) if profile.tls_tricks_for(tls_compat) != profile.tls_tricks_for(false) => {
            TricksChoice::Default
        }
        Some(pasted) => choice_of(pasted),
        None => TricksChoice::Default,
    }
}

/// Off / «Мягко» / «Сильно» for the presets, the value itself otherwise.
fn choice_of(tricks: TlsTricks) -> TricksChoice {
    match tricks {
        TlsTricks::Off => TricksChoice::Off,
        TlsTricks::Record => TricksChoice::Soft,
        TlsTricks::STRONG => TricksChoice::Strong,
        TlsTricks::Hello(split) => custom(false, split),
        TlsTricks::Both(split) => custom(true, split),
    }
}

fn custom(record: bool, split: HelloSplit) -> TricksChoice {
    let pair = |s: Span| (s.min, s.max);
    TricksChoice::Custom {
        record,
        split: TricksSplit {
            len: pair(split.len),
            interval_ms: pair(split.interval_ms),
        },
    }
}

fn row_tricks(choice: TricksChoice) -> RowTricks {
    let span = |(min, max): (u16, u16)| Span::new(min, max);
    RowTricks::Set(match choice {
        TricksChoice::Default => return RowTricks::Default,
        TricksChoice::Off => TlsTricks::Off,
        TricksChoice::Soft => TlsTricks::Record,
        TricksChoice::Strong => TlsTricks::STRONG,
        TricksChoice::Custom { record, split } => {
            let split = HelloSplit {
                len: span(split.len),
                interval_ms: span(split.interval_ms),
            };
            if record {
                TlsTricks::Both(split)
            } else {
                TlsTricks::Hello(split)
            }
        }
    })
}
