//! The demo's Happ routing: one subscription offering a Russian provider's profile and a canned
//! preview for anything pasted (`happ://routing/off` previews as «off»).
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};

use crate::split_tunnel::routing::{
    EntryNote, Kept, PreviewEntry, PreviewRule, RouteKind, RoutingImported, RoutingOffer,
    RoutingPreview, RoutingSource, SmartRuStep,
};

/// The subscriptions with a profile in `scene`.
pub(super) fn offers(scene: &str) -> Vec<RoutingOffer> {
    match scene {
        "empty" | "loading" | "failed" => Vec::new(),
        _ => vec![RoutingOffer {
            group_id: "g1".into(),
            group: "Demo VPN".into(),
            profile: Some("Simple-RU-routing".into()),
        }],
    }
}

/// The preview of `source` under `token`, with Smart RU `smart_on` now.
pub(super) fn preview(source: &RoutingSource, token: u64, smart_on: bool) -> RoutingPreview {
    let empty = RoutingPreview {
        token,
        name: None,
        off: false,
        add: Vec::new(),
        smart_ru: None,
        covered: Vec::new(),
        skipped: Vec::new(),
        kept: Vec::new(),
    };
    if let RoutingSource::Pasted(text) = source
        && text.trim().eq_ignore_ascii_case("happ://routing/off")
    {
        return RoutingPreview { off: true, ..empty };
    }
    let entry = |text: &str, route, note| PreviewEntry {
        text: text.into(),
        route,
        note,
    };
    RoutingPreview {
        name: Some("Simple-RU-routing".into()),
        add: ["connectivitycheck.gstatic.com", "www.gstatic.com"]
            .map(|pattern| PreviewRule {
                pattern: pattern.into(),
                route: RouteKind::Vpn,
            })
            .into(),
        smart_ru: Some(SmartRuStep {
            turn_on: !smart_on,
            from: vec!["geosite:category-ru".into(), "geoip:ru".into()],
        }),
        covered: vec![
            entry("geosite:private", RouteKind::Direct, EntryNote::Local),
            entry("geoip:private", RouteKind::Direct, EntryNote::Local),
        ],
        skipped: vec![
            entry("geosite:youtube", RouteKind::Vpn, EntryNote::NotShipped),
            entry(
                "geosite:category-ban-ru",
                RouteKind::Vpn,
                EntryNote::NotShipped,
            ),
            entry("geosite:apple", RouteKind::Direct, EntryNote::NotShipped),
            entry("geosite:twitch", RouteKind::Direct, EntryNote::NotShipped),
            entry("203.0.113.0/24", RouteKind::Direct, EntryNote::IpRule),
        ],
        kept: vec![Kept::Dns("94.140.14.14, 94.140.15.15".into())],
        ..empty
    }
}

/// What importing `preview` does; `None` when `token` is not the latest preview.
pub(super) fn import(preview: Option<&RoutingPreview>, token: u64) -> AppResult<RoutingImported> {
    let preview = preview.filter(|p| p.token == token).ok_or_else(|| {
        AppError::msg(
            ErrorKind::Conflict,
            Msg::new("splitTunneling.routing.stale"),
        )
    })?;
    Ok(RoutingImported {
        added: preview.add.len(),
        over_limit: 0,
        smart_ru_on: preview.smart_ru.as_ref().is_some_and(|s| s.turn_on),
    })
}
