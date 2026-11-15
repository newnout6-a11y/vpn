//! View models of the «Маршрутизация Happ» panel: a Happ routing profile (pasted, or the one a
//! subscription sent) previewed against the user's own rules, imported only on the user's click.
use vpnte_base::Msg;

/// Where a routing profile comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutingSource {
    /// A pasted `happ://routing/…` link, its base64 or the profile's JSON.
    Pasted(String),
    /// The profile the subscription with this group id sent.
    Subscription(String),
}

/// A subscription whose provider sent a routing profile (pushed with the page state).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingOffer {
    pub group_id: String,
    /// The subscription's name as the Servers page shows it.
    pub group: String,
    /// The profile's own name, when it has one.
    pub profile: Option<String>,
}

/// Where a rule sends traffic, as the Settings page's domain rules say it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RouteKind {
    Vpn,
    Direct,
    Block,
}

impl RouteKind {
    /// Catalog key of the short label («VPN», «Напрямую», «Блокировать»).
    pub const fn label_key(self) -> &'static str {
        match self {
            RouteKind::Vpn => "domainRouting.actionVpn",
            RouteKind::Direct => "domainRouting.actionDirect",
            RouteKind::Block => "domainRouting.actionBlock",
        }
    }
}

/// A rule the import adds to the user's list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreviewRule {
    /// The pattern as the Settings page shows it (`example.com`, `~word`).
    pub pattern: String,
    pub route: RouteKind,
}

/// Why an entry of the profile is not added.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryNote {
    /// The local network always goes direct.
    Local,
    /// The same rule is already in the user's list.
    Present,
    /// The user has a rule for this site with another route; the user's rule stays.
    YourRule(RouteKind),
    /// The profile names this site earlier.
    Repeated,
    /// A list (geosite / geoip / provider file) the app does not ship.
    NotShipped,
    /// An address or range: the user's list holds sites only.
    IpRule,
    /// A regular expression.
    Regexp,
    /// Not a site name.
    Invalid,
    /// Russian sites are Smart RU's: only a «direct» list switches it on.
    RussianSites,
}

impl EntryNote {
    /// Catalog key of the reason shown next to the entry.
    pub const fn key(self) -> &'static str {
        match self {
            EntryNote::Local => "splitTunneling.routing.noteLocal",
            EntryNote::Present => "splitTunneling.routing.notePresent",
            EntryNote::YourRule(_) => "splitTunneling.routing.noteYourRule",
            EntryNote::Repeated => "splitTunneling.routing.noteRepeated",
            EntryNote::NotShipped => "splitTunneling.routing.noteNotShipped",
            EntryNote::IpRule => "splitTunneling.routing.noteIpRule",
            EntryNote::Regexp => "splitTunneling.routing.noteRegexp",
            EntryNote::Invalid => "splitTunneling.routing.noteInvalid",
            EntryNote::RussianSites => "splitTunneling.routing.noteRussianSites",
        }
    }
}

/// An entry of the profile as written, with where it would send traffic and its note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreviewEntry {
    pub text: String,
    pub route: RouteKind,
    pub note: EntryNote,
}

/// The profile sends Russian sites direct: that is Smart RU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmartRuStep {
    /// Smart RU is off now and the import switches it on.
    pub turn_on: bool,
    /// The entries that ask for it (`geosite:category-ru`, `geoip:ru`).
    pub from: Vec<String>,
}

/// A setting of the profile that stays as the user has it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kept {
    /// `GlobalProxy` off: the provider sends what no list names direct; here it goes through
    /// the VPN.
    RestDirect,
    /// The profile's DNS servers, as written.
    Dns(String),
    /// Fixed DNS answers for this many names.
    DnsHosts(usize),
    /// FakeDNS on.
    FakeDns,
}

impl Kept {
    /// The line shown under «Не переносится».
    pub fn msg(&self) -> Msg {
        match self {
            Kept::RestDirect => Msg::new("splitTunneling.routing.keptRest"),
            Kept::Dns(servers) => {
                Msg::new("splitTunneling.routing.keptDns").arg("servers", servers)
            }
            Kept::DnsHosts(count) => {
                Msg::new("splitTunneling.routing.keptHosts").arg("count", count)
            }
            Kept::FakeDns => Msg::new("splitTunneling.routing.keptFakeDns"),
        }
    }
}

/// What importing a profile would do. Nothing has changed yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingPreview {
    /// Hands exactly this plan to `import_routing`.
    pub token: u64,
    pub name: Option<String>,
    /// The provider turns its routing off (`happ://routing/off`): nothing to import.
    pub off: bool,
    /// Rules appended to the user's list, in the profile's order.
    pub add: Vec<PreviewRule>,
    pub smart_ru: Option<SmartRuStep>,
    /// Entries that already work: the local network, rules the user has.
    pub covered: Vec<PreviewEntry>,
    /// Entries not imported, each with its reason.
    pub skipped: Vec<PreviewEntry>,
    /// Settings of the profile that stay as the user has them.
    pub kept: Vec<Kept>,
}

impl RoutingPreview {
    /// The import would change something.
    pub fn changes(&self) -> bool {
        !self.add.is_empty() || self.smart_ru.as_ref().is_some_and(|s| s.turn_on)
    }
}

/// What an import did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RoutingImported {
    /// Rules added to the user's list.
    pub added: usize,
    /// Rules left out because the list is full.
    pub over_limit: usize,
    /// Smart RU was switched on.
    pub smart_ru_on: bool,
}
