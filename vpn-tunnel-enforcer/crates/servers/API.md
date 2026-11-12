# vpnte-servers — API for dependent crates

The user's server list: groups (manual keys, one group per subscription URL + device), rows with
DPAPI-sealed typed profiles, the selection, archive and purge, key-health / country / ping results,
text and subscription import (fetch, parse, reconcile), the background refresh, and the one-time
Electron import. Depends on `vpnte-base`, `vpnte-core`, `vpnte-profiles`. The crate has no cargo
features.

```toml
vpnte-servers.workspace = true
```

| module | what |
| --- | --- |
| `model` | stored document `ServersDoc` (`profiles.json`), `ServerGroup`, `ServerRow`, outcomes / status, secret-free summaries |
| `store` | `Servers`: the one owner of the list (read, select, add, archive, groups, probe results), `ServersEvent` |
| `parse` | pasted text / subscription body -> `ParseReport` (deep links, base64 layers, JSON, Clash, `.conf`, links) |
| `subscription` | `SubscriptionFetcher` (routes, UA / HWID, redirects, DoH retry), canonical URL, outcome texts |
| `refresh` | `reconcile`, intervals, `add_from_input`, `refresh_group`, `sweep`, `spawn_scheduler`, `import_legacy_direct` |
| `legacy` | Electron `server-picker` / `server-groups` / `settings` -> `ServersDoc` + report |
| `LOCALES` | the crate's locale fragments, `&[(ru_json, en_json)]` |

**Elevation: nothing here needs it.** Files live under the data dir, DPAPI runs as the current user,
requests go out as the user (direct or through the user's / Happ's local proxy).
**Blocking vs async:** every `Servers` method that changes the list writes `profiles.json`
atomically and may call DPAPI; they are quick for normal lists, but run `Servers::open`,
`legacy::from_legacy` and `Servers::import_legacy` from `spawn_blocking` or at startup. The `refresh`
methods are async and need a tokio runtime (`spawn_scheduler` spawns onto the current one); they
parse fetched bodies and pasted text on tokio's blocking pool.
**Secrets:** keys and subscription URLs live only in `vpnte_core::secret::Secret` (sealed on disk,
redacted `Debug`); summaries, events, logs and errors never carry them.

## Wiring (app)

```rust
use std::sync::Arc;
use vpnte_servers::{legacy, refresh::RefreshCtx, store::Servers, subscription::*};

let servers = Arc::new(Servers::open(&dirs.root));                  // never fails; read-only -> notice()
let fetcher = Arc::new(SubscriptionFetcher::new(Hwids::current(), settings_store.clone()));
let ctx = RefreshCtx::new(fetcher, ops.clone());                     // ops: vpnte_core::ops::OperationRegistry
let scheduler = servers.spawn_scheduler(ctx.clone(), shutdown.clone()); // sweep after 10 s, then every 60 s
let mut events = servers.subscribe();                                // ServersEvent, see below
// locales: [vpnte_core::LOCALES, vpnte_profiles::LOCALES, vpnte_servers::LOCALES, …].concat()

// One-time Electron import (after vpnte_core::legacy opened the three documents):
let (doc, report) = legacy::from_legacy(picker.as_ref(), groups.as_ref(), settings.as_ref(), now_ms());
if servers.import_legacy(doc)? {                                     // false: the list had data already
    if let Some(direct) = &report.direct {                           // old single-key input, may fetch
        servers.import_legacy_direct(&ctx, direct, cancel.clone()).await?;
    }
}
```

UI actions map to: paste / «Add» -> `servers.add_from_input(&ctx, text, target_group, device,
cancel)`; «Refresh» -> `refresh_group(&ctx, &id, Owner::Manual, cancel)`; device change of a
subscription -> `set_group_device(&id, d)` then `refresh_group`; list -> `servers.view()`; connect ->
`servers.active()` then `active.row.profile()?` (the typed `Profile` for `emit_singbox`).

## model (`vpnte_servers::model`)

```rust
pub const ARCHIVE_TTL_MS: UnixMs;                         // 30 days: archived rows are purged after it
pub const GROUP_NAME_MAX_CHARS: usize;                    // 60
pub const REFRESH_OVERRIDE_MIN: RangeInclusive<u16>;      // 1..=1440 minutes
pub struct ProfileId(pub String);  pub struct GroupId(pub String);   // serde transparent, Electron ids kept
impl ProfileId / GroupId { pub fn random() -> Self; pub fn as_str(&self) -> &str }  // + Display, From<&str>, From<String>

pub struct ServersDoc { pub active_profile_id: Option<ProfileId>, pub groups: Vec<ServerGroup>,
                        pub profiles: Vec<ServerRow> }     // Document: "profiles.json", v1, holds secrets
impl ServersDoc {
    pub fn group(&self, &GroupId) -> Option<&ServerGroup>;     pub fn group_mut(..) -> Option<&mut ServerGroup>;
    pub fn row(&self, &ProfileId) -> Option<&ServerRow>;       pub fn row_mut(..) -> Option<&mut ServerRow>;
    pub fn manual_group(&self) -> Option<&ServerGroup>;        // by kind, never by name
    pub fn subscription_group(&self, url: &Url, device: ClientDevice) -> Option<&ServerGroup>; // group key
    pub fn ensure_manual_group(&mut self, now: UnixMs) -> GroupId;
}
pub struct ServerGroup { pub id: GroupId, pub name: String /* "" = default name */, pub kind: GroupKind,
    pub imported_at: UnixMs, pub refresh_override_min: Option<u16>, pub fetch: FetchState,
    pub info: vpnte_profiles::model::SubscriptionMeta /* traffic, expiry, title, links */ }
pub enum GroupKind { Manual, Subscription { url: Secret /* canonical http(s) URL */, device: ClientDevice } }
impl ServerGroup {
    pub fn manual(GroupId, now) -> Self;  pub fn is_manual(&self) -> bool;
    pub fn url(&self) -> Option<Url>;     // None: manual, locked secret, or not http(s)://host
    pub fn device(&self) -> Option<ClientDevice>;
    pub fn title(&self) -> Msg;           // the name, or servers.group.manualDefault / subscriptionDefault
    pub fn status(&self, now: UnixMs) -> GroupStatus;   // derived, never stored
}
pub struct FetchState { pub last_attempt_at, pub last_success_at: Option<UnixMs>,
                        pub last_outcome: Option<FetchOutcome>, pub last_count: Option<u32> }
pub enum FetchOutcome { Ok { partial: bool }, EmptyList, Unparseable(BodyKind), Http(u16), Network(NetFail), Timeout }
pub enum BodyKind { Html, Json, Base64, Uris, Other }      pub enum NetFail { Dns, Connect, Tls, Proxy, Reset }
pub enum GroupStatus { Unknown, Active, Expired, Unreachable, Failed }
// Unknown: manual / never fetched; Expired: plan date passed, empty list, HTTP 404/410;
// Failed: other HTTP or unusable body; Unreachable: network or timeout.
pub fn clean_group_name(name: &str) -> String;            // trim, collapse whitespace, <= 60 chars

pub enum Origin { Feed, Manual }        // only Feed rows are reconciled; keys pasted into a group are Manual
pub enum ArchiveReason { Provider, User }   pub struct Archived { pub at: UnixMs, pub reason: ArchiveReason }
pub enum CountrySource { ExitIp, HealthTrace, EntryIp, Legacy }
pub struct VerifiedCountry { pub iso2: Iso2, pub at: UnixMs, pub ip: Option<IpAddr>, pub source: CountrySource }
impl VerifiedCountry { pub fn supersedes(&self, old: &VerifiedCountry) -> bool }  // exit/trace > entry > legacy, then newer
pub struct HealthRecord { pub online: bool, pub at: UnixMs, pub rtt_ms: Option<u32>,
                          pub reason: Option<HealthReason>, pub egress_ip: Option<IpAddr> }
pub enum HealthReason { NoOutbound, ConfigFailed, TlsFailed, AuthFailed, Timeout, HandshakeFailed,
    Hy2ConfigFailed, Hy2AuthFailed, Hy2UdpBlocked, Hy2TlsFailed, Hy2HandshakeFailed,
    EngineSetting /* not a key fault: the engine setting does not run the key */ }
// the probes' classifier verdict (vpnte_probes::discipline::{Verdict, Reaction}, same wire names);
// a name this version does not know reads as Unknown instead of failing the whole list
pub enum ServerVerdict { Healthy, Frozen, Stalled, HandshakeFailed, KeyRejected, IpBanned, UdpBlocked,
    Offline, Deferred, NotVerified, Unknown }                  // kebab-case
pub enum ServerReaction { None, SwitchServer, TryAnotherFingerprint, PreferTcpTransport, RetryLater, Unknown }
pub struct VerdictRecord { pub verdict: ServerVerdict, pub reaction: ServerReaction, pub at: UnixMs }  // camelCase
pub struct ServerRow { pub id: ProfileId, pub group_id: GroupId, pub origin: Origin,
    pub name: String, pub protocol: String, pub server: String, pub port: u16,   // plain copies
    pub device: ClientDevice, pub engine: EnginePref /* own engine; Auto (omitted) = the setting */,
    pub profile: Secret /* the typed Profile as JSON */, pub imported_at: UnixMs,
    pub last_seen_at, pub missing_since: Option<UnixMs>, pub archived: Option<Archived>,
    pub country: Option<VerifiedCountry>, pub health: Option<HealthRecord>,
    pub verdict: Option<VerdictRecord> /* beside health: may come from another check, compare `at` */ }
impl ServerRow {
    pub fn new(&Profile, GroupId, Origin, ClientDevice, now) -> AppResult<Self>;
    pub fn profile(&self) -> AppResult<Profile>;    // Conflict servers.locked (other PC / account), Internal servers.unreadable
    pub fn set_profile(&mut self, &Profile) -> AppResult<()>;   // also refreshes the plain copies
    pub fn identity(&self) -> Option<[u8; 16]>;  pub fn is_locked(&self) -> bool;
    pub fn archived_for(&self, ArchiveReason) -> bool;
    pub fn claimed_country(&self) -> Option<Iso2>;   // from the name (derived)
    pub fn display_country(&self) -> Option<Iso2>;   // verified, else claimed
    pub fn purge_at(&self) -> Option<UnixMs>;
}
// Secret-free view types (what lists render):
pub struct Ping { pub rtt_ms: Option<u32> /* None: no answer */, pub at: UnixMs }   // memory only
pub struct ServerSummary { id, group_id, origin, name, protocol, server, port, device, engine,
    country: Option<Iso2>, country_verified: bool, missing_since, archived, purge_at, health,
    ping: Option<Ping>, locked: bool, selected: bool }          // all pub
pub struct GroupSummary { id, name, title: Msg, manual: bool, device: Option<ClientDevice>,
    host: Option<String> /* never the URL */, url_locked: bool, status: GroupStatus, imported_at,
    fetch: FetchState, info: SubscriptionMeta, refresh_override_min, servers: usize, archived: usize }
pub struct ServersView { pub groups: Vec<GroupSummary>, pub servers: Vec<ServerSummary>,
    pub active: Option<ProfileId>, pub fallback: bool, pub notice: Option<Msg> }
impl ServerSummary { pub fn of(&ServerRow, Option<Ping>, selected: bool) -> Self }
impl GroupSummary { pub fn of(&ServerGroup, rows: &[ServerRow], now: UnixMs) -> Self }
```
Stored serde shapes (camelCase, kebab-case enums, `{"ok":{"partial":true}}`, `{"http":404}`) are
the on-disk format: change them only additively.

## store (`vpnte_servers::store`)

```rust
pub struct Servers;                                         // Send + Sync, share in Arc
impl Servers {
    pub fn open(root: &Path) -> Self;                       // <root>\profiles.json; purges archive > 30 d if writable
    pub fn subscribe(&self) -> broadcast::Receiver<ServersEvent>;
    pub fn read<R>(&self, f: impl FnOnce(&ServersDoc) -> R) -> R;   // no lock held after it returns
    pub fn mode(&self) -> vpnte_core::store::Mode;  pub fn notice(&self) -> Option<Msg>;  // read-only / set aside
    pub fn set_aside(&self) -> AppResult<()>;               // maintenance: move a broken file aside, start empty
    // reading and selection
    pub fn view(&self) -> ServersView;
    pub fn get(&self, &ProfileId) -> Option<ServerRow>;
    pub fn active(&self) -> Option<Active>;                 // selection unless user-removed, else first usable row
    pub fn select(&self, &ProfileId, SelectBy) -> AppResult<ServerRow>;   // bumps geo_generation
    pub fn geo_generation(&self) -> u64;
    pub fn find_subscription(&self, &Url, ClientDevice) -> Option<GroupId>;
    pub fn all_hosts(&self) -> Vec<String>;                 // lower case, de-duplicated (traffic-history filter)
    // adding
    pub fn add(&self, Vec<Profile>, AddTarget) -> AppResult<AddReport>;
    pub fn import_legacy(&self, ServersDoc) -> AppResult<bool>;          // adopts only into an empty list
    // archive, groups, devices
    pub fn remove(&self, &ProfileId) -> AppResult<()>;      // soft delete: archived{user}, selection cleared
    pub fn restore(&self, &ProfileId) -> AppResult<()>;
    pub fn purge(&self, &ProfileId) -> AppResult<()>;       // delete now
    pub fn purge_expired(&self, now: UnixMs) -> AppResult<usize>;
    pub fn rename_group(&self, &GroupId, &str) -> AppResult<()>;          // empty name: no change
    pub fn delete_group(&self, &GroupId, delete_servers: bool) -> AppResult<()>;  // false: rows -> manual group
                                        // (a key it already holds is not doubled: that copy goes, a selection follows)
    pub fn set_refresh_override(&self, &GroupId, Option<u16>) -> AppResult<()>;   // minutes 1..=1440 / None
    pub fn set_group_device(&self, &GroupId, ClientDevice) -> AppResult<()>;      // feed rows follow; refresh next
    pub fn set_profile_device(&self, &ProfileId, ClientDevice) -> AppResult<()>;  // manual rows only
    pub fn set_profile_engine(&self, &ProfileId, EnginePref) -> AppResult<()>;   // any row; kept by refreshes
    // probe results
    pub fn record_health(&self, Vec<HealthUpdate>) -> AppResult<usize>;  // skips rows deleted / re-keyed meanwhile
    pub fn record_verdicts(&self, Vec<VerdictUpdate>) -> AppResult<usize>;  // same guards; an older verdict never wins
    pub fn verdicts(&self) -> HashMap<ProfileId, VerdictRecord>;         // rows that have one (page, automation)
    pub fn record_country(&self, &ProfileId, VerifiedCountry, expected_generation: u64) -> AppResult<bool>;
    pub fn record_ping(&self, &ProfileId, rtt_ms: Option<u32>);          // memory only
}
pub enum SelectBy { User, Automation }   // user may pick provider-archived rows, automation no archived row
pub struct Active { pub row: ServerRow, pub fallback: bool /* not the user's selection: say so */ }
pub enum AddTarget { Keys { group: Option<GroupId> /* None: manual group */, device: ClientDevice },
                     Subscription(Box<NewSubscription>) }
pub struct NewSubscription { pub url: Url /* canonical */, pub device: ClientDevice,
                             pub info: SubscriptionMeta, pub partial: bool }
pub struct AddReport { pub group: GroupId, pub added: Vec<ProfileId>, pub restored: Vec<ProfileId>,
                       pub duplicates: usize, pub selected: Option<ProfileId> /* set when nothing was selected */ }
pub struct HealthUpdate { pub id: ProfileId, pub identity: [u8; 16] /* row.identity() at probe start */,
                          pub record: HealthRecord, pub country: Option<VerifiedCountry> }
pub struct VerdictUpdate { pub id: ProfileId, pub identity: [u8; 16], pub record: VerdictRecord }
pub fn subscription_name(url: &Url, info: &SubscriptionMeta) -> String;   // title > web-page host > URL host > ""
```
Every change is applied under the store's writer lock and written through before listeners hear
of it; an `Err` from inside a change rolls it back completely. Duplicates are detected by
`Profile::identity()` within the target group only; re-adding a removed key restores its row.
Country lookups: read `geo_generation()` before the lookup and pass it back to `record_country`
(a selection made meanwhile discards the result).

### Events (`Servers::subscribe`)
```rust
pub enum ServersEvent {
    Changed,                            // groups or rows changed: re-read view()
    ActiveChanged(Option<ProfileId>),   // the stored selection changed (None: cleared -> active() falls back)
    Ping(ProfileId),                    // a ping was recorded (memory only)
    RefreshStarted(GroupId),            // a fetch of this group began (show a spinner)
    RefreshFinished(GroupId),           // ...ended, success or not: re-read the group's fetch / status
}
```
Events carry ids only; on `RecvError::Lagged` re-read `view()`. Nothing else pushes.

## parse (`vpnte_servers::parse`): pure, synchronous

```rust
pub const MAX_PROFILES: usize;   // 5000 per text: the cut leaves a skipped entry (never "complete")
pub const MAX_SKIPPED: usize;    // 5000 listed, further problems summed into one entry
pub fn parse_text(input: &str) -> Result<ParseReport, TooLarge>;   // paste, <= 1 MiB; never fetches
pub fn parse_body(raw: &[u8]) -> Result<ParseReport, TooLarge>;    // subscription body, <= 16 MiB (gzip/zlib/brotli/UTF-16)
pub fn too_large(limit: usize) -> AppError;                         // Validation servers.parse.tooLarge {mib}
pub fn no_profiles(report: &ParseReport) -> AppError;               // lone skip -> its reason, else allSkipped / nothingFound
```
`ParseReport { profiles, skipped: Vec<Skipped { excerpt /* redacted */, reason }>, meta }` comes from
`vpnte_profiles::model`; show a skip reason with `vpnte_profiles::caps::skip_msg(&reason)`. A deep
link that carries a subscription URL is one skipped entry here: route user input through
`Servers::add_from_input`, which fetches.

## subscription (`vpnte_servers::subscription`)

```rust
pub const REQUEST_TIMEOUT: Duration;   // 25 s per request (connect <= 10 s)
pub const MAX_REQUESTS: usize;         // 6 = first request + 5 redirects
pub const DOH_MAX_IPS: usize;          // 3 pinned addresses for the DoH retry
pub struct Hwids;                      // Clone, Eq; Debug prints "Hwids(..)"
impl Hwids {
    pub fn current() -> Self;          // env VPNTE_SUBSCRIPTION_HWID, else the Electron app's hash
    pub fn of(id: &MachineIdentity, fixed: Option<String>) -> Self;
    pub fn get(&self, device: ClientDevice) -> &str;
}
pub struct RoutePlan { pub routes: Vec<vpnte_core::net::Route>, pub doh: bool }
pub fn route_plan(settings: &Settings) -> RoutePlan;   // auto: direct, user proxy, socks5h 10808, http 10809
pub struct SubscriptionFetcher;                        // share in Arc
impl SubscriptionFetcher {
    pub fn new(hwids: Hwids, settings: Arc<Store<Settings>>) -> Self;   // routes re-read at every fetch
    pub fn with_plan(hwids: Hwids, plan: RoutePlan) -> Self;           // fixed routes (probes, tests)
    pub fn plan(&self) -> RoutePlan;
    pub async fn fetch(&self, url: &Url, device: ClientDevice, cancel: &CancellationToken)
        -> Result<ParseReport, FetchError>;   // Ok has >= 1 profile; meta = headers over body `#key:` lines
}
pub enum FetchError { Failed(FetchOutcome), InvalidUrl, Cancelled }   // Copy; From<FetchError> for AppError
pub fn outcome_msg(outcome: FetchOutcome) -> Msg;     // group status line (servers.fetch.*)
pub fn is_complete(report: &ParseReport) -> bool;      // only Duplicate skips: absence is evidence
pub fn canonical_source(input: &str) -> Option<Url>;   // URL / happ:// / mantaray:// -> http(s) URL, no fragment
pub fn normalize_redirect(location: &str, base: &Url) -> Option<String>;
pub fn classify_body(body: &str) -> FetchOutcome;      // EmptyList | Unparseable(kind)
```
Plan: each route in turn (a transport failure moves to the next route); on a route that answers,
every User-Agent of the device with the HWID headers, then without; 429, or 404/410 to every
identified request, stops; then one DoH-pinned direct retry for domain hosts (not in local-proxy
mode). Redirects are followed by hand: `https -> http` and public -> private hops are refused.
Failure = strongest evidence: empty list > unusable body > HTTP 4xx > other HTTP > network > timeout.
Logs carry host, route label and agent family only (never path, query, HWID or headers).

## refresh (`vpnte_servers::refresh`)

```rust
pub const DEFAULT_INTERVAL: Duration;                    // 30 min
pub const PROVIDER_INTERVAL: (Duration, Duration);       // 15 min ..= 24 h (provider value in hours)
pub const OVERRIDE_INTERVAL: (Duration, Duration);       // 1 min ..= 24 h (user override in minutes)
pub const FIRST_SWEEP_DELAY: Duration;  pub const SWEEP_PERIOD: Duration;   // 10 s / 60 s
pub const MISSING_GRACE_MS: UnixMs;                      // 15 min missing before a provider archive
pub fn refresh_interval(group: &ServerGroup) -> Duration;
pub fn is_due(group: &ServerGroup, now: UnixMs) -> bool;
pub fn reconcile(group: &ServerGroup, rows: &mut Vec<ServerRow>, fresh: Vec<Profile>, complete: bool,
                 now: UnixMs) -> AppResult<RefreshReport>;   // pure; never touches the selection
pub struct RefreshReport { pub added: Vec<ProfileId>, pub updated: usize, pub restored: usize,
                           pub archived: usize, pub pending_absent: usize, pub partial: bool }
#[derive(Clone)] pub struct RefreshCtx { pub fetcher: Arc<SubscriptionFetcher>, pub ops: OperationRegistry,
                                         pub deadline: Duration /* 120 s */ }
impl RefreshCtx { pub fn new(fetcher: Arc<SubscriptionFetcher>, ops: OperationRegistry) -> Self }
pub enum AddOutcome { Added { report: AddReport, skipped: Vec<Skipped> },
                      Refreshed { group: GroupId, report: RefreshReport } }
pub struct SweepReport { pub refreshed: usize, pub failed: usize }
impl Servers {
    pub async fn add_from_input(self: &Arc<Self>, ctx: &RefreshCtx, input: &str, into: Option<GroupId>,
                                device: ClientDevice, cancel: CancellationToken) -> AppResult<AddOutcome>;
    pub async fn refresh_group(self: &Arc<Self>, ctx: &RefreshCtx, id: &GroupId, owner: Owner,
                               cancel: CancellationToken) -> AppResult<RefreshReport>;
    pub async fn import_legacy_direct(self: &Arc<Self>, ctx: &RefreshCtx, direct: &LegacyDirect,
                                      cancel: CancellationToken) -> AppResult<Option<AddOutcome>>;
    pub async fn sweep(self: &Arc<Self>, ctx: &RefreshCtx, cancel: &CancellationToken) -> SweepReport;
    pub fn spawn_scheduler(self: &Arc<Self>, ctx: RefreshCtx, shutdown: CancellationToken) -> JoinHandle<()>;
}
```
`add_from_input`: a subscription URL (plain or in a `happ://` / `mantaray://` link) is fetched as
`device`: known for that device -> that group is refreshed (`Refreshed`); `into: Some(g)` -> its
keys are appended to `g` as manual rows; else a new subscription group. Any other text is parsed
and added to `into` or the manual group; `skipped` lists entries that were not imported.
`refresh_group` runs as operation `refresh:<id>` (`FeatureKind::Refresh`, 120 s; `Owner::Manual`
pre-empts a scheduled run, an equal owner gets `core.ops.busy`). A failure stores its typed outcome
and changes no row; a cancel stores nothing more; the deadline stores `Timeout`. After a success the
provider metadata replaces `info`, and the provider title renames the group only while its name is
an automatic one (empty, a host, or the provider's previous title). Missing keys: kept while the
answer is partial, archived for the provider after 15 min of complete answers without them; a
provider-archived key that comes back is restored; a key whose host, port or credential changed
loses its `health` and `verdict`; a key the group already holds as a manual row is not added
again as a feed row; the selection is never changed by a refresh.
A stamp from the future (wrong clock) makes a group due instead of blocking it.
`import_legacy_direct`: the old single-key input goes in like a paste as `pc`, and the old selected
index (clamped) becomes the selection; only into an empty list (`Ok(None)` otherwise).

## legacy (`vpnte_servers::legacy`)

```rust
pub fn from_legacy(picker: Option<&Value>, groups: Option<&Value>, settings: Option<&Value>, now: UnixMs)
    -> (ServersDoc, LegacyReport);   // inputs: the opened server-picker / server-groups / settings documents
pub struct LegacyReport { pub imported: usize, pub groups: usize, pub locked: usize /* needed the old key */,
                          pub skipped: Vec<LegacySkip>, pub direct: Option<LegacyDirect> }
pub struct LegacySkip { pub name: String /* display name, never a key */, pub reason: Msg }
pub struct LegacyDirect { pub input: Secret /* settings.directVpnInput */, pub selected: usize }
```
Inputs come from `vpnte_core::legacy` (secrets already plain, a locked stand-in or `null`). Ids are
kept; the first manual group absorbs other manual groups, subscriptions whose URL is not
`http(s)://host` and rows of unknown groups; mixed-device subscriptions are split per device
(` · android` etc.); subscription URLs are stored canonical (deep link unwrapped, fragment dropped),
and old groups that share a canonical URL are merged into the first of them;
every key is re-sealed and verified. With an empty picker an accepted settings cache becomes rows;
otherwise a non-empty `directVpnInput` is handed on in `direct` for `Servers::import_legacy_direct`.
Nothing under the old data directory is written.

## Errors and i18n keys

Register `vpnte_servers::LOCALES` at start (with `vpnte_core::LOCALES` and `vpnte_profiles::LOCALES`:
skip reasons and legacy row errors use `profiles.*`, store / registry errors `core.*`, cancel and
timeout the base `errors.*`). Every `Msg` this crate returns has its key under `servers.`:

| Key | Args | Kind / where |
| --- | --- | --- |
| `servers.notFound` | — | `Conflict`: row gone (`select`, `remove`, `restore`, `purge`, `set_profile_device`) |
| `servers.locked` | — | `Conflict`: key / URL sealed under another PC or account (`ServerRow::profile`, `select`, `set_group_device`, `import_legacy_direct`) |
| `servers.unreadable` | — | `Internal`: stored key damaged (`ServerRow::profile`) |
| `servers.deviceFollowsGroup` | — | `Validation`: `set_profile_device` on a feed row |
| `servers.select.archived` | — | `Conflict`: `select` of a user-removed row (or any archived row by automation) |
| `servers.group.title` | `name` | `ServerGroup::title` / `GroupSummary::title` (user / provider name) |
| `servers.group.{manualDefault,subscriptionDefault}` | — | default group names (`title`) |
| `servers.group.notFound` | — | `Conflict`: group gone (group edits, `add` into a group, `refresh_group`) |
| `servers.group.keepManual` | — | `Validation`: `delete_group(manual, false)` |
| `servers.group.overrideInvalid` | — | `Validation`: override outside 1..=1440 |
| `servers.group.manualNoRefresh` | — | `Validation`: override / refresh of the manual group |
| `servers.group.manualNoDevice` | — | `Validation`: `set_group_device` on the manual group |
| `servers.group.deviceTaken` | — | `Conflict`: that URL already has a group for the device |
| `servers.legacy.{groupUnreadable,rowUnreadable,noOutbound,sealFailed}` | — | `LegacySkip::reason` |
| `servers.parse.tooLarge` | `mib` | `Validation`: paste over 1 MiB (`too_large`) |
| `servers.parse.nothingFound` | — | `Validation`: nothing importable (`no_profiles`, `add` with no profiles) |
| `servers.parse.allSkipped` | `count` | `Validation`: every entry skipped (`no_profiles`) |
| `servers.parse.damagedBase64` | — | `Validation`: the lone entry is a base64 blob that does not decode (`no_profiles`) |
| `servers.fetch.{ok,partial,emptyList,timeout}` | — | `outcome_msg`; `emptyList` (`Validation`), `timeout` (`Timeout`) as fetch errors |
| `servers.fetch.body.{html,json,base64,uris,other}` | — | `outcome_msg(Unparseable(kind))`; `Validation` |
| `servers.fetch.http` | `code` | `outcome_msg(Http(code))`; `Network` |
| `servers.fetch.net.{dns,connect,tls,proxy,reset}` | — | `outcome_msg(Network(fail))`; `Network` |
| `servers.fetch.invalidUrl` | — | `Validation`: `FetchError::InvalidUrl` |
| `servers.refresh.groupChanged` | — | `Conflict`: group deleted or re-pointed while its fetch ran |
| `servers.refresh.unusableUrl` | — | `Validation`: subscription URL locked or not `http(s)://host` |

Also passed through: `core.store.readOnly` (`Conflict`, document read-only), `core.ops.busy`
(`Conflict`, the same refresh / import is running), `errors.cancelled` (`Cancelled`: user cancel or
pre-emption, show nothing), `errors.timeout` (`Timeout`: the 120 s budget), deep-link errors
(`DeepLinkError::msg`, `profiles.*`) from `add_from_input`.

## Not implemented / not run

- Not run: the DoH-pinned retry (needs public DoH servers), redirect checks that resolve names with
  the system DNS, a successful HTTPS fetch, Happ's real local proxies (stand-ins on loopback are
  tested). Everything else ran: 104 tests (loopback HTTP, real DPAPI, temp dirs).
- HWIDs are computed at start (`Hwids::current`), not persisted. Identical concurrent fetches are not
  coalesced (the registry serialises them per group / import). Pings are never persisted. Events
  carry ids only. A group has one device (old groups with several devices are split on import).
- The persistent `profiles.json` keeps no ping, no `enabled`, no resolved IPs, no old status texts.
