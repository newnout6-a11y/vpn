# vpnte-update — API for dependent crates

The update channel (package p-updates; research/updates.md §4): one feed `update.json` signed
with our own Ed25519 key in the minisign format (`update.json.minisig`, prehashed), the downloader
of what it lists, and the store of downloaded engines. Depends on `vpnte-base`, `vpnte-core`.
Used by `vpnte-engine` (elevated pin check), `vpnte-app` (`svc_update`, `svc_core` engine paths)
and, later, the helper service (its own update through the feed's `service` entry).

```toml
vpnte-update.workspace = true
```

| module | what |
| --- | --- |
| `policy` | compiled trust: the two feed keys (placeholders until the owner creates them), mirrors, the 90-day limit, engine ranges, bundled versions |
| `feed` | the feed model and `verify` — the one check every reader runs (AT-11-010) |
| `fetch` | the feed from the mirrors through the ways; `seq` and `issued` rules |
| `net` | `Way` (route + `Via`), clients (https-only redirects, idle timeout) |
| `download` | `.part` file, size cap, streaming SHA-256, `Range` resume, held result |
| `store` | `EngineStore`: resolve / install / revert / trial / tidy |
| `check` | the check schedule (2-5 min, 24 h + up to 1 h, retries 1 h / 3 h) |
| `pending` | `updates\pending.json` around the app's own installer |
| `dirs` | `%LOCALAPPDATA%\VPN Tunnel Enforcer\{engines,updates}` (`<data>\local` on an overridden data dir) |
| `version` | `Version` (`a.b.c`), `Range` (`>=1.14.4 <1.15.0`) |

No user-facing text is formatted here (no `LOCALES`): the app maps outcomes to `app.update.*`.

## `policy`
```rust
pub fn trusted_keys() -> &'static [PublicKey];  pub fn keys_ready() -> bool;  // false: nothing is checked
pub const FEED_BASES: [&str; 3];                 // update-feed branch (raw), GitHub Pages, jsDelivr; never api.github.com
pub const MAX_FEED_AGE: Duration;                // 90 days
pub const SINGBOX: &str = "sing-box";  pub const XRAY: &str = "xray";
pub fn engine_range(id) -> Option<Range>;        // sing-box ">=1.14.4 <1.15.0", xray ">=26.11.9"
pub fn engine_allowed(id, Version) -> bool;      // singbox_process::version_supported delegates here
pub fn bundled_version(id) -> Option<Version>;   // from the compiled resources/engines.toml
pub fn app_version() -> Version;
```
The keys are `const CURRENT_KEY` / `BACKUP_KEY` (the `RW…` line of `minisign -G`); `cargo xtask feed
--verify` reads the same two lines.

## `feed`
```rust
pub const SCHEMA: u32 = 1;  pub const FEED_FILE: &str = "update.json";  pub const SIG_FILE: &str = "update.json.minisig";
pub use minisign_verify::PublicKey;
pub struct Feed { schema, seq: u64, issued: String /* RFC 3339 */, app: AppChannels,
                  engines: Vec<EngineEntry>, service: Option<ServiceEntry> }   // unknown fields ignored
pub struct AppChannels { stable: Option<AppRelease>, beta: Option<AppRelease> /* null */, warn_below: Option<Version> }
pub struct AppRelease { version, severity: Severity, notes: Notes /* lang -> text */, file: FileEntry,
                        rollback_to: Option<Version>, rollback_file: Option<FileEntry> }
pub enum Severity { Security, Critical, Normal /* default, unknown words */ }  // is_security()
pub struct FileEntry { name, size: u64, sha256: String, urls: Vec<String> }
pub struct EngineEntry { id, version, app: Range, severity, notes, tested_on: Option<String>, tested: Option<String>,
                         archive: ArchiveEntry { url, size, sha256 }, files: Vec<MemberEntry { path, name, sha256 }> }
pub struct ServiceEntry { version, size, sha256, urls }   // vpnte-service.exe of a release
pub enum FeedError { NoKeys, Signature, Format(String), Schema(u32) }
pub fn verify(bytes: &[u8], sig: &str, keys: &[PublicKey]) -> Result<Feed, FeedError>;  // prehashed only
pub fn verify_trusted(bytes: &[u8], sig: &str) -> Result<Feed, FeedError>;             // compiled keys
impl Feed { pub fn engine(&self, id: &str) -> Option<&EngineEntry>; }
```
`verify` checks the signature over the exact bytes first, then the schema, then parses.
Freshness (`seq`, `issued`) is the network reader's rule (`fetch`); the elevated pin check relies on
the compiled range floor instead (the remembered `seq` lives where the user can write).

## `fetch`, `net`
```rust
pub enum Via { Session, Direct }  pub struct Way { route: vpnte_core::net::Route, via: Via }  // Way::direct()
pub async fn fetch_feed(bases: &[&str], ways: &[Way], keys: &[PublicKey], max_seq: u64) -> Result<Fetched, FetchError>;
pub struct Fetched { feed, bytes, sig, source: Source { host, via }, stale: bool }
pub enum FetchError { Unreachable, Refused(FeedError), Older }
pub fn freshness(&Feed, max_seq, now: jiff::Timestamp) -> Freshness;   // Fresh | Older | Stale
```
Order: each mirror, each way (session first); a refused signature tries the other way; an older
`seq` moves to the next mirror; a stale feed is returned only when nothing fresher answered.

## `download`
```rust
pub struct Wanted<'a> { urls: &'a [String], size: u64, sha256: &'a str, name: &'a str }
pub async fn download(&Wanted, ways: &[Way], dir: &Path, progress: Option<&watch::Sender<u64>>,
                      cancel: &CancellationToken) -> Result<Verified, DownloadError>;
pub struct Verified { path: PathBuf, file: File /* read sharing only: no write / rename / delete */ }
pub enum DownloadError { Unreachable, TooLarge, Mismatch, Cancelled, Io(io::Error) }
pub fn open_held(&Path) -> io::Result<File>;  pub fn sha256_of(&mut impl Read) -> io::Result<[u8; 32]>;
pub fn parse_sha(&str) -> Option<[u8; 32]>;
```
`CREATE_NEW` `<16 hex>.part`, leftovers swept; a source sending more than `size` or other bytes is
passed over; a dropped transfer resumes with `Range` (206 from the right offset) or starts over;
the finished file is renamed, reopened held and hashed once more through that handle.

## `store`
```rust
pub struct EngineStore;  impl EngineStore {
    pub fn new(root /* <local>\engines */, resources: PathBuf) -> Self;   // compiled keys
    pub fn with_keys(root, resources, &'static [PublicKey]) -> Self;     // tests
    pub fn not_below_bundled(self) -> Self;  // the helper service: a version equal to the bundled one counts too
    pub fn resolve(&self, id) -> Resolved { exe, origin: Origin::{Bundled, Downloaded { version, on }} };
    pub async fn install(&self, &EngineEntry, feed: &[u8], sig: &str, archive: Verified, &impl EngineCheck)
        -> Result<Installed, InstallError>;   // Unknown | NotAllowed | Feed | Member | VersionMismatch | ConfigRefused | Io
    pub fn revert_previous(&self, id) -> io::Result<bool>;  pub fn revert_bundled(&self, id) -> io::Result<()>;
    pub fn record_start(&self, id, ok: bool) -> io::Result<Option<RolledBack>>;   // 3 failures in a row = back
    pub fn fallback(&self, id) -> Resolved;   // what a switch back would run now (previous if usable, else bundled)
    pub fn tidy(&self, id);  pub fn prune(&self, id);  pub fn state(&self) -> StoreState;  pub fn version_dir(..);
}
pub trait EngineCheck { async fn version(&self, id, exe) -> io::Result<Version>;
                        async fn check_configs(&self, id, exe) -> Result<(), String>; }
```
Layout: `<root>\<id>\<version>\` = the listed members + `wintun.dll` (copy of the bundled one, for
sing-box) + the signed feed it came from; `<root>\state.json` (active / previous / trial / installed
dates / `failed`: versions whose trial failed here, which the helper service never installs again;
the app still offers them). The bundled files are never touched. `resolve` uses a downloaded version only while its
files exist, its stored feed verifies and lists it, it fits the compiled range and the entry's app
range, and it is newer than the bundled one.

## Wiring
- App: `svc_core::build` resolves `Backend::engines` through `EngineStore::resolve` (after `tidy`);
  `svc_update` runs the checker, the offers, the downloads, installs and the app's own update.
- Engine: `pin::check` adds the pins of the feed stored next to a downloaded exe (see engine API).
- Helper service (`vpnte_service::update`, p-svc-update; p-svc-fix): the same keys and
  `feed::verify`; `fetch`, `download` and an `EngineStore` over `<install>\engines` with
  `not_below_bundled` (after it took a newer release's exe, its folder still holds the previous
  release's engine files, which the new exe's pins refuse); `Feed::service` for its own exe. It
  checks only when the app asks (no `check::run` schedule), skips `EngineState::failed` versions and
  never switches back to a `fallback` its pins refuse.
