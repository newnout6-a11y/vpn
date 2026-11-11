# vpnte-cleanup — API map for dependent crates

One-shot removal of what the old Electron app left in the system. One module, `legacy` (behind the
default cargo feature `cleanup-legacy`), plus the crate's locale layer (always built). The only
consumer is `vpnte-app` (start-up, `--cleanup`, maintenance page).

- **`run` / `uninstall` are blocking** (COM, BFE, INetCfg, Toolhelp, process waits up to ~3 s per
  image name, the INetCfg write lock up to 5 s): call them from `tokio::task::spawn_blocking`.
- **Only `run` / `uninstall` need elevation.** They first check `vpnte_winnet::elevation::is_elevated()`;
  unelevated they return `Err(AppError { kind: Permission, msg: "cleanup.legacy.needsAdmin" })`
  before anything is read or written (the marker is not touched either). Everything else (`LOCALES`,
  the marker / report / record methods, `StepId::key`) is pure and works unelevated, e.g. for the
  maintenance page. Under the privilege model of CONTRACT §1 this work belongs in the helper service
  `vpnte-service`; the code is not adapted yet (a `noadmin-*` follow-up): today the app calls it only
  when the process itself is elevated, and must hand the service the per-user marker store when it
  moves there.
- No events, no tasks, no shared state: calls return plain data. User-facing text is `Msg` / `Notice`;
  `StepRecord::detail` and the `tracing` lines (`info` per step, `warn` per failed step) are English.
- Machine-wide data is found through the ProgramData known folder (`%ProgramData%\VPNTE`, not the
  environment variable). Nothing under the old per-user Electron dir is touched (that is core's
  `legacy` import).

## Crate root
```rust
pub const LOCALES: &[(&str, &str)];   // (ru_json, en_json) per package, file-name order: [cleanup-legacy]
```
Register it with every other crate's layer at start, after the UI's base layer:
`vpnte_base::i18n::init(&[ui_layers, vpnte_core::LOCALES, .., vpnte_cleanup::LOCALES].concat())`
(later layers override earlier ones; every key here is under `cleanup.`).

## `legacy` — the cleanup
```rust
use vpnte_cleanup::legacy::{self, CleanupMarker, CleanupReport, Context, Mode, Outcome, Run, StepId, StepRecord, MAX_ATTEMPTS};

pub const MAX_ATTEMPTS: u32 = 3;   // runs started without completing, after which Startup stops retrying

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Context {
    pub resources: PathBuf,        // DataDirs::resources of the running install: its sing-box.exe names the
                                   // `sing-tun (<path>)` firewall rule that `uninstall` deletes
    pub level: KillSwitchLevel,    // kill-switch level after the settings import
    pub strict_ready: bool,        // Protection::startup() returned Ok
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode { Startup /* honours the marker */, Again /* maintenance "run again": ignores it */ }
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Run {
    NotDue,                        // Startup only: completed earlier, or MAX_ATTEMPTS failed runs
    Deferred,                      // an old Electron instance runs, or could not be ruled out (process
                                   // list / a candidate's image unreadable): nothing done, no attempt
                                   // counted; try on a later start
    Finished(CleanupReport),       // steps ran; the marker holds their records
}
pub fn run(marker: &Store<CleanupMarker>, ctx: &Context, mode: Mode) -> AppResult<Run>;
pub fn uninstall(ctx: &Context) -> AppResult<CleanupReport>;   // `--cleanup` / uninstaller; no marker
```
`run` counts the attempt in the marker **before** acting (a crash mid-run counts, no crash loop), runs
the start-up steps, then stores their records (a failed marker write is logged, the report is still
returned). Errors: `Permission` (unelevated), `Internal` (ProgramData known folder unreadable), or the
store error of the first marker write (`core.store.*`).
`uninstall` is never `Deferred` and has no Strict gate (the app is going away): it reads only
`ctx.resources`; `level` / `strict_ready` matter to `run` alone. Errors: `Permission`, `Internal`.

### Marker (`vpnte_core::store::Document`, per-user data dir)
```rust
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CleanupMarker {
    pub completed_at: Option<UnixMs>,     // first run without a failed step
    pub attempts: u32,                    // runs started (Startup and Again)
    pub last_attempt_at: Option<UnixMs>,
    pub steps: Vec<StepRecord>,           // records of the last finished run
}
impl Document for CleanupMarker { const FILE = "legacy-network-cleanup.json"; const VERSION = 1; }
impl CleanupMarker {
    pub fn is_due(&self) -> bool;         // !completed && attempts < MAX_ATTEMPTS
    pub fn gave_up(&self) -> bool;        // !completed && attempts >= MAX_ATTEMPTS: offer "run again"
}
```

### Report
```rust
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CleanupReport {
    pub steps: Vec<StepRecord>,           // one per step that ran, in run order
    pub firewall_reset: bool,             // old strict mode had Windows Firewall at Block: reset to Allow
    pub firewall_allow_all: bool,         // old rules without a journal: every profile set to Allow
}
impl CleanupReport {
    pub fn outcome(&self, step: StepId) -> Option<Outcome>;   // None = step did not run
    pub fn failed(&self) -> bool;
    pub fn exit_code(&self) -> i32;        // 0 | 1, for `--cleanup`
    pub fn notices(&self) -> Vec<Notice>;  // empty on a clean machine; see i18n below
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StepRecord { pub step: StepId, pub outcome: Outcome,
    pub changed: bool /* serde default */, pub detail: String /* English, no secrets */ }
impl StepRecord { pub fn msg(&self) -> Msg; }   // cleanup.legacy.step.<step.key()>.<outcome>
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]       // wire: "processes", "sing-tun-rules", "legacy-wfp", ...
pub enum StepId { Processes, Journals, Firewall, SingTunRules, LegacyWfp, Adapters, DnsPolicy,
    TunAdapter, Tasks, Files }
impl StepId { pub fn key(self) -> &'static str; }   // camelCase i18n segment: "singTunRules", ...
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome { Done, Skipped /* deliberately left alone: no retry */, Failed /* retried */ }
```

### Steps (spec firewall-recovery §6.6 / §6.7), in run order
Each step is independent and adds one record. `S` = start-up / `Again`, `U` = `uninstall`.

| Step | Runs | What it does | Not `Done` when |
| --- | --- | --- | --- |
| `processes` | S U | `winnet::process::sweep_orphans([%ProgramData%\VPNTE\runtime], [vpnte-sing-box, vpnte-xray, vpnte-etw-sidecar, vpnte-external-proxy].exe)` | a process survived, a candidate's image was unreadable (not checked) or the sweep failed: `failed` |
| `journals` | S U | reads `manifests\{firewall.json, latest-physical-adapter-lockdown.json, recovery-policy.json, tun-owner.json}` through the trust check (owner SYSTEM / Administrators, protected DACL, Allow entries only for them, no reparse point) and the old validators (salvage: an invalid entry is skipped, valid neighbours are used) | folder untrusted or a journal rejected: `skipped` (never acted on) |
| `firewall` | S U | profile outbound defaults first (old strict evidence → every Block back to Allow; else the journal's values, `NotConfigured` → Allow; else, when `VPNTE-killswitch*` rules exist, all Allow; else untouched), written with read-back; then every `VPNTE-killswitch*` rule removed (bounded re-enumerating loop). Rules are kept when a profile write failed | firewall unavailable, a rule / profile read, write or removal failed, or S with `Strict` and `!strict_ready`: `failed` |
| `legacyWfp` | S U | every filter of the old sublayer `VPNTE.IPv6.v1` on CONNECT_V6 / RECV_ACCEPT_V6 / OUTBOUND_IPPACKET_V6 (one transaction), then the sublayer | BFE error: `failed` (also S with `Strict` and `!strict_ready`); sublayer key with a foreign name: `skipped` |
| `singTunRules` | S U | sing-box's `sing-tun (<path>)` inbound rules of the old staged copies `runtime\<instance>\tun-runtime\vpnte-sing-box.exe`; U also `<ctx.resources>\sing-box.exe` (S keeps it: sing-box re-adds it on every TUN start). Paths compare case-insensitively, without `\\?\`, also in canonical spelling | firewall unavailable / removal failed: `failed` |
| `adapters` | S | with a valid adapter journal, per present NIC: IPv6 binding re-enabled (INetCfg, read back) where the old app turned it off; static IPv4 DNS (or DHCP) restored only while the current list still holds only forced / TUN resolver addresses; resolver cache flushed. Without one: physical adapters whose static DNS is only `192.168.250.253/254` go back to DHCP. Teredo / 6to4 / ISATAP are reported, not restored | a write or read failed: `failed` |
| `dnsPolicy` | S | HKLM `...\Policies\Microsoft\Windows NT\DNSClient\DisableSmartNameResolution` and `...\Services\Dnscache\Parameters\DisableParallelAandAAAA` restored from the journal (`exists:false` → deleted) only while they still read 1; no journal → untouched | write / read-back failed: `failed`; value without a valid snapshot or unreadable: `skipped` |
| `tunAdapter` | S | report only: the old Wintun adapter of `tun-owner.json` (no device removal) | disabled / inactive leftover: `skipped` ("remove it in Device Manager"); adapter list unreadable: `failed` |
| `tasks` | S U | `\VPNTE\BootRecoveryTask`, `\VPNTE Boot Recovery` deleted when the principal resolves to S-1-5-18 and the only action runs `vpnte-recover.ps1` through Windows PowerShell (`-File` or `-EncodedCommand`), then the `\VPNTE` folder if empty. The autostart task `\VPN Tunnel Enforcer` is NOT touched (same name as the new app's: `winnet::autostart::sync` re-points or deletes it) | foreign task kept: `skipped`; a read / delete failed: `failed` |
| `files` | S U | under `%ProgramData%\VPNTE`: in a trusted `manifests`, journals whose replay finished in this run, `tmp-*`, `*.ps1`, `*.corrupt-*`, `recovery-result.json`; `runtime\<instance>\{tun-runtime, external-proxy-runtime}` (engine configs with credentials) whenever every folder on the way is a real folder; then empty folders up to the root. Kept: `traffic-forensics`, `windows-firewall-before-reset-*.wfw` (named in the detail), journals not replayed | root not a plain folder or `manifests` untrusted: `skipped`; a delete failed: `failed` |

A journal is deleted only when it was valid and its own replay finished: `firewall.json` after
`firewall` done and `legacyWfp` done / skipped (a salvaged one whose saved values were used, i.e. an
invalid profile entry and no strict evidence, stays); `recovery-policy.json` after `firewall` done; the
adapter journal after an `adapters` replay without a failure, without salvaged (skipped) entries and
without recorded Teredo / 6to4 / ISATAP states (those are left for a manual restore), and `dnsPolicy`
done; `tun-owner.json` when the adapter is enabled or gone (U deletes only the first two).

## Usage (app)
```rust
// Start-up, only when the process is elevated (see the privilege note above), after the settings
// import and after `Protection::startup()` (spec §6.6 step 0: with `Strict` the old blocks are only
// removed once the persistent WFP set is in place). winnet's API.md example comments `startup()` as
// running "after ... legacy cleanup": for this crate it must come first, or with `Strict` the
// `firewall` / `legacyWfp` steps fail on every start until the retries run out.
let marker = Arc::new(Store::<CleanupMarker>::open(&dirs.root));
let strict_ready = protection.startup().is_ok();
let ctx = Context { resources: dirs.resources.clone(), level: settings.kill_switch, strict_ready };
let m = marker.clone();
match tokio::task::spawn_blocking(move || legacy::run(&m, &ctx, Mode::Startup)).await {
    Ok(Ok(Run::Finished(report))) => report.notices().into_iter().for_each(|n| notifier.show(n)),
    Ok(Ok(Run::NotDue | Run::Deferred)) => {}
    Ok(Err(e)) => tracing::warn!(error = %e, "legacy cleanup not run"),
    Err(e) => tracing::warn!(error = %e, "legacy cleanup panicked"),
}

// Maintenance page: list `marker.snapshot().steps` as `record.msg()` (+ `detail` in diagnostics);
// offer "run legacy cleanup again" when `marker.read(CleanupMarker::gave_up)`; the action calls
// `legacy::run(&marker, &ctx, Mode::Again)` and shows `report.notices()`.

// `--cleanup` / uninstaller (elevated): our own WFP objects first, then the old leftovers.
let wfp_ok = vpnte_winnet::wfp::remove_all().is_ok();
let code = match legacy::uninstall(&ctx) {
    Ok(report) => report.exit_code().max(i32::from(!wfp_ok)),
    Err(_) => 1,
};
std::process::exit(code);
```
Also the app's job, not this crate's: re-point or delete the old autostart task with
`winnet::autostart::sync` (same task name), the proxy-baseline replay of the old journals, and our
own WFP provider (`wfp::remove_all` / `Protection`).

## i18n keys (fragment `locales/cleanup-legacy.{ru,en}.json`)
| Key | Args | Where |
| --- | --- | --- |
| `cleanup.legacy.needsAdmin` | — | `AppError` of `run` / `uninstall` when unelevated (`Permission`) |
| `cleanup.legacy.notice.firewallResetTitle` / `.firewallReset` | — | `notices()`, `Level::Warn`, when `firewall_reset` |
| `cleanup.legacy.notice.firewallAllowAllTitle` / `.firewallAllowAll` | — | `notices()`, `Level::Warn`, when `firewall_allow_all` |
| `cleanup.legacy.notice.failedTitle` + body `.summary` | `changed`, `failed` (counts) | `notices()`, `Level::Warn`, some step failed |
| `cleanup.legacy.notice.doneTitle` + body `.summary` | `changed`, `failed` | `notices()`, `Level::Success`, something changed, nothing failed |
| `cleanup.legacy.step.<key>.<done\|skipped\|failed>` | — | `StepRecord::msg()`; `<key>` = `StepId::key()`: `processes`, `journals`, `firewall`, `singTunRules`, `legacyWfp`, `adapters`, `dnsPolicy`, `tunAdapter`, `tasks`, `files` |

Notices come in this order: firewall warnings first, then at most one summary; a machine without
leftovers gets none. They are plain `Notice` values (no category set): the app picks the toast /
banner channel.

## Not implemented (decided, see `progress/cleanup-legacy.md`)
- Proxy-baseline replay (spec §6.6 step 6): the journal is left untouched for the app.
- Teredo / 6to4 / ISATAP restore (needs `netsh`, forbidden): prior states are only reported.
- Removal of the old Wintun device (SetupDi `DIF_REMOVE`): report only.
- The old EOS hosts-file line and its backup / log: left in place (editing `hosts` is riskier).
- A read-only `scan()` API: diagnostics read the marker's step records instead.
- Quarantine of corrupt journals: they stay where they are (old `*.corrupt-*` copies are deleted).
- Hosting in `vpnte-service` (privilege model of 2026-11-11): pending `noadmin-*` follow-up.

## Not verified on a real machine (needs elevation; the unit tests cover the decisions)
Every acting path: firewall profile writes and rule removal, legacy WFP deletion, INetCfg write lock /
apply, `SetInterfaceDnsSettings`, HKLM policy writes, task deletion, orphan termination, deletions
under `%ProgramData%\VPNTE`, a full elevated `run` / `uninstall`. Also unknown: whether
`INetFwRules::Remove` deletes one or all same-named rules (the removal loop handles both). Ignored
tests (`#[ignore = "needs elevation"]`, named `elevated_*` for CI's `-- --ignored elevated_`, each
cleans up after itself): `elevated_removes_exactly_the_matching_rules` (throw-away firewall rule),
`elevated_removes_the_legacy_policy`, `elevated_write_lock_path_is_a_no_op_when_enabled`.
Verified read-only here: rule enumeration and profile reads, INetCfg binding walk,
`GetInterfaceDnsSettings`, account / SID lookups, HKLM policy reads, the process snapshot, the
ProgramData known folder, the ACL check, and that unelevated calls change nothing.
