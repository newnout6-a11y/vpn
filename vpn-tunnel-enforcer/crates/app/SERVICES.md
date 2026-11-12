# SERVICES — how the app crate is wired (work package `app-base`)

`crate::services` holds the shared types; `crate::svc_core` builds them. Everything the API
packages (`api_*`), `svc_tunnel` and `boot` / `root` share goes through one `Arc<Backend>`.
Add a field or a `TunnelOps` method only additively, re-reading `services.rs` right before the
edit. Privileged operations exist only when the process is elevated (NOADMIN §0): otherwise they
return `svc_core::needs_admin()` (`Permission`, `app.base.needsAdmin`: «Доступно, только если
приложение запущено от имени администратора») and the UI shows them as unavailable, never as
working.

## Start order (`root::run`, app-main)
1. `crate::setup::run(&args)`; `Some(code)` = exit. Then the single-instance check (a second
   launch hands over and exits before touching the data dir).
2. `let backend = svc_core::build(&args)?;` — blocking, **no tokio runtime needed**: data dir +
   `lock` (a second holder gets `Conflict` `core.store.dataDirLocked`), `logging::init`,
   `import::import_if_needed` (before any store is opened), every store, server list, operation
   registry, engine paths, notifier. No network activity, no system change. A first start without
   legacy import writes `routing_mode = Soft` unless the process is elevated. `build` installs
   the global log subscriber and its panic hook: never call `logging::init` again.
3. Inside the tokio runtime: `let built = svc_tunnel::build(&backend)?;` (`Built { tunnel,
   automation }`)
   `let _ = backend.tunnel.set(built.tunnel);` (`Backend::tunnel()` returns `Internal`
   `app.base.tunnelMissing` until then).
4. `vpnte_ui::lang::init_locales(&svc_core::locale_layers())` before `vpnte_ui::launch`; the
   initial theme is `backend.themes.read(|t| t.theme(&settings.active_theme_id))`, the language
   `settings.locale.unwrap_or_else(vpnte_ui::lang::os_lang)`.
5. Background tasks that do network work are started by their owners, never by `build`, each
   under a child of `backend.shutdown`: the subscription scheduler
   (`backend.servers.spawn_scheduler(backend.refresh.clone(), backend.shutdown.child_token())`,
   app-main), the rule-set auto refresh and every tunnel-side monitor (app-tunnel).

Shutdown (app-main, bounded): `backend.shutdown.cancel()`; `tunnel.shutdown(budget).await`;
`tokio::time::timeout(.., backend.ops.close())`; `if let Some(c) = backend.clipboard.get() {
c.shutdown() }`; last, `drop(backend.log.lock().take())` drains the app log (the process exits
without running destructors of the `Arc<Backend>`).

## `Backend` fields and who uses them
| Field | What | Used by (UI trait) |
| --- | --- | --- |
| `dirs` | data root, `logs`, `history`, `cache`, legacy dir (read only), `resources` | Logs (`open_log_folder`, `read_log`: `logging::tail(&dirs.logs, ..)`), Settings (`open_logs_folder`), Tray (`open_logs`) |
| `lock`, `log` | data-dir lock (process life); log guard (take + drop at the end of shutdown) | app-main |
| `elevated` | process elevated: TUN / WFP available in-process | everyone who labels a privileged feature; `TunnelOps::tun_available` |
| `engines` | `sing-box.exe` / `xray.exe`, canonical when present | app-tunnel (`RealEngines`, WFP `EnginePaths`); `probe_ctx` |
| `settings` | `Store<Settings>` (`settings.json`) | Settings, Wizard, Dashboard (`soft_mode`, `smart_ru`), Tray (`minimize_to_tray`), app-tunnel (`InputsSource`, `LifecycleDeps::settings`), notifier |
| `protection` | `Store<ProtectionDoc>` (`protection.json`): level, leak protection, public Wi-Fi, LAN, exceptions | written only by app-tunnel through `TunnelOps` (WFP `Persist` callbacks); read by Settings (`KillSwitchView`) |
| `themes` | `Store<ThemesDoc>` (`themes.json`): custom themes; `theme(id) -> Theme` resolves an id | Settings (`set_theme`, `themes` list), app-main (initial theme) |
| `soft` | `Store<SoftDoc>` (`soft.json`): `DevTargets` of a Soft session (`soft_git` / `soft_gradle` / `soft_studio`) | Settings (save); app-tunnel reads it at every Soft apply and re-applies on change while a Soft session runs (subscribe) |
| `cleanup` | `Store<CleanupMarker>` (`legacy-network-cleanup.json`): the old version's network cleanup | app-tunnel (elevated start-up run, skipped while the per-machine 1.x is installed); Maintenance (failures, "run again") |
| `rules` | `Store<RulesDoc>` (`rules.json`): split tunnel, DNS profiles + active, domain rules | Settings (`dns`, `domains` sections); app-tunnel (`InputsSource`; the tunnel regenerates fragments on change) |
| `rule_sets` | `RuleSetService` over `cache/rulesets.json` | Settings (`refresh_rule_sets`, `RuleSetView`); app-tunnel (`active(..)`, `prune()` before an engine start) |
| `history` | connection history (`history/connections.json`) | Logs (`history`, `export_history`, `clear_all`); app-tunnel (`LifecycleDeps::history`) |
| `servers`, `refresh` | server list; subscription fetcher + registry (`RefreshCtx`) | Servers (all list actions, `add_from_input`, `refresh_group`), Dashboard panels (`servers`, `select_server`), Wizard (`check_key`, key import), app-tunnel (`ProfileSource`) |
| `ops` | operation registry (single flight per resource, cancel, list) | Servers (refresh, health check), Tray (`check_route`), Settings (exports); app-main closes it at shutdown |
| `geo` | country / ASN lookups (one cache and backoff) | Dashboard (exit country), Servers (`verify_country`, `geo`); whoever saves `disable_geo_lookup` calls `geo.set_enabled(!value)` (app-settings) |
| `notifier` | toasts + in-app list | app-tunnel (lifecycle `Notifier`, WFP notices), Tray (`check_route` verdict), app-main (`subscribe()` feeds the toast host; `set_on_activate` shows the window) |
| `import` | `Option<ImportReport>` of this start | app-main (first-run notice), Settings (maintenance text) |
| `shutdown` | app-wide `CancellationToken` | every background task (child tokens) |
| `clipboard` | secret clipboard, started by `Backend::clipboard()` inside the runtime | Servers (`copy_key`), Dashboard (`copy_ip`), Logs (`copy_text`) |
| `tunnel` | `OnceLock<Arc<dyn TunnelOps>>`, read with `Backend::tunnel()` | Dashboard, Panels, Tray, Servers, Settings, Wizard |
| `lang()` | method: the stored language, else Windows' (texts the backend renders: dialogs, exports, group names) | every page that renders a `Msg` itself; shared helpers: `support::{files, detached, blocking, changed}` |

Documents are the single in-process copy: never open a second `Store` of the same type. Store
writes are blocking file I/O (+ DPAPI for secrets): use `spawn_blocking` on hot async paths. A
read-only store (newer version, unreadable) still opens; show `store.notice()` as the banner.

## `TunnelOps` methods and who calls them
Lane operations return `Result<Done, ConnError>` (`ConnError::kind()` / `user_msg()` /
`warnings()`; `AppError::from(err)` for the UI, `Cancelled` is quiet); `Done::warnings` are extra
messages to show.

| Method | Calls it |
| --- | --- |
| `connect(source)` | Dashboard `connect` (`Source::Ui`), Tray `start` (`Source::Tray`) |
| `disconnect(source)` | Dashboard `disconnect`, Tray `stop` |
| `cancel()` | Dashboard `cancel`, Servers `cancel_switch` (publish `cancelling` first) |
| `switch_server(id, source)` | Panels `select_server`, Servers `select` (idle: selection only) |
| `apply_settings_change(old, new)` | Settings `save`, Dashboard `set_smart_ru`, Wizard `finish`: after the settings store was written |
| `snapshot()` / `session()` | Dashboard `ConnView`, Tray `TrayState`, Servers `tunnel_running` / `tunnel_busy`, Settings `connected` / `direct_session` |
| `runtime_status()` | Dashboard (`restarting`, `proxy_down` reason), Tray (`restart`, `proxy_addr`, `engine_running`) |
| `kill_switch()` | Settings `kill_switch` section, Dashboard `firewall` / `recheck_firewall`, Tray `kill_switch` |
| `set_kill_switch_level` / `add_exception` / `remove_exception` | Settings, Wizard `finish` (level) |
| `set_protection_toggles(toggles)` | Settings `save` when `leak_protection` changed (read the others from `kill_switch().settings`) |
| `release_kill_switch()` | Dashboard `release_kill_switch` |
| `ip_evidence()` | Dashboard `ExitIp`, Tray `public_ip` / `leak` |
| `leak_check(cancel)` | Dashboard `run_leak_check`, Tray `check_route` (as an `ops` operation, verdict as a notice) |
| `traffic()` | Panels `traffic`, Tray speeds |
| `ping(ids, cancel)` | Panels `ping_one` / `ping_all`, Servers `ping_one` / `ping_many` |
| `probe_ctx(device)` | Servers `check_group_health` (`key_health::check_many`), and anyone pinging by hand (`.net`) |
| `tun_available()` | Settings routing-mode choice, Wizard `Routing::Hard` option: shown unavailable with `app.base.needsAdmin` |
| `shutdown(budget)` | app-main (Tray `quit`) |
| `proxies()` | Panels proxy column and actions (`api_dashboard/proxies.rs`), Servers `start_proxies`; `None` = the column stays empty, actions answer `Conflict` |
| `live_checks()` | Servers `live_check` / `live_history` / `live_batch` (`api_servers/live.rs`); `None` = `Conflict` `app.servers.liveUnavailable` |

## What `app-tunnel` must provide (`svc_tunnel::build(&Arc<Backend>) -> AppResult<Arc<dyn TunnelOps>>`)
- Every method above, exactly as documented on the trait. Runs inside the tokio runtime.
- `wfp::Protection` only when `backend.elevated` (then `startup()`, the watchdog under
  `backend.shutdown`, its `notices()` forwarded to `backend.notifier` as
  `NoticeCategory::ConnectionError`). Unelevated: `kill_switch().wfp == None`; strict, leak
  protection and exceptions return `needs_admin()`; off / standard are Soft-mode behaviour
  (NOADMIN §2) and are persisted in both `Settings::kill_switch` and `protection.json`.
- Keep the two copies of the level in sync: `Settings::kill_switch` (read by the lifecycle at start)
  and `ProtectionDoc::settings.level` (the WFP model); `apply_settings_change` hands a changed
  `kill_switch` to the protection (or refuses it with `needs_admin()` when it cannot be enforced).
- The lifecycle's collaborators: `ProfileSource` over `backend.servers`, `SoftProxy`,
  `Monitor` (public-IP monitor), `Forensics` (traffic sampler + domain history, no capture), the
  external proxy slots as `ExternalProxies` (`svc_proxies`, built in `build`: a VPN stop stops
  the unleased slots), and `backend.notifier` as the lifecycle `Notifier` (it implements
  `vpnte_tunnel::lifecycle::Notifier`). The tweak journal (`tweaks::Journal`) and the domain
  history (`forensics::domains::HistoryService`, needs a runtime) are opened by app-tunnel, once.
- The tunnel's peers (package wire-proxies-live): `build` also starts the slots' manager with the
  control API on 127.0.0.1 (`svc_proxies`) and the live-check runner over the tunnel's state
  (`svc_live`, history pruned at start); `shutdown` stops every slot and the runner after the
  lifecycle stop, within the same budget.
- Hard without TUN capture: `connect` fails with `Permission` and a message that offers Soft;
  never falls back to Soft silently.
- `ping` records every result with `backend.servers.record_ping` (memory only).

## Notifier (`svc_core::notify`)
`backend.notifier.notify(notice, Some(category))` (`None` = uncategorised). Owner decision D-12:
every notice reaches the log and the in-app list (`subscribe()` -> `InAppNotice`); the switches
decide only the Windows toast: `desktop_notifications` off or the category off -> list only
(`popup: false`); method in-app -> `popup: true`, no toast; system -> toast, popped up in the window
too when Windows blocks or fails it or its setting is unknown; both -> toast + popup. Identical
title + body within 1.5 s are dropped (`COALESCE`). Sound: off silences all; on keeps info /
success silent. Toasts run on the notifier's own thread (no runtime needed, never blocks).
The root shows `popup` notices as in-app toasts; a list view may show all.

## Locale layers
`svc_core::locale_layers()`: `crates/base/locales/base.*`, then the `LOCALES` of core, winnet,
profiles, view, servers, engine, forensics, automation, probes, tunnel, proxies, cleanup, and the
app's fragments: one pair per app package. **Every app package ships `crates/app/locales/<package>.{ru,en}.json`**
(top-level key `app`) and adds it to `svc_core::APP`.

## Automation (`svc_auto`, package w3-automation)
`svc_tunnel::build` builds the automation over its own lifecycle and the one tweak journal
(`crates/automation/API.md`, "Wiring in the app"): `AppCoordinator` (owner order on top of the
lane; `TunnelOps::connect` starts through `AppCoordinator::start`, so the adaptive bypass picks the
mode of the user's starts too), one `Scheduler` (its store `schedules.json` is opened only there),
`Reactions` + the verdict feed, `Rotation`, `Adaptive`, the AutoPilot launch run, the runtime's
`Failover`, `Browsers` (an elevated process only) and location privacy. The forwarder runs from
the start; the long tasks start after the start-up recovery, each under a child of
`backend.shutdown`. The root hands `built.automation` to `api_lists::contexts` (Schedule page) and
`api_settings::contexts` (rotation, adaptive, location privacy, browser hardening).
`TunnelOps::resumed` wakes the scheduler; `TunnelOps::shutdown` rolls location privacy back.
