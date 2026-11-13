# SERVICES — how the app crate is wired (work package `app-base`)

`crate::services` holds the shared types; `crate::svc_core` builds them. Everything the API
packages (`api_*`), `svc_tunnel` and `boot` / `root` share goes through one `Arc<Backend>`.
Add a field or a `TunnelOps` method only additively, re-reading `services.rs` right before the
edit. Privileged operations exist only when the process is elevated (NOADMIN §0): otherwise they
return `svc_core::needs_admin()` (`Permission`, `app.base.needsAdmin`: «Доступно, только если
приложение запущено от имени администратора») and the UI shows them as unavailable, never as
working.

## Start order (`root::run`, app-main)
0. `main`: `--crash-watch <pid>` (ks-b) returns into `crash_watch::run` before anything below:
   the crash watcher holds no instance mutex, no log, no data-dir lock, no UI. `--restore-proxy`
   (p-proxy-restore) returns into `restore::run` the same way.
1. `crate::setup::run(&args)`; `Some(code)` = exit. Then the single-instance check (a second
   launch hands over and exits before touching the data dir).
2. `let backend = svc_core::build(&args)?;` — blocking, **no tokio runtime needed**: data dir +
   `lock` (a second holder gets `Conflict` `core.store.dataDirLocked`), `logging::init`,
   `import::import_if_needed` (before any store is opened), every store, server list, operation
   registry, engine paths, notifier. No network activity, no system change. A first start without
   legacy import writes `routing_mode = Soft` unless the process is elevated. `build` installs
   the global log subscriber and its panic hook: never call `logging::init` again.
3. Inside the tokio runtime: `let built = svc_tunnel::build(&backend)?;` (`Built { tunnel,
   automation, domains, feed, journal }`)
   `let _ = backend.tunnel.set(built.tunnel);` (`Backend::tunnel()` returns `Internal`
   `app.base.tunnelMissing` until then). `built.domains` (the one domain history + site-name
   enricher, `svc_tunnel::DomainHistory`) goes to `api_lists` (Traffic page); `built.feed` (the
   engine cores' lines and last config) and `built.journal` (the tweak journal) go to
   `api_maintenance` (diagnostics export).
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
| `tun_available()` | Settings routing-mode choice, Wizard `Routing::Hard` option: true with the helper service installed (or in an elevated process without it); otherwise shown unavailable with «Для туннеля нужна служба-помощник.» and the install button |
| `service_installed()` | svc-wire: Settings «Установить службу-помощник» after Windows ran the service's install verb: Tunnel mode and "Always" go through the service from now on (`true` when it is there; default `false`) |
| `shutdown(budget)` | app-main (Tray `quit`) |
| `proxies()` | Panels proxy column and actions (`api_dashboard/proxies.rs`), Servers `start_proxies`; `None` = the column stays empty, actions answer `Conflict` |
| `live_checks()` | Servers `live_check` / `live_history` / `live_batch` (`api_servers/live.rs`); `None` = `Conflict` `app.servers.liveUnavailable` |
| `kill_switch_view()` | ks-a: Dashboard `pause` / `no_pause_vpn` strips, Tray `paused` (default: never paused) |
| `retry_now()` | ks-a: Dashboard / Tray «Подключить» in the paused state; `false` = nothing paused, then a plain connect |
| `always_available()` | ks-a: Settings kill switch ("Always" offered only with the helper service), maintenance repair (default `false`) |
| `proxy_taken()` | ks-b: Dashboard `proxy_taken` line: another program holds the system proxy our proxy-mode session set (default: never) |
| `reclaim_proxy()` | ks-b: Dashboard «Вернуть»: the journalled system proxy written again, original baseline kept (default: nothing to do) |

## What `app-tunnel` must provide (`svc_tunnel::build(&Arc<Backend>) -> AppResult<Arc<dyn TunnelOps>>`)
- Every method above, exactly as documented on the trait. Runs inside the tokio runtime.
- `wfp::Protection` only when `backend.elevated` (then `startup()`, the watchdog under
  `backend.shutdown`, its `notices()` forwarded to `backend.notifier` as
  `NoticeCategory::ConnectionError`). Unelevated: `kill_switch().wfp == None`; strict, leak
  protection and exceptions return `needs_admin()`; off / standard are Soft-mode behaviour
  (NOADMIN §2) and are persisted in both `Settings::kill_switch` and `protection.json`.
- The choice at start (svc-wire, owner decision 12.11.2026, `svc_tunnel/mod.rs`): with the helper
  service installed, the lifecycle's runtime is `svc_tunnel::remote::Split` — Tunnel-mode starts go
  to the service over its pipe (`remote::Remote`; the pipe's server must be the installed exe),
  proxy mode stays in-process — and the kill switch is applied by the service (no in-process WFP,
  also when elevated); "Always" is offered. A session the service kept after the window crashed is
  taken over by a connect of the same upstream once start-up recovery ran (`take_over`).
- Keep the two copies of the level in sync: `Settings::kill_switch` (read by the lifecycle at start)
  and `ProtectionDoc::settings.level` (the WFP model); `apply_settings_change` hands a changed
  `kill_switch` to the protection (or refuses it with `needs_admin()` when it cannot be enforced).
- The lifecycle's collaborators: `ProfileSource` over `backend.servers`, `SoftProxy`,
  `Monitor` (public-IP monitor), `Forensics` (traffic sampler + domain history, no capture), the
  external proxy slots as `ExternalProxies` (`svc_proxies`, built in `build`: a VPN stop stops
  every slot), and `backend.notifier` as the lifecycle `Notifier` (it implements
  `vpnte_tunnel::lifecycle::Notifier`). The tweak journal (`tweaks::Journal`) and the domain
  history (`forensics::domains::HistoryService`, needs a runtime) are opened by app-tunnel, once.
- The tunnel's peers (package wire-proxies-live): `build` also starts the slots' manager with the
  control API on 127.0.0.1 (`svc_proxies`) and the live-check runner over the tunnel's state
  (`svc_live`, history pruned at start); `shutdown` stops every slot and the runner after the
  lifecycle stop, within the same budget.
- Hard without TUN capture: `connect` fails with `Permission` and a message that offers Soft;
  never falls back to Soft silently.
- `ping` records every result with `backend.servers.record_ping` (memory only).
- WP-12 lab build only (feature `lab`, package w7-mihomo; a production build has none of it):
  `svc_tunnel::lab::with_lab_engine` reads the lab record `<data>\lab\at-12.json` once
  (`vpnte_engine::lab::activate`, logged; the gate decides every engine choice from then on) and
  gives `RealEngines` the mihomo exe next to sing-box plus `<data>\lab\runs` for its run homes.
  AmneziaWG then connects in Proxy mode through mihomo chained behind sing-box (tunnel API "WP-12").

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
The automatic server choice (`svc_auto::pick`, package w7-autopick: connect at launch, stall
watch, candidate warm-up, retries after every server failed) is started by the root with
`svc_auto::spawn_autopick(&backend, &built.automation)` right after the tunnel is stored (its host
needs `TunnelOps::{probe_ctx, runtime_status, snapshot}`); the root then hands the
automation to `api_dashboard::contexts` (the status strip) as well. The user's own actions reach it
through `AppCoordinator::user_acted` (fix-autopick): `TunnelOps::disconnect` and a `cancel` with an
operation in flight are `UserAct::Stop`, `switch_server` is `Pick`, `apply_settings_change`,
`set_kill_switch_level`, `set_protection_toggles` and the launch choice are `Change`, a window / tray
connect is `Connect`; every act but `Change` also drops a restore that waits after a lost switch.

## Links from browsers and messengers (`api_servers::phones`, package w7-phones)
`api_servers::contexts` also provides an `api_servers::LinkInbox` root context. The root offers it the
`--open-link` link of this start (`Wiring::first_link`) and every `Command::OpenLink` of a later launch
(after `show_window`); the overlay `vpnte_ui::servers::LinkHandoff` (in the shell's overlays) opens the
Servers page, whose add dialog takes the link once (`ServersApi::take_link`). Nothing is imported until
the user confirms there. Link schemes: `setup::links` (installer `--setup register-links`, uninstall,
`sync_at_start` in the release housekeeping of the installed copy; a portable copy registers only from
the panel's «Открывать ссылки здесь») over `vpnte_winnet::url_scheme`; the Servers page's «Ссылки»
panel changes them on the user's click. A later launch hands a link only to a pipe served by this exe
in this session; a link it could not hand over is reported in a short box (`app.phones.linkNotTaken`).

## Proxy-mode crash guardian (`crash_watch`, `svc_tunnel::soft`, package ks-b)
While the tweak journal holds Soft values, `SoftTweaks` keeps two guards: the crash watcher (the
app exe with `--crash-watch <own pid>`, started by `crash_watch::arm` before the first write;
CreateProcessW without inherited handles, no window, out of the job when allowed) and the
system-proxy watch (`soft::taken`: registry change notifications on the per-user Internet
Settings, the read-back after each change, the start page's `proxy_taken` line). Both stop once
a rollback left nothing journalled (`crash_watch::disarm` terminates the process the app
started). The watcher waits on the app's handle; after an exit without rollback it runs
`Soft::rollback_left_by(app)` on the journal under its file lock, only while the dead app is the
journal's last writer (the next start's recovery may run at the same moment). Measured working
set while waiting: `progress/ks-b.md`.

## Logon restore of a proxy session (`restore`, package p-proxy-restore, RU-2026 14c)
No watcher survives a logoff or a power loss, and with autostart off nothing starts the app
again, so `crash_watch::arm` / `disarm` also keep `HKCU\…\RunOnce\VPN Tunnel Enforcer proxy
restore` = `"<exe>" --restore-proxy` in step with the journal. At the next sign-in Windows
deletes the value and starts that process: `Soft::rollback_orphaned` under the journal lock,
only while the journal's last writer no longer runs (an app autostarted at the same sign-in
keeps its session); no window, mutex or log; nothing created without a `tweaks.json`; the
`RunOnce` key is never written while Windows works through it (what a failed rollback leaves
waits for the next start). The watcher updates the value inside the same journal lock as its
rollback (complete = removed, incomplete = kept for the next sign-in), so it never removes the
value of a newer session. `root::run` calls `restore::at_start(root)` after `svc_core::build`: an earlier
run's value goes (the start-up recovery owns what is left) and a hidden top-level window rolls
the Soft values back at `WM_ENDSESSION(TRUE)` (logoff, shutdown) without the variables
broadcast. A process on an overridden data dir (`VPNTE_DATA_DIR`) never touches the value: the
sign-in process would read the default journal. Decisions: `progress/p-proxy-restore.md`.
