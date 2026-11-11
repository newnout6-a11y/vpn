# VPN Tunnel Enforcer — Rust rewrite: shared contract for implementers

Read this file fully before writing code. Slice specs (`.tmp/rewrite/spec/<slice>.md`) say WHAT to build;
this file says HOW the pieces fit and overrides a spec wherever they disagree.

## 1. Product decisions (fixed)
- One Windows binary (crate `vpnte-app`, written last), Rust 2024, rustc 1.99, version 2.0.0. UI = Dioxus
  0.7.10 desktop (WebView2) in-process with the backend. No IPC layer, no Node, no PowerShell / netsh /
  schtasks / cmd, no C# / C++ helpers.
- Child processes allowed: `sing-box.exe` 1.14.4 (+`libcronet.dll`, `wintun.dll`), `xray.exe` 26.11.9,
  `pktmon.exe` (opt-in packet capture), `curl.exe` (adapter-bound leak probes). Engine config goes over stdin
  (`sing-box run -c stdin --disable-color`, `xray run -config stdin:`): no credentials on disk; engine output
  is read from pipes. Children: CREATE_NO_WINDOW + kill-on-close Job Object.
- sing-box owns routes and DNS hijack (TUN `auto_route` + `strict_route`, dual stack). The app never rewrites
  physical adapter settings. Kill switch / leak protection = WFP filters in our own provider + sublayer:
  dynamic session for `standard` (gone when the process dies), persistent only for `strict`. Default: Off.
- **Privilege model (owner requirement of 2026-11-11, replaces "the process runs elevated").** The application
  never runs elevated and never triggers UAC on its own (manifest `asInvoker`, no self-relaunch). Unprivileged
  by itself: UI, storage, probes, external proxies, soft-mode tweaks, autostart, and **proxy capture**: the
  engine listens on a loopback mixed inbound and the app points the per-user system proxy at it. Privileged
  operations (TUN capture, the WFP kill switch and leak protection, browser policies, packet capture / ETW,
  removal of the old version's system leftovers) run in the optional helper service `vpnte-service`
  (LocalSystem, installed once by the per-machine installer), which the app drives over a named pipe; when the
  process happens to be elevated (development, CI) the app hosts the same code in-process. Without service and
  without elevation those operations return `ErrorKind::Permission` and the UI shows them as unavailable, never
  as working. Libraries therefore never self-elevate, privileged modules take everything through parameters
  and return plain data (they may live in another process than the UI), and "not available" is reported
  honestly. Work finished under the old assumption is adapted by dedicated follow-up packages (`noadmin-*`):
  if you are reviewing or integrating something else, do NOT redesign for this yourself; keep the code as its
  brief says and just add no new dependency on running elevated. `--no-elevate` / `VPNTE_NO_ELEVATE=1` are
  accepted and mean nothing any more.
- Data dir `%APPDATA%\VPN Tunnel Enforcer\` (override: env `VPNTE_DATA_DIR`). JSON documents, atomic writes,
  secrets wrapped with DPAPI. One-time non-destructive import from the Electron dir
  `%APPDATA%\vpn-tunnel-enforcer\` (override: env `VPNTE_LEGACY_DIR`).
- Engines / resources dir: env `VPNTE_RESOURCES_DIR`, else `<exe dir>\resources`. In tests use
  `concat!(env!("CARGO_MANIFEST_DIR"), "/../../resources")` (the binaries are there on this machine).
- Posture: sensible, not paranoid. Keep what protects the user (no plaintext keys on disk, an honest kill
  switch, never report a success that was not observed: "not checked" is its own state). Drop proof machinery
  (journals-before-effects, ACL/SHA staging, manifests, acceptance matrices, per-call audit logs). When a spec
  offers a lean and a heavy variant, take the lean one. Planned WP-12 features are NOT implemented.

## 2. Workspace
Root `vpn-tunnel-enforcer/Cargo.toml`; crates in `vpn-tunnel-enforcer/crates/<name>` (package `vpnte-<name>`,
Rust path `vpnte_<name>`). Dependencies, never reversed:

```
base        frozen contract: AppError, Msg, shared enums, i18n lookup, HTTP/TLS defaults        (lead)
core        paths, Store<T>, Secret (DPAPI), settings, redact, logging, net, socks5, resolve,
            operation registry, legacy-data primitives                                         -> base
winnet      Win32: adapters/routes, processes/jobs, counters, ICMP, WFP protection, registry,
            env, elevation, autostart, single instance, clipboard, power events, toasts       -> base
profiles    typed profile model, importers, sing-box emitter, exporters                        -> base
view        pure UI logic: start-page state, labels, traffic maths, mascot brain               -> base
ui          Dioxus UI: frame, shell, widgets, start page, mascot, tray, all pages              -> base (+ view)
servers     server list, groups, subscriptions                                                 -> base, core, profiles
engine      sing-box / xray config, process supervision, Clash API, routing and DNS rules      -> base, core, winnet, profiles
forensics   traffic stats, domain history, capture, ETW, diagnostics export                    -> base, core, winnet
automation  scheduler, rotation, autopilot, adaptive bypass, soft-mode tweaks, hardening       -> base, core, winnet
probes      IP / leak checks, diagnostics, availability, speed, pings, live checks             -> base, core, winnet, profiles, engine
tunnel      runtime actor (start/stop/switch), lifecycle FSM, session history                  -> base, core, winnet, profiles, servers, engine
proxies     external loopback proxy slots + local control API                                  -> base, core, winnet, profiles, engine
app         bootstrap and wiring: implements the UI's API traits over the backend (binary)     -> everything (lead)
```
Specs were written before this layout was final. Translate: a spec's `core::error/msg/types/i18n` = crate
`vpnte-base`; a module a spec places in another crate than the one above lives where this file says.
A crate that needs something from a crate it does not depend on takes it as a small trait or as plain data
(for example automation asks for connections through its own `Coordinator` trait; the app implements it).

## 3. Decisions that override individual specs
1. **Shared vocabulary lives in `vpnte-base` and already exists** — read `crates/base/src/{error,msg,types,
   i18n,http}.rs` first and use them: `AppError` / `ErrorKind` / `AppResult`, `Msg`, `Lang`, `UnixMs` /
   `now_ms`, `ProxyKind`, `ClientDevice`, `KillSwitchLevel`, `EnginePref` / `Engine`, `Owner` (ordered by
   priority), `OutboundFault`, `AdaptiveMode`, `Creds`, `Loopback`, `Verdict` (has `NotChecked`), `Level`,
   `Notice`, `http::client_builder`. Do not redefine equivalents and do not edit `vpnte-base`. If a shared
   type is missing, define it in your own module and note it in your progress file.
2. **User-facing text is never formatted in backend code.** Return `Msg::new("crate.area.name").arg("n", v)`.
   Each work package ships its own fragment files `crates/<crate>/locales/<package-id>.ru.json` and
   `.en.json` (i18next style: nested keys, `{{var}}`, `_one/_few/_many/_other` plurals) with all keys under
   one top-level key equal to the crate name (`"tunnel": {...}`); UI packages may also reuse the keys of
   `crates/ui/assets/locales/{ru,en}.json` (the old app's strings) and put new keys in their fragment under
   the same top-level sections. Russian wording quoted in a spec is copied verbatim; write a natural English
   equivalent. Log lines are English and never localized.
3. **Profiles are typed.** `vpnte_profiles::model::Profile` is the only stored / parsed form. sing-box JSON is
   produced only by `vpnte_profiles::emit_singbox`; Xray JSON only by `vpnte_engine::xray_config`. Where a
   spec passes "the stored outbound `serde_json::Value`", read "the fragment emitted from `&Profile`".
   Outbound normalisation (TLS / uTLS / ALPN defaults, mux, UDP / QUIC, WireGuard endpoint) is implemented
   once, in `emit_singbox`, not again in the engine.
4. **Persistence** goes through `vpnte_core::store::Store<T: Document>` (one in-memory copy, atomic
   write-through, change notification). Each crate owns its document types. File layout: storage spec §6.1.
5. **Legacy import.** `vpnte_core::legacy` holds the primitives (Electron store reader, Chromium safeStorage
   decryption). Each crate that owns documents exposes its own `from_legacy` / `import_legacy` taking the
   already decrypted `serde_json::Value`; the app orchestrates. Nothing under the legacy dir is ever written,
   renamed or deleted.
6. **Time.** Persisted timestamps are `UnixMs`. Civil time and zones: `jiff`. Monotonic deadlines: `Instant`.
7. **Async.** tokio. Cancellation = `tokio_util::sync::CancellationToken`. Mutable shared state has one owner
   task (actor: `mpsc` inbox, `watch` for state, `broadcast` for events) or a `parking_lot` lock held briefly
   and never across `.await`.
8. **Win32.** `windows` 0.62 (workspace dependency with a shared feature list; if a feature is missing add it
   in your crate: `windows = { workspace = true, features = ["Win32_X"] }`). Look every signature up in the
   registry sources (`C:\Users\Redmi\scoop\persist\rustup\.cargo\registry\src\index.crates.io-*\windows-0.62.2\`),
   do not guess. Each `unsafe` block is small and has a `// SAFETY:` line.
9. **TLS / HTTP.** reqwest 0.13 + rustls 0.23 with the `ring` provider through
   `vpnte_base::http::client_builder` (no cmake / NASM on the build machine, so no aws-lc). App requests
   never use the system proxy implicitly.
10. **UI.** The `ui` crate never calls backend crates. A UI package defines, in its own module, the view-model
    types it renders and an `XxxApi` trait (async actions + state as signals / watch receivers) and ships a
    demo implementation with realistic fake data plus a `demo_<name>` binary; the app implements the trait
    over the backend later. Follow `.tmp/rewrite/ref/dioxus-cookbook.md` (verified patterns for Dioxus 0.7.10).
    The start page must match the reference in `.tmp/rewrite/ref/ui/` exactly; every other page is rebuilt in
    the same visual language (paper / ink / rule / signal tokens, square corners, mono captions, hairlines)
    with the shared widgets, never with the old rounded "Mac" look.
    Convention for every `XxxApi` (so the app can implement all of them the same way): `trait XxxApi: 'static`,
    handed to components through context as `Rc<dyn XxxApi>` (`use_context::<Rc<dyn XxxApi>>()`). Pushed state
    is exposed as `tokio::sync::watch::Receiver<T>` (one `Clone + PartialEq` snapshot struct per page or
    panel) that the page's root turns into a `Signal` with one `use_future` pump; actions are async methods
    declared with `#[async_trait::async_trait(?Send)]` returning `vpnte_base::AppResult<T>`, called from
    `spawn` / `use_action`. View-model types hold display data only (never secrets) and no Dioxus types.

## 4. Rules for every implementer
1. **Work incrementally — hard technical limit.** Any single model response that streams longer than about
   four minutes is cut off by the API relay and lost. Create your files early; write at most ~150 lines per
   tool call and append with Edit; keep the thinking before each step short; never hold a big design in your
   head for one large write. Keep `crates/<crate>/progress/<package-id>.md` (done / next / not run / needs
   from others / dropped spec items) and update it every few steps so that another agent can continue.
2. **Read narrowly.** Specs are 100–270 KB. First list the headings (`Grep '^#{2,3} '`), then read only the
   sections your brief points to (offset / limit). Do not load a whole spec.
3. **Stay in your lane.** Edit only the modules and binaries assigned to your package (a module may be one
   file `<m>.rs` or a directory `<m>/mod.rs` + files), your locale fragments, your progress file, and for UI
   packages your own files under `crates/ui/assets/` (`css/pages/<your page>.css`, `js/<yours>.js`,
   `css/widgets.css` only for the widgets package). In your crate's `Cargo.toml` you may only ADD lines to
   `[dependencies]` (re-read the file right before editing; never touch `[features]`, `[[bin]]`, `lib.rs`).
   Never edit other crates, the workspace `Cargo.toml`, `resources/`, the old TypeScript sources, `docs/`.
   Never run git commands that change the repository (commit, add, checkout, stash, reset, clean).
4. **Your package builds alone.** Your modules sit behind the cargo feature named after your package, so
   unfinished modules of other agents do not break your build:
   `cargo check -p vpnte-<crate> --no-default-features --features <package-id>` (same for `test` and
   `clippy --all-targets -- -D warnings`). Other packages of your crate listed under "builds on" are finished
   and switched on by your feature; anything else in your crate is NOT available to you. Crates you depend on
   are finished: read their `API.md` (public API map), then `src/`, before using them, and use them as they are.
5. **Build / test** from `vpn-tunnel-enforcer/` with `export PATH="$HOME/.cargo/bin:$PATH"` and the
   `CARGO_TARGET_DIR` given in your brief. "Blocking waiting for file lock" means another agent is building:
   wait. Never run `cargo clean`, never build the whole workspace. Format only your own files
   (`rustfmt --edition 2024 <files>`). Finish with zero warnings in your files.
6. **Dependencies.** Prefer `name.workspace = true`. Anything else: an explicit current version in your
   crate's `Cargo.toml` (`cargo search <crate> --limit 1`). Keep the list short.
7. **Machine safety.** Nobody is at the computer and the shell is NOT elevated. Never trigger UAC, never kill
   or restart processes you did not start, never change system network / firewall / registry state except
   what a test creates and removes itself under a throw-away key or temp dir, never touch the running VPN
   client (Happ; xray on ports 10808 / 10809) or the API gateway on 127.0.0.1:8787. NEVER stop processes by
   image name for `xray.exe` or `sing-box.exe` (`taskkill /IM`, `Stop-Process -Name`): the user's own VPN
   runs an `xray.exe` and this session's network goes through it. Stop every process you
   start (engines, demo binaries, browsers). Code that needs admin: write it against the real API, unit-test
   the pure parts, add integration tests marked `#[ignore = "needs elevation"]` that clean up after
   themselves, and say in your progress file what was not executed.
8. **Style.** Fast, current, ordered, concise. Small modules with one job; no speculative abstraction; no dead
   code; no `todo!()` / `unimplemented!()` left behind; no `unwrap()` / `expect()` on fallible runtime paths
   (tests and proven invariants excepted); errors are `thiserror` enums or `AppError`. Comments explain WHY
   (field experience, Windows quirks), not what the next line does. Public items get a one-line doc comment.
9. **Secrets.** Never log keys, UUIDs, passwords, subscription URLs or full server configs. Never copy real
   credentials from the user's data or old fixtures into code or tests; use obvious fakes. Do not read the
   user's real app data.
10. **Tests.** Port the vectors of your spec's "Test vectors to port" section as unit tests next to the code;
    keep an `AT-xx-yyy` tag in the test's doc comment. Generated engine configs get a test that pipes the JSON
    through the real engine check when the binaries exist in `resources/` (skip quietly otherwise).
11. **Honesty.** Your final answer is a report for the lead: implemented, stubbed, not run, dropped and why.
    Never "should work".
