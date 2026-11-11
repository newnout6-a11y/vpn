# VPN Tunnel Enforcer — Rust rewrite: shared contract for implementers

Read this file fully before writing code. Slice specs (`.tmp/rewrite/spec/<slice>.md`) say WHAT to build;
this file says HOW the pieces fit and overrides a spec wherever they disagree.

## 1. Product decisions (fixed)
- One Windows binary (crate `vpnte-app`), Rust 2024, rustc 1.99, version 2.0.0. UI = Dioxus 0.7.10 desktop
  (WebView2) running in-process with the backend. No IPC layer, no Node, no PowerShell/netsh/schtasks/cmd,
  no C#/C++ helpers.
- Child processes allowed: `sing-box.exe` 1.14.4 (+`libcronet.dll`, `wintun.dll`), `xray.exe` 26.11.9,
  `pktmon.exe` (opt-in packet capture), `curl.exe` (adapter-bound leak probes). Engine config goes over stdin
  (`sing-box run -c stdin --disable-color`, `xray run -config stdin:`): no credentials on disk; engine output
  is read from pipes. Children: CREATE_NO_WINDOW + kill-on-close Job Object.
- sing-box owns routes and DNS hijack (TUN `auto_route` + `strict_route`, dual stack). The app never rewrites
  physical adapter settings. Kill switch / leak protection = WFP filters in our own provider + sublayer:
  dynamic session for `standard` (gone when the process dies), persistent only for `strict`. Default level: Off.
- The process runs elevated (manifest `asInvoker`; at start `ensure_or_relaunch()` via ShellExecute "runas").
  `--no-elevate` / env `VPNTE_NO_ELEVATE=1` skips that: UI, soft mode, probes and external proxies work,
  privileged operations return `ErrorKind::Permission`. Development and automated UI checks use this mode.
- Data dir `%APPDATA%\VPN Tunnel Enforcer\` (override: env `VPNTE_DATA_DIR`). JSON documents, atomic writes,
  secrets wrapped with DPAPI. One-time non-destructive import from the Electron dir
  `%APPDATA%\vpn-tunnel-enforcer\` (override: env `VPNTE_LEGACY_DIR`).
- Engines/resources dir: env `VPNTE_RESOURCES_DIR`, else `<exe dir>\resources`. In tests:
  `concat!(env!("CARGO_MANIFEST_DIR"), "/../../resources")` (binaries are there on this machine).
- Posture: sensible, not paranoid. Keep what protects the user (no plaintext keys on disk, an honest kill
  switch, never report a success that was not observed: "not checked" is its own state). Drop proof machinery
  (journals-before-effects, ACL/SHA staging, manifests, acceptance matrices, per-call audit logs). When a spec
  offers a lean and a heavy variant, take the lean one. Planned WP-12 features are NOT implemented.

## 2. Workspace
Root `vpn-tunnel-enforcer/Cargo.toml`; crates in `vpn-tunnel-enforcer/crates/<name>` (package `vpnte-<name>`,
Rust path `vpnte_<name>`). Dependency direction, never reversed:

```
base        errors, Msg, shared enums, i18n lookup, HTTP/TLS plumbing, paths, Store<T>, Secret (DPAPI),
            settings, redact, logging, net helpers, operation registry, legacy-data primitives
winnet      Win32: adapters/routes, processes/jobs, ICMP, WFP protection, registry, env, elevation,
            autostart, single instance, clipboard, power events, toasts               -> base
profiles    typed profile model, importers, emit/export, subscriptions, server list   -> base
engine      sing-box/xray config, process supervision, Clash API, routing/DNS rules   -> base, winnet, profiles
probes      IP/leak checks, diagnostics, availability, speed, pings, live checks      -> base, winnet, profiles, engine
forensics   traffic stats, domain history, capture, ETW, diagnostics export           -> base, winnet
tunnel      runtime actor (start/stop/switch), lifecycle FSM, session history         -> base, winnet, profiles, engine
proxies     external loopback proxy slots + local control API                         -> base, winnet, profiles, engine, probes
automation  scheduler, rotation, autopilot, adaptive bypass, soft-mode tweaks         -> base, winnet, profiles, probes
app         Dioxus UI, tray, notifications, bootstrap, wiring (binary)                 -> everything
```
Specs were written before this layout was final. Translate: spec `core::…` = crate `vpnte-base`.

## 3. Decisions that override individual specs
1. **Shared vocabulary lives in `vpnte-base` and already exists** — read `crates/base/src/{error,msg,types,
   i18n,http}.rs` first and use them: `AppError`/`ErrorKind`/`AppResult`, `Msg`, `Lang`, `UnixMs`/`now_ms`,
   `ProxyKind`, `ClientDevice`, `KillSwitchLevel`, `EnginePref`/`Engine`, `Owner` (ordered by priority),
   `OutboundFault`, `AdaptiveMode`, `Creds`, `Loopback`, `Verdict` (has `NotChecked`), `Level`, `Notice`,
   `http::client_builder`. Do not redefine equivalents. If a shared type is missing, define it in your own
   crate and note it in PROGRESS.md; the lead moves it later.
2. **User-facing text is never formatted in backend code.** Return `Msg::new("crate.area.name").arg("n", v)`.
   Each crate ships `crates/<name>/locales/{ru,en}.json` (i18next style: nested keys, `{{var}}`, `_one/_few/
   _many/_other` plurals) with its keys under a top-level key equal to the crate name (`"tunnel": {...}`).
   Russian wording quoted in a spec is copied verbatim into `ru.json`; write a natural English equivalent.
   Log lines are English and never localized.
3. **Profiles are typed.** `vpnte_profiles::Profile` (spec profiles §6.2) is the only stored/parsed form.
   sing-box JSON is produced only by `vpnte_profiles::emit_singbox`; Xray JSON only by `vpnte_engine::xray`.
   Where a spec passes "the stored outbound `serde_json::Value`", read "the fragment emitted from `&Profile`".
   Outbound normalisation rules (TLS/uTLS/ALPN defaults, mux, UDP/QUIC, WireGuard endpoint) are implemented
   once, in `emit_singbox` (policy struct), not again in the engine.
4. **Persistence** goes through `vpnte_base::store::Store<T: Document>` (one in-memory copy, atomic
   write-through, change notification). Each crate owns its document types. File layout: storage spec §6.1.
5. **Legacy import.** `vpnte_base::legacy` holds the primitives (Electron store reader, Chromium safeStorage
   decryption). Each crate that owns documents exposes `pub mod legacy` / `import_legacy(..)` for its part;
   `vpnte-app` orchestrates. Nothing under the legacy dir is ever written, renamed or deleted.
6. **Time.** Persisted timestamps are `UnixMs`. Civil time/zones: `jiff`. Monotonic deadlines: `Instant`.
7. **Async.** tokio. Cancellation = `tokio_util::sync::CancellationToken`. Mutable shared state has one owner
   task (actor with an `mpsc` inbox, `watch` for state, `broadcast` for events) or a `parking_lot` lock held
   briefly and never across `.await`.
8. **Win32.** `windows` 0.62 (workspace dependency; its feature list is shared — add a feature locally if you
   need one that is missing). Look signatures up in the registry sources
   (`C:\Users\Redmi\scoop\persist\rustup\.cargo\registry\src\index.crates.io-*\windows-0.62.2\`), do not guess.
   Each `unsafe` block is small and has a `// SAFETY:` line.
9. **TLS/HTTP.** reqwest 0.13 + rustls 0.23 with the `ring` provider via `vpnte_base::http::client_builder`
   (there is no cmake/NASM on the build machine, so no aws-lc). App requests never use the system proxy
   implicitly.

## 4. Rules for every implementer
1. **Work incrementally — hard technical limit.** Any single model response that streams longer than about
   four minutes is cut off by the API relay and lost. Create your files early; write at most ~150 lines per
   tool call and append with Edit; keep the thinking before each step short; never hold a big design in your
   head for one large write. Update `crates/<crate>/PROGRESS.md` (section for your package: done / next /
   not run / needs from others / dropped spec items) every few steps so that another agent can continue.
2. **Read narrowly.** Specs are 100–270 KB. First list the headings (`Grep '^#{2,3} '`), then read only the
   sections your package needs (offset/limit). Do not load a whole spec.
3. **Stay in your lane.** Edit only the files assigned to your package (plus your crate's `Cargo.toml`
   dependencies, `locales/*.json` and your PROGRESS section). `lib.rs` module lists are already written: do not
   edit them (ask via PROGRESS if a module is missing). Never edit other crates, the workspace `Cargo.toml`,
   `assets/`, `resources/`, the old TypeScript sources, `docs/`. Errors reported in files you do not own are not
   yours: wait a minute and re-run; never "fix" them.
4. **Keep your crate compiling.** Several agents work in one crate. Add code in small increments that compile
   (`cargo check -p vpnte-<crate>` after each). Publish your public types and function signatures early so
   dependants can code against them; after that change them only additively.
5. **Build/test** from `vpn-tunnel-enforcer/` with `export PATH="$HOME/.cargo/bin:$PATH"` and the
   `CARGO_TARGET_DIR` given in your brief. Only build your own package (`-p`). "Blocking waiting for file lock"
   means another agent is building: wait. Never run `cargo clean`. Format only your own files
   (`rustfmt --edition 2024 <files>`). Finish with zero warnings from
   `cargo clippy -p vpnte-<crate> --all-targets -- -D warnings` in your files.
6. **Dependencies.** Prefer `name.workspace = true`. Anything else goes into your crate's `Cargo.toml` with an
   explicit current version (`cargo search <crate> --limit 1`). Keep the list short.
7. **Machine safety.** Nobody is at the computer and the shell is NOT elevated. Never trigger UAC, never kill
   or restart processes you did not start, never change system network/firewall/registry state except what a
   test creates and removes itself under a throw-away key or temp dir, never touch the running VPN client
   (Happ; xray on ports 10808/10809) or the API gateway on 127.0.0.1:8787. Code that needs admin: write it,
   unit-test the pure parts, and add integration tests marked `#[ignore = "needs elevation"]` that clean up
   after themselves (CI runs them elevated). Say in PROGRESS.md what was not executed.
8. **Style.** Fast, current, ordered, concise. Small modules with one job; no speculative abstraction; no dead
   code; no `todo!()`/`unimplemented!()` left behind; no `unwrap()`/`expect()` on fallible runtime paths (tests
   and proven invariants excepted); errors are `thiserror` enums or `AppError`. Comments explain WHY (field
   experience, Windows quirks), not what the next line does. Public items get a one-line doc comment.
9. **Secrets.** Never log keys, UUIDs, passwords, subscription URLs or full server configs. Never copy real
   credentials from the user's data or old fixtures into code/tests; use obvious fakes. Do not read the user's
   real app data unless your brief says so.
10. **Tests.** Port the vectors of your spec's "Test vectors to port" section as unit tests next to the code;
    keep an `AT-xx-yyy` tag in the test's doc comment. Generated engine configs get a test that pipes the JSON
    through the real engine check when the binaries exist in `resources/` (skip quietly otherwise).
11. **Honesty.** Your final answer is a report for the lead: implemented, stubbed, not run, dropped and why.
    Never "should work".
