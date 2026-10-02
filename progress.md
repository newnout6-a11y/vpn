## 2026-06-19 - Task: Fix stale traffic-forensics running status after reinstall
### What was done
- Reconciled traffic-forensics status reads against the current managed sidecar process so stale manifests from a crash, app restart, or installer update are marked stopped with `stopReason: "zombie-recovery"` instead of keeping the UI on packet collection.
- Added a regression test for stale `running: true` plus `sidecar.running: true` when the managed sidecar process is already gone.
- Documented the manifest lifecycle invariant for diagnostics UI status.
### Testing
- `npm.cmd test -- trafficForensics.test.ts systemDiagnostics.test.ts speedTest.test.ts` passed: 3 files, 17 tests.
### Notes
- `vpn-tunnel-enforcer/src/main/trafficForensics.ts`: reconciles stale running manifests during status reads.
- `vpn-tunnel-enforcer/src/main/trafficForensics.test.ts`: covers zombie status recovery without a live managed sidecar.
- `vpn-tunnel-enforcer/docs/traffic-observability-rfc.md`: documents that diagnostics status must use reconciled manifest state.
- Rollback: revert the three file changes above or restore the previous commit/worktree state before this task.

## 2026-06-19 - Task: Rebuild Windows installer with traffic-forensics zombie-status fix
### What was done
- Rebuilt the production Electron app and packaged the Windows NSIS installer containing the stale traffic-forensics status recovery.
- Verified the built main bundle contains the `zombie-recovery` status reconciliation path.
### Testing
- `npm.cmd run build` passed.
- `npm.cmd run dist:win` passed and produced `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`.
- Codebase memory index was refreshed after the implementation and packaging checks.
### Notes
- `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`: rebuilt installer artifact for installing the fixed app.
- `vpn-tunnel-enforcer/out/main/index.js`: generated build output includes the stale manifest recovery code.
- `.codebase-memory/graph.db.zst`: refreshed codebase-memory artifact.
- Rollback: install the previous installer artifact or rebuild from the prior worktree state before this task.

## 2026-06-19 - Task: Surface live packet-capture health in diagnostics UI
### What was done
- Added live traffic-forensics health to status reads: ETL size, live snapshot time, artifact count, sidecar event counts, sidecar data-event counts, and explicit warnings when sidecar is running without TCP/DNS/WFP data.
- Expanded the diagnostics card so the UI shows `pktmon`, live snapshot, sidecar, and artifact health next to packet collection status.
- Added sidecar heartbeat/provider polling events so a running-but-silent PowerShell sidecar is visible instead of looking healthy by implication.
### Testing
- `npm.cmd test -- trafficForensics.test.ts systemDiagnostics.test.ts speedTest.test.ts` passed: 3 files, 18 tests.
- `npm.cmd run build` passed.
- `npm.cmd run dist:win` passed and produced `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`.
- Codebase memory index was refreshed after the UI/health changes.
### Notes
- `vpn-tunnel-enforcer/src/main/trafficForensics.ts`: computes live forensic health from artifacts and `events.ndjson`.
- `vpn-tunnel-enforcer/src/main/trafficForensics.test.ts`: covers health reporting when sidecar has only lifecycle events.
- `vpn-tunnel-enforcer/src/renderer/components/DiagnosticsCard.tsx`: displays packet-capture health in the UI.
- `vpn-tunnel-enforcer/resources/vpnte-etw-sidecar.ps1`: writes heartbeat/provider polling health rows.
- `vpn-tunnel-enforcer/docs/traffic-observability-rfc.md`: documents the live health requirement.
- `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`: rebuilt installer artifact containing the UI health surface.
- `.codebase-memory/graph.db.zst`: refreshed codebase-memory artifact.
- Rollback: revert the listed files or rebuild from the prior worktree state before this task.

## 2026-06-19 - Task: Reconcile running traffic-forensics manifests after stop artifacts appear
### What was done
- Fixed the status path so a manifest cannot keep reporting `running: true` once stop artifacts such as `pktmon-stop.txt`, `pktmon-stop.ps1`, or `pktmon-trace.*` exist.
- Added a regression test for the exact contradiction seen in the installed app: `running: true`, sidecar stopped, packet monitor stopped, and stop artifacts present.
- Documented stop-artifact reconciliation as a required diagnostics invariant.
### Testing
- `npm.cmd test -- trafficForensics.test.ts systemDiagnostics.test.ts speedTest.test.ts` passed: 3 files, 19 tests.
- `npm.cmd run build` passed.
- `npm.cmd run dist:win` passed and produced `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`.
- Verified the built main bundle contains `status-reconciled-stop`.
- Codebase memory index was refreshed after the stop-artifact reconciliation change.
### Notes
- `vpn-tunnel-enforcer/src/main/trafficForensics.ts`: reconciles stale running manifests using stop artifacts during status reads.
- `vpn-tunnel-enforcer/src/main/trafficForensics.test.ts`: covers stop-artifact reconciliation.
- `vpn-tunnel-enforcer/docs/traffic-observability-rfc.md`: documents that stop artifacts override stale `running: true`.
- `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`: rebuilt installer artifact containing the stop-artifact reconciliation fix.
- `.codebase-memory/graph.db.zst`: refreshed codebase-memory artifact.
- Rollback: revert the listed files or rebuild from the prior worktree state before this task.

## 2026-06-19 - Task: Add sidecar warmup grace period for diagnostics UI
### What was done
- Added a 30 second warmup window for newly started traffic-forensics sidecars so lifecycle-only startup events are shown as `warming up` instead of an immediate warning.
- Kept the warning after the warmup window when the sidecar is still running but has no TCP/DNS/WFP data events.
- Rebuilt the Windows installer with the warmup UI and health-status behavior.
### Testing
- `npm.cmd test -- trafficForensics.test.ts systemDiagnostics.test.ts speedTest.test.ts` passed: 3 files, 20 tests.
- `npm.cmd run build` passed.
- `npm.cmd run dist:win` passed and produced `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`.
- Verified generated `out/main/index.js` and `out/renderer/assets/index-BJ5XmtU1.js` contain `sidecarWarmingUp`.
### Notes
- `vpn-tunnel-enforcer/src/main/trafficForensics.ts`: reports `sidecarWarmingUp` and delays the no-data sidecar warning for 30 seconds.
- `vpn-tunnel-enforcer/src/main/trafficForensics.test.ts`: covers both warmup silence and post-warmup warning behavior.
- `vpn-tunnel-enforcer/src/renderer/components/DiagnosticsCard.tsx`: displays sidecar `warming up` and preserves normal Russian UI text.
- `vpn-tunnel-enforcer/docs/traffic-observability-rfc.md`: documents the 30 second sidecar warning grace period.
- `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`: rebuilt installer artifact containing the warmup fix.
- Rollback: revert the listed source/doc changes and rebuild the installer from the prior worktree state.

## 2026-06-19 - Task: Native real-time ETW sidecar (Rust/ferrisetw)
### What was done
- Added a native real-time ETW consumer `vpnte-etw-sidecar.exe`, built from the new Rust crate `vpn-tunnel-enforcer/native/vpnte-etw-sidecar/` (uses the `ferrisetw` crate over StartTrace/EnableTraceEx2/ProcessTrace + TDH parsing), replacing the PowerShell Event-Log poller as the primary source of normalized traffic events.
- CLI matches the existing integration contract: `--events <path> --session <id> --providers <csv>`. Subscribes to TCPIP, DNS-Client, WFP, Winsock-AFD, and WebIO and appends normalized NDJSON rows (categories tcp/dns/wfp/afd/webio) per `trafficForensics.ts`/`trafficForensicsSummary.ts`.
- Trace session uses a stable name `VPNTE-ETW` and reclaims any orphaned session before start (bounds orphaned kernel sessions to one despite TerminateProcess kills). DNS rows carry `queryName`/`queryResults`; TCP/AFD rows decode SOCKADDR/IN_ADDR blobs into the 5-tuple. 30s `health` heartbeat + `event-cap-reached` back-pressure guard; metadata only, never payloads.
- Wired packaging: `electron-builder.yml` ships the `.exe` next to `vpnte-etw-sidecar.ps1`; new `scripts/build-sidecar.mjs` + `npm run build:sidecar` (invoked by `dist*`, no-op with warning when Rust/Windows absent).
- Updated docs (`docs/traffic-observability-rfc.md` Phase 4 → implemented, README build section) and tests.
### Testing
- `cargo test --release` in the crate: 11 unit tests passed (provider/category mapping, GUID table, event/reason derivation, SOCKADDR IPv4/IPv6 parsing, arg parsing).
- Live admin smoke test on Windows Server 2022: real tcp/dns/afd data events captured (888+ data events incl. full TCP 5-tuples and resolved DNS names); verified orphan reclamation keeps a single `VPNTE-ETW` session across abrupt kills.
- `npm.cmd test -- trafficForensics.test.ts systemDiagnostics.test.ts speedTest.test.ts` passed: 3 files, 21 tests (added a synthetic tcp/dns/wfp NDJSON test asserting `sidecarDataEvents>0` and no warning).
- `npm.cmd run dist:win` passed and produced `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`; `vpnte-etw-sidecar.exe` is bundled in the install root.
### Notes
- `vpn-tunnel-enforcer/native/vpnte-etw-sidecar/`: new Rust crate (src/main.rs, src/classify.rs, Cargo.toml).
- `vpn-tunnel-enforcer/scripts/build-sidecar.mjs`, `package.json`: `build:sidecar` script wired into `dist*`.
- `vpn-tunnel-enforcer/electron-builder.yml`: bundles the native `.exe` (preferred over the `.ps1` fallback).
- `vpn-tunnel-enforcer/src/main/trafficForensics.test.ts`: synthetic native-event data-event test.
- The `.exe` is gitignored (like sing-box.exe/wintun.dll) and rebuilt from source via `npm run build:sidecar`.
- Rollback: revert the listed files and the `native/` crate, then rebuild.

## 2026-06-19 - Task: Rebuild installer with local Rust ETW sidecar binary
### What was done
- Installed/activated the Rust toolchain in the local user profile for this build session.
- Built `vpn-tunnel-enforcer/native/vpnte-etw-sidecar` in release mode and copied the generated `vpnte-etw-sidecar.exe` into `vpn-tunnel-enforcer/resources/`.
- Rebuilt the Windows NSIS installer so the native Rust sidecar is bundled and preferred over the PowerShell fallback.
### Testing
- `npm.cmd test -- trafficForensics.test.ts systemDiagnostics.test.ts speedTest.test.ts` passed: 3 files, 21 tests.
- `npm.cmd run build:sidecar` passed and produced `vpn-tunnel-enforcer/resources/vpnte-etw-sidecar.exe`.
- `npm.cmd run build` passed.
- `npm.cmd run dist:win` passed and produced `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`.
- Verified `vpn-tunnel-enforcer/dist/win-unpacked/vpnte-etw-sidecar.exe` exists alongside the `.ps1` and `.cmd` fallback files.
### Notes
- `vpn-tunnel-enforcer/resources/vpnte-etw-sidecar.exe`: generated native sidecar binary, intentionally ignored by Git.
- `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`: rebuilt installer artifact containing the native sidecar.
- Rollback: delete `resources/vpnte-etw-sidecar.exe` and rebuild to package only the PowerShell sidecar fallback.

## 2026-06-20 - Task: Refresh from GitHub and rebuild ETW diagnostics installer
### What was done
- Pulled GitHub `main` through PR #4 (`ad62b72`), which adds rich ETW diagnostics to the diagnostics card and extends traffic-forensics health output.
- Rebuilt the native Rust ETW sidecar and the Windows NSIS installer from the refreshed codebase.
- Verified the generated renderer bundle contains the new ETW diagnostics UI fields and the unpacked app contains the native `vpnte-etw-sidecar.exe`.
### Testing
- `npm.cmd test -- trafficForensics.test.ts systemDiagnostics.test.ts speedTest.test.ts` passed: 3 files, 21 tests.
- `npm.cmd run dist:win` passed and produced `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`.
- Verified `vpn-tunnel-enforcer/dist/win-unpacked/vpnte-etw-sidecar.exe` exists.
- Verified generated bundles contain `sidecarEngine`, `sidecarCategoryCounts`, `sidecarTopDomains`, and the ETW diagnostics UI text.
### Notes
- `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`: rebuilt installer artifact from GitHub `main` `ad62b72`.
- `vpn-tunnel-enforcer/resources/vpnte-etw-sidecar.exe`: regenerated native sidecar binary, ignored by Git.
- `progress.md`: records this local refresh/rebuild step.
- Rollback: reinstall the previous installer artifact or rebuild from the previous commit before PR #4.

## 2026-06-20 - Task: Refresh ETW noise filtering and rebuild installer
### What was done
- Pulled GitHub `main` through PR #5 (`7b9fd19`), which filters high-volume ETW rundown/data-path noise so the native sidecar does not exhaust the data-event cap immediately.
- Rebuilt the Rust `vpnte-etw-sidecar.exe` and the Windows NSIS installer from the refreshed codebase.
- Verified the rebuilt sidecar binary is present in both `resources/` and `dist/win-unpacked/`.
### Testing
- `npm.cmd test -- trafficForensics.test.ts systemDiagnostics.test.ts speedTest.test.ts` passed: 3 files, 21 tests.
- `cargo test --release` in `vpn-tunnel-enforcer/native/vpnte-etw-sidecar` passed: 12 tests.
- `npm.cmd run dist:win` passed and produced `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`.
- Verified the Rust sources contain `filteredNoise` heartbeat reporting and rundown/data-path filtering.
### Notes
- `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`: rebuilt installer artifact from GitHub `main` `7b9fd19`.
- `vpn-tunnel-enforcer/resources/vpnte-etw-sidecar.exe`: regenerated native sidecar binary with noise filtering, ignored by Git.
- `progress.md`: records this local refresh/rebuild step.
- Rollback: reinstall the previous installer artifact or rebuild from commit `ad62b72`.

## 2026-06-20 - Task: Refresh stale ETW data guard and rebuild installer
### What was done
- Pulled GitHub branch `devin/1781904822-stale-forensics-data` through commit `c7d7b96`, which prevents a previous app run's stale `events.ndjson` from appearing as live ETW diagnostics after restart/reinstall.
- Rebuilt the Rust sidecar and Windows NSIS installer from the refreshed codebase.
- Verified the generated main bundle contains the stale-session health guard and the unpacked app still includes the native sidecar.
### Testing
- `npm.cmd test -- trafficForensics.test.ts systemDiagnostics.test.ts speedTest.test.ts` passed: 3 files, 22 tests.
- `cargo test --release` in `vpn-tunnel-enforcer/native/vpnte-etw-sidecar` passed: 12 tests.
- `npm.cmd run dist:win` passed and produced `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`.
- Verified `vpn-tunnel-enforcer/dist/win-unpacked/vpnte-etw-sidecar.exe` exists.
### Notes
- `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`: rebuilt installer artifact from commit `c7d7b96`.
- `vpn-tunnel-enforcer/resources/vpnte-etw-sidecar.exe`: regenerated native sidecar binary, ignored by Git.
- `progress.md`: records this local refresh/rebuild step.
- Rollback: reinstall the previous installer artifact or rebuild from commit `7b9fd19`.

## 2026-06-20 - Task: Add manual traffic-forensics restart button
### What was done
- Added a Diagnostics card button `Перезапустить сбор` that forces the current traffic-forensics capture to stop and then starts a fresh session using the previous mode/target.
- Exposed a new `restart-traffic-forensics` IPC path through main, preload, and the renderer API.
- Restored the Diagnostics card source text to valid UTF-8 while adding the new control.
- Rebuilt the Windows NSIS installer with the button and native Rust sidecar.
### Testing
- `npm.cmd test -- trafficForensics.test.ts systemDiagnostics.test.ts speedTest.test.ts` passed: 3 files, 22 tests.
- `cargo test --release` in `vpn-tunnel-enforcer/native/vpnte-etw-sidecar` passed: 12 tests.
- `npm.cmd run build` passed.
- `npm.cmd run dist:win` passed and produced `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`.
- Verified generated bundles contain `restart-traffic-forensics`, `restartTrafficForensics`, and `Перезапустить сбор`.
### Notes
- `vpn-tunnel-enforcer/src/main/trafficForensics.ts`: adds manual restart helper.
- `vpn-tunnel-enforcer/src/main/index.ts`: registers the restart IPC handler.
- `vpn-tunnel-enforcer/src/preload/index.ts`: exposes `restartTrafficForensics`.
- `vpn-tunnel-enforcer/src/renderer/App.tsx`: updates the renderer API type.
- `vpn-tunnel-enforcer/src/renderer/components/DiagnosticsCard.tsx`: adds the button and refreshes status after restart.
- `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`: rebuilt installer artifact containing the UI restart control.
- Rollback: revert the listed source files and rebuild the installer.

## 2026-06-20 - Task: Fix locked traffic-forensics cleanup aborting capture start
### What was done
- Analyzed `vpn-tunnel-enforcer-diagnostics-2026-06-19T21-52-06-890Z.zip` and confirmed the visible `pktmon: EBUSY ... rmdir` error was caused by old locked session directories being pruned during a new capture start.
- Changed old session pruning to best-effort cleanup so a locked historical `pktmon.etl` is logged as cleanup debt but no longer aborts a new `pktmon` capture.
- Made diagnostics export re-check the latest manifest after copying the traffic-forensics tree and explicitly include the referenced latest session directory when it exists, preventing `latest-session.json` from pointing at a missing folder in ZIPs.
- Updated the sidecar build script so it finds the standard rustup cargo path under the user profile even when `.cargo\bin` is not on PATH.
- Rebuilt the Windows NSIS installer with the cleanup fix, diagnostics export consistency fix, manual restart button, and native Rust ETW sidecar.
### Testing
- `npm.cmd test -- trafficForensics.test.ts systemDiagnostics.test.ts speedTest.test.ts` passed: 3 files, 22 tests.
- `C:\Users\Redmi\.cargo\bin\cargo.exe test --release` in `vpn-tunnel-enforcer/native/vpnte-etw-sidecar` passed: 12 tests.
- `npm.cmd run build` passed.
- `npm.cmd run dist:win` passed; build output confirmed native sidecar was rebuilt and copied before packaging.
- Verified `vpn-tunnel-enforcer/dist/win-unpacked/vpnte-etw-sidecar.exe` exists and the generated bundles contain `failed to prune old traffic-forensics session`, `restart-traffic-forensics`, and `Перезапустить сбор`.
### Notes
- `vpn-tunnel-enforcer/src/main/trafficForensics.ts`: makes old session pruning non-fatal and ensures exported diagnostics include the latest referenced session directory.
- `vpn-tunnel-enforcer/scripts/build-sidecar.mjs`: resolves cargo from the rustup user profile path when PATH does not contain cargo.
- `vpn-tunnel-enforcer/docs/traffic-observability-rfc.md`: documents cleanup and ZIP consistency invariants for traffic forensics.
- `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`: rebuilt installer artifact containing this fix.
- Rollback: revert the listed source files plus the previous manual restart button changes if needed, then rebuild `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`.

## 2026-09-12 - Task: Support mobile hotspot and tethering without DNS deadlocks or probe failures
### What was done
- Investigated and resolved why VPNTE failed on mobile phone hotspot and USB tethering while other clients (Happ) worked:
  1. Converted remote DNS servers to IP literals (e.g. `1.1.1.1` for Cloudflare, `8.8.8.8` for Google) with TLS SNI retention in `tunController.ts`, removing dependency on cellular carrier DNS bootstrap.
  2. Removed private RFC1918 CIDRs from Wintun `route_exclude_address`, routing all LAN traffic into TUN and handling private IP bypass via sing-box `route.rules` placed strictly AFTER `{ protocol: 'dns', action: 'hijack-dns' }`, preventing DNS leaks to mobile gateways.
  3. Added an outbound allow rule for `process.execPath` in `firewallKillSwitch.ts` under `DefaultOutboundAction=Block`.
  4. Increased `TUNNEL_PROBE_URL_TIMEOUT_MS` from 4000ms to 8000ms in `serverPicker.ts` with retry logic to handle cellular jitter and avoid premature 11s tunnel restart loops.
  5. Preserved IPv6 binding (`ms_tcpip6`) on tethering and cellular adapters in `physicalAdapterLockdown.ts` by inspecting adapter names, descriptions, gateway subnets, and CLAT default routes, preventing 464XLAT breakage.
  6. Avoided TUN adapter alias collisions with USB RNDIS devices by implementing dynamic alias resolution in `tunAdapter.ts`.
  7. Added `udp_fragment: true` to SOCKS outbounds in `tunController.ts`.
### Testing
- `npm run typecheck` (`tsc --noEmit`): passed with 0 errors.
- `npm test`: 96 test suites passed, 924 passed, 3 skipped.
- `npm run build`: built main, preload, and renderer bundles cleanly.
### Notes
- Files modified: `tunController.ts`, `firewallKillSwitch.ts`, `physicalAdapterLockdown.ts`, `tunAdapter.ts`, `serverPicker.ts`, `connectionPlanner.ts`.
- Tests added/updated: `tunAdapter.test.ts`, `tunControllerConfig.test.ts`, `firewallKillSwitchValidation.test.ts`, `physicalAdapterLockdownSource.test.ts`, `serverPickerTunnelProbe.test.ts`.

## 2026-09-13 - Task: Fix Kimi Desktop project chats, stuck Dashboard warning, and Gemini split-session detection
### What was done
- Researched via Sentinel multi-agent swarm and resolved three interacting network and UI issues:
  1. **R1 (Kimi Desktop Project Chats)**: Added dedicated Inbound and Outbound allow rules for both IPv4 (`127.0.0.0/8`) and IPv6 (`::1/128`) loopback in `firewallKillSwitch.ts`, preventing WFP `DefaultOutboundAction=Block` from dropping Happy Eyeballs localhost sockets. Added direct-out and direct DNS routing in `smartRoute.ts` for Moonshot AI / Kimi domains (`.kimi.com`, `.kimi.ai`, `.moonshot.cn`, `.volces.com`, `.aliyun.com`, `.trustdecision.com`) to bypass domestic Chinese IP geo-blocking of datacenter VPNs. Hardened `getProxyOwnerProcesses` in `tunController.ts` to capture `xray.exe`, `happd.exe`, `Happ.exe`.
  2. **R2 (Dashboard Stuck Warning & Watchdog Recovery)**: Decoupled watchdog confirmation in `tunController.ts` via `hasRecentWatchdogConfirmation` to check real traffic activity (> 1024 B/s download/upload) and probe confirmation, immediately suppressing failure counts and invoking `markProxyRecovered()`. Expanded `ipMonitor.ts` with multi-provider endpoints (`cloudflare`, `ipify`, `icanhazip`, `myip`) with racing and failover under HTTP 429 rate limits. Added self-healing in `App.tsx` and `Dashboard.tsx` (`isProxyActuallyDown`) to clear stale `proxyDown` flags when traffic is actively flowing.
  3. **R3 (Gemini "Unusual Traffic" & Google Split-Session Leak)**: Pinned all Google and Gemini domains (`GOOGLE_AND_GEMINI_PINNED_SUFFIXES`) to `proxy-out` and `dns-remote` strictly before RU domain and `geoip-ru` rules in `smartRoute.ts`, preventing Google Global Cache (GGC) nodes inside Russia or maps from splitting active Google sessions. Intercepted STUN UDP ports 19302 and 3478 to prevent WebRTC leaks.
### Testing
- `npm run typecheck` (`tsc --noEmit`): 0 errors.
- `npm test`: 98 test suites passed, 950 tests passed, 3 skipped, 0 failures.
- Added tests: `src/main/ipMonitor.test.ts` (10 tests), `src/main/watchdogTrafficRecovery.test.ts` (10 tests).
- `npm run build`: built cleanly in 3.67s without dynamic bundle require errors.



## 2026-09-29 — WP-1: Secrets, IPC, and trusted boundary
### What was done
- Added a process-wide Electron IPC trust boundary installed before any `ipcMain.handle` registration. Every invoke now requires the main renderer frame, an exact development origin or the packaged `file://.../renderer/index.html`, and a bounded plain structured-clone payload. Subframes, hostile file pages, foreign origins, dangerous prototypes, cyclic payloads, excessive depth/size, and unsupported values fail closed.
- Added a `safeStorage`-backed `SecretRef` format and migrated persisted server-profile `outbound` and `sourceUri` values without changing the in-memory `ServerProfile` contract. Migration builds the complete encrypted replacement before committing it, preserves a one-time pre-migration backup when a real store file exists, records completion metadata, and leaves the legacy store unchanged on injected encryption failures.
- Applied the same secure-storage policy to settings fields that can contain raw keys, subscription links, or complete cached outbounds (`directVpnInput`, `directVpnCachedInput`, `directVpnCachedSource`, `directVpnCachedProfiles`). Production refuses plaintext persistence when OS encryption is unavailable; the test-only cipher is gated by `NODE_ENV=test` and is never a production fallback.
- Removed the duplicate plaintext `electron-store` instance from `serverPicker.ts`; profile reads/writes now share one encrypting facade with server groups, config import/export, and tunnel startup.
- Removed the unused renderer-facing `connection-history:add` mutation channel and added strict runtime validation for notification preference patches.
- Made runtime binary staging fail closed when the privileged runtime directory cannot be verified as admin-only. No sing-box/Wintun/Cronet file is copied after ACL verification fails.
- Hardened the external-proxy control boundary: strict loopback `Host`/port validation prevents DNS rebinding; control-token files receive protected Windows ACLs and are deleted if ACL application fails.
- Moved subscription HWID, device metadata, and fingerprint-bearing User-Agent values out of curl argv. Curl reads all subscription headers through stdin (`-H @-`), so WMI/process listings no longer disclose the stable device identity.
- Added an effective renderer `<meta>` CSP for packaged `file://` builds and explicitly enabled Chromium sandboxing alongside context isolation and disabled Node integration.
- Added a final recursive text/JSON secret-redaction pass immediately before diagnostics compression, covering copied manifests and future staged artifacts that might otherwise bypass source-specific redactors.
- Added explicit warnings before single-key, batch-key, proxy-list, and full-config exports. Clipboard exports are cleared after 60 seconds only when the clipboard still contains the exported secret, so newer user content is never destroyed.
- Added focused tests traced to AT-01-001…011: atomic migration/rollback, safeStorage fail-closed behavior, diagnostics final scan, hostile sender/origin, generic malformed IPC payloads, DNS-rebinding Host headers, packaged CSP, sandbox parity, export/clipboard cleanup, and property-based secret redaction.

### Verification
- `npm run typecheck`: passed.
- Focused WP-1 and adjacent regression suites: passed, including profile/group refresh, profile switching, VPN parser regressions, IPC channel contract, notification preferences, connection history, secure-store rollback, CSP/sandbox, diagnostics redaction, clipboard cleanup, and 500 property-based redactor cases.
- Full `npm test` on Linux: 1122 passed, 12 skipped, 43 failed. The failure count is identical to the pre-WP-1 baseline; failures remain in Windows-only PowerShell/ACL/ETW/pktmon/sing-box smoke suites and seven existing live-server suites that cannot load in this environment. WP-1 introduced no additional full-suite failures.
- `python3 docs/04-приёмочные-тесты/traceability/check-coverage.py`: AC 927/927, F 210/210.
- Windows L3 acceptance remains required for real DPAPI persistence, NTFS ACL read-back, WMI argv inspection, packaged CSP smoke, and diagnostic ZIP scanning on OS-W11-24H2.

### Rollback and chronology
- Reverting this WP-1 commit restores plaintext profile/settings persistence, per-module unguarded IPC registration, argv subscription headers, response-header-only CSP, and warning-only runtime ACL behavior.
- The `*.pre-safe-storage-v1.bak` files are intentionally never deleted automatically. They allow recovery after a migration fault but contain legacy plaintext secrets and should be removed by a future verified cleanup step only after successful Windows acceptance.

## 2026-09-29 — WP-3: Firewall baseline, adapters, DNS, and boot recovery
### What was done
- Corrected kill-switch normalization: missing, undefined, malformed, and legacy-absent values now remain OFF; only explicit `true` enables the global firewall policy.
- Made firewall activation transactional at the manifest boundary. If durable manifest commit fails after rules/default-block were applied, VPNTE immediately restores the captured profile defaults and removes its rules; a manifest-less Block state is no longer reported as success.
- Reworked baseline rollback into independent named steps. HKCU Internet Settings, HKCU Environment, HKLM Connections, and WinINet notification all continue after an earlier failure; every failure is reported and the manifest remains for retry until all steps succeed.
- Corrected packaged boot-recovery path to the actual `extraResources` destination (`process.resourcesPath/vpnte-recover.ps1`). The scheduled-task action uses UTF-16LE `-EncodedCommand`, eliminating nested quoting failures for Program Files paths. Registration failures are visible in logs, clear the process guard, and can be retried; concurrent settings operations cannot register duplicate tasks.
- Restricted SYSTEM recovery to a single canonical ProgramData location. Recovery validates protected ACL, owner SID, and write-capable ACEs before loading a manifest; all AppData and cross-user profile scanning was removed.
- Hardened ProgramData manifest persistence before every write using the verified admin/SYSTEM-only directory policy. A failed ACL check or write is fatal instead of a warning, so SYSTEM never consumes an untrusted fallback manifest. userData remains diagnostic-only and is no longer authoritative for rollback.
- Replaced hard-coded `Ethernet 5`/`VPNTE-TUN` cleanup with driver-identity discovery. Boot recovery removes only adapters whose InterfaceDescription identifies Wintun, preventing deletion/disable of a physical NIC with a colliding alias.
- Changed physical-adapter lockdown on an empty adapter set from false success to explicit `applied: false`; no transition settings or manifest are changed in that branch.
- Added strict app/IP exception validation. IP/CIDR masks are bounded for IPv4/IPv6; app exceptions require an existing readable `.exe` and persist its canonical path; equivalent duplicates are rejected.
- Serialized exception mutations and synchronized a changed exception set with an already-active firewall policy. Failed live application restores the previous in-memory and persisted set, so UI/scheduler races cannot silently lose or partially apply updates.
- Fixed DNS replace-import referential integrity: when the imported active ID is absent, selection is reset to an existing imported DNS profile (or null) instead of retaining a dangling deleted ID.
- Updated source and behavioral tests for authoritative ProgramData recovery, encoded task registration, explicit kill-switch defaults, IP/CIDR/app-path validation, config import, rollback continuation, and existing firewall validation.

### Verification
- `npm run typecheck`: passed.
- Focused WP-3 suites: 10 files / 91 tests passed.
- Full Linux run: 1139 passed, 12 skipped, 43 failed. The same 43 pre-existing Windows-only/fixture failures remain; WP-3 added no new full-suite failures.
- Required Windows L3 matrix remains: OS-W10-22H2, OS-W11-23H2, OS-W11-24H2 plus NET-FLAP and NET-IPV6-ONLY, including pktmon/external leak oracle, SYSTEM reboot recovery, real NTFS ACL abuse, adapter hot-plug, and injected partial rollback.

### Rollback and chronology
- This commit follows WP-1 commit `8f77f19` and is intentionally isolated so firewall/recovery behavior can be reverted independently.
- Reverting restores the old default-on normalization bug, AppData SYSTEM manifest search, hard-coded adapter deletion, nested schtasks quoting, fail-open ProgramData writes, and sequential rollback abort behavior.

## 2026-09-30 — Merge PR #13: Harden VPN recovery, firewall transactions, and secret boundaries
### What was done
- Merged GitHub PR #13 (`genspark_ai_developer` -> `main`), integrating the complete security change-sets across WP-1 and WP-3.
- Trusted recovery storage: all recovery manifests and intermediate scripts are isolated to `%ProgramData%\VPNTE\manifests`, validated against strict schema, restricted to SYSTEM (`S-1-5-18`) and Administrators (`S-1-5-32-544`), and protected against reparse-point / symlink hijacking.
- Transactional firewall policy: manifests are committed in a `prepared` phase before changing outbound actions or adding rules; any failed step triggers immediate rollback and compensation.
- Strict recovery safety: `vpnte-recover.ps1` maintains fail-closed behavior (`DefaultOutboundAction Block`) if `strictMode` was active, refusing to unblock traffic until explicit user action.
- Secret export consent: native confirmation dialogs in main process for single-key, bulk-key, and proxy exports; removed plaintext URIs from IPC return values; implemented 60s fingerprint-checked clipboard auto-clear in main.
- IPC import boundary: domain routing and configuration file imports require native open-dialog selection with one-time capability tokens, preventing unprivileged renderers from reading arbitrary host paths.
- Windows platform compatibility: resolved Node 24 `util.isObject` compatibility for `sudo-prompt` in `admin.ts`, cross-platform path separators in `bootRecoveryRegistration.test.ts`, and mocked `recoveryManifest` in `granularKillSwitch` tests to prevent unmocked elevated executions during unit testing.

### Verification
- `npm run typecheck`: passed with 0 errors.
- `npm test`: 150 test suites passed, 1413 tests passed, 0 failed, 10 skipped.
- `npm run build`: built main, preload, and renderer production bundles cleanly in 3.17s.
- `npm run test:vpn-profiles`: 12/12 profile parsing checks passed.
- `python docs/04-приёмочные-тесты/traceability/check-coverage.py`: AC 927/927 (100%), F 210/210 (100%).

## 2026-09-30 — WP-4 / F-064: Explicit subscription refresh failures
### What was done
- Failed subscription fetches now return `ok: false` with the original error through `groups:refresh`, so the existing renderer error branch displays the failure and automatic refresh counts it as failed.
- Empty subscription responses also return an explicit error instead of reporting a successful refresh with zero changes.
- Saved profiles and the active profile remain unchanged on failure; attempt/error metadata is retained for diagnostics and retry scheduling.
- Added 11 regression cases traced to the failure-result subset of AT-04-007 / AC-SRV-SUB-001…006 / F-064: DNS/TCP/TLS/HTTP/timeout/parser failures, empty responses, partial multi-device fetch failure, IPC propagation, automatic counters, and a successful retry after failure.

### Verification
- Before the fix, `npm.cmd test -- src/main/serverGroupsRefresh.test.ts`: 11 new regressions failed, 13 existing tests passed.
- After the fix, `npm.cmd test -- src/main/serverGroupsRefresh.test.ts`: 24/24 tests passed.
- `npm.cmd run typecheck`: passed with 0 errors after correcting the typed test fixture.
- `npm.cmd test -- --reporter=dot`: 150 files passed, 2 skipped; 1424 tests passed, 10 skipped, 0 failed.
- `python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py` from `vpn-tunnel-enforcer`: exit 0, AC 927/927, F 210/210.
- The network boundary is mocked in these regressions. This scoped repair does not establish completion of the full WP-4 transaction, parser, fuzzing, or Windows acceptance matrix.

### Rollback
- Revert this change to restore the previous `ok: true` responses for failed/empty refreshes; no store migration or schema change was introduced.

## 2026-09-30 — WP-11: Electron 42 → 44 migration
### What was done
- Pinned Electron 44.4.3, electron-vite 5.0.0, electron-builder 26.15.3 and Node 24 types (24.13.3) in the app manifest and lockfile. This addresses F-166 and the Electron/toolchain subset of F-167; the rest of WP-11 is separate work.
- Replaced electron-vite's deprecated externalizeDepsPlugin with build.externalizeDeps, retaining the existing main snapshot banner and sandboxed preload bundle.
- Migrated secret clipboard handling to Electron 44's Promise-based read/write API and ClipboardItem types. Copy-key IPC acknowledges only a completed write; shutdown awaits cleanup. Serialized operations and ownership-bound timeouts preserve a replacement key's 60-second deadline, failed-write cleanup, and foreign clipboard data. Seven additional regressions cover asynchronous failures/delays and races (AT-01-008, AC-SRV-EXP-001…003, F-158).
- Added explicit prepare:electron hooks before dist targets because modern Electron downloads its runtime on demand. Added test:electron with isolated userData, actual production preload and actual IPC/security/secret-storage modules; no VPN runtimes, network settings or user clipboard are changed by this smoke harness.
- Reviewed upstream breaking changes for Electron 43/44 and electron-vite 5. References: https://www.electronjs.org/docs/latest/breaking-changes and https://electron-vite.org/guide/migration .
- Verified the user-downloaded electron-v44.4.3-win32-x64.zip against the npm package's upstream checksums: 158247567 bytes, SHA-256 790a355b684d5c7cc8dc3cdd8c4cca7c4b2d054685427c7554a956879a82e70b. The background installer also completed successfully and installed runtime 44.4.3.

### Verification
- npm.cmd run typecheck: exit 0, no errors; also executed by final build/packaging commands.
- npm.cmd test -- src/main/appLoggerRotation.test.ts src/main/xrayEngine.live.test.ts src/main/secretClipboard.test.ts src/main/serverKeyExportSecurity.test.ts: 34 passed, 1 skipped, exit 0.
- npm.cmd test -- --reporter=dot --maxWorkers=4: 150 files passed, 2 skipped; 1431 tests passed, 10 skipped, 0 failed, exit 0. Earlier default-worker runs had an Xray timeout and an existing appLoggerRotation.test.ts stat/rename race; these failures are not concealed or treated as passes. The interrupted pre-download run was also not a successful validation.
- npm.cmd run test:electron: exit 0, 8 native smoke checks passed on Electron 44.4.3 / embedded Node 24.21.0: native safeStorage encrypted file round-trip; production contextBridge/sandbox; reload; invalid payload rejected before handler; unregistered WebContents rejected; navigated file origin rejected; development loopback parity; exact runtime version. Traces AT-01-001/003/004/007/010 for the corresponding regression subsets.
- npm.cmd run dist:win: final rebuild exit 0, native ETW sidecar built and NSIS packaged with Electron 44.4.3. Optional mksnapshot was absent and reported an explicit fallback warning; bundler and sidecar deprecation warnings remain.
- python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py: exit 0, AC 927/927, F 210/210. git diff --check: exit 0.
- Final artifact: vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe, 139144849 bytes, SHA-256 4B4C702EFBB5D1326F25BBFDE5D52C4C0482FA0F05CF5903DBAFBB196232BE1B, Authenticode NotSigned. Application version remains 1.1.22; no release was published or installed.
- Full Windows VM install/upgrade/uninstall matrix and active-tunnel acceptance were not run. Native clipboard/Win32 acceptance and cross-version DPAPI migration against an actual Electron 42 store remain separate from the native round-trip smoke. This does not claim completion of all WP-11 or all referenced AT tests. Normative docs were not edited.
- Automatic approval review rejected cleanup of known interrupted-download temporary directories outside the workspace with reason "blocked by policy"; those directories were left intact. Smoke harness directories under .tmp were removed successfully by the harness.

### Rollback
- Revert this migration commit and reinstall the app dependencies from its restored lockfile. No user-store schema or encrypted data format changed.

## 2026-09-30 — WP-3/WP-11: Localized SYSTEM breaks installer recovery read-back
### Finding and fix
- The installer screenshot showed `Recovery task read-back mismatch` after the registration call in vpnte-recover.ps1. Native ScheduledTasks inspection reproduced the localization: New-ScheduledTaskPrincipal -UserId SYSTEM returns UserId `СИСТЕМА` on this Windows installation. The old allow-list rejects that name even though NTAccount.Translate resolves it to S-1-5-18; the native startup trigger is MSFT_TaskBootTrigger.
- Resolve the principal account to its SID before read-back comparison. Only S-1-5-18 is accepted; an unresolvable account fails closed. Existing RunLevel, action executable/arguments, action count and startup-trigger checks remain mandatory. Registration errors still abort the installer.
- Added native PowerShell regression coverage of the actual production resolver/read-back condition using New-ScheduledTask CIM objects without registering or executing tasks. It accepts the native localized name, SYSTEM, NT AUTHORITY\\SYSTEM and S-1-5-18, and rejects 10 altered-principal/action/trigger cases. Traces the registration subsets of AT-03-002 / AT-11-001/007, AC-LEAK-RCV-001…004, F-043/F-150/F-203.

### Verification
- npm.cmd test -- src/main/bootRecoveryTaskReadBack.test.ts src/main/bootRecoveryRegistration.test.ts src/main/bootRecoveryScriptSource.test.ts src/main/eosInstallerCompatibility.test.ts: 4 files / 12 tests passed, exit 0. The initial harness exceeded Windows command-line length; embedding only the resolver fragment corrected the harness, then all native cases passed.
- npm.cmd run typecheck: exit 0, no errors.
- npm.cmd test -- --reporter=dot --maxWorkers=4: 151 files passed, 2 skipped; 1432 tests passed, 10 skipped, 0 failed, exit 0.
- python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py: exit 0, AC 927/927, F 210/210.
- npm.cmd run dist:win: exit 0; installer rebuilt with Electron 44.4.3. Source and unpacked recovery resource hashes match: 20D25BF66364EDF64AEB9455B63A3CD5F9BC543BA18C6EC285A8D248EA8EF849.
- Updated artifact: vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe, 139145006 bytes, SHA-256 85E26D483780AE9961A369EEE08319BC76D03AA66564B398F4DFE9F6CE238420, Authenticode NotSigned. This replaces the installer from the preceding migration entry.
- git diff --check: exit 0. No real task was created/changed by the regression test, and no network recovery was invoked. Actual elevated installation and reboot acceptance await rerunning the rebuilt installer; this does not claim the full VM acceptance matrix passed.

### Rollback
- Revert this fix to restore the previous name-based comparison; no store schema, task action or recovery policy changed.

## 2026-09-30 — WP-3 / WP-0 regression: cancellation recovery and immediate UI feedback
### Evidence and changes
- At 23:16 MSK, app.log records refusal to start because `happ-tun` is active, followed by cancel-tun, baseline rollback command failures, and the warning shown in the user's screenshot. The full native error was lost behind the logger's truncation of a long EncodedCommand. Current native processes include Happ; no live network recovery was invoked during this investigation.
- A production rollback command generated with a minimal valid nine-value fixture is 10,482 characters. A harmless PowerShell payload of comparable length fails with exit 1 through the Windows shell and succeeds with exit 0 through direct execFile/spawn. The diagnostic did not execute the captured recovery script or modify network/registry settings; its temporary file under the app's .tmp was removed.
- Baseline PowerShell calls now use execFile directly. The already-elevated execElevated branch recognizes only the fixed generated PowerShell invocation and also bypasses cmd.exe; other shell commands and the existing non-elevated sudo-prompt path retain their semantics. Packaged startup requires elevation. Native stderr is reported before the log length limit, with the encoded snapshot omitted.
- Clarification to the initial explanation: startDirectVpnProtection starts baseline preparation before tunController checks competing TUNs. The retained snapshot can come from this same refused connection attempt, not necessarily an earlier connection. This ordering and recovery ownership policy were not changed.
- The cancellation button immediately shows a spinner and `Отменяем…` / `Cancelling…`, disables repeat clicks and keeps the global busy state until cleanup IPC returns, including across Dashboard remounts and intermediate stopped events. Success, recovery warnings and failures are visibly reported; failed cancellation does not claim the tunnel stopped.
- Connection generations now survive Dashboard remounts. Preparation checks the generation after each awaited lookup/settings save, and late start success/failure cannot overwrite a cancelled operation or initiate a start after cancellation.
- Traces: WP-3 AT-03-003/007/012 subsets, F-033, AC-LEAK-RCV-001…004 recovery-report subset; WP-0 AT-00-003/008 and F-021 cancellation/UI subsets. This scoped regression repair does not claim completion of either entire WP or their L3 acceptance matrix.

### Verification
- Initial targeted run: 2 UI tests failed because both the power button and cancellation button share the status label. The test queries were narrowed by aria-busy; no production behavior was changed to satisfy this query issue.
- With VPNTE_PWSH set to native powershell.exe: npm.cmd test -- src/main/admin.test.ts src/main/adminPowerShellTransport.test.ts src/main/systemNetwork.test.ts src/renderer/pages/Dashboard.cancel.test.tsx src/renderer/store.connectionBusy.test.ts src/renderer/AppSource.test.ts --reporter=dot --maxWorkers=4: 6 files / 70 tests passed, exit 0. Includes native script parsing, harmless native transport success/failure and real React DOM cancellation checks.
- npm.cmd run typecheck: exit 0, no errors.
- npm.cmd test -- --reporter=dot --maxWorkers=4: 153 files passed, 2 skipped; 1444 tests passed, 10 skipped, 0 failed, exit 0.
- python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py: exit 0, AC 927/927 and F 210/210.
- npm.cmd run dist:win: exit 0, rebuilt NSIS installer with Electron 44.4.3. Existing optional mksnapshot fallback/bundler/sidecar warnings remain; the DOM test exposed an existing MacToast/framer-motion ref warning without a failed assertion.
- Artifact: vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe, 139144754 bytes, SHA-256 7050457F3B7166205031CAD1257E1A5939E46CF8C74C1D130EA4167AB804004F. Version remains 1.1.22; no release published or live installation performed.
- Native transport tests run the production elevated branch with only the elevation check simulated; they execute harmless PowerShell on this Windows host. Actual elevated recovery of the user's retained manifest, live cancellation after installing this build and the full VM acceptance matrix remain unverified. The retained snapshot was not deleted. Normative documents were not edited.

### Rollback
- Revert this regression fix; no persisted store schema, snapshot format or ownership policy changed.

## 2026-09-30 — WP-3 / WP-0: native rollback array decoding and cancellation circle colour
### Finding and fix
- The repeated user scenario now logs `Invalid baseline recovery report` (23:38:44–23:38:58 MSK), rather than the earlier PowerShell launch failure. Native Windows PowerShell is 5.1.26100.9444.
- Added a regression that executes the production JSON decoding/report loop with only Restore-Snapshot replaced by a harmless effect stub. Before the fix, all ten cases fail: the report has one step instead of nine. Windows PowerShell ConvertFrom-Json emits the decoded array as one pipeline object; wrapping the assignment in @() adds another array layer.
- Assign the decoded array directly before foreach. Keep the strict nine-step/name/type report validation, independent failure collection, trusted manifest checks and snapshot retention rules. This fixes the actual protocol boundary rather than relaxing verification. Existing mocked command responses had hidden the native array shape.
- Ten native cases now verify all-success and each single failed step, including exact ordered step names and continuing after failure. Another native case executes production Restore-Snapshot/Get-Snapshot for DWord, String, ExpandString, QWord, Binary, MultiString, empty and absent values below a GUID-named HKCU test subtree; the subtree is deleted in finally. Real network registry keys, HKLM and the user's retained manifest are not touched. No test subtrees remain.
- The large power circle immediately switches to a distinct violet cancellation colour and matching glow/backdrop. Cancellation overrides connected/server-switch colours and hides their animations until cleanup finishes; the status text keeps theme-appropriate contrast. The colour returns to the normal state after cleanup. React DOM tests cover both a pending connection and a still-connected tunnel.
- Traces: AT-03-003/007/012 subsets, F-033, AC-LEAK-RCV recovery-report subset; AT-00-008 / F-021 cancellation visual feedback. Normative documents and recovery ownership policy were not changed.

### Verification
- With VPNTE_PWSH set to powershell.exe: npm.cmd test -- src/main/systemNetwork.test.ts src/renderer/pages/Dashboard.cancel.test.tsx --reporter=dot --maxWorkers=4: 2 files / 44 tests passed, exit 0. Includes native parser, production report-loop matrix and isolated native registry read-back.
- npm.cmd run typecheck: exit 0, no errors.
- npm.cmd test -- --reporter=dot --maxWorkers=4: 153 files passed, 2 skipped; 1456 tests passed, 10 skipped, 0 failed, exit 0.
- python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py: exit 0, AC 927/927 and F 210/210.
- npm.cmd run dist:win: exit 0, rebuilt NSIS with Electron 44.4.3. Existing build/optional mksnapshot and MacToast ref warnings remain non-fatal. git diff --check: exit 0.
- Artifact: vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe, 139144897 bytes, SHA-256 F50BD23408CFBCEC7C6EA0583178E3351EC677A209AC65351B95A5380D402BBA, Authenticode NotSigned. Supersedes the preceding same-version installer.
- Live recovery using the user's retained snapshot, visual acceptance in the installed app and full Windows VM acceptance remain unverified. No live VPN/network operation or installation was performed during this fix.

### Rollback
- Revert this fix; persisted snapshots and settings formats are unchanged.

## 2026-09-30 — WP-0 / WP-9: cancellation presentation polish
### Changes
- Per owner feedback, the visible `Отменяем…` label now appears only on the small cancellation button. The status paragraph is screen-reader-only while cancelling, preserving its polite live announcement; normal visible status returns after cleanup. The button remains disabled and shows its spinner until cleanup completes.
- Added two static violet rings, a soft halo and a restrained surface highlight around the large cancellation circle. Other state colours and the small warning-coloured button remain unchanged. No additional repeating animation was introduced.
- Extended the real React DOM regression to cover the visible button label, hidden live status during cancellation/remount and restored visible status after cleanup. Traces: AT-00-008 / F-021 and AT-09-009 subsets; no normative documents changed.

### Verification
- npm.cmd test -- src/renderer/pages/Dashboard.cancel.test.tsx --reporter=dot --maxWorkers=4: 1 file / 7 tests passed, exit 0.
- npm.cmd run typecheck: exit 0, no errors.
- npm.cmd test -- --reporter=dot --maxWorkers=4: 153 files passed, 2 skipped; 1456 tests passed, 10 skipped, 0 failed, exit 0.
- python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py: exit 0, AC 927/927 and F 210/210.
- The compiled renderer stylesheet includes the cancellation ring rules and sr-only utility. Installed-app visual acceptance is not claimed; no live connection or installation was performed.
- npm.cmd run dist:win: exit 0, rebuilt NSIS installer with Electron 44.4.3. Existing build warnings and the MacToast/framer-motion ref warning remain non-fatal. git diff --check: exit 0.
- Artifact: vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe, 139144989 bytes, SHA-256 1B2420B66299738C559FCF30F1B3583E7EF30FE511EC1044107B36F407B0673C, Authenticode NotSigned. Supersedes the preceding same-version installer.

### Rollback
- Revert this scoped UI change; connection lifecycle and persisted settings are unchanged.
## 2026-10-01 — WP-2 / WP-3: failed connection, native adapter identity and startup hang
### Measured evidence
- app.log records the attempt from 00:00:08.380 to 00:01:25.194 MSK (76,814 ms). Xray reports ready at 00:00:18.058; at 00:00:20.111 the async startup callback rejects with `VPNTE TUN driver identity mismatch`. The application logs an unhandled rejection instead of completing the attempt. The user closes the app at 00:01:19.949; cleanup then settles the pending start. This is a hung validation path, not a measured 77-second server handshake.
- At 00:00:35.760, the live-exception update and compensation report unknown, matching the screenshot. Native in-memory execution of the production script fails before the fix for empty and multi-rule lists (2/3 cases); its extra @() wrapper nests ConvertFrom-Json arrays. The previous log omitted the underlying script errors, so it cannot independently prove which policy produced this particular warning. New logging preserves bounded native errors with EncodedCommand omitted.
- A read-only adapter inventory shows `sing-tun Tunnel` as InterfaceDescription and `Wintun Userspace Tunnel` as DriverDescription, with a SWD/Wintun PnP identity. The failed VPNTE adapter had already disappeared; these local metadata observations and native fixtures explain why matching the friendly interface description is incorrect. Native production ownership verification rejects the valid sing-tun/Wintun fixture before the fix (1 failed positive case).

### Changes and scope
- Match DriverDescription and PnPDeviceID when recording TUN ownership, keeping exact alias, GUID and IPv4 /30 checks. Boot recovery applies the same driver/device checks after selecting the exact recorded GUID; an existing device with mismatched identity preserves the ownership journal and reports a warning. Foreign adapters remain untouched.
- Decode the firewall rule list directly, retaining strict rule/filter/set read-back, compensation and durable pending-journal semantics. No protection validation was relaxed.
- Catch failures throughout the asynchronous startup poll callback, wait for the parallel firewall transaction before rollback, independently attempt process/Xray/adapter/firewall cleanup, then settle the connection with failure even if cleanup or a status listener throws. Prevent overlapping native polls. Add ownership-phase timing and replace the misleading intermediate claim that VPN continues without required kill-switch protection.
- Real callback tests cover successful start, required firewall failure, unready TUN, probe failure, ownership failure during a pending firewall transaction, all cleanup failures, a throwing status listener and overlapping ticks. Native PowerShell tests use fake cmdlets/storage exclusively.
- Traces: AT-02-004/005 and AT-03-002/008/009 subsets, AC-CONN-MODE-004.3, F-131, F-031 and F-204 regression boundaries. This scoped repair does not claim completion of all WP-2 or full Windows L3 acceptance. Normative documents and owner decisions were not changed.

### Validation
- Initial typecheck found an inferred Promise<never> in the test stub; an explicit Promise<void> fixed it. Initial full runs exposed one whitespace-dependent source assertion after adding try/catch indentation; it now ignores indentation, with behavior covered by the actual callback tests.
- Native full-script boot harness initially exceeded Windows command-line limits and used a Unix-only ProgramData fixture. It now runs its mocked harness from a unique app .tmp file and uses the real known-folder value with all I/O/network boundaries still mocked. Temporary harness files/directories were removed.
- With VPNTE_PWSH=powershell.exe: npm.cmd test -- src/main/bootRecoveryExecution.test.ts src/main/bootRecoveryBehavior.test.ts src/main/recoveryManifestStorage.test.ts src/main/firewallTransactions.test.ts src/main/tunControllerStartup.test.ts src/main/auditFixesRegression.test.ts --reporter=dot --maxWorkers=4: 6 files / 79 tests passed, exit 0.
- npm.cmd run typecheck: exit 0, no errors.
- npm.cmd test -- --reporter=dot --maxWorkers=4: 154 files passed, 2 skipped; 1477 tests passed, 10 skipped, 0 failed, exit 0.
- python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py: exit 0, AC 927/927 and F 210/210. git diff --check: exit 0.
- No actual VPN connection, registry/firewall/adapter modification, installation or reboot was performed by this task. A fresh installed-app connection and its normal latency remain unverified; no connection-time guarantee is made. Read-only inspection currently sees another active Happ TUN, which must be considered separately when retrying.
- npm.cmd run dist:win: exit 0, Electron 44.4.3 NSIS rebuilt. Packaged main JS contains the driver/device checks, caught startup-failure path and ownership timing; packaged recovery script hash matches source: B96EFEF41BCE618AF3DAF455469437981D37D9E30DF6A19208BF48EE4C7F6C0C. The initial ASAR lookup used slash separators; using the archive's native Windows path confirmed its entry.
- Artifact: vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe, 139145575 bytes, SHA-256 6835F8894A83FF345A6E685C137CCCF01911089EB62038F531FA5F2C5EF687E2, Authenticode NotSigned. Supersedes the preceding same-version installer. Existing optional snapshot/build warnings remain non-fatal.

### Rollback
- Revert this scoped regression repair; manifest schemas, firewall policies and saved settings formats are unchanged.
## 2026-10-02 — WP-2 / WP-3 / WP-7 / WP-8: phone hotspot detection and failure-path logging

### Evidence and acceptance boundary
- The latest installed-client attempt (16:59:37–17:01:12 MSK) started the local Xray SOCKS and TUN, but all four foreign HTTPS probes timed out repeatedly. Russian sites are eligible for direct-out under the user's Smart RU setting; their availability does not verify VPN egress. The user's ordinary-Wi-Fi comparison is accepted and does not need repetition.
- The physical uplink was MediaTek Wi-Fi attached to a Galaxy S24 Ultra network with a modern 10/8 hotspot DHCP subnet. The existing classifier returned isCellularOrTethering=false because it ignored the connected network profile and used device descriptions/legacy DHCP subnet patterns. IPv6 was already disabled in the pre-start snapshot: this classifier defect alone does not establish the cause of this attempt's egress failure.
- Read-only elevated inspection confirmed that the selected IPv4 VPN endpoint was excluded from TUN routing, MTU was already 1280, and sing-box proxy-out used the local Xray SOCKS. The short last Xray run contained 27 dial attempts and one protocol tunneling-request record; this does not prove an HTTPS response. The sampled sing-box connection-refused records coincide with user stop/adaptive restart and cannot be treated as the initial cause. Exact upstream TCP/TLS/REALITY failure remains unconfirmed in the old evidence.

### Changes
- Read connected network profiles and IPv4 gateways in the physical adapter snapshot. Recognize modern phone profiles (including Galaxy) without treating every private 10/8 network as tethering. Keep the existing mobile IPv6 exception and the recorded pre-existing IPv6 state. Profile names are used transiently and are not stored in manifests or diagnostic messages. Strictly validate candidate subnet IPs.
- Log classifier method, original IPv6 state, resolver source/count and default-route count; log bootstrap DNS methods, safe error codes, durations and fallback results. Explicitly label Xray readiness as local SOCKS readiness with remoteVerified=false.
- For failed foreign HTTPS races, preserve fixed target identifiers, response status, safe error codes and elapsed time, including the existing literal-IP target that does not need DNS. Cancel remaining requests after a winner and discard late results after a session change.
- Before returning a failed health check to adaptive recovery, collect bounded (256 KiB each) Xray/sing-box log summaries from the current session. Record unreadable/missing logs honestly, count protocol progress separately from successful egress, and count timeout/reset/access/TLS/REALITY/local-SOCKS failures without copying addresses or messages.
- Compare TCP CONNECT to the selected VPN endpoint through mixed-direct-in with certificate-validated HTTPS to the existing literal-IP reflector through Xray SOCKS, bypassing TUN and DNS. Each additional path probe has a 3-second overall deadline; late sockets are closed. Rate-limit collection to one per 30 seconds per session and suppress stale publication. Assessments describe measured path differences, never assert carrier/DPI blocking. Diagnostics do not mark a failed health check successful.
- Bound the Xray stderr accumulator to its last 64K characters. Traces: AT-02-006, AT-03-006, AT-07-002 and AT-08-001 subsets; F-207 buffer boundary. This is a scoped hotspot/observability repair, not complete Windows L3 or whole-WP acceptance. Normative documents and code-signing decisions were not changed.

### Validation and artifact
- Initial focused run exposed a missing default export in a TLS test mock and typecheck exposed a variadic mock signature; both were corrected. A later assessment typecheck and a filesystem mock default export were also corrected before final validation.
- npm.cmd test -- src/main/networkFailureDiagnostics.test.ts src/main/physicalAdapterLockdownSource.test.ts src/main/serverPickerTunnelProbe.test.ts src/main/xrayDns.test.ts src/main/xrayDnsNative.test.ts src/main/xrayEngine.test.ts src/main/xrayRuntimeLifecycle.test.ts --reporter=dot --maxWorkers=4: 7 files / 67 tests passed at that revision.
- Initial full run: 1896 passed, 4 failed native PowerShell tests by timeout, 10 skipped. npm.cmd test -- src/main/firewallExceptionReadback.test.ts src/main/recoveryManifestStorage.test.ts src/main/recoveryPsProtocol.test.ts src/main/systemSnapshot.test.ts src/main/networkFailureDiagnostics.test.ts src/main/appLoggerRedaction.test.ts --reporter=dot --maxWorkers=2: all 6 files / 166 tests passed. Production timeout thresholds were not relaxed.
- npm.cmd test -- src/main/physicalAdapterHotspot.test.ts --reporter=dot: 3 behavior tests passed, including both original IPv6 states and ordinary Wi-Fi with the same 10/8 gateway.
- Final npm.cmd run typecheck: exit 0. Final npm.cmd test -- --reporter=dot --maxWorkers=4: exit 0, 176 files passed / 2 skipped, 1905 tests passed / 10 skipped / 0 failed.
- python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py: exit 0, AC 927/927 and F 210/210. git diff --check: exit 0.
- npm.cmd run dist:win: exit 0; Electron 44.4.3 NSIS rebuilt. ASAR inspection confirmed five new classifier/diagnostic/bootstrap/readiness markers in the packaged main bundle. Existing optional mksnapshot and bundling warnings remain non-fatal.
- Artifact: vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe, 139159588 bytes, SHA-256 0EE7F14562CF300AC1C9624A1DCE0026C3121ACA4F2653885031A71F39D06E90, Authenticode NotSigned. Supersedes the previous same-version installer. No installation, actual VPN connection, adapter/firewall mutation or live hotspot acceptance was performed. A retry with this build is required to confirm availability or capture the new failure-path event.

## 2026-10-02 — WP-4 / WP-2: Happ comparison identifies lossy Xray configuration handling

- Owner confirms Happ works on the same phone uplink where VPNTE fails. Read-only comparison found the installed Happ Xray binary and VPNTE bundled Xray binary have identical SHA-256 hashes and both report version 26.7.28, commit 5ca6f4b. The client configuration path is therefore the next repair target; earlier recommendations to change provider/server were premature.
- Fetched the selected Norway profile's subscription with the existing VPNTE PC subscription identity, without changing persisted application state or publishing credentials. Its Xray JSON sets `norwayvless1` REALITY fingerprint to `firefox` and mux to `{enabled:true, concurrency:6, xudpConcurrency:4, xudpProxyUDP443:'reject'}`. The persisted VPNTE profile has `chrome`. `applyClientDeviceToOutbound` overwrites the imported fingerprint; `xrayOutboundToProfiles` omits Xray mux, and `toXrayOutbound` rebuilds the outbound without restoring mux.
- The provider's `bridgenorwayvless1` uses `streamSettings.sockopt.dialerProxy = LOOP-L1-BRIDGE`, backed by loopback outbounds and routing balancers. The current importer discards that chain and the runtime compiler does not restore it. Consequently a VPNTE profile named as a bridge is currently a direct connection, so its Wi-Fi success does not verify the provider's bridge path.
- Happ documents JSON passthrough at https://www.happ.su/main/dev-docs/examples-of-links-and-parameters. VPNTE needs to preserve source TLS settings, mux, and the referenced outbound/routing dependencies while retaining its managed local listeners and traffic-isolation policy. Arbitrary passthrough of provider listeners or direct application-routing exceptions is not proposed.
- Normative discrepancy recorded against `docs/01` section 3.4 and `docs/03` section 3.1 (preservation of imported uTLS/ALPN). The owner subsequently approved its repair and requested a broader Happ comparison. The implementation and checks below follow that approval. These confirmed defects do not establish which individual setting causes the hotspot stall or prove a repaired connection succeeds.

### Approved repair and extended comparison
- Preserve explicit source fingerprint/ALPN before device defaults and adaptive rotation; profile metadata now reports the actual fingerprint. Preserve native Xray outbound fields inside the encrypted outbound rather than translate away mux, XUDP, sockopt, XHTTP mode/extra and other stream settings.
- Compile the reachable provider connection graph with consistent outbound/balancer/virtual-inbound names: bridge dialer dependencies, loopback routes, VLESS/Hysteria helpers, fallback, observatory/burstObservatory and policy. Full composite JSON imports as one connection; the current authoritative response imports as 10 profiles. Independent outbounds retain only their own dependencies to avoid quadratic copies.
- Keep managed loopback listeners, application routing, DNS and isolation. Do not inherit provider global direct exceptions, API, listeners or file paths; reject missing/cyclic/unsupported dependencies and plain application fallback. Allow freedom only as a physical dialer of an encrypted VPN outbound. Fail closed on unmatched conditional virtual routes.
- Auto uses Xray for native JSON, with a clear refusal for forced sing-box. Health checks compile the same graph and attach physical probe detours only at leaves. Bootstrap every reachable hostname with bounded parallelism and cancellation. URI export refuses to silently drop the graph. Effective-configuration logging records fingerprint/mux/counts, while diagnostics redact the entire native payload.
- Additional findings recorded in `vpn-tunnel-enforcer/docs/happ-compatibility-audit-2026-10-02.md`: adaptive network identity conflates Wi-Fi and hotspot on one card; profile learning identity omits transport/REALITY/fingerprint/native graph; URI XHTTP/gRPC and some sing-box multiplex translation still differ. These are follow-up proposals, including the recorded TЗ-03 §2.3 discrepancy; they were not silently folded into the approved import repair.
- Traces: AT-04-001/002/006 and AT-02-002/005 subsets, F-051/F-052. No normative documents, active app settings, network, adapter or firewall state were changed.

### Verification and artifact
- `npm.cmd run typecheck`: exit 0; packaging also reran typecheck successfully.
- `npx.cmd vitest run src/main/nativeXrayCompatibility.test.ts src/main/vpnProfilesClientDevice.test.ts src/main/xrayEngine.test.ts src/main/tunControllerConfig.test.ts src/main/lifecycleCleanup.test.ts src/main/appLoggerRotation.test.ts src/main/xrayEngine.live.test.ts`: 7 files passed, 170 tests passed, 1 skipped, exit 0.
- Initial full `npm.cmd test -- --reporter=dot`: 1912 passed / 7 failed / 10 skipped, plus an unhandled harness error. Four extraction-harness failures were repaired to include the new startup dependencies; logger/live-core timeout cases passed in the focused rerun. Production timeout thresholds were not increased.
- Final `npm.cmd test -- --maxWorkers=4`: exit 0, 177 files passed / 2 skipped; 1923 tests passed / 10 skipped / 0 failed. Expected RootErrorBoundary stderr is not a failing test.
- `python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py`: exit 0, AC 927/927, F 210/210. `git diff --check`: exit 0.
- The synthetic full VLESS/Hysteria/bridge fixture passed the bundled Xray `run -test` in the permanent regression suite. A separate read-only inspection ran all 10 actual subscription documents through the current production import/compiler in memory, replaced secrets/addresses/URLs before temporary disk writes, then checked every structural copy with the bundled Xray: 10/10 passed, 10 imported profiles. Temporary inspection artifacts were removed. No real server connection was performed by these config checks.
- `npm.cmd run dist:win`: exit 0; Electron 44.4.3 NSIS rebuilt. ASAR inspection confirmed native payload, preserved source marker, namespaced balancers, effective configuration logging and connection-graph DNS bootstrap. Existing optional snapshot/bundling warnings remain non-fatal.
- Artifact: `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe`, 139163262 bytes, SHA-256 `ACAF462C12DCAF77A243FF5679657CA244F1C288ECA19574B3B6AC8152125873`, Authenticode NotSigned. Supersedes the preceding same-version installer. Installation and live hotspot L3 acceptance remain unverified.
- After installation, refresh the subscription: previously flattened stored profiles cannot reconstruct their lost native fields or bridge dependencies. Use Auto/Xray and a full provider configuration.

### Repair rollback
- Revert this scoped import/compiler repair and refresh the subscription with the chosen version. Older clients cannot use native graph metadata. No network ownership manifest format was changed.

### Rollback
- Revert this scoped repair. Persisted settings and manifest formats remain compatible. Diagnostic-only physical TCP probes contact only the selected VPN endpoint; reflector probes always use the VPN engine.

## 2026-10-02 — WP-10 / WP-4: approved Happ comparison follow-up

### Evidence and changes
- Owner reports the repaired client now works on the phone uplink and explicitly authorizes all remaining recorded findings, including the normative adaptive-key discrepancy. Fresh installed-client logs confirm preserved native JSON / firefox / mux with 19 outbounds, 5 balancers, 5 virtual routes at 20:09:24 MSK, TUN with kill switch at 20:09:30, and three successful tunnel probes at 20:09:55 (last 200 ms). The combined configuration repair succeeds; this does not identify a single causal setting or prove all Windows L3 leak criteria.
- Adaptive learning uses a versioned private HMAC of physical NLA profile/GUID, gateways and subnet plus canonical connection parameters, transport, REALITY/obfs, device/fingerprint and native graph. Ignore cosmetic fields, DHCP host addresses and IPv6 lockdown changes on dual-stack. Native reads are bounded to four seconds; unknown identity skips reuse and persistence. Recheck identity after the unchanged stable probe window, invalidate on network changes, and fence late reads/learning after cancellation or newer lifecycle state. Old keys expire automatically; TTL 30 days / maximum 24 records retained. No raw identity or credentials enter the learning log/store.
- Preserve XHTTP mode and nested extra through URI/VMess import, Xray conversion and export, including saved legacy transport.method. Remove the second URL decode that damaged literal percent escapes. Preserve explicit gRPC gun/multi independently of idle_timeout, reject conflicting/unknown modes. Auto chooses Xray for these Xray-specific transport settings; forced sing-box gives a clear refusal.
- Preserve explicit sing-box multiplex on VLESS/VMess/Trojan/Shadowsocks, normalize legacy mux, reject unsupported protocol combinations. Copy/file export automatically selects complete native JSON for graphs and JSON for multiplex-bearing sing-box profiles; retain managed graph boundaries and native main-owned secret-export consent. Bulk export becomes a JSON array when required; re-import preserves bridge/mux/balancers. Ordinary URI exports remain available.
- Traces: AT-10-007 / F-126 / F-128, AT-04-001/002/006, AT-02-004, AT-01-008 subsets. Normative docs and code-signing decisions were not changed. Full details in vpn-tunnel-enforcer/docs/happ-compatibility-audit-2026-10-02.md.

### Validation and artifact
- Focused command: `npx.cmd vitest run src/main/adaptiveBypass.test.ts src/main/adaptiveNetworkIdentity.test.ts src/main/transportCompatibility.test.ts src/main/nativeXrayCompatibility.test.ts src/main/tunControllerConfig.test.ts src/main/serverKeyExportSecurity.test.ts src/main/serverPickerSwitch.test.ts src/main/profileRotation.test.ts src/main/lifecycleCleanup.test.ts src/main/auditFixesRegression.test.ts --maxWorkers=4`: 10 files / 250 tests passed, exit 0. Includes real bundled Xray preflight for four XHTTP modes / two gRPC modes / exported bridge graph and bundled sing-box checks for four multiplex protocols. Native script behavior uses fake cmdlets only.
- Initial focused failures exposed a missing test import and a real double-decoding bug. Initial full run: 1958 passed / 12 failed / 10 skipped plus two errors; repaired the new cancellation generation guard and default/named child_process mock. Typecheck found a test parameter type and duplicate import, also repaired. Production verification thresholds/timeouts were not relaxed.
- Final `npm.cmd run typecheck`: exit 0. Final `npm.cmd test -- --maxWorkers=4`: 179 files passed / 2 skipped, 1972 tests passed / 10 skipped / 0 failed, exit 0 (105.12 s).
- `python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py`: exit 0, AC 927/927, F 210/210. `git diff --check`: exit 0.
- `npm.cmd run dist:win`: exit 0, Electron 44.4.3 NSIS rebuilt. Seven packaged-ASAR markers verified: NLA read, learning decision, v2 key, XHTTP extra, native JSON export, gRPC multi_mode, unsupported multiplex refusal. Existing optional snapshot/bundling warnings remain non-fatal.
- Artifact: `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe`, 139165276 bytes, SHA-256 `0200D166C2221072C7771F11BB87AA5C269EC4C94F3F9A844EC6912F2C088ED6`, Authenticode NotSigned. Supersedes the preceding same-version installer. This follow-up installer has not been installed or exercised on a live uplink by the agent; the user's working connection was not changed. Already refreshed native profiles require no subscription refresh for this follow-up.

### Rollback
- Return to the preceding native-graph repair build. Native profiles stay compatible; the preceding build does not reuse new v2 learning keys. No network ownership manifest format changed.
