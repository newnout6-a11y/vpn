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
