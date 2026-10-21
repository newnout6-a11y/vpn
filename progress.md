## 2026-10-10 - Task: Address CodeRabbit and Revix review findings on PR #23
### What was done
- Sealed indeterminate IP auto-verification safety gates against incomplete adapter inspection (`LeakSelfTestResult.physicalAdapterInspectionComplete`): if physical adapter enumeration fails or is cancelled, rebaselining is strictly rejected.
- Verified route ownership after leak self-test and enforced exact baseline matching (`expectedIp`) in `ipMonitor.recheck`: fresh network samples are adopted as VPN baseline only when they match `leakResult.defaultRoutePublicIp` and TUN routes remain active.
- Passed all dynamic auto-verification log parameters and error messages through redactSensitiveText in compliance with Revix rule redact-before-log-event, safely retaining plain-text IP strings for debugging while sanitizing secrets and user paths.
- Modularized auto-verification logic into `src/main/indeterminateIpAutoVerify.ts` and prevented in-flight guard latching on synchronous early returns via `.finally()`.
- Restored original `suppressLeakSelfTestsFor(ms)` cancellation semantics on zero-ms calls while maintaining test isolation via `resetLeakTestThrottlesForTest()`.
- Replaced fragile substring checks in `indeterminateIpAutoVerify.test.ts` with end-to-end behavioral tests covering clean adoption, failed adapter enumeration, physical leaks, DNS leaks, route drops, IP sample mismatches, and sequential early returns.
- Added regression tests in `leakSelfTest.test.ts` for adapter enumeration failure, cancellation, and clean probe notifications.
### Testing
- `npm run typecheck` passed (exit code 0).
- `npm test` passed: 216 files, 2874 passed (100% green).
- `python ../docs/04-приёмочные-тесты/traceability/check-coverage.py` passed: AC 927/927, F 210/210, 0 missing.
### Notes
- Git branch: `codex/wfp-firewall-lifecycle-perf` (PR #23).

## 2026-10-10 - Task: Auto-verify indeterminate VPN IP and disable probe socket keep-alive
### What was done
- Identified why `⚠️ 13.143.214.3 — VPN-IP изменился, требуется проверка` stayed indeterminate: Node's default global agent keep-alive pooled sockets across network transitions during startup, and no automatic re-verification mechanism existed to clear indeterminate states without user intervention.
- Configured dedicated HTTP and HTTPS agents with `keepAlive: false` in `src/main/ipMonitor.ts` so public IP probes never reuse pre-transition TCP sockets.
- Implemented `verifyIndeterminateVpnIp` in `src/main/index.ts`: when an indeterminate IP is reported while TUN is running, it verifies active routes and executes `runLeakSelfTest()`. If the physical adapter is blocked with zero leaks and egress is proven safe through TUN, it automatically calls `ipMonitor.recheck(true)` to rebaseline the IP and transition verdict to `'passed'` without requiring manual button clicks.
- Added `setLeakSelfTestCompletedCallback` in `src/main/leakSelfTest.ts` to trigger automatic rebaseline if any periodic leak test confirms clean zero-leak operation during an indeterminate state.
- Added automated tests in `indeterminateIpAutoVerify.test.ts`, `ipMonitor.test.ts`, and `leakSelfTest.test.ts`.
### Testing
- `npm run typecheck` passed (exit code 0).
- `npm test` passed: 216 files, 2862 passed (100% green).
- `python ../docs/04-приёмочные-тесты/traceability/check-coverage.py` passed: AC 927/927, F 210/210, 0 missing.
### Notes
- Git branch: `codex/wfp-firewall-lifecycle-perf` (PR #23).

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

## 2026-10-02 — WP-10 / WP-0: remove cold network-identity imports

- Owner approved starting with the measured identity-reader regression. Replaced cold Get-NetAdapter / Get-NetConnectionProfile / Get-NetRoute module imports with three fresh read-only CIM queries, preserving visible/up/MAC-bearing physical adapter selection, NLA Name/InstanceID, GUID, active default gateways, v2 HMAC privacy and IPv4 preference. A failed query still produces unknown identity; bounded hidden process remains 4000 ms / 256 KiB. No cached network snapshot or helper queue dependency was added.
- Added a monotonic `Network identity read completed` event with reader/durationMs/known only. Regression tests exposed and fixed empty `.NextHop` expansion into `[null]`; profile-only and completely empty identities now have proper array semantics.
- Actual Windows read-only comparison with the previous HEAD reader: 2329→448 / 2270→429 / 2403→469 ms, 3/3 identical normalized identities on the current network, no raw topology printed/persisted. This is reader latency, not installed full-connect acceptance. Previous installed cycles were 9939 / 8504 ms; firewall awaits remain 3161 / 2867 ms. Full investigation and actual Happ control-path observations recorded in docs-factory8090/07-журнал-ускорения-lifecycle.md, stage 26.
- `npm.cmd run typecheck`: exit 0. Focused `npx.cmd vitest run src/main/adaptiveNetworkIdentity.test.ts src/main/adaptiveBypass.test.ts src/main/serverPickerSwitch.test.ts src/main/profileRotation.test.ts src/main/lifecycleCleanup.test.ts --maxWorkers=4`: 5 files / 122 tests passed, exit 0. Initial focused run had 2 gateway-empty failures, both repaired.
- Full `npm.cmd test -- --maxWorkers=4`: exit 0, 179 files passed / 2 skipped, 1981 tests passed / 10 skipped / 0 failed, 83.97 s. `python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py`: exit 0, AC927/927 F210/210. `git diff --check`: exit 0. Normative docs unchanged.
- `npm.cmd run dist:win`: exit 0, typecheck repeated successfully; seven packaged-ASAR markers confirmed. Installer `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe`, 139165757 bytes, SHA256 `AAB87DB5754FEEB3429856F93F31A110AA1C11CBD79797B6F0C629022CAB00D1`, Authenticode NotSigned. Current network and installed client unchanged; live full-connect timing of this artifact remains unmeasured. Own temporary benchmark/test/build artifacts removed after recording results.

### Rollback
- Revert this scoped reader/timing change; the adaptive key format and stored profiles remain compatible. This restores the slower module-based identity read. No firewall or network ownership manifest format changed.

## 2026-10-02 — WP-0 / WP-2 / WP-6 / WP-7: repair route evidence, IP waves and early cancel

- Owner approved repairing the three installed-log findings. Latest installed cycles before this patch: connect 6872/5420/5449 ms, ordinary stop 3762/3694 ms, cancel 3402 ms. CIM identity is already 498/474/469 ms. The old /0-/1 route heuristic misreported a live TUN with 60 fragmented routes; 57 public-IP successes occurred in 10 s. Full measured phases recorded in lifecycle journal stage 27.
- Route evidence now uses trusted TUN ownership plus fresh CIM adapter/address checks and Windows-selected routes for three IPv4 canaries, without forcing the route's interface or sending packets. Unknown/invalid/late evidence fails closed. This is supporting route evidence, not full egress/IPv6 leak acceptance.
- One in-flight HTTP provider wave per owner; abort losers and old generations, with no result cache between completed waves; back off 429 providers. Post-start checks use four 2 s waits and route proof before one baseline adoption; rebaseline does not duplicate the immediate timer wave. A failed fresh baseline returns null and profile switching retries rather than publishing cached data as freshly verified.
- Early cancellation still awaits the startup owner/native compensation. Skip redundant runtime kill/wait only after fresh exit proof; errors retain kill/wait and all network rollback steps. Add runtime-stop-preflight timing; expected Xray firewall cancellation is info while real failure remains warn.
- Final `npm.cmd run typecheck`: exit 0. Focused 11-file command listed in stage 27: 192 tests passed; final baseline-specific two-file run: 15 passed. Full `npm.cmd test -- --maxWorkers=4`: exit 0, 181 files passed / 2 skipped, 2017 tests passed / 10 skipped / 0 failed, 106.28 s. Coverage checker: AC927/927, F210/210, exit 0. Initial failures and their resolution recorded in stage 27.
- Normative docs and network ownership formats unchanged. Full installed cancellation ≤1 s and new live start/stop/egress/IPv6 acceptance remain unverified; current connection was not changed.
- `npm.cmd run dist:win`: exit 0, eight packaged-ASAR markers verified; main SHA256 b45dc2614702858c815dc2fea5f91dc37d95465c2a3a2e39bbf497ac9c386f04. Installer `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe`, 139166458 bytes, 23:18:45 MSK, SHA256 BEE4F9D7ACAE234DFFFBF8072ED5F55A59E4810DA12FECDF86139FA92B0B0EAF, Authenticode NotSigned. Optional V8 snapshot remains unavailable; application builds successfully. Artifact supersedes the previous same-version installer and was not installed by the agent.

### Rollback
- Revert the scoped route/IP/cancel change. Settings, profile and ownership manifest formats remain compatible. Own temporary test/build logs removed after recording results.


## 2026-10-02/03 — WP-3 / WP-0: ускорение правил Windows Firewall

- Владелец разрешил исправить и измерить firewall участок. Начальный checkout 74c5019 был чистым. New/Get/Remove собственных правил теперь используют COM HNetCfg.FwPolicy2/FwRule; snapshot/set/restore профилей, NotConfigured, durable journal, TUN barrier, Allow-before-Block и независимый CIM read-back исключений сохранены. Lazy handle не кеширует коллекции или proof; после удаления выполняется свежая проверка. Physical-adapter policy запрещает новый firewall API. Backend указан в command timing.
- Native disabled-rule benchmark, три пары production типов: create CIM604/562/590 vs COM212/72/73 ms; read CIM326/333/346 vs COM77/25/35; verified remove CIM954/1022/1149 vs COM172/157/167. 3/3 CIM signatures совпали. Расширенные IPv6/duplicate-name fixtures тоже 3/3 совпали, 14 rules/API. Исправлена найденная native проверкой ошибка COM interface setter: явная VARIANT array allocation вместо string[] cast. Исходный IPv6 loopback отклоняется обоими API, прежняя обработка сохранена.
- Все тестовые правила были выключены, уникальный benchmark namespace, profilesUnchanged/activeOwnRulesUnchanged/cleanupOk=true. Финальное CIM/COM чтение текущих правил: 11/11, имена равны. Остаток VPNTE-benchmark rules — 0. Действующий VPN и установленный клиент не менялись. Измерено ускорение компонентов; новые full start/stop/cancel времена и L3 egress/leaks/boot acceptance ещё не подтверждены. Полные данные, первые failed runs и границы записаны в lifecycle journal, этап 28.
- `npm.cmd run typecheck`: exit 0. Focused шестью suites (точная команда в этапе 28): 139 passed / 1 skipped, exit 0. Финальный `npm.cmd test -- --maxWorkers=4`: exit 0, 182 files passed / 2 skipped, 2040 tests passed / 10 skipped / 0 failed, 109.29 s. `python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py`: exit 0, AC927/927 F210/210. `git diff --check`: exit 0. Нормативные docs не менялись.
- `npm.cmd run dist:win`: exit 0, Electron 44.4.3 NSIS. 10 packaged-ASAR markers проверены, main совпадает с compiled output, SHA256 62b4552ec859d52b45cfd0f82df2f23e2cbfb11d09925a6fb31b4031e05d3949. Optional snapshot пропущен как раньше.
- Installer `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe`, 139167722 bytes, 03.10.2026 00:02:15 MSK, SHA256 DDEDA7E356AD54EDD40BDEE8AFC59972845F1FBE5CFF634B77755E89623C16BC, NotSigned. Artifact заменяет предыдущий с тем же номером; агентом не установлен. Удаление собственных временных файлов отклонено automatic approval review (`blocked by policy` без пояснения), они оставлены в `.tmp`; прежние артефакты сохранены.

### Откат

- Revert scoped firewall API change; settings/profile/recovery manifest форматы совместимы. Возвращает прежние NetSecurity операции с правилами.

## 2026-10-03 — WP-3 / WP-0: adapter apply и ранняя отмена

- Владелец разрешил продолжать ускорение по прежней схеме. Начальный checkout 2a5c410, чистый. Установленная COM-сборка: starts 4501/3578/3273 ms, stops 3276/2966 ms, cancel 3296 ms; firewall await уже 502/643/403 ms. Adapter lockdown тёплый 1833/1813 ms, native mutation 1130/1132 ms. При cancel новый adapter batch запускался уже после сигнала отмены и Xray exit, затем компенсировался. Baseline rollback остаётся ~1 s.
- Adapter apply получил startup AbortSignal и проверки перед новыми effects. Общие snapshot reads разрешено завершить; после отмены до journal/native dispatch новые изменения не отправляются. Durable journal и уже отправленные native пакеты остаются под владельцем компенсации после runtime exit proof. Отмена и поздний native отказ не запускают преждевременный rollback из parallel apply wrapper.
- Свежая GUID/binding проверка пропускает повторный Disable IPv6 только при доказанном boolean=false; missing/ambiguous/nonboolean/read-back failure не проходят. Mobile/464XLAT исключение сохранено. Два reg.exe add заменены .NET Registry с проверкой DWORD=1, пропуском повторной записи и read-back после изменений. Baseline восстановления прежних значений/отсутствия сохранён. Missing policy proof и частичные ошибки сохраняют conservative recovery journal.
- Неизвестный результат helper, timeout/exit/stop и nonzero reply больше не переигрываются fallback transport; fallback разрешён только известному отказу до dispatch. Диагностика включает cancelled, phase/pendingRecovery, ipv6AlreadyOff. Нормативные docs и manifest/settings/profile форматы не менялись.
- Safe replay старого/нового production apply после abort: mutation batches 1→0, journal writes 2→0. Native read-only proof текущего GUID/IPv6/DNS-policy: первый 433 ms, тёплые 343/313/336/330/306 ms, 6/6 доказательства успешны, binding unchanged. Это отдельный компонент, не полный installed apply. Реальные уникальные HKCU registry fixtures: warm reg 11–12 ms/value, .NET 0–1 ms/value; первый cold .NET 62 ms vs reg27. 12/12 independent reg query proofs, cleanupOk=true. Реальные HKLM/сетевые настройки и установленный клиент не менялись.
- Финальные `npm.cmd run typecheck`: exit 0; focused seven-suite command из lifecycle journal этапа29: 174 passed, exit 0. `npm.cmd test -- --maxWorkers=4`: 183 files passed / 2 skipped, 2073 tests passed / 10 skipped / 0 failed, exit 0, 113.14 s. `python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py`: AC927/927 F210/210, exit 0. `git diff --check`: exit 0. Первые test typing / CLIXML / benchmark-interface setup замечания и границы записаны в журнале.
- `npm.cmd run dist:win`: exit 0, 7 packaged-ASAR markers, main SHA256 ab4a2493df59584735f6e33949d3c5821067722828fc959242747b8d119f81a2, совпадает с compiled output. Installer dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe: 139168386 bytes, 03.10.2026 00:32:56 MSK, SHA256 1C830BDB249EB61B2BE2DBD7CA92E7A3ABC9E4014F5334BD20E0FABE376ABC53, NotSigned. Agent did not install it; новые full start/stop/cancel и L3 acceptance пока не измерены. 11 собственных временных файлов этого этапа удалены, прежние сохранены.

### Откат

- Revert scoped adapter/cancellation change; сетевые baseline/settings/profiles совместимы. Возвращает прежние повторные native операции и apply после отмены.

## 2026-10-03 — WP-3 / WP-2 / WP-0: baseline rollback и остановка runtime

- Владелец разрешил следующий измеренный участок и запросил тесты. Начальный checkout cf3b16b, чистый. Установленная сборка этапа29: cold start4938 / warm3037/3116 ms, stops3394/3198 ms, cancel2221 ms. Baseline обычных stops1104/1118 ms; runtime stop788/787 ms + отдельный fresh exit wait231/171 ms. Adapter cancellation уже прерывает новые эффекты в snapshot phase.
- Девять typed baseline restore/read-back и WinINet notification объединены в один PowerShell. SID guard, trusted journal, независимые шаги, сохранение manifest при partial/notification/malformed outcome и operation lock сохранены. Новый baseline native phase timing разделяет registryMs/notifyMs.
- Остановка трёх фиксированных owned runtime exe передана existing recovery worker через закрытый stop-runtime request; прежний 8000 ms deadline и отдельный fresh exit proof сохранены. Только типизированный unavailable до dispatch допускает fallback. Unknown/dispatched failures не переигрываются. Malformed counts/names и CIM query failure не превращаются в успех. Прежний prefix ownership predicate сохранён; external proxy исключён.
- Actual Windows benchmarks, три alternating pairs: runtime fresh PS489/455/441 vs warm worker150/92/92 ms; baseline two PS975/796/811 vs merged573/545/526 ms. Остановка только собственных renamed Node children в unique .tmp fixture; tracked exits и свежий inspect-runtime доказаны 6/6, workerExited/cleanupOk=true. Baseline только unique HKCU subtree, 9 verified slots / 6 types / cleanupOk во всех 6 samples. WinINet declaration компилируется, DLL calls подменены; реальные уведомления и сетевые настройки не изменялись. Это компоненты, полные installed stop/cancel ещё не подтверждены.
- Focused baseline до изменений: 224 passed / 1 skipped. Expanded final nine-suite command из lifecycle journal этапа30: 299 passed / 1 skipped / 0 failed, exit0,52.62 s. Первый expanded focused и первый full run выявили два устаревших source oracles после переноса fixed stop script; они обновлены на shared production script / stop-runtime с сохранением исключения external proxy. Полный первый run2127 passed/1 failed/10 skipped не принят как окончательная проверка.
- `npm.cmd run typecheck` повторён после последнего test oracle fix: exit0. `python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py`: exit0,AC927/927,F210/210. Нормативные docs не менялись.
- Окончательный `npm.cmd test -- --maxWorkers=4` — **184 files passed / 2 skipped, 2128 tests passed / 10 skipped / 0 failed**, exit 0, **106.17 s**. Последние три focused suites — **132 passed**, exit 0. Typecheck после последней правки — exit 0; runtime/test source затем не менялся. Ожидаемый RootErrorBoundary stderr сохранён. Точные команды и первые отказы записаны в lifecycle journal этапа 30.
- `npm.cmd run dist:win`: exit0, Electron44.4.3 NSIS. Optional snapshot пропущен как прежде. 6 packaged-ASAR markers, main совпадает с compiled output; SHA2561763c21247e138d95973fe701ceb3aae3a6ce6f8796f3474d66c581fc5206527. Installer dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe:139168882 bytes,03.10.2026 01:04:20 MSK,SHA25668AAA3C8FBB630D4952A0D16EE0890FFD32510FCBE803C47C2C6007A885BC6B6,NotSigned. Агентом не установлен, заменяет предыдущий same-version artifact. Runtime source после сборки не менялся, последний fix только test oracle.

- Итоговые traceability AC 927/927 / F 210/210 и `git diff --check` — exit 0. Удалены 12 собственных временных файлов этапа 30; предыдущие артефакты сохранены.

### Откат

- Revert scoped baseline/stop change; manifest/settings/profile форматы совместимы. Возвращает два baseline процесса и свежий PowerShell для runtime stop.

## 2026-10-03 — WP-0 / WP-7 / WP-10: переключение серверов и ложный IP leak

- По прямой команде владельца исправлены четыре подтверждённых дефекта: прежняя adaptive verification после ручной смены, пропущенный IP rebaseline при adaptive fallback, устаревший профиль в UI и классификация любого отличия VPN-IP как видимого real IP. Начальный checkout `0c38ac7`, чистый.
- Ручной IPC до первого ожидания инвалидирует и отменяет старые adaptive/IP пробы, сериализуется с уже отправленным protected restart. Новая проверка привязана к текущему профилю/runtime, owner guards стоят после каждой пробы/ожидания. All adaptive branches и manual switch используют общий protected IP barrier: сохранение native protection, fresh route proof, один свежий IP sample, корректное снятие suppression. Старый IP getter из критического пути удалён (в исходном логе ожидание **8467 ms** внутри switch **12568 ms**).
- Adaptive fallback обновляет selected profile и существующий renderer event. UI получает IP baseline/verdict из main: mismatch — `indeterminate`, unavailable — `not-checked`, без false real-IP alarm или геолокации неподтверждённого IP. Независимые physical/DNS alarms сохранены. Удалённые/disabled профили не используются как новые цели.
- Первый focused run:96 passed/2 failed, исправлены устаревшие test oracles. Expanded focused:108 passed. Первый full:2150 passed/1 failed/10 skipped; source route guard oracle перенесён на общий helper с сохранением проверки порядка и отказа. Последующая focused группа:59 passed. Детальные точные команды и причины записаны в lifecycle journal этапа31.
- Финальный `npm.cmd run typecheck` — exit0. `npm.cmd test -- --maxWorkers=4` — **188 files passed / 2 skipped, 2156 passed / 10 skipped / 0 failed**, exit0,129.93 s. `python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py` — exit0,AC927/927,F210/210. Нормативные docs не менялись; полная Windows acceptance/общая scheduler-rotation coordination не объявляется закрытой.
- `npm.cmd run dist:win` — exit0,Electron44.4.3 NSIS. Packaged main/preload равны compiled outputs,6 main/3 renderer markers подтверждены. Main SHA25650f1a1c68d92edad6509eaf96f8d273db72f23290959a099badc7c84244f48d1. Installer1.1.22:139170274 bytes,03.10.2026 12:02:17 MSK,SHA2564368E9C63E696578947055D94B9C67D83A1D459A98492863AB4BBC5927E2547F,NotSigned. Агентом не установлен. Installed latency новой смены ещё не измерена.

### 2026-10-03 — PR #16: подтверждены и исправлены три замечания ревью

- Проверены repo/ветка/remote head 4f11942 и чистый исходный worktree. Fallback commit/UI теперь после fresh route/IP и окна 20 s с >=2/3 HTTP-пробами; мёртвый sibling не сохраняется, provisional runtime останавливается с сохранением firewall/adapter protection. Manual cancel и runtime ownership ограждены.
- Route proof повторяется до 3 раз через 500 ms; null/invalid native Xray endpoint блокирует graph publication/config write/spawn вместо DNS deadlock. Новые executable regressions и обновлённые source oracles.
- `npm.cmd run typecheck`: exit 0. Focused command (точный список в lifecycle journal этап 32): 6 files / 121 passed / 0 failed, exit 0, 6.50 s. `npm.cmd test -- --maxWorkers=4`: 189 files passed / 2 skipped, 2172 passed / 10 skipped / 0 failed, exit 0, 96.16 s. `python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py`: exit 0, AC 927/927, F 210/210. `git diff --check`: exit 0.
- Нормативные docs не менялись; полный Windows L3/installed acceptance не запускался. Installer в этом PR repair не пересобирался и не установлен агентом.

## 2026-10-03 — WP-2 / WP-0: DNS при смене сервера

- В installed логе Norway switch 6160 ms: один успешный DNS запрос native graph 3025 ms, stage 3029 ms. Fresh-IP barrier около 0.79 s, identity 461 ms, protected stop 300 ms. Главный измеренный участок — DNS. PR #16/ветка проверены, remote пустой ee254b2 включён fast-forward без source изменений.
- После 100 ms ожидания основного DNS запускается существующий IPv4 system lookup; первый валидный результат завершает операцию. Быстрый основной DNS не вызывает lookup; ранняя ошибка сразу вызывает fallback. Ошибка одной ветки не отменяет другую. Resolver принадлежит операции, отмена и поздние OS результаты ограждены; исправлен повторный cancel. Межсетевой application cache и новые сетевые исключения не добавлены. Fresh route/IP и adaptive health проверки сохранены.
- Первые новые тесты поймали double cancel: 138 passed / 2 failed. После исправления focused command из lifecycle journal этапа 33: 140 passed, exit 0. На реальном локальном DNS стенде primary 3053 ms → новый путь 115 ms; fake-clock fixture 3025 ms → 120 ms. Это компонент, installed switch ускорение пока не измерено.
- `npm.cmd run typecheck`: exit 0. `npm.cmd test -- --maxWorkers=4`: 189 files passed / 2 skipped, 2183 passed / 10 skipped / 0 failed, exit 0, 132.10 s. `python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py`: AC 927/927 / F 210/210, exit 0. Нормативные docs не изменены.
- `npm.cmd run dist:win`: exit 0, Electron44.4.3 NSIS; packaged main/preload равны compiled outputs, 4 main markers подтверждены. Main SHA256 0c26e9868cc2c304d6f951b9756dd8dba88b021da9013f6022885e7b267880c3. Installer1.1.22:139170825 bytes,03.10.2026 20:30:50 MSK,SHA2566875F8B743AAEEF6E378DEF6CBC5AFDB739FF521CCB7E88DDD9D68CF2511AA72,NotSigned. Агентом не установлен. Итоговый diff check exit0.

## 2026-10-04 — WP-1: локальная приёмка секретов и доверенной границы

- Продолжены оставленные изменения после `7da36fb` в `codex/wp1-security-acceptance`: DPAPI prefix/schema v2, auth в proxyOverride/adaptive secret, default-redacted config export с отдельным native-consent режимом, IPC audit/typed validation, узкая CSP, fresh runtime tree ACL/owner/reparse и SHA-256 staging. Пользователь разрешил завершить изменения, коммит и PR; VM отсутствует, VM-проверки исключены из этой сессии, но не засчитаны как PASS.
- Исправлены review/native находки: backup-step audit; preflight всех startup stores до recovery; graceful startup refusal без network cleanup; сохранение Chromium Local State ключа между процессами; builtin PowerShell Security import вместо PS7 module discovery; ACL oracle не принимает failed inspection за безопасный owner refusal; p99 покрывает все envelope-классы bounded histogram.
- Финальные `npm run typecheck` и `npm run build`: exit 0. `npm test -- --maxWorkers=4`: 200 files passed / 2 skipped; **2397 passed / 10 skipped / 0 failed**, 108.44 s. Native Electron smoke: 8 checks PASS. Локальные native WP-1 subsets PASS; same-version DPAPI/store migration после исправления повторена 2/2 PASS. Полный `test:wp1:fuzz`: 155 × 100000 = **15500000 rejected envelopes**, zero handler effects, p99 upper bound 1 ms на всех каналах; 3 × 100000 redactor cases PASS, 342.01 s.
- Traceability: AC927/927, F210/210, exit 0; это покрытие ссылок, не полная приёмка. Подробные команды, ранние отказы и AT-01-001…011 границы записаны в `vpn-tunnel-enforcer/docs/wp1-security-acceptance-2026-10-04.md`.
- Настоящий Electron 42→44 остаётся NOT-CHECKED: нет `VPNTE_ELECTRON42_EXE`, runner честно возвращает exit77. Clipboard не менялся; native TTL/installed/full VPN secret scan/elevated ACL abuse/OS matrix/VM также NOT-CHECKED. Полный WP-1 не объявляется принятым. Нормативные `docs/`, действующий VPN/Firewall/DNS/IPv6 и установленный клиент не менялись; installer не пересобирался.
- Совместимость: новый reader читает legacy ciphertext; прежний executable не понимает новый `enc:dpapi:v1:` prefix. Непроверенный downgrade после новых записей не рекомендован, ciphertext/backup вручную не удалять и не переписывать.

## 2026-10-04 — WP-1 / WP-2: исправления ревью PR #21

- Исправлен подтверждённый пробел runtime namespace: единый per-userData instance path `%ProgramData%\VPNTE\runtime\<hash>\`, OS known-folder сверка даже при уже существующем runtime, root-first ACL/owner/reparse-проверка всех предков, включая DELETE_CHILD/DELETE/WRITE_DAC/WRITE_OWNER. SYSTEM/Admins и TrustedInstaller разрешены для системных предков; InheritOnly не считается эффективным правом на родителя. Для исполняемого дерева проверяются также наследуемые write-гранты, опасные для новых файлов.
- Application-компоненты создаются с ограниченным DACL атомарно. Никаких Set-Acl/icacls repair для уже существующих недоверенных каталогов, рекурсивного bootstrap или ужесточения AppData. Небезопасный pre-existing компонент блокирует запуск. Обновлены getters, firewall program path, логи, диагностика, cleanup и форензика. Версионный diagnostic probe выполняется только после проверки; форензика отказывается от elevated scripts при failed ACL и от session/ETL paths вне текущего root.
- Исправлены остальные подтверждённые замечания: export mode enum в preload, allowlisted startup failure details и ограниченный размер обычных Error, настоящий quit-helper вместо new Function, cleanup helper с сохранением primary/cleanup ошибок и overall PASS только после удаления owned fixture. Широкий secret redactor не ослаблялся.
- Проверки: typecheck/build exit 0; финальный full Vitest с `--maxWorkers=4`: **203 files passed / 2 skipped; 2439 passed / 10 skipped / 0 failed**, 99.45 s. Native read-only PowerShell policy/known-folder/script syntax тесты проходят; focused runtime/path/diagnostic/forensics: 123/123; hostile session paths: 4/4; cleanup Node tests: 10/10; Electron smoke: 8 checks; WP-1 native subsets: 6; same-version migration: PASS. Traceability AC927/927 и F210/210, exit 0.
- Промежуточный full run с default workers: два существующих bundled-core preflight теста превысили 5 s; отдельный повтор 85/85 и финальный full run с 4 workers прошли без изменения таймаутов.
- Старые runtime/forensics данные не мигрируются и не исполняются; перед обновлением нужен штатный stop старого клиента. Installer/живой VPN/сеть/clipboard не менялись. ProgramData bootstrap с elevation и concurrent ACL abuse, VM/OS matrix, реальный 42→44 и rollback-reader остаются NOT-CHECKED. Полный WP-1 не объявляется принятым; нормативные `docs/` не редактировались.

## 2026-10-04 — PR #21: второй проход ревью, логи и capture cleanup

- Исправлены unsafe runtime mkdir при очистке логов и hard-coded developer fixture paths. Missing runtime не создаётся; existing logs требуют ACL proof. Все forensics/staging/sidecar fixtures изолированы в уникальном os.tmpdir.
- Stop `pktmon/netsh` требует native exit=0 и acknowledgement до best-effort artifacts. При ошибке capture остаётся running/cleanupPending с повторяемым stop; concurrent stops объединены, restart и diagnostic deletion не подавляют ошибку. Runtime ACL refusal допускает path-free cleanup только провайдера с in-memory ownership текущего процесса, не произвольного disk manifest. Потеря сайдкара/stop artifacts не доказывает остановку packet capture (F-198); UI честно показывает unknown/pending, включая failed status request.
- Legacy AppData marker читается ограниченно и только как недоверенный hint: warning/блок нового capture без выполнения старых scripts, импорта PID/paths или изменения данных. Автоматический reclaim и controlled installer shutdown/handoff после прерванного обновления **не реализованы**; WP-11/L3 oracle остаётся открыт.
- Typecheck/build/dist:win exit 0; финальный full run: **206 files passed / 2 skipped; 2459 passed / 10 skipped / 0 failed**, 98.86 s. Cleanup Node tests 10/10. Native PowerShell control-flow tests используют harmless provider stubs; действующий pktmon/VPN/Firewall/DNS/clipboard не трогались. Traceability AC927/927, F210/210, exit 0. Нормативные docs не изменены; полный WP-1/AT-08-004/005 L3 не заявляется.
- Пересобран `VPN-Tunnel-Enforcer-Setup-1.1.22.exe` (139179636 bytes, NotSigned), без установки. SHA-256 `AEEA3D7D04098422D50C72F72100C6C7D9CAC6F08DD08CE6831BE374ED177EC6`; packaged main/preload/renderer проверены, dist/checksums.txt обновлён. Подробнее: `vpn-tunnel-enforcer/docs/wp1-security-acceptance-2026-10-04.md`.

## 2026-10-04 — PR #21: третий проход, capture race и локализация

- Два regression cases подтвердили гонку до патча: новый capture стартовал до окончания старой stop finalization. Общая promise-очередь сериализует start/stop/restart/staging; внутренние recovery/restart не создают nested wait. Late old-sidecar callbacks игнорируются, persistence объединяет наблюдение sidecar с текущим provider state; status projection не перезаписывает состояние.
- Legacy false-stopped hints с ошибкой/неподтверждёнными метаданными блокируют новый capture без выполнения старых scripts или изменения данных. CleanupPending после process restart определяется отсутствием текущего ownership, не доверяет timestamp. Новые предупреждения/status block переведены RU/EN; UI test проверяет смену языка.
- Узкий production delta: +57 строк net с переводами; добавлено 17 regression cases. Focused suite 59/59; typecheck/build/dist:win exit 0; full suite **2476 passed / 10 skipped / 0 failed**, 206 files passed / 2 skipped, 109.40 s. Traceability AC927/927, F210/210, exit 0.
- EXE 1.1.22 пересобран (139180033 bytes, NotSigned), не установлен; SHA-256 `7C42C3F6F08F12B827C4C64BD429FF25A2CCFA4DEAA0FF8DE4FFC3DD15BA8DD4`. 40 packaged files и новые markers проверены; dist/checksums.txt обновлён. VM и live capture не запускались, VPN/Firewall/DNS/clipboard не трогались. Полный WP-1/L3 и installer handoff/42→44/rollback не объявлены принятыми; нормативные docs не менялись.

## 2026-10-04 — WP-8 / WP-11: согласованный shutdown перед обновлением (PR #21)

- По команде владельца исправлен второй retained concern, не credential downgrade. Main shutdown ждёт capture stop/finalization до helper disposal/exit; неполные capture/network/env receipts блокируют выход, показывают RU/EN предупреждение и сохраняют helpers для retry. Остальные cleanup steps не пропускаются после отказа.
- `--shutdown-for-update` использует существующий single-instance IPC. NSIS ждёт открытый handle исходного primary и dedicated success exit 73, затем отсутствие VPNTE processes. Ordinary exit/crash/timeout/unknown identity не дают успех; image-name taskkill удалён, default builder force-kill override заменён тем же gate. PowerShell встроен immutable EncodedCommand, literal InstallDir передаётся в process environment без interpolation/temp-script execution.
- Старые EXE без команды требуют предварительного штатного «Выхода»; orphan kernel captures после прошлых убийств и старый chained uninstaller не объявлены автоматически исправленными. ТЗ/AT-11-002/009/F-183 учтены, полного installed/L3 PASS нет.
- +24 regression cases; focused shutdown/lifecycle 99/99, финальный full run **2500 passed / 10 skipped / 0 failed**, 207 files passed / 2 skipped, 115.64 s. Typecheck/build/dist:win exit 0, embedded command/source и PS syntax проверены; AC927/927, F210/210 exit 0. Native fixtures не трогают реальный клиент/захват/сеть; настоящий handle проверен на безвредных PowerShell children с exit 0/73.
- EXE 1.1.22: 139180341 bytes, NotSigned, SHA-256 `F08247EA9B97B6651EE6A19AC62E0391F1607D83D8DDD41010380025B07C1F4B`; 40 packaged files сверены, checksums обновлён, установка не выполнялась. VM отсутствует, нормативные docs не менялись; cross-version credential recovery и installed active-upgrade/OS matrix остаются NOT-CHECKED.

## 2026-10-04 — PR #21: проверки результата shutdown после ревью be104c1

- Закрыты два actionable пробела CodeRabbit: main проверяет `success` и полноту `killed/candidates` owned-runtime stop; строгий `autoconfig.isApplied('env')` передаёт ошибку чтения в shutdown guard вместо UI fallback `applied:false`. Неизвестное состояние не даёт exit 73; helpers и env backup сохраняются без blind rollback, capture cleanup продолжается.
- `env.isApplied()` использует проверенный parser registry value: access-denied/timeout/неразбираемый успешный stdout отклоняются; только распознанный missing-value с exit 1 и без termination indicators означает отсутствие. Parser также не допускает подготовки ложного backup перед apply. UI `getStatus()` контракт не менялся. Новых зависимостей или менеджеров нет.
- Nitpick Revix: 10 harmless PowerShell cases перенесены в `installerShutdown.itest.ts`; отдельный `npm run test:installer-shutdown` использует opt-in integration mode, обычный test glob их не запускает. Суммарно добавлено 35 regression cases, старые native cases не потеряны.
- Typecheck/build/dist:win exit 0; focused 134/134, native integration 10/10; full **2525 passed / 10 skipped / 0 failed**, 208 files passed / 2 skipped, 90.36 s. AC927/927, F210/210 exit 0. Первый test launch поймал незакрытую скобку в редактируемом Vitest config, исправлено до этих финальных прогонов.
- EXE 1.1.22 пересобран, **139180693 bytes, NotSigned**, SHA-256 `D157455011C95E1580DFA4E6FCF260330746E09AD78EB74228C7E0423909B70F`. Все 185 файлов `out/` совпали с packaged ASAR по SHA-256; runtime/env strict markers подтверждены, checksums EXE/blockmap обновлены. Установка не выполнялась; VM и live network/capture/registry не трогались. Legacy capture recovery, credential downgrade и installed/L3 matrix не расширялись; нормативные docs не менялись.

## 2026-10-05 — PR #21: финальный согласованный env ownership / residual polling follow-up

- По команде владельца завершены два замечания к c2c5342; новые раунды ревью не запрашивать и будущие замечания без отдельной команды не исправлять.
- Чужие proxy variables без VPNTE backup не считаются нашей cleanup obligation: status не читает registry и не требует rollback; чужие значения остаются нетронутыми. Валидный backup является durable pending receipt, даже если HTTP_PROXY уже восстановлен/отсутствует. Короткий process-local флаг удерживает ранее наблюдавшееся обязательство при исчезновении receipt; исчезнувший known backup не пересоздаётся из изменённого окружения.
- Rollback проверяет все четыре HTTP_PROXY/HTTPS_PROXY/ALL_PROXY/NO_PROXY: уже восстановленные пропускает, неизвестные не изменяет, после set/delete требует readback. Ошибка команды/readback/retirement сохраняет obligation и backup для retry; независимые entries продолжаются. Production delta **+21 строки net**, без новых зависимостей/схем/менеджеров.
- Native remaining fixture больше не выбрасывает ошибку из Start-Sleep: настоящий production polling достигает 5s deadline и проверяется конкретное сообщение отказа. Дополнительно проверяется освобождение после нескольких polls, число запросов и конкретные причины остальных отказов; процессов VPNTE/сети тесты не трогают.
- Typecheck/build/dist:win exit 0; focused **181/181**, opt-in native **11/11**; full **2572 passed / 10 skipped / 0 failed**, 208 files passed / 2 skipped, 105.66 s. AC927/927, F210/210 exit 0. Registry fixture полностью in-memory, покрывает чужой proxy, partial rollback каждой переменной, exit-zero mismatch, недоступный/повреждённый/исчезнувший receipt и повторные попытки.
- EXE 1.1.22: **139180562 bytes, NotSigned**, SHA-256 `721C1083EE77336116F35A6DB2D679738FA51B1C604F65DEBD278546C711947C`. Все 185 out-files совпадают с packaged ASAR; readback/shutdown markers подтверждены, checksums обновлён. Не устанавливался; VM/live registry/VPN/Firewall/DNS/capture не трогались. Полный installed/L3/OS/42→44/credential rollback не заявлен; нормативные docs не менялись.
- Граница: backup уже служит recovery metadata, не новым защищённым ownership store. Его потеря между процессами не восстанавливается process-local флагом; не добавлен автоматический reclaim отсутствующих/legacy receipts. Эти retained limits не объявлены устранёнными.

## 2026-10-05 — WP-1 / PR #21: диагностика отказа runtime по запросу владельца

- По логу от 04.10 подтверждён отказ Direct VPN до запуска Xray на подготовке runtime; конкретная нативная причина старой сборкой не записывалась. Без изменения ACL/VPN добавлена ограниченная PowerShell failure receipt: operation/path, allowlisted policy reason, корневой exception type/HResult, owner/ACE SID и rights. Bootstrap/elevation/readback отказы записывают её в `runtime-acl`; сырой stderr/argv/exception message не выводится, логи проходят существующий redactor. Проверки доверия и запрет исправлять небезопасные существующие каталоги сохранены.
- Вызов `powershell.exe` вместо `powershell` теперь попадает в уже существующий direct execFile transport в `admin.ts`, минуя предел cmd.exe для длинного EncodedCommand. Это обнаруженная возможная причина старого отказа, не доказанный диагноз старого запуска.
- AT-01-002/009: 14 дополнительных регрессий, включая native read-only/synthetic owner/inheritance/write/access-denied receipts, nonzero exit и secret non-disclosure. Typecheck/dist:win PASS; полный Vitest **2586 passed / 10 skipped / 0 failed**, 208 файлов passed / 2 skipped; traceability AC927/927, F210/210; diff --check PASS.
- Пересобран локальный `VPN-Tunnel-Enforcer-Setup-1.1.22.exe`: **139181284 bytes, NotSigned**, SHA-256 `7263614ab230a2e876780e5c48b0c2f3fd8032c058d45e74693afc949de6b876`. Все 185 out-files совпадают с ASAR, diagnostic markers подтверждены. EXE не устанавливался; приложение/VPN не запускались; системные ACL/Firewall/DNS/IPv6/registry/capture не менялись. VM/L3/исправление реального ACL не заявлены; нормативные docs не изменялись. Чужая whitespace-правка `connectionLifecycle.ts` сохранена и исключена из коммита.

## 2026-10-05 — WP-0: снижение нагрузки тестов с сохранением проверок

- По запросу владельца обычный Vitest ограничен двумя workers с изоляцией файлов. Main/shared/preload запускаются в Node.js; renderer и `recoveryManifestStorage.test.ts` остаются в jsdom. Последняя native-фикстура зависит от различий разрешения mock `child_process`; слепой перенос в Node менял смысл её проверок. Integration сохраняет исходный glob `src/**/*.itest.ts` и Node.js. Бюджеты fuzz и настройки coverage сохранены; код приложения не изменялся.
- Добавлены семь регрессий конфигурации: реальная коллекция Vitest сравнивается с исходными glob для обоих режимов; проверяются пропуски, дубли, окружения, изоляция и лимит процессов. Тесты поддерживают исполнимость существующих AT-* (включая native AT-03-012 и integration AT-11-002), без заявления о выполнении их отдельных приёмочных сценариев.
- Из `vpn-tunnel-enforcer`: `node scripts/check-vitest-config.mjs` — exit 0; `npx.cmd vitest run src/main/testRunnerConfig.test.ts` — **7 passed**, exit 0; `npm.cmd run typecheck` — exit 0; `python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py` — **AC927/927, F210/210**, exit 0.
- Полный `npm.cmd test -- --reporter=dot --reporter=json --outputFile=.tmp/test-load-audit-20261005/production-npm-test.tests.json` без переопределения workers — **2593 passed / 10 skipped / 0 failed**, **209 файлов passed / 2 skipped**, **125.40 с**, exit 0. Машинное сравнение имён/файлов с исходным прогоном подтвердило сохранение всех **2596 прежних случаев**, плюс семь новых; нормализовано только динамическое время `startedAt` в имени одного теста. `git diff --check` — exit 0.
- Для минимальной одновременной нагрузки доступен `npm test -- --maxWorkers=1` из папки приложения. Coverage run, Electron/native smoke и VM/L3 в этой задаче не запускались; новые закрытия F/AC не заявлены. Нормативные docs не изменялись. Предсуществующая whitespace-правка `connectionLifecycle.ts` сохранена и исключена из коммита; исследовательские результаты находятся в игнорируемой `.tmp/test-load-audit-20261005/`.

## 2026-10-05 — WP-1 / WP-2 / WP-6 / WP-9: исправления по логам приложения и движков

- По команде владельца исправлены повторная DPAPI-проверка неизменённых encrypted backups (477 сообщений за пять минут), завершение Xray до sing-box (152 ошибки при остановке), скрытая локальным SOCKS политика Mux UDP/443 и неверное обещание всего трафика через VPN при Smart RU. Кеш содержит только SHA-256 аутентифицированных байтов; текущий файл и доступность шифрования проверяются при каждом обращении. Native cleanup сортирует owned processes и ждёт выхода sing-box перед upstream; ошибки cleanup продолжают фиксироваться. Default/reject UDP/443 даёт быстрый TCP fallback с reject/default, allow/skip и остальной допустимый UDP сохранены. UI сообщает запуск и ожидание проверки выхода на RU/EN.
- Добавлено 20 regression cases с AT-трассировкой. `npm.cmd run typecheck` — exit 0; `npx.cmd vitest run src/main/recoveryPsProtocol.test.ts src/main/tunShutdownOrder.test.ts src/main/secretStorage.test.ts src/main/ownedRuntimeStop.test.ts src/main/ownedRuntimeStatus.test.ts --reporter=dot` — 153 passed, exit 0; итоговый `npm.cmd test -- --reporter=dot` — **2613 passed / 10 skipped / 0 failed**, **211 файлов passed / 2 skipped**, **151.22 с**, exit 0. Дополнительный byte-cache case проверен итоговым full run. `python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py` — AC927/927, F210/210, exit 0. `npm.cmd run dist:win` и `git diff --check` — exit 0.
- Новый EXE 1.1.22 — **139182096 bytes, NotSigned**, SHA-256 `3D1EC7178467B27FA3D7609BAC3304380D3450C1B9DDBEB201DCCC19F84E9E0C`; 185 out-files побайтно сверены с ASAR, markers подтверждены, checksums обновлён. Не установлен; реальный VPN/Firewall/DNS/IPv6/capture не запускались и не менялись. Native dispatcher проверен с fake cmdlets; Process.WaitForExit дополнительно проверен на безвредном отдельном child.
- Первичный native regression run выявил две ошибки нового кода/fixture (PS comment syntax и expected result); исправлены до итогового PASS. Проверка ASAR первоначально использовала неверный Windows separator; повторная проверка успешна. 150 рабочих TCP upload reset, таймауты provider health-ветвей и шесть DNS parse errors не имеют установленной первопричины; не объявлены исправленными. Graceful-период/full AT-02-009 и L3/VM не заявляются принятыми. Нормативные docs не изменялись, существующая правка `connectionLifecycle.ts` сохранена и исключена.
- Трассировка локальных регрессий: backups — AT-01-001/010; stop order — F-029, AT-02-005/009; UDP configuration — AT-02-008, AT-06-001; сообщения Smart RU — F-078/079, AT-06-003/09-011. Связь с AT не означает полной приёмки соответствующих сценариев. Основание UDP-политики: [Xray Mux](https://xtls.github.io/en/config/outbound.html), [Xray UDP/443 handler](https://github.com/XTLS/Xray-core/blob/main/app/proxyman/outbound/handler.go), [sing-box reject/default](https://sing-box.sagernet.org/configuration/route/rule_action/). Полные логи приложения и движков и журналы проверок сохранены в игнорируемой `.tmp/engine-log-read-20261005/`.
- По замечанию владельца отдельный MD-отчёт удалён; результаты остаются в существующем журнале прогресса.

## 2026-10-06 — WP-2 / WP-6: совместимость Xray с браузерными прокси

- Владелец подтвердил зависание Google при включённом «ЮБуст»: Chrome запрашивал `185.69.221.62:59751`, а Xray заменял назначение на `www.google.com:59751` после TLS sniffing. В генерируемом SOCKS inbound включён `routeOnly: true`: HTTP Host/TLS SNI/QUIC используются для маршрутизации без замены исходного адреса и порта. Native connection graph, balancers и fallback сохраняются. Изменение не требует отключения sniffing или расширения обхода VPN.
- AT-02-008 / AT-06-001: добавлены три регрессии и расширена проверка обычного SOCKS-конфига. Два теста запускают настоящий комплектный Xray и передают HTTP / синтетический TLS ClientHello между loopback-сокетами на динамических нестандартных портах; проверяются исходные байты назначения и выбор доменного маршрута. До изменения production-кода — 4 failed / 38 passed / 1 skipped, включая два реальных таймаута; после — 42 passed / 1 skipped. Пропуск относится к внешнему REALITY handshake без тестового ключа; локальные новые сценарии выполнены. Временные fixture-каталоги удалены.
- Из `vpn-tunnel-enforcer`: `npx.cmd vitest run src/main/xrayEngine.test.ts src/main/nativeXrayCompatibility.test.ts src/main/xrayEngine.live.test.ts --reporter=dot` — 42 passed / 1 skipped, exit 0; `npm.cmd run typecheck` — exit 0; `npm.cmd test -- --reporter=dot` — 2616 passed / 10 skipped / 0 failed, 211 файлов passed / 2 skipped, 137.08 с, exit 0; `python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py` — AC927/927, F210/210, exit 0; `npm.cmd run dist:win` — exit 0; `git diff --check` — exit 0.
- Установщик 1.1.22 пересобран: 139181950 bytes, NotSigned, SHA-256 `A7ADD23BAAA0C2D37633CF62F72541D18C510D0E61EB7C82B469F1295B3709A3`. Все 185 файлов `out/` совпали с packaged ASAR; `routeOnly: true` присутствует, `dist/checksums.txt` обновлён. Установленная копия и её активный туннель не изменялись; реальный поиск с расширением после установки новой сборки и полный L3/VM не проверялись. Нормативные документы не менялись, предсуществующая whitespace-правка `connectionLifecycle.ts` исключена из коммита.

## 2026-10-06 — WP-11 / WP-8: установщик и ограничение логов

- По команде владельца удалён сломанный NSIS NGEN-блок с вложенными кавычками: установщик больше не пытается менять глобальную переменную DOTNET_NGEN_OPT и выполнять общесистемный ngen update. Для standalone uninstall добавлен customUnInstall до удаления файлов: удаляется только BootRecoveryTask в \VPNTE\ с SYSTEM principal и действием, указывающим на скрипт этой установки. Отсутствие задачи допускается; чужое действие, отказ доступа/удаления и неуспешный read-back останавливают удаление с ошибкой. При --updated задача сохраняется для нового установщика. Трассировка локальных контрактов — AT-11-005/009, F-167; реальные uninstall/upgrade и OS/VM-матрица не выполнялись.
- Добавлена ротация sing-box.log/xray.log во время работы: проверка размеров каждые 5 секунд, native ACL-проверка только перед записью, сериализованные проверки, ограниченное чтение хвоста, отказ hard-link/reparse leaf. Текущий файл усекается на месте после сохранения предыдущего поколения: реальные append handles продолжают писать без перезапуска/переподключения. Целевой объём шести retained log-files — 50 МиБ (app.log/app.prev.log по 5; по 10 для текущего/предыдущего файла каждого движка). Это периодический предел: за 5 секунд между проверками и при отказе ACL/доступа превышение возможно; отказ виден в app.log и повторяется безопасно. Объём настроек, packet capture, конфигураций и Chromium cache в этот лимит не входит.
- Xray и предыдущее поколение включены в getFullLogs с существующим redaction. Очистка логов ждёт текущую ротацию, очищает оба движка и возобновляет единичный watcher. AT-08-001/AT-01-009 здесь — поддерживающие локальные регрессии диагностических источников/доверенного namespace, без заявления о полном L3 PASS.
- Добавлено 20 regression cases: 7 файловых/таймерных, 9 native PowerShell task-removal fixtures с fake cmdlets, 2 installer contracts и 2 сценария настоящих комплектных Xray/sing-box. В последних после ротации проходит loopback SOCKS-запрос, лог продолжает расти без NUL holes, процесс остаётся жив. Установленный клиент, реальная сеть, маршруты, DNS, firewall и Task Scheduler не изменялись. Read-only запрос отсутствующей задачи подтвердил реальный ObjectNotFound, отличаемый от отказа доступа.
- Из vpn-tunnel-enforcer: npx vitest run src/main/appLoggerCleanup.test.ts src/main/engineLogRetention.test.ts src/main/engineLogRetention.live.test.ts src/main/installerCleanup.test.ts src/main/installerShutdown.test.ts src/main/bootRecoveryTaskReadBack.test.ts src/main/appLoggerRotation.test.ts src/main/appLoggerRedaction.test.ts src/main/appLoggerError.test.ts --reporter=dot — 41 passed, exit 0; npm run typecheck — exit 0; npm test -- --reporter=dot --reporter=json --outputFile=.tmp/installer-logs-tests-20261006.json — 2636 passed / 10 skipped / 0 failed, 214 файлов passed / 2 skipped, 146.24 с, exit 0; python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py — AC927/927, F210/210, exit 0; npm run dist:win и git diff --check — exit 0. Финальные production-изменения после полного прогона — только отступы; NSIS contract-test адаптирован к LF/CRLF, удалено неиспользованное чтение fixture-source. Финальный npx vitest run src/main/installerCleanup.test.ts src/main/appLoggerCleanup.test.ts --reporter=dot — 14 passed, exit 0; production build повторно выполнил typecheck.
- NSIS 1.1.22: 139183217 bytes, NotSigned, SHA-256 C2DF288E5FF75C490BC0DB2A594964E46FDC67A96A6F1698FB880EC487336AC9. Все 185 out-files побайтно совпали с ASAR; packaged recovery script совпал с исходником, markers ротации/удаления присутствуют. ASAR SHA-256 FF2D9E1BEB85F1812C95D1835F3E4E5C4696640760992355684457D65D70BD04; dist/checksums.txt обновлён. Опциональный mksnapshot отсутствует: сборка штатно пропустила только snapshot. EXE не устанавливался.
- Первый native fixture использовал слишком длинный EncodedCommand; исправлен на чтение проверяемого source-файла. Первичная ASAR-сверка использовала неверный разделитель Windows; повторная сверка успешна. Временные fixture-каталоги удалены, JSON полного прогона остаётся в игнорируемой .tmp. Новые MD-файлы не создавались, нормативные документы не изменены. Предсуществующая whitespace-правка connectionLifecycle.ts сохранена и исключена из коммита.

## 2026-10-06 — PR #22: остановка при отказе и отдельные интеграционные тесты
- При отказе/таймауте/ошибке проверки выхода runtime stop возвращает ошибку до завершения Xray и снятия сетевой защиты; status/PID сохраняются, повторная остановка допускается. Native PowerShell прекращает цикл при неподтверждённом выходе sing-box. Рабочий код: 8 добавленных / 5 удалённых строк, включая комментарии; новые абстракции не добавлены. AT-02-005/009, F-029: обновлены регрессии отказа, таймаута, неизвестного выхода и retry; настоящий stop body проверяет отсутствие rollback и возобновление мониторинга при отказе.
- Xray/engine-log fixtures перенесены в .itest.ts без изменения содержимого; native installer fixtures отделены от двух unit contracts. npx.cmd vitest run --mode integration src/main/engineLogRetention.itest.ts src/main/xrayEngine.itest.ts src/main/installerCleanup.itest.ts --reporter=dot — 17 passed / 1 skipped (внешний REALITY без ключа). Focused stop/protocol/config: 171 passed; npx.cmd vitest run src/main/lifecycleCleanup.test.ts src/main/tunShutdownOrder.test.ts --reporter=dot — 95 passed. Первичный red run: 6 failed; первый full run: один устаревший тест требовал rollback при отказе runtime, ожидание исправлено.
- npm.cmd run typecheck и npm.cmd run build — exit 0; npm.cmd test -- --reporter=dot --reporter=json --outputFile=.tmp/pr22-review-fixes-final-tests-20261006.json — 2623 passed / 9 skipped / 0 failed, 212 файлов passed / 2 skipped, 130.55 с, exit 0. python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py — AC927/927, F210/210, exit 0; git diff --cached --check — exit 0. Установленный VPN/системная сеть не менялись, NSIS не пересобирался, полный Windows/L3 не выполнялся. Предсуществующая whitespace-правка connectionLifecycle.ts исключена; новые MD-файлы не создавались.

## 2026-10-06 — PR #22: сохранить watchdog при отказе остановки
- По повторному ревью перенесён единственный stopProxyWatchdog после подтверждённого выхода runtime: отказ/таймаут/ошибка проверки сохраняют живой upstream, мониторинг и сетевую защиту. Удалён tunShutdownOrder.test.ts с поиском фрагмента исходника и точными последовательностями mock calls; пять сценариев перенесены в существующий AST harness полного stop (AT-02-005/009, F-029). Проверяются состояния runtime/upstream/watchdog/baseline/firewall/adapters до proof, после успеха, при трёх отказах и retry. Два дублировавшихся случая уже покрыты full-stop/native tests; новых рабочих сущностей нет, код и тесты уменьшились на 34 строки до записи журнала.
- Red run: npx.cmd vitest run src/main/lifecycleCleanup.test.ts --reporter=dot — 5 failed / 88 passed до переноса строки. Green: npx.cmd vitest run src/main/lifecycleCleanup.test.ts src/main/tunControllerRecoverySource.test.ts --reporter=dot — 113 passed; npm.cmd test -- --reporter=dot --reporter=json --outputFile=.tmp/pr22-watchdog-tests-20261006.json — 2621 passed / 9 skipped / 0 failed, 211 файлов passed / 2 skipped, 134.42 с. npm.cmd run typecheck и npm.cmd run build — exit 0; python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py — AC927/927, F210/210, exit 0; git diff --cached --check — exit 0. Установленный клиент и системная сеть не менялись; installer/L3 не проверялись. Новых MD-файлов нет; предсуществующая whitespace-правка connectionLifecycle.ts исключена.

## 2026-10-06 — WP-2 / WP-3: отказ остановки в main и сохранение мониторинга (PR #22)

- По самостоятельной проверке кода исправлены три подтверждённых дефекта: shutdown продолжал снимать сетевую защиту после неподтверждённого выхода runtime; обычный Stop очищал IP/счётчики и восстанавливал адаптеры при success:false; монитор чужого TUN отключался до подтверждения выхода. Верхний Stop теперь проверяет результат до побочных действий, сохраняет живую сессию и снимает свой флаг при исключении. Shutdown сначала выполняет native backstop и свежий inspect-runtime с requireProof=true; при отказе/частичном kill, живом процессе или ошибке запроса прекращает очистку и не допускает installer ACK. После восстановившего выход fallback контроллер повторно подтверждает остановку и согласует своё состояние.
- Обработчик stopping/error/adapting сохраняет счётчики, sampler и forensics, пока runtime отмечен живым; трей не показывает off/protected при неподтверждённой остановке. Монитор чужого TUN выключается рядом с watchdog после exit proof. История закрывается после подтверждённой остановки со снимком счётчиков до сброса. В рабочих исходниках 48 добавленных / 43 удалённых строки, прирост 5; новые рабочие сущности и MD-файлы не создавались.
- Существующий AST harness полных production-функций расширен на 16 случаев (AT-02-005/009, AT-03-007, AT-11-002): отказ/исключение Stop и retry, ожидание результата без очистки/истории, сохранение счётчиков, свежий proof и согласование контроллера после fallback, живой/неизвестный runtime, шесть статусов main. Имеющиеся five-case проверки полного stop теперь учитывают также competing monitor. Старые фикстуры отказа сетевого rollback уточнены: runtime уже остановлен, сетевое восстановление не подтверждено. Red: npx.cmd vitest run src/main/lifecycleCleanup.test.ts --reporter=dot — 18 failed / 89 passed на старом коде; промежуточно 4 старые фикстуры отказа сети требовали уточнения. Финальный npx.cmd vitest run src/main/lifecycleCleanup.test.ts src/main/tunControllerRecoverySource.test.ts src/main/mainIpcRegression.test.ts --reporter=dot — 149 passed, exit 0.
- Из vpn-tunnel-enforcer: npm.cmd test -- --reporter=dot --reporter=json --outputFile=.tmp/pr22-main-stop-tests-20261006.json — 2637 passed / 9 skipped / 0 failed, 211 файлов passed / 2 skipped, 135.67 с, exit 0; npm.cmd run typecheck — exit 0; npm.cmd run build (включая финальный typecheck) — exit 0; python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py — AC927/927, F210/210, exit 0; git diff --check — exit 0. Проверки lifecycle выполнялись с fake OS boundaries; установленный клиент, системная сеть и нормативные документы не менялись. NSIS не пересобирался; реальные upgrade/L3 не проверялись. Предсуществующая whitespace-правка connectionLifecycle.ts исключена из коммита.

## 2026-10-07 — сверка WP-1/WP-3/WP-11 после PR #21/#22 и порядок работ

- Обновлены статусы плана ТЗ-06, индекс docs, адресные строки срезов томов 2/3 и существующий отчёт WP-1. PR #21 (`5764bc8`) реализовал default masking/main-owned opt-in export, DPAPI preflight, IPC/CSP и runtime ACL/hash; #21/#22 (`324c7cc`) реализовали controlled installer shutdown и сохранение защиты до runtime exit proof. F-144/F-183 больше не представлены отсутствующей реализацией, но полная приёмка не объявляется.
- Раздел 7 ТЗ-06 согласован с порядком docs/README.md: миграция Electron выполнена; WP-1 частично проверен; следующий рекомендуемый фокус — адресная матрица AT-03-001…012 и остаток WP-3, затем WP-0 → WP-2 → WP-10. WP-3 уже реализовывался, однако packet oracle/SYSTEM reboot/NAT64/hot-plug/DNS/ACL/OS matrix не приняты; отдельный остаток WP-1 сохраняется.
- Из vpn-tunnel-enforcer: npm.cmd run typecheck — exit 0; npm.cmd test -- --reporter=dot — 211 файлов passed / 2 skipped, 2648 тестов passed / 9 skipped / 0 failed, 157.84 с, exit 0. Из корня: python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py — AC927/927, F210/210, exit 0. Inline python -X utf8 - проверил 52 local links, четыре столбца таблиц, неизменность требований перед срезами и порядок WP; первый отказ был неточным строковым ожиданием checker, исправленный checker — PASS. git diff --check — exit 0.
- Только документация: source/tests/resources и действующая система не изменялись. Windows/L3/native/full fuzz/42→44/NSIS не выполнялись; старые результаты отчётов не выданы за свежий прогон. Предсуществующая правка connectionLifecycle.ts сохранена и исключена из коммита.

## 2026-10-07 — решение владельца: WP-1 завершён

- По прямому сообщению владельца «wp -1 завершён» текущий статус WP-1 изменён на завершён в индексе, плане ТЗ-06 (§10.10), пояснениях срезов томов 2/3 и отчёте WP-1. Предыдущая частичная отметка заменена; следующий рекомендуемый пакет — WP-3, затем WP-0. Исторические PASS/FAIL/NOT-CHECKED сохранены, невыполненные системные проверки не объявлены PASS.
- Только документация. npm.cmd run typecheck — exit 0; npm.cmd test -- --reporter=dot — 211 файлов passed / 2 skipped, 2648 тестов passed / 9 skipped / 0 failed, 159.09 с, exit 0. python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py — AC927/927, F210/210, exit 0. Inline python -X utf8 -: согласованный статус в пяти документах, локальные ссылки и неизменность нормативных требований перед срезами — PASS; git diff --check — exit 0. Предсуществующая правка connectionLifecycle.ts сохранена отдельно.

## 2026-10-07 — WP-3 / AT-03-007: ошибка вместо успеха при неполном rollback

- Исправлён подтверждённый аудитом ложный общий успех: обычный Stop после подтверждённого выхода runtime, но при ошибках baseline/firewall/adapters/DNS, возвращает success:false, сводку ошибок и рекомендацию повторить остановку/проверить диагностику. currentStatus сохраняет предупреждение; статус error заменяет stopped, поэтому UI не получает сообщение об обычном восстановленном маршруте. Независимость шагов отката и повторная попытка сохранены. В рабочих исходниках суммарно +5 строк; нормативные документы не менялись.
- Внутренний runtimeStopped отделяет доказанный выход процесса от полного успеха очистки. Main закрывает завершившуюся сессию и очищает связанные ресурсы, сохраняя ошибочный результат для IPC; внутренние подтверждения в IPC не передаются. При неподтверждённом выходе main по-прежнему сохраняет живую сессию/мониторинг/защиту. Shutdown выполняет свежий native exit proof и повторяет неподтверждённые сетевые шаги; оставшийся отказ блокирует ACK и освобождение recovery helper. Исполняемые тесты расширены; удалена устаревшая source assertion, закреплявшая success:true при неполном rollback.
- Red: npx.cmd vitest run src/main/lifecycleCleanup.test.ts --reporter=dot — 12 failed / 104 passed на старом коде, exit 1. Green: npx.cmd vitest run src/main/lifecycleCleanup.test.ts src/main/tunControllerRecoverySource.test.ts src/main/mainIpcRegression.test.ts --reporter=dot — 155 passed, exit 0; после этого добавлены ещё две регрессии свежего shutdown proof, включённые в полный прогон. Из vpn-tunnel-enforcer: npm.cmd run typecheck — exit 0; npm.cmd test -- --reporter=dot --reporter=json --outputFile=.tmp/wp3-stop-tests-20261007.json — 211 файлов passed / 2 skipped, 2656 тестов passed / 9 skipped / 0 failed, 159.24 с, exit 0. Из корня: python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py — AC927/927, F210/210, exit 0; git diff --check — exit 0.
- Закрыт конкретный дефект общего результата AT-03-007 (том 2 §2.1), а не весь WP-3 или полный AT с единым correlation id всех шагов. Дефекты recovery/schema, hot-plug и IPv6/NAT64 из аудита остаются открытыми. Исходные находки F-040/F-148 относятся к другим компонентам и этим изменением не объявляются закрытыми. Проверки lifecycle используют подменённые OS boundaries; installed клиент, системная сеть, L3/reboot и NSIS не менялись и не проверялись. Предсуществующая whitespace-правка connectionLifecycle.ts исключена из коммита.

## 2026-10-07 — WP-3 / AT-03-003/006/012: recovery preflight и смена NIC

- Boot recovery проверяет ACL и версии всех пяти входных журналов до сетевых изменений; использует единый прочитанный набор. Неизвестная версия и недоверенный ACL оставляют сеть неизменной с ошибкой. Повреждённое доверенное содержимое изолируется в карантин; для firewall допускается предусмотренный ТЗ Allow fallback только при собственных правилах и отсутствии выбранного strict. Неизвестная strict policy не разрешает сброс. Обычный firewall rollback также различает corruption, неподдерживаемую версию и ошибку доверия; неподдерживаемый/недоверенный вход не вызывает системных изменений. Quarantine требует повторной проверки каталога/файла и подтверждения rename.
- Lockdown снимает свежий набор GUID перед применением и после native batch; повторное использование журнала также проверяет фактический набор. Добавление, исчезновение, замена NIC или ошибка запроса вызывают компенсацию; неподтверждённая компенсация сохраняет pending journal и предупреждение. Переименование того же GUID допустимо. Это исправляет обнаружение hot-plug внутри apply, но не является доказательством L3 защиты при смене NIC в течение всей активной сессии.
- Red: новые NIC-регрессии — 7 failed / 33 passed; новые boot-регрессии — 8 failed / 45 passed в объединённом прогоне. Green: `npx.cmd vitest run src/main/bootRecoveryExecution.test.ts src/main/bootRecoveryBehavior.test.ts src/main/bootRecoveryScriptSource.test.ts src/main/physicalAdapterLifecycle.test.ts` — 67 passed; `npx.cmd vitest run src/main/firewallTransactions.test.ts src/main/recoveryManifestStorage.test.ts` — 108 passed / 1 skipped. Boot execution теперь запускается автоматически на Windows с PowerShell, без обязательного VPNTE_PWSH; все системные эффекты в harness подменены.
- Проверки из vpn-tunnel-enforcer: `npm.cmd run typecheck` — exit 0; `npm.cmd test -- --reporter=json --outputFile=.tmp/wp3-recovery-nic-tests-20261007.json` — 2682 passed / 4 skipped / 0 failed, exit 0. Из корня: `python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py` — AC927/927, F210/210, exit 0; `git diff --check` — exit 0. Предсуществующая правка connectionLifecycle.ts исключена.
- IPv6/NAT64: выявлено противоречие тома 2 §1.1.3 — явный Windows Firewall Block перекрывает Allow. Владелец выбрал отдельный WFP-фильтр, разрешил уточнить нормативный механизм и увеличить объём кода. Реализация и Windows L3 остаются следующими шагами; WP-3 не объявлен завершённым.

## 2026-10-07 — WP-3 / AT-03-010: отдельная IPv6 WFP-политика и независимое восстановление

- По прямому решению владельца уточнены том 2 §1.1.3/§2.1 и AT-03-010; решение записано в §10.11 ТЗ-06. Вместо невыполнимого приоритета обычного Allow над Block ::/0 реализован собственный WFP sublayer `VPNTE.IPv6.v1`: persistent блокировка обоих ALE-направлений, boot-time блокировка до запуска BFE и узкие soft permit. Нативный помощник — C# поверх штатного user-mode WFP API, без драйвера; закреплённый SHA-256 одинаково проверяется приложением и recovery-скриптом до компиляции. Новый ресурс включён в electron-builder.
- Разрешение VPN ограничено совместными условиями App ID + endpoint `/128` + LUID физического интерфейса; TUN проверяется по GUID/драйверу/PnP/подсети. DNS64-префикс /32, /40, /48, /56, /64, /96 признаётся только по обеим контрольным ответам ipv4only.arpa; разрешается синтезированный адрес сервера, а не весь NAT64-префикс. Неизвестные endpoint не получают разрешение. У локального прокси автоматически доказаны только уже установленные IPv6 TCP-соединения; неизвестный UDP endpoint остаётся заблокированным. Это ограничение доступности, а не доказательство работоспособности CLAT.
- Подготовленная политика сохраняется в доверенный firewall.json до эффектов; native apply атомарен, read-back проверяет точный набор до/после commit, перечисление включает boot-time/disabled фильтры. Live-исключения отражаются в WFP и Firewall; компенсация каждого механизма выполняется независимо. Ошибка cleanup сохраняет журнал, включая boot recovery; strict recovery WFP не снимает. Повторный старт проверяет IPv6, прежний обход проверки через `isKillSwitchActive()` удалён.
- Устранены общие mutable-флаги ошибки чтения журнала: read-only probes не карантинируют файлы, recovery сериализован с firewall-мутациями. Вложенная будущая IPv6-схема блокирует изменения; карантин повторно проверяет fingerprint повреждённого содержимого и выполняется через типизированный привилегированный worker, без повторения uncertain completion. Native fixture проверяет отказ для изменённого/недоверенного содержимого и настоящий rename только в собственной `.tmp`-папке. Расширение скрипта обнаружило лимит командной строки Windows: фиксированный worker теперь передаётся с gzip-сжатием в памяти; настоящий PowerShell framing/read/quarantine/exit снова прошёл.
- Проверки из `vpn-tunnel-enforcer`: `npx.cmd vitest run src/main/wfpIpv6.test.ts --reporter=dot` — 17 passed, включая компиляцию production C#, SDK x64 ABI и транзакционные fault fixtures; `npx.cmd vitest run src/main/recoveryManifestStorage.test.ts src/main/recoveryPsWorker.test.ts src/main/firewallTransactions.test.ts --reporter=dot` — 145 passed / 1 skipped после исправления transport; дополнительные регрессии включены в финальный полный прогон. `npm.cmd test -- --reporter=json --outputFile=.tmp/wp3-wfp-final-tests-20261007.json` — **2718 passed / 4 skipped / 0 failed**, 214 файлов в JSON-отчёте (213 с passed-тестами), 136.57 с, exit 0. `npm.cmd run typecheck`, `npm.cmd run build`, `npm.cmd run dist:win` — exit 0. `python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py` из корня — AC927/927, F210/210, exit 0. Проверка локальных ссылок изменённых документов и `git diff --check` — exit 0.
- В `dist/win-unpacked/resources/` подтверждены C#-ресурс и recovery; проверка SHA-256 в ресурсе, boot script и main внутри app.asar — PASS (`99382d8ef48069fa80ca8cb5811e7dec708e4440f98a04e74eed2a742d69997e`). Инсталлятор `dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe`: SHA-256 `5ee9a07fb135641fcede5e52799b90be778cb7d12598886a04e2506545300aa9`, Authenticode `NotSigned`. Проверка asar первоначально использовала POSIX-путь на Windows; исправленная проверка с `path.normalize(pkg.main)` прошла. Установка не выполнялась.
- Нативная попытка read-only enumeration вернула Win32 error 5 / Access denied в текущем непривилегированном процессе. Реальные фильтры не устанавливались/не удалялись; безопасность и доступность WFP, persistent→boot переход, packet oracle, IPv6-only/NAT64/464XLAT, SYSTEM reboot и OS-матрица **не подтверждены** этими fixtures. Затронута реализация AC-LEAK-NET-003…005, AT-03-001/003/004/007/008/010/012, F-016/F-030/F-031/F-033/F-034/F-043/F-186; находки и весь WP-3 не объявлены полностью принятыми. Следующий шаг — Windows/L3 WP-3, после приёмки WP-0. Предсуществующая whitespace-правка connectionLifecycle.ts исключена из коммита.

### 2026-10-07 — WP-3: исправление регрессии установленного kill-switch и задержек отмены

- По `%APPDATA%/vpn-tunnel-enforcer/logs/app.log` в установленной сессии 19:15–19:16 подтверждён отказ нового WFP-кода из `5fcb825`: Windows PowerShell 5.1 передаёт JSON-массив одним объектом в pipeline, присваивание массива `id` полю Guid падает (`System.Object[] → System.Guid`). Подключение отменено с rollback, успешная защита не заявлена. Декодирование правил заменено явным `foreach`; нативный тест теперь исполняет настоящие генерируемые apply/verify-скрипты с production C# и fake WFP engine. Прежняя фикстура проверяла C# с вручную созданными правилами и не покрывала этот мост JSON/PowerShell.
- IPv6/NAT64 discovery через отдельный `Resolve-DnsName` занял 11642 мс; запрос отмены ждал завершения старта 8816 мс. Теперь отдельный Node Resolver ограничен общим таймером 1500 мс, имеет одну попытку, получает AbortSignal от lifecycle и отменяет DNS при Cancel. Отсутствие AAAA/таймаут не создаёт IPv6 transport permit: изоляция сохраняется, доступность IPv6-only аплинка без доказанных адресов не обещается. Проверены stalled DNS, немедленная отмена, уже отменённый старт, отсутствие IPv6, передача сигнала и запрет эффектов после отмены.
- В логах каждого WFP-запроса helper отвергал `Add-Type`, вызывая protected-file fallback и повторную компиляцию (подготовка заняла ещё 2000 мс). Добавлена отдельная helper policy `wfp-ipv6`: исключён из запретов только точный bundled загрузчик после проверки SHA-256; произвольный Add-Type, изменённый загрузчик и посторонние firewall/adapter mutations остаются запрещены. Сборка типа повторно используется внутри постоянного PowerShell, свежие native reads выполняются каждый раз. Сама внутренняя stop-процедура в проблемной сессии заняла 1290 мс; длительная отмена включала ожидание неотменяемого discovery и повторный cleanup. Ускорение реального installed подключения после исправления пока не измерено.
- Проверки из `vpn-tunnel-enforcer`: `npx.cmd vitest run src/main/wfpIpv6.test.ts src/main/elevatedPsHelper.test.ts src/main/elevatedPsHelperNative.test.ts src/main/firewallTransactions.test.ts src/main/firewallManifestSecurity.test.ts --reporter=dot` — 120 passed / 1 skipped, exit 0. `$env:VPNTE_PWSH = (Get-Command pwsh.exe).Source; npx.cmd vitest run src/main/wfpIpv6.test.ts --reporter=dot` — 24 passed на PowerShell 7.6, exit 0; нативная фикстура также прошла на штатном Windows PowerShell 5.1. `npm.cmd run typecheck` — exit 0.
- Первый полный `npm.cmd test -- --reporter=json --outputFile=.tmp/wp3-runtime-regression-tests-20261007.json` — 2722 passed / 6 failed / 4 skipped, exit 1: извлечённый startup callback в тестовом стенде не имел нового `startAbortController`. Стенд дополнен настоящим AbortController и проверкой передачи сигнала; `npx.cmd vitest run src/main/tunControllerStartup.test.ts src/main/wfpIpv6.test.ts src/main/elevatedPsHelper.test.ts src/main/firewallTransactions.test.ts --reporter=dot` — 129 passed / 1 skipped, exit 0. Финальный `npm.cmd test -- --reporter=json --outputFile=.tmp/wp3-runtime-regression-final-20261007.json` — **2728 passed / 4 skipped / 0 failed**, 214 файлов в JSON, 124.27 с, exit 0.
- `npm.cmd run dist:win` — exit 0; проверено наличие decoder, новой helper policy, DNS deadline и AbortSignal в main внутри packaged app.asar. Инсталлятор `dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe` пересобран; SHA-256 `fb6a28e04d6b2405c53974c1c5c4541894e80ce991f80f683a52ef13f7c53e13`. Из корня: `python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py` — AC927/927, F210/210, exit 0; `git diff --check` — exit 0. Установка, реальное подключение, изменения системной сети и reboot в этой проверке не выполнялись; WP-3 остаётся частичным. Предсуществующая правка connectionLifecycle.ts не включена.

## 2026-10-07 — WP-3: фактический native WFP read-back и лишнее DNS-ожидание

- В новой installed-сессии (app.log, 16:40 UTC) старый JSON/Guid отказ исчез. DNS вернул ENODATA примерно за 16 мс; stop занял 274 мс. Новая причина отказа — `Foreign WFP sublayer; unchanged`, ошибочно скрытая за общим `DefaultOutboundAction`. Elevated диагностика внутри откаченной транзакции показала: перед Ensure собственный sublayer отсутствует (`0x80320007`), после создания GUID/name/description/flags/provider совпадают, но BFE вернул weight 65533 вместо запрошенного 65535. Фиксированный requested weight больше не используется как доказательство чужого владельца: идентичность проверяется отдельно, безопасность — по фактическому приоритету и отсутствию более высоких/равных активных hard permit.
- Реальный BFE, в отличие от прежнего fake engine, выявил ещё два дефекта: ненулевой enum template с пустым Layer GUID даёт `0x80320004`; Windows добавляет `INDEXED (0x40)` к persistent фильтру (`flags=65`). Перечисление теперь идёт отдельно по трём требуемым слоям; INDEXED принимается как оптимизация поиска. Неизвестные flags и disabled persistent фильтры по-прежнему отвергаются, disabled boot допустимы после BFE transition. Проверены негативные flags, приоритеты ниже/равно/выше и неактивный hard permit. SHA-256 C# одинаково обновлён в main и recovery: `26aa1dd13059f6a3582ebbae2421833323d03340771bfbce5198d1dad628e712`.
- На текущем компьютере обнаружен активный `sing-tun` hard permit на ALE_AUTH_CONNECT_V6 с weight 65535, sublayer `13f79b99-1874-4007-8639-6a38f4804c99`; одновременно работают Happ.exe, happd.exe и sing-box.exe. Конкретный App ID чужого фильтра не сопоставлялся с процессом: принадлежность Happ вероятна, не объявлена доказанной. Такой permit может обойти более низкую IPv6-политику, поэтому production activation отклоняется с понятным сообщением о конфликте. Чужие фильтры и процессы не изменялись. По исходнику SagerNet sing-tun strict_route создаёт собственный hard permit для ядра; пустой собственный WFP-контейнер теперь резервируется **до** запуска нашего sing-box, а фильтры трафика по-прежнему устанавливаются только после подтверждения TUN и записи recovery journal. Проверены ожидание раннего reserve и прекращение старта при конфликте. Нормативные документы не изменялись.
- DNS discovery больше не выполняется, если существующий read-only этап подготовки не обнаружил физический IPv6 default route: для IPv4-only аплинка нет запроса DNS и дополнительного helper roundtrip. При физическом IPv6 discovery сохраняет предел 1500 мс и AbortSignal; узкие endpoint permits создаются только после доказательства адреса/маршрута. Проверены hostname и IPv4 literal без IPv6, отсутствие подтверждённого снимка, timeout/cancel и сохранение блокировок. Работоспособность NAT64/CLAT этим не доказана.
- Из `vpn-tunnel-enforcer`: `npx.cmd vitest run src/main/wfpIpv6.test.ts src/main/firewallTransactions.test.ts src/main/elevatedPsHelper.test.ts src/main/tunControllerStartup.test.ts src/main/tunControllerPreparation.test.ts` — **142 passed / 1 skipped**, exit 0. `npm.cmd run typecheck` — exit 0. `npm.cmd test -- --reporter=json --outputFile=.tmp/wp3-wfp-native-final-20261007.json` — **2734 passed / 4 skipped / 0 failed**, exit 0 (170.2 с по интервалу testResults; параллельно выполнялась сборка). Ожидаемый stderr RootErrorBoundary не является провалом теста. Из корня `python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py` — AC927/927, F210/210, exit 0.
- Elevated Windows PowerShell: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/test-wfp-ipv6-native.ps1 -OutputPath .tmp/wp3-native-20261007.json` — exit 0: `ok=true`, `rules=23`, `aborted=true`, **priority=conflict**. Скрипт проверил настоящие Add/Enum/read-back для block/LAN/TUN/VPN/user-app/user-IP на всех трёх слоях внутри транзакции без commit. Тестовый wrapper отделяет ABI-проверку от отдельно вызываемой production проверки приоритета; успешный ABI smoke **не означает успешное включение защиты**. Более ранние native прогоны действительно падали на enum layer и flags до исправления. Трафиковые фильтры не оставлены; AT-03-001/010 L3 с внешним capture, мобильная сеть и reboot не выполнялись, WP-3 остаётся частичным.
- `npm.cmd run dist:win` — exit 0. Пересобран `dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe`, 139195283 байта, SHA-256 `0bf0b174d59098597b8253cd2049aca374fac3e68645b8079b4960cfce225748`. Проверены reserve/uplink/conflict и новый hash в main из app.asar, совпадение bundled C# и recovery pin. Установщик в этом прогоне не устанавливался, фактическое подключение после обновления не измерено. Предсуществующая правка connectionLifecycle.ts исключена из коммита.

## 2026-10-07 — WP-3: отказ обязательного LAN Allow в установленной сессии

- Свежий app.log (19:49 UTC / 22:49 МСК): WFP reserve, prepare и apply выполнены; Windows Firewall отказался продолжать без `VPNTE-killswitch-allow-lan`. Весь start-direct-vpn с компенсацией занял 8347 мс. Долгого IPv6 DNS discovery в этой попытке нет; start Xray занял 2583 мс (prepare-runtime 1400 мс, allow-firewall 955 мс, включая очередь). Позднейший обычный stop в 19:50 UTC занял 409 мс и подтвердил cleanup. Happ TUN обнаружен после отказа; он не объявляется причиной данной попытки.
- Причина доказана без изменения системной сети: настоящий `HNetCfg.FwRule.RemoteAddresses` отвергает `::1/128` и `::1`; остальные IPv4/IPv6 LAN CIDR принимаются вместе. Ошибочный комментарий про несовместимость смешанных семейств исправлен: сам API допускает оба семейства ([INetFwRule](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwrule)). Исключён только IPv6 loopback из обязательного LAN-правила; отдельная WFP loopback-политика, IPv4 loopback и IPv6 LAN `fc00::/7`, `fe80::/10`, `ff00::/8` сохранены. Нормативные документы не менялись.
- Новый AT-03-001/010 regression исполняет извлечённый из настоящей enable-транзакции LAN-блок и production COM API с реальным unregistered FwRule; Rules.Add заменён коллекцией в памяти. Проверяется успешное создание обязательного правила и read-back полного набора LAN-адресов. До исправления: `npx.cmd vitest run src/main/firewallTransactions.test.ts -t 'real Windows COM address validation'` — 1 failed / 67 skipped, `WARN allow-lan: Value does not fall within the expected range.`, exit 1. После: `npx.cmd vitest run src/main/firewallTransactions.test.ts src/main/firewallRulesApi.test.ts src/main/wfpIpv6.test.ts --reporter=dot` — 117 passed / 1 skipped, exit 0, Windows PowerShell 5.1. Повтор нового теста с `$env:VPNTE_PWSH=(Get-Command pwsh.exe).Source` — 1 passed / 67 skipped на PowerShell 7, exit 0.
- Из vpn-tunnel-enforcer: `npm.cmd run typecheck` — exit 0; `npm.cmd test -- --reporter=json --outputFile=.tmp/wp3-lan-native-final-20261007.json` — 2735 passed / 4 skipped / 0 failed, exit 0 (165.24 с по интервалу testResults; параллельно сборка). Из корня: `python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py` — AC927/927, F210/210, exit 0. `git diff --check` — exit 0.
- `npm.cmd run dist:win` — exit 0. Исправленные LAN scopes проверены внутри packaged app.asar. Пересобран `dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe`, 139195308 байт, SHA-256 `5b758ebc6fcff8bf702e6d569655bcd2cab313a5e727e5fc3dc784f8067b44d8`. Установка и реальное подключение после этой правки не выполнялись; native property validation не заменяет L3 трафик/reboot/NAT64, WP-3 остаётся частичным. Предсуществующая whitespace-правка connectionLifecycle.ts исключена из коммита.

## 2026-10-07 — WP-3: проверка свежих логов и двух дополнительных регрессий

- Installed app.log (19:59–20:00 UTC / 22:59–23:00 МСК) после c1acb05: три успешных start-direct-vpn за 6824, 4986 и 4986 мс; initial-apply-policy, commit recovery journal и kill-switch подтверждены. Отключения целиком по IPC заняли 2690, 2865 и 2778 мс (внутренний stop 2440, 2540, 2414 мс); cancel-tun — 2121 мс, отменённый start вернул явный отказ. Все networkCleanup baseline/firewall/adapters подтверждены. SIGKILL Xray следует за пользовательским stop, а не является самостоятельным падением. Startup warning об отсутствии owned DNS baseline сохраняет чужие настройки. Новых error в этом интервале нет, долгого IPv6 discovery нет. Ответы старта содержат vpnIp=null: внешний egress IP и отсутствие утечек этим не доказаны.
- Проверены изменения d0471a7..c1acb05: WFP native flags/ABI, приоритеты, prepare/DNS/NAT64, отмена, apply/verify/rollback, live exceptions, manifests/quarantine, helper policy, worker launcher и boot recovery. Найден пропуск в новой проверке WFP priority: она учитывала только статический PERMIT с CLEAR_ACTION_RIGHT, игнорируя deciding callouts. FWP_ACTION_CALLOUT_TERMINATING/UNKNOWN могут вернуть PERMIT; callback может снять ACTION_WRITE ([FWPM_ACTION0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_action0), [classifyFn](https://learn.microsoft.com/en-us/windows/win32/api/fwpsu/nc-fwpsu-fwps_callout_classify_fn1)). Более высокий/равный deciding callout теперь признаётся непроверенным конфликтом; disabled/inspection, soft permit и более низкий приоритет не вызывают этот отказ. Чужие фильтры не изменяются. SHA-256 C# одинаково обновлён в main и recovery: 6eebcb4430e2b8969d94d9afb09eb803296dfd8cbea5eaf24b8a78407db06249.
- Скомпилированный production C# regression проверяет все три слоя, оба типа deciding callout, флаги CLEAR_ACTION_RIGHT/PERMIT_IF_CALLOUT_UNREGISTERED, disabled и приоритеты ниже/равно/выше. До исправления `npx.cmd vitest run src/main/wfpIpv6.test.ts -t 'transaction/ABI regressions'` — 1 failed / 27 skipped, exit 1 (`higher deciding callout must be rejected`); после проходит также с `$env:VPNTE_PWSH=(Get-Command pwsh.exe).Source`: 1 passed / 27 skipped, exit 0. Это доказательство дефекта статической проверки, не выполненный трафиковый тест с kernel callout.
- Второй дефект воспроизведён настоящими Windows FileStream/Replace/Move на временных файлах: FileShare.Read|Delete не мешает атомарной замене pathname; проверялись старые повреждённые байты, а в quarantine уходил новый файл. Production quarantine теперь проверяет хэш реально перенесённого файла с read-lock. Если перенесена замена, её возвращают только в свободный исходный путь и отказывают recovery до сетевых эффектов. Если там уже появился ещё более новый baseline, он не перезаписывается, обе версии сохраняются и успех не выдаётся. Исправление общее для typed worker и privileged fallback.
- AT-03-003/012 native quarantine дополнен replaced/replaced-again: до исправления `npx.cmd vitest run src/main/recoveryManifestStorage.test.ts -t 'native quarantine with replaced'` — 1 failed / 1 passed / 58 skipped, exit 1 (ошибочный успех вместо отказа). После тот же фильтр на PowerShell 7 — 2 passed / 58 skipped, exit 0; полный focused на штатном Windows PowerShell 5.1 прошёл. Временные диагностические файлы удалены; системная сеть и реальные manifests тестами не изменялись.
- Из vpn-tunnel-enforcer: `npx.cmd vitest run src/main/wfpIpv6.test.ts src/main/firewallTransactions.test.ts src/main/firewallRulesApi.test.ts src/main/bootRecoveryExecution.test.ts src/main/elevatedPsHelper.test.ts src/main/elevatedPsHelperNative.test.ts src/main/recoveryManifestStorage.test.ts src/main/recoveryPsWorker.test.ts src/main/tunControllerStartup.test.ts --reporter=dot` — 258 passed / 1 skipped, exit 0 (до второго исправления). После обоих: `npx.cmd vitest run src/main/recoveryManifestStorage.test.ts src/main/recoveryPsWorker.test.ts src/main/firewallTransactions.test.ts src/main/wfpIpv6.test.ts --reporter=dot` — 179 passed / 1 skipped, exit 0. `npm.cmd run typecheck` — exit 0.
- Первый общий прогон после обоих исправлений: `npm.cmd test -- --reporter=json --outputFile=.tmp/wp3-wfp-recovery-audit-final-20261007.json` — 2736 passed / 1 failed / 4 skipped, exit 1. Упавший старый twitchHlsProbe.test.ts действительно ходит к двум внешним Twitch-серверам с бюджетом 3500 мс на каждый, но лимит теста 5000 мс; сбой произошёл на 5020 мс. Этот код в задаче не менялся. `npx.cmd vitest run src/main/twitchHlsProbe.test.ts --reporter=verbose` — 14 passed, exit 0. Финальный повтор без параллельной сборки: `npm.cmd test -- --reporter=json --outputFile=.tmp/wp3-wfp-recovery-audit-recheck-20261007.json` — **2737 passed / 4 skipped / 0 failed**, exit 0, 164.81 с по testResults. Нестабильность сетевого теста остаётся отдельным ограничением; первый отказ не скрыт. `python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py` — AC927/927, F210/210, exit 0; `git diff --check` — exit 0.
- `npm.cmd run dist:win` — exit 0. В packaged app.asar проверены quarantine moved-file read-back и новый pin; bundled C# и boot recovery содержат совпадающий pin. Финальный dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe — 139195820 байт, SHA-256 ff02ba30045149049c344f8117f5b0c148fd0516acf23ad9c25f561e4cf72d0a. Эта сборка в проверке не устанавливалась; L3 с внешним capture, NAT64/CLAT, матрица Windows и reboot не выполнены. Нормативные документы не менялись; предсуществующая whitespace-правка connectionLifecycle.ts исключена из коммита.

## 2026-10-07 — WP-3: лишняя WFP-проверка Xray и параллельная подготовка runtime

- По команде владельца проверены installed app.log/app.prev.log. До отдельной WFP-политики повторные успешные start-direct-vpn: 3404/3664 мс; свежие 22:59 — 4986/4986 мс, 23:24 — 4504 мс; первый свежий запуск 23:23 — 7781 мс. Это отдельные наблюдения, а не статистика или одинаковый лабораторный стенд. В последних двух успешных запусках kill-switch подтверждён; прежний DefaultOutboundAction/WFP отказ не повторился.
- На запуске 23:24 Xray allow-firewall занял 645 мс: COM presence read 219 мс и ненужный здесь WFP presence read 416 мс, включая ожидание общей helper queue. Затем отдельно prepare-runtime sing-box занял 694 мс. Установка IPv6-политики занимает дополнительное время и остаётся обязательной; ошибки защита/скорость не подменяются ложным успехом.
- ensureKillSwitchProgramAllowed проверяет доверенный manifest и свежие собственные Windows Firewall rules; WFP-only presence не вызывает добавление COM Allow и не ставится в эту очередь. isKillSwitchActive, orphan WFP cleanup, reservation перед strict_route, journal/apply/read-back WFP и профиль Block сохранены. Не добавлен кэш состояния защиты.
- В Direct VPN/Xray подготовка sing-box ACL/бинарников перекрывается с Xray startup; существующая дедупликация делит только ещё выполняющуюся проверку ACL, завершённые proofs по-прежнему не кешируются. Конфигурация ждёт фактические SOCKS port/resolved endpoint Xray. Cancellation проверяется до/после ACL и перед конфигурацией; finally удерживает владельца start до завершения параллельной подготовки файлов. SHA-256/identity/reparse проверки ресурсов сохранены. Local proxy validation и прямой sing-box path сохранены. Трассировка: AT-01-009, AT-02-002/005, AT-03-003/004/010/012, F-030/F-043.
- Регрессии выполняют production preparation с подменёнными OS-границами: actual endpoint/port barrier, отказ ACL, отмена во время ACL/после staging, Xray failure, ранний отказ staging, ownership до его завершения, orphan WFP/Firewall и недоверенный journal. При заданных задержках Xray 1500 мс / staging 700 мс join завершён за 1500 мс вместо последовательных 2200; это компонентное доказательство, не новая installed latency.
- Из vpn-tunnel-enforcer: `npm.cmd run typecheck` — exit 0. `npx.cmd vitest run src/main/tunControllerPreparation.test.ts src/main/tunControllerStartup.test.ts src/main/firewallTransactions.test.ts src/main/runtimeDirSecurity.test.ts src/main/runtimeArtifact.test.ts src/main/xrayRuntimeLifecycle.test.ts src/main/tunControllerRecoverySource.test.ts src/main/wfpIpv6.test.ts --reporter=dot` — **279 passed / 1 skipped**, 8 файлов, 9.44 с, exit 0. Первый focused из 3 файлов до адаптации тестового стенда: 99 passed / 3 failed / 1 skipped; две старые проверки порядка ожидали последовательную подготовку, третья считала объявление PS-функции её вызовом. Стенд исправлен; production/native обходов проверок для получения PASS нет.
- Полный `npm.cmd test -- --reporter=json --outputFile=.tmp/wp3-connect-overlap-20261007.json` — **2750 passed / 4 skipped / 0 failed**, 214 файлов в JSON, 128.48 с, exit 0. `python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py` — AC927/927, F210/210, exit 0 (трассировка, не L3). `git diff --check` — exit 0.
- `npm.cmd run dist:win` — exit 0, Electron 44.4.3/NSIS; optional mksnapshot штатно пропущен. ASAR main побайтово совпадает с compiled output; проверены parallel startup/join/cancel markers и отсутствие WFP presence в program allow; неизменённый bundled WFP source совпадает с pin. Main SHA-256 a067ce8725dc23649ee3e8ac5a9139b4b71f1665b8f6a7f20c01fca206dca44b. `dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe`: **139195623 байт**, **07.10.2026 23:38:27 МСК**, SHA-256 **73d20f139b9641c636bcb2ca0b397a8d5a94b3da77fe6f3ed589d45bea153330**, Authenticode NotSigned.
- Сборка агентом не установлена; новое реальное время подключения, L3 packet oracle, NAT64/CLAT и reboot не проверены. Нормативные документы не менялись, WP-3 остаётся частичным. Предсуществующая whitespace-правка connectionLifecycle.ts исключена из коммита. Revert scoped commit возвращает последовательную подготовку и лишний presence round-trip, формат manifests/settings не меняется.

## 2026-10-08 — WP-3: проверка первого подключения и перенос чтения runtime ACL в worker

- По запросу владельца проверен installed app.log. После предыдущего исправления 07.10 в 23:49 первое/повторное start-direct-vpn заняли 4108/2821 мс. После запуска приложения 08.10 в 08:45:59 первое подключение в 08:46:04 заняло **6563 мс**, повторное — **4080 мс**. В обоих свежих подключениях kill-switch подтверждён; новых ошибок защиты в просмотренных логах до 09:10:52 нет. Это наблюдения отдельных запусков, без одинакового стенда и статистической оценки.
- На первом утреннем запуске Xray prepare-runtime занял 2836 мс, на повторном — 887 мс; весь Xray startup — 3587/1384 мс. Physical DNS sources — 2182/391 мс; adapter lockdown — 3138/1686 мс; TUN kill-switch — 1583/1195 мс, часть этапов перекрывается. Prepare-runtime включает чтение ACL, staging и проверки ресурсов: все 2836 мс не приписываются ACL. Уже существующий прогрев helper/recovery worker завершился до первого подключения; повторный прогрев не добавлялся.
- Чтение ACL использует существующий постоянный RecoveryPsWorker через новую фиксированную операцию inspect-runtime-acl. Standalone/bootstrap и worker разделяют один алгоритм инспекции: известный ProgramData, родительская цепочка root-first, owner/ACE/type/reparse, полный список потомков. Каждая попытка получает свежий снимок; кэш успешных proofs не добавлен. Изменение ACL, ошибка, неполный снимок, закрытый worker/очередь/таймаут запрещают успех. Standalone чтение разрешено только при unavailable до dispatch. Создание защищённых каталогов остаётся прежней отдельной фиксированной командой; SHA-256/identity проверки бинарников сохранены. Прогрев worker импортирует встроенный ACL-модуль по пути PSHOME. В журнал добавлены transport/durationMs чтения ACL. Трассировка: AT-01-009, AT-03-012, F-002/F-005/F-006/F-104.
- Native компонентный замер выполнен без повышения прав на существующем C:\Windows\System32\WindowsPowerShell\v1.0\Modules\Microsoft.PowerShell.Security: одинаковые production проверки отказались авторизовать этот системный каталог как runtime. До прогрева Security-модуля отдельные процессы: 522/461/446 мс; worker: 186/22/26 мс. После штатного warmup: standalone **502/406/488 мс**, worker **146/77/34 мс**. Worker завершён с подтверждённым exit. Защищённый runtime приложения недоступен процессу Codex (исходный замер остановился на EPERM); измерение на системном каталоге доказывает выигрыш транспорта, а не время elevated подключения или запуск после reboot. Временный read-only harness .tmp/runtime-acl-transport-bench.cjs использовался командой `node .tmp/runtime-acl-transport-bench.cjs 'C:\Windows\System32\WindowsPowerShell\v1.0\Modules\Microsoft.PowerShell.Security'`.
- Добавлены регрессии на свежую проверку изменённого родителя, недопустимый/неполный worker proof, сохранение bounded diagnostic отказа, отсутствие fallback после busy/closed/timeout/exited/protocol/rejected, повторную native валидацию входных полей/путей и целостность frames после отказа. Native dispatcher с подменёнными cmdlets возвращает полную цепочку и отклоняет writable parent без OS mutations.
- Из vpn-tunnel-enforcer: `npx.cmd vitest run src/main/runtimeDirSecurity.test.ts src/main/recoveryPsWorker.test.ts src/main/recoveryPsProtocol.test.ts src/main/recoveryPsWorkerNative.test.ts` — **220 passed**, 4 файла, 132.35 с, exit 0 (до последних dispatcher регрессий). `npx.cmd vitest run src/main/runtimeDirSecurity.test.ts src/main/recoveryPsProtocol.test.ts src/main/recoveryPsWorkerNative.test.ts src/main/recoveryPsWarmup.test.ts` — **197 passed**, 3 совпавших файла, 113.93 с, exit 0. `npm.cmd run typecheck` — exit 0.
- Полный `npm.cmd test -- --reporter=json --outputFile=.tmp/wp3-cold-acl-20261008.json` — **2769 passed / 4 skipped / 0 failed**, 214 файлов в JSON, 147.31 с по testResults, exit 0. `python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py` — AC927/927, F210/210, exit 0; это трассировка, не Windows L3 acceptance. `git diff --check` — exit 0.
- `npm.cmd run dist:win` — exit 0; optional mksnapshot штатно пропущен. Packaged app.asar main совпадает с compiled output; проверены inspect-runtime-acl / Read-RuntimeAclSnapshot / inspection timing. Main SHA-256 **7f196dee5e5189350382b4f6453bfa2466aa8c68829f3abe563c6b58868aabb1**. Installer dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe: **139195897 байт**, **08.10.2026 09:13:27 МСК**, SHA-256 **db709aa533c21e7ccdbcb4d5327760eb556774a609f180a5c15fa7ed204ea36b**, Authenticode NotSigned.
- Установка сборки и новый замер первого/повторного подключения остаются ручной проверкой; L3 packet oracle, NAT64/CLAT и reboot не выполнялись. Нормативные документы не менялись, WP-3 остаётся частичным. Предсуществующая whitespace-правка connectionLifecycle.ts исключена из коммита.

## 2026-10-08 — WP-3: устранение задержек прогрева и DNS в очереди подключения

- По команде владельца разобран installed app.log после утренней сборки: start-direct-vpn 09:18:58.472 → 09:19:04.116 — **5644 мс**; повторные подключения — **2480/2524 мс**. Во всех трёх kill-switch подтверждён и leak-test успешен. Последняя запись лога — 09:26:25; новых подключений во время исправления нет. Эти отдельные наблюдения не являются статистикой после reboot.
- Первый запрос Firewall ждал уже выполнявшийся необязательный прогрев адаптеров: total 1180 мс при native execution 22 мс. Прогрев закончился в 09:18:59.711, через 1239 мс после кнопки. Далее чтение физических адаптеров/DNS занимало helper 734 мс; WFP reservation получил total 830 мс при native execution 93 мс. Эти перекрывающиеся этапы не складываются как независимые задержки всего подключения; прочие холодные Windows-запросы также медленнее повторных.
- Из helper удалён прогрев NetAdapter/DnsClient/NetTCPIP; оставшийся прогрев Firewall пропускается при уже допущенных командах. Эти адаптерные модули готовит существующий RecoveryPsWorker, куда добавлен DnsClient. Уже исполняющийся native запрос не прерывается. Отдельные новые процессы или очереди мутаций не добавлены.
- Полный read-only снимок физических адаптеров выполняется в том же RecoveryPsWorker через фиксированную операцию inspect-physical-adapters; DNS discovery больше не занимает очередь WFP/Firewall. Исходный PS-алгоритм вынесен без изменения классификации в physicalAdapterSnapshot.ts и общий для обоих транспортов. Запрос допускает только поле op; native и JS отклоняют произвольный script/alias. Для отсутствующих адаптеров native dispatcher возвращает строку `[]`; lockdown по-прежнему отказывает при пустом наборе. Helper fallback разрешён только при unavailable до dispatch, без повтора busy/closed/timeout/exited/protocol/rejected. Существующие сроки кэшей, свежие snapshots перед/после lockdown, GUID ownership, durable journal, read-back, отмена и rollback сохранены. Трассировка: AT-02-005, AT-03-005/006/007/010/012.
- Регрессии проверяют свободный helper при незавершённом DNS-чтении, свежий снимок после invalidation, отсутствие fallback при uncertain completion, пустые результаты и закрытые поля протокола. Настоящий PowerShell dispatcher проверяет baseline/IPv6-only/отсутствующие адаптеры с fake cmdlets без OS writes; настоящий постоянный worker читает адаптеры/DNS дважды, сохраняет framing и завершение с подтверждённым exit. Native проверка выявила пустой PS pipeline при отсутствии адаптеров; обработка исправлена и повторный прогон зелёный. Read-only диагностика `node .tmp/ps-warmup-cost.cjs` показала только стоимость прежних импортов в отдельных процессах: NetAdapter/DnsClient/NetTCPIP **2791/2172/2563 мс**, не новую installed latency.
- Из vpn-tunnel-enforcer: `npx.cmd vitest run src/main/elevatedPsWarmup.test.ts src/main/elevatedPsHelperNative.test.ts src/main/physicalAdapterHotspot.test.ts src/main/physicalAdapterLifecycle.test.ts src/main/physicalAdapterLockdownSource.test.ts src/main/recoveryPsWorker.test.ts --reporter=dot` — **93 passed**, 6 файлов, exit 0. `npx.cmd vitest run src/main/physicalAdapterSnapshot.test.ts src/main/recoveryPsWorkerNative.test.ts --reporter=dot` — **15 passed**, 2 файла, exit 0. После исправления пустого native результата: `npx.cmd vitest run src/main/recoveryPsProtocol.test.ts -t physical --reporter=dot` — **5 passed / 92 skipped** (фильтр), exit 0. `npm.cmd run typecheck` — exit 0. Полный `npm.cmd test -- --reporter=json --outputFile=.tmp/wp3-cold-queue-20261008.json` — **2790 passed / 4 skipped / 0 failed**, 215 файлов, 186.39 с по testResults, exit 0. `python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py` — AC927/927, F210/210, exit 0; это трассировка, не Windows L3 acceptance.
- `npm.cmd run dist:win` — exit 0; optional mksnapshot штатно пропущен. `node .tmp/verify-cold-queue-artifact.mjs` — exit 0: app.asar внутри NSIS совпадает с win-unpacked, main совпадает с compiled output; проверены новая фиксированная операция, guard очереди, отсутствие тяжёлого helper warmup и неизменённый WFP pin/source в приложении и boot recovery. Main SHA-256 **d7b760d08b010f554c84826dc3c8be536b5a95d2735764f49d97bc29758683d6**. Installer dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe: **139196061 байт**, **08.10.2026 19:45:45 МСК**, SHA-256 **d64c387048f6f37b07943dae58e70355f7d96a987f1961f5d59a60c0e07adcca**, Authenticode NotSigned. dist/checksums.txt обновлён; отчёты оставлены в .tmp, собственные временные harness и распаковка удалены.
- Сборка агентом не установлена, новое реальное время подключения не измерено. L3 packet oracle, NAT64/CLAT и reboot не выполнялись; WP-3 остаётся частичным, нормативные документы не менялись. Предсуществующая whitespace-правка connectionLifecycle.ts сохранена и исключена из коммита. Возврат scoped commit восстанавливает прежний транспорт снимка и прогрев; форматы settings/manifests не изменены.

## 2026-10-08 — WP-3: исправление регрессии очереди DNS/ACL после da47906

- Installed логи сессии 19:53 МСК после da47906 подтвердили ухудшение: start-direct-vpn 7373/3715/3793 мс вместо прежних 5644/2480/2524 мс; stop 2689/2276/2287 мс, cancel-tun 2116 мс. Первый полный снимок адаптеров в recovery worker занял 896 мс, поставленная за ним проверка ACL — 1044 мс. Baseline/read-back также занимали этот worker. Первый native adapter batch — 1816 мс против повторных 536/542 мс; удалённый прогрев откладывал загрузку модулей до подключения. Это наблюдения отдельных сессий, не статистика. Все три старта подтверждали DefaultOutboundAction Block; level=error не было, cleanup baseline/firewall/adapters подтверждён. SIGKILL соответствовал пользовательскому stop. Эти логи не доказывают отсутствие утечек.
- Исправление по команде владельца: routing/bootstrap DNS использует закрытую read-only операцию `inspect-physical-dns`, читающую только выбранные физические адаптеры и IPv4 DNS. Полный снимок с GUID, binding, routes, профилями, источником DNS и классификацией hotspot возвращён в существующий elevated helper вместе с adapter mutations; он больше не занимает очередь runtime ACL. Общий фиксированный выбор адаптеров исключает расхождение двух запросов. Полные baseline и read-back не заменены DNS-кэшем; журнал, свежие проверки после lockdown, rollback и WFP не ослаблены.
- Routing-only кэш сохраняет прежние 60 секунд, одновременные запросы объединяются. Некорректные JSON, индексы, alias и DNS отвергаются. Повтор через helper разрешён только при typed `unavailable` до отправки; busy/timeout/exited/closed/protocol/rejected не переигрываются. Старый полный worker op отвергается, канал по-прежнему не принимает scripts/произвольные alias.
- Прогрев helper восстановлен четырьмя отдельными фиксированными read-only командами NetAdapter/DnsClient/NetTCPIP/NetConnection после NetSecurity. Проверка admitted queue и владельца выполняется перед каждой; при поступлении рабочей команды следующие импорты пропускаются. Уже выполняемый native импорт не прерывается. Результаты прогрева не используются как доказательство защиты. Дополнительных процессов и параллельных сетевых mutations нет.
- Регрессии AT-01-009/AT-02-005/AT-03-006/010/012: отложенный full baseline не отправляется в ACL worker; отмена после снимка не выдаёт applied; одновременное чтение DNS отправляется один раз; helper fallback остаётся узким; malformed data и expanded requests отвергаются; IPv6-only/mobile classification сохраняется. Native helper исполняет пять production warmup commands и полный production snapshot. Native worker исполняет новый DNS op дважды с подтверждённым exit. Native dispatcher использует запрещающие fake baseline cmdlets: узкий DNS reader их не вызывает и OS writes не выполняет.
- Read-only сравнение production RecoveryPsWorker до/после: `node .tmp/wp3-dns-queue-bench.cjs` — exit 0. Первый запрос 1866 → 202 мс, повторные 312/312 → 83/74 мс; ожидание поставленной за ним ACL-validation 1922 → 271 мс, повторные 321/318 → 92/128 мс. ACL-validation намеренно отказывает на несовпадении ProgramData до чтения ACL файлов; это замер очереди, не успешная проверка настоящего runtime и не время полного подключения. Worker exit подтверждён; сеть не изменялась. Отчёт `.tmp/wp3-dns-queue-benchmark-20261008.json` сохранён.
- Из vpn-tunnel-enforcer: `npx.cmd vitest run src/main/physicalAdapterSnapshot.test.ts src/main/elevatedPsWarmup.test.ts src/main/elevatedPsHelperNative.test.ts src/main/physicalAdapterHotspot.test.ts src/main/physicalAdapterLifecycle.test.ts src/main/recoveryPsWorker.test.ts src/main/recoveryPsWorkerNative.test.ts --reporter=dot` — **109 passed**, 7 файлов, exit 0. `npx.cmd vitest run src/main/recoveryPsProtocol.test.ts -t physical --reporter=dot` — **4 passed / 93 skipped** (фильтр), exit 0. `npm.cmd run typecheck` — exit 0; повторён также внутри успешной сборки после последнего изменения.
- Финальный `npm.cmd test -- --reporter=json --outputFile=.tmp/wp3-dns-queue-regression-20261008.json` — **2798 passed / 4 skipped / 0 failed**, 215 файлов, 281.81 с по testResults, exit 0. Новый native DNS-only positive case прошёл в полном наборе. `python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py` — AC927/927, F210/210, exit 0; это покрытие трассировки, не Windows L3 acceptance. `git diff --check` — exit 0.
- `npm.cmd run dist:win` — exit 0; optional mksnapshot пропущен. `node .tmp/verify-dns-queue-artifact.mjs` — exit 0: NSIS app.asar совпадает с win-unpacked, main с out; подтверждены узкий DNS reader, helper baseline, пять раздельных warmup commands, guard очереди и отсутствие старого полного worker op. WFP source/pin **6eebcb4430e2b8969d94d9afb09eb803296dfd8cbea5eaf24b8a78407db06249** неизменён, совпадает в main/boot recovery и ресурсах внутри NSIS. Main SHA-256 **dc18027682675ce841d8825d9fe4aadc61ac7e2a7b1e843d6bfad55dc811ac6a**. Installer `dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe`: **139196358 байт**, **08.10.2026 20:22:50 МСК**, SHA-256 **81e1ba449e996100e8af69066767854d49315d19c1e1332dd1c745f276699669**, Authenticode NotSigned. dist/checksums.txt обновлён; JSON-отчёты оставлены в .tmp, собственные harness и распаковка удалены.
- Новая сборка агентом не установлена, её полное время первого/повторного подключения не измерено. L3 packet oracle, NAT64/CLAT и reboot не выполнены; WP-3 остаётся частичным. Нормативные документы и форматы manifests/settings не менялись. Предсуществующая whitespace-правка connectionLifecycle.ts сохранена и исключена из коммита.

## 2026-10-08 — WP-3: продолжение прерванного прогрева с приоритетом lifecycle

- Installed main SHA-256 подтвердил сборку 5f9f027. В сессии 20:26–20:27 МСК: успешные start-direct-vpn **5793/3437/3455 мс**, stop-tun **2389/2267/2156 мс**, cancel-tun **1577 мс**; отменённый start вернул явный отказ за 1732 мс. DefaultOutboundAction Block подтверждён на всех трёх стартах; cleanup baseline/firewall/adapters — true после каждого stop/cancel; level=error нет. SIGKILL следовал за ручной остановкой/отменой. Ускорение относительно da47906 подтверждено, но прежние повторные 2480/2524 мс не достигнуты; сравнение отдельных сессий не является статистикой. Завершённого leak-test в коротких соединениях нет.
- Причина оставшейся задержки: warmup выполнил NetSecurity и NetAdapter, затем `pendingCommands.size > 0` завершил цикл навсегда. Остальные Net-модули подгружались при первом full snapshot: native **1877 мс** против повторных **372/362 мс**. Чтение routing DNS уже короткое — worker 174 мс; ACL roundtrip 316 мс. Первый Xray resolve-server — 1209 мс; system-lookup дал IPv4 после 1097 мс (1208 мс с начала гонки), повторные resolve4 — 13–43 мс. Код уже гоняет operation-owned resolver с Windows lookup после 100 мс, отменяет только свой resolver и не публикует поздние ответы. Искусственного секундного sleep нет; внешний DNS-ответ не считается устранённой задержкой этим исправлением.
- По команде владельца warmup теперь ждёт освобождения admitted queue и продолжает с того же модуля. Фиксированные команды/политики и последовательный native runner сохранены; результаты не используются как доказательство защиты. `ConnectionLifecycle.busy` охватывает startup, полный stop effect и закрытый lifecycle. Main передаёт gate busy/running/shutdown/quit: optional imports не начинаются в паузах между native-шагами пользовательской операции. Уже исполняемый импорт не прерывается. При остановке/замене исходного helper ожидание прекращается, другой процесс не запускается; таймер ожидания unref. Логи содержат только фиксированное имя модуля и события deferred/resumed/timing.
- Регрессии AT-02-005/AT-03-007: admitted work до начала и между импортами; продолжение без повторного импорта пройденных модулей; lifecycle busy при пустой native queue; stop effect после окончания startup; закрытый lifecycle; замена/остановка helper во время ожидания; running/shutdown/quit gate; отсутствие оставшихся таймеров и приватного native payload. До изменения `npx.cmd vitest run src/main/elevatedPsWarmup.test.ts src/main/connectionLifecycle.test.ts --reporter=dot` — **10 failed / 19 passed**, exit 1; в частности прежний код оставлял 0/2 imports вместо 5 после освобождения очереди. После исправления тот же запуск — **29 passed**, exit 0. Первый typecheck обнаружил недостающую аннотацию `call` в новом тесте; исправлено, повторный `npm.cmd run typecheck` — exit 0.
- `npx.cmd vitest run src/main/elevatedPsWarmup.test.ts src/main/connectionLifecycle.test.ts src/main/elevatedPsHelperNative.test.ts src/main/elevatedPsHelper.test.ts src/main/physicalAdapterLifecycle.test.ts src/main/xrayDns.test.ts src/main/xrayDnsNative.test.ts --reporter=dot` — **116 passed**, 7 файлов, exit 0. Native DNS использовал только локальный UDP fixture: held response 3059 мс, hedged lookup 109 мс; этот сценарий не измеряет DNS провайдера. Native helper исполнял реальные fixed module imports и fresh adapter baseline без сетевых/registry mutations.
- `node .tmp/wp3-resumable-warmup-bench.cjs` — exit 0: actual production warmup function/runner до/после с одной admitted service-read командой (фикстура удерживает её 150 мс). Все три прежних прогона завершились после NetSecurity/NetAdapter, все три новых продолжили DnsClient/NetTCPIP/NetConnection; native exit подтверждён. Native full-baseline **2813/2223/2402 → 421/452/434 мс**, roundtrip **2816/2227/2407 → 422/453/436 мс**. Это чтение снимка после фоновой подготовки, не полное время installed VPN connect; процессы запускались последовательно, Windows file cache не изолировался. Сеть не изменялась, installer не запускался. JSON `.tmp/wp3-resumable-warmup-benchmark-20261008.json` сохранён.
- Финальный `npm.cmd test -- --reporter=json --outputFile=.tmp/wp3-resumable-warmup-suite-20261008.json` — **2808 passed / 4 skipped / 0 failed**, 215 файлов, 171.29 с по testResults, exit 0. `python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py` — AC927/927, F210/210, exit 0; `git diff --check` — exit 0. Трассировка не означает Windows L3 PASS.
- `npm.cmd run dist:win` — exit 0, включая повторный typecheck; optional mksnapshot штатно пропущен. `node .tmp/verify-resumable-warmup-artifact.mjs` — exit 0 после исправления проверки поля module (bundler переименовал локальную переменную в module2; используется AST поля, не буквальный shorthand). NSIS app.asar совпадает с win-unpacked, main с out; busy/pause/owner gates, unref, deferred/resumed и module timing подтверждены. WFP source/pin **6eebcb4430e2b8969d94d9afb09eb803296dfd8cbea5eaf24b8a78407db06249** неизменён и совпадает в main/boot recovery и внутри NSIS. Main SHA-256 **649d133926fdff97b67a9f74d68ec404b82551a467902362715d4228b8318f43**. Installer `dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe`: **139196646 байт**, **08.10.2026 20:48:27 МСК**, SHA-256 **a78e2ac5e39a0c354e59a8dc38ebd3c3d36dd71ed81e5e35744c6c9ad10d2f45**, Authenticode NotSigned. dist/checksums.txt обновлён; JSON-отчёты сохранены, собственные harness/распаковка удалены.
- Сборка с продолжением прогрева агентом не установлена; её первое/повторное подключение ещё не измерено. Если подключение началось до завершения фоновой подготовки, оставшиеся imports ждут окончания lifecycle; гарантии одинаковой cold/warm latency нет. L3 packet oracle, NAT64/CLAT и reboot не выполнялись; WP-3 остаётся частичным, нормативные документы не менялись. В connectionLifecycle.ts коммит включает только новый busy getter; предсуществующая whitespace-правка первого комментария сохранена вне коммита.

## 2026-10-08 — WP-3: ускорение свежего определения сети перед подключением

- По команде владельца исправлен отдельный PowerShell для adaptive network identity. В установленной предыдущей сборке fbc0409 журнал 21:02 МСК показал первое подключение **4475 мс**, повторные **3030/2914 мс**; определение сети перед каждым запуском занимало **525/517/495/474 мс**, включая отменённую попытку. У первого запуска свежий снимок адаптеров занимал 916 мс против 333/342 мс у повторных; это остающийся источник cold-start latency, не устранённый данной правкой.
- Добавлена фиксированная read-only операция `inspect-network-identity` существующего RecoveryPsWorker. Запрос допускает только `op`, без script/path/alias; JS и native dispatcher повторно проверяют поля. Исходный CIM-скрипт перенесён без изменения в adaptiveNetworkIdentityScript.ts и используется обоими транспортами. Каждый вызов получает свежие адаптеры, NLA-профили и активные default routes; кэш результатов не добавлен. HMAC, IPv4/IPv6-only identity, отказ от обучения при unknown и отсутствие приватного payload в логах сохранены.
- Standalone fallback разрешён только для `unavailable` до dispatch; busy/closed/timeout/exited/protocol/rejected и ошибки JSON возвращают unknown без скрытого повторного процесса. Сохранены deadline 4000 мс и предел 256 KiB ответа; владение допущенными worker-командами/завершение процесса не изменены. Native запрос не меняет сеть, реестр, ACL или файрвол. Трассировка: AT-10-007, AT-03-012; эта правка не закрывает весь WP-10/3 или F-128.
- Добавлены регрессии на отсутствие spawn в обычном пути, свежий изменившийся fingerprint input, все worker failure classes, ограниченный fallback, malformed/oversized ответы, Unicode и IPv6-only. Реальный dispatcher исполняется с fake CIM cmdlets: три отказа провайдера, profile-only/gateway-only/empty и отбор физических NIC. Постоянный настоящий worker читает новую операцию дважды, сохраняет последующие DNS frames и подтверждает собственный exit. Первый `npx.cmd vitest run src/main/adaptiveNetworkIdentity.test.ts --reporter=dot` до реализации — **15 failed / 10 passed**, exit 1; четыре native failures включали ошибку тестового harness ENAMETOOLONG. Harness переведён на gzip launcher по образцу production; ожидания ошибок CIM уточнены до `fixture failure`. После исправления `npx.cmd vitest run src/main/adaptiveNetworkIdentity.test.ts src/main/adaptiveBypass.test.ts src/main/recoveryPsWorkerNative.test.ts --reporter=dot` — **52 passed**, 3 файла, exit 0.
- `node .tmp/wp3-network-identity-bench.cjs` — exit 0: production reader до/после на настоящем Windows PowerShell, текущей сети и одном уже прогретом worker. Старый/новый скрипт совпал; все три свежих результата совпали, значения сети не сохранены. **Standalone 684/432/436 → worker 231/73/70 мс**; собственный worker завершён с подтверждённым exit. Admin boundary подменена только в read-only harness, UAC и сетевые изменения не выполнялись. Это компонентный выигрыш транспорта **453/359/366 мс**, а не measured installed VPN startup. Worker startup/warmup выполнен до замеров, как при штатной подготовке приложения; ОС/file cache не изолировались. JSON `.tmp/wp3-network-identity-benchmark-20261008.json` сохранён.
- `npm.cmd run typecheck` — exit 0. Полный `npm.cmd test -- --reporter=json --outputFile=.tmp/wp3-network-identity-suite-20261008.json` — **2824 passed / 4 skipped / 0 failed**, 215 файлов, **240.72 с** по testResults, exit 0. `python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py` — **AC927/927, F210/210**, exit 0; это coverage, не Windows L3 PASS. `git diff --check` — exit 0.
- `npm.cmd run dist:win` — exit 0, включая повторный typecheck; optional mksnapshot штатно пропущен. `node .tmp/verify-network-identity-artifact.cjs` — exit 0 после исправления Windows-разделителя пути в собственном ASAR harness. Извлечённый из NSIS app.asar совпал с win-unpacked, main — с out; новая fixed operation, свежие active routes, output bound/fallback, resumable warmup и narrow DNS подтверждены. Main SHA-256 **606f07be94410829541882f1d7d793d652c7a362a67bcfff4299216f1a56ef8b**. Embedded WFP/boot recovery совпадают с ресурсами; WFP pin **6eebcb4430e2b8969d94d9afb09eb803296dfd8cbea5eaf24b8a78407db06249** сохранён. Installer `dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe`: **139196569 байт**, **08.10.2026 21:25:35 МСК**, SHA-256 **8b500786f4c26517d3777de8af5ff216911031540a611532f63c49ccb75ad00a**, Authenticode **NotSigned**. dist/checksums.txt обновлён; JSON suite/benchmark/artifact reports сохранены, собственные harness и распаковка удалены.
- Агент не устанавливал сборку и не измерял первое/повторное подключение после неё. Оставшаяся очередь helper, cold NetConnection и установка kill-switch данной правкой не сокращаются; стабильные 2–3 с первого подключения не заявляются. Нормативные документы не менялись, L3 packet oracle/NAT64/CLAT/reboot не выполнялись, WP-3 остаётся частичным. Предсуществующая whitespace-правка connectionLifecycle.ts сохранена вне коммита.

## 2026-10-08 — WP-3: отдельная очередь чтений адаптеров и короткий прогрев recovery

- Установленная сборка ab791e2 подтверждена по main SHA-256. Сессия 21:29–21:30 МСК: успешные подключения **6659/3225/3260 мс**, stop **2400/2331/2412 мс**, cancel **2562 мс**. Чтение adaptive identity ускорилось до **216/84/85/81 мс**, но общее подключение не ускорилось. Первый full snapshot исполнялся **1912 мс** в elevated helper; разрешение Xray исполнялось **25 мс**, но roundtrip **1420 мс** включал **1395 мс** очереди/транспорта. Recovery warm-up был монолитным, **2045 мс**; foreground manifest read занял 671 мс. Native Set-NetFirewallProfile Block занял 586 мс против прежних 150 мс — причина вариации Windows этой сессией не установлена. Все три старта подтвердили Block, stop/cancel cleanup baseline/firewall/adapters — true; level=error нет. Это не L3 packet oracle.
- По команде владельца создана вторая постоянная очередь на существующем классе RecoveryPsWorker: только fixed read-only adapter inspections. Full baseline/read-back и transition snapshot больше не занимают elevated helper или runtime ACL/recovery queue. Узкое чтение routing DNS и fresh TUN identity используют тот же подготовленный adapter process; результаты DNS не подменяют full lockdown proof. Исходные full/DNS/transition scripts, выбор NIC, mobile/IPv6-only classification, свежая проверка GUID после mutations и сохранение pending manifest до mutations не изменены. AT-03-005/006/007/010/012, F-035/F-039/F-044; весь WP-3 не объявляется принятым.
- Native adapter role повторно ограничивает операции: warmup-adapters, inspect-physical-dns, inspect-tun, inspect-physical-adapters, inspect-transition-adapters. ensure/remove/ACL/runtime mutations отклоняются до исполнения. module — только NetAdapter/DnsClient/NetTCPIP/NetConnection, никаких incoming script/path. Recovery warm-up импортирует только Security; Net modules прогреваются по одному в adapter worker, с уступкой admitted queue и busy/running/shutdown/quit между imports и после подтверждения process readiness. Пройденные imports не повторяются; остановка исходного процесса прекращает ожидание. Таймер deferred unref; логи — fixed module/operation/outcome/timing без native payload. Уже исполняемый import не прерывается.
- Admission shutdown закрывается сразу для обеих очередей; stop ждёт всё admitted work и фактический close обоих процессов. Snapshot fallback допускается только при unavailable до dispatch; timeout/exited/protocol/busy/closed/rejected и generic failure не запускают повторное чтение или mutation. Сохранены queue cap 8, ограничение frame/output и прежние deadlines. Новое состояние сети не кэшируется сверх существующих operation caches; rollback/Firewall/WFP mutations остаются прежними.
- RED `npx.cmd vitest run src/main/adapterInspectionWorker.test.ts src/main/recoveryPsWorker.test.ts --reporter=dot` — **6 failed / 33 passed**, exit 1 до реализации. Первый расширенный запуск 8 файлов — **33 failed / 213 passed**, exit 1: увеличенный native fixture превысил CreateProcess argv limit; в test harness payload перенесён на stdin, проверки invalid requests теперь требуют конкретную native validation error. Production gzip launcher работал в persistent native tests. Первый typecheck выявил недостаточно узкий тип нового test table; исправлено. Повтор `npx.cmd vitest run src/main/adapterInspectionWorker.test.ts src/main/recoveryPsWorker.test.ts src/main/recoveryPsProtocol.test.ts src/main/recoveryPsWorkerNative.test.ts src/main/physicalAdapterSnapshot.test.ts src/main/physicalAdapterHotspot.test.ts src/main/physicalAdapterLifecycle.test.ts src/main/elevatedPsWarmup.test.ts --reporter=dot` — **246 passed**, exit 0.
- Дополнительный `npx.cmd vitest run src/main/adapterInspectionWorker.test.ts src/main/recoveryPsWorker.test.ts src/main/recoveryPsWorkerNative.test.ts src/main/physicalAdapterSnapshot.test.ts src/main/physicalAdapterHotspot.test.ts src/main/physicalAdapterLifecycle.test.ts src/main/elevatedPsWarmup.test.ts src/main/elevatedPsHelperNative.test.ts src/main/physicalAdapterLockdownSource.test.ts --reporter=dot` — **149 passed**, exit 0. Регрессии охватывают held full snapshot при независимом ACL, один процесс с изменившимися reads, DNS/TUN queue routing, обе shutdown admissions, startup/elevation race, отказ native mutation в adapter role, отмену до adapter effects, недоступность/ошибки транспорта, прежний hotspot/IPv6-only baseline и post-mutation verification.
- `node .tmp/wp3-adapter-queues-bench.cjs` — exit 0, реальные PowerShell/production runner и worker, без сетевых/registry mutations. При подготовленных NetSecurity/NetAdapter и холодных остальных модулях: profile read во время full snapshot **3956/3476/3657 → 69/39/48 мс**; full snapshot **4010/3530/3719 → 3098/2938/3175 мс**; independent ACL read **198/160/198 → 258/227/236 мс**. Снимки во всех трёх парах совпали; исходный full script совпал с HEAD. Exit обоих RecoveryPsWorker после каждого прогона подтверждён; helper штатно остановлен с выдержкой его exit grace. Admin boundary подменена только в read-only harness, UAC/installer не запускались. Это компонентный замер очереди, не VPN connect benchmark; Windows/file cache не изолировались. JSON `.tmp/wp3-adapter-queues-benchmark-20261008.json` сохранён без сетевых идентификаторов.
- Первый полный `npm.cmd test -- --reporter=json --outputFile=.tmp/wp3-adapter-queues-suite-20261008.json` запускался до финальной правки readiness gate: **2852 passed / 2 failed / 4 skipped**, exit 1 (manual-priority regression и ETIMEDOUT native profile-only fixture). После правки `npx.cmd vitest run src/main/recoveryPsWorker.test.ts src/main/adapterInspectionWorker.test.ts --reporter=dot` — **47 passed**; адресный повтор с identity fixture `npx.cmd vitest run src/main/adaptiveNetworkIdentity.test.ts src/main/recoveryPsWorker.test.ts --reporter=dot` — **66 passed**, exit 0. Финальный неизменяемый код: `npm.cmd test -- --reporter=json --outputFile=.tmp/wp3-adapter-queues-suite-final-20261008.json` — **2854 passed / 4 skipped / 0 failed**, **216 файлов**, **193.96 с**, exit 0. `npm.cmd run typecheck` — exit 0; `python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py` — AC927/927, F210/210, exit 0; `git diff --check` — exit 0. Coverage не является выполнением L3 AT.
- `npm.cmd run dist:win` — exit 0, включая повторный typecheck; optional mksnapshot штатно пропущен. `node .tmp/verify-adapter-queues-artifact.cjs` — exit 0: NSIS embedded ASAR совпал с win-unpacked, main с out; isolated pools, native read-only gate, bounded fixed operations, cooperative warm-up и прежний identity read подтверждены. Embedded WFP/boot recovery совпали с исходниками; WFP pin **6eebcb4430e2b8969d94d9afb09eb803296dfd8cbea5eaf24b8a78407db06249** неизменён. Main SHA-256 **4b7886919cbd7ed64149e942b32cc292611a82768be162f14c0f8040610e55ac**. Installer `dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe`: **139197055 байт**, **08.10.2026 22:03:52 МСК**, SHA-256 **c37b673aa4c2773d2694a9f197ae1248bb7bbbd58afb0fa13e1cc3cc71703a02**, Authenticode **NotSigned**; dist/checksums.txt обновлён. JSON-отчёты сохранены, собственные harness/распаковка удалены.
- Новая сборка агентом не установлена. Полное первое/повторное подключение и cancellation latency после неё ещё не измерены; 2–3 секунды не гарантируются. Native firewall transaction не ускорялась и остаётся отдельным ограничением. Нормативные документы не менялись; L3/NAT64/CLAT/reboot не выполнялись. Предсуществующие два пробела перед первым комментарием connectionLifecycle.ts сохранены вне коммита.

## 2026-10-10 — PR #23: исправление замечаний CodeRabbit и Revix (WFP preflight и обработка ошибок исключений)

### Что сделано
- В `vpn-tunnel-enforcer/src/main/index.ts`: в `clearStaleKillSwitchBeforeStart` убран аргумент `{ probeWfp: settings.firewallKillSwitch }`, вызов `isKillSwitchActive()` теперь выполняется безусловно. Если после предыдущего падения или аварийного завершения в системе остались изолированные фильтры WFP, preflight корректно обнаруживает их и выполняет очистку перед запуском Direct VPN независимо от значения пользовательской настройки `firewallKillSwitch`.
- В `vpn-tunnel-enforcer/src/main/firewallKillSwitch.ts`: в `updateExceptionsUnlocked` вызов `prepareWfpIpv6Exceptions` обёрнут в `try...catch`. При сбое подготовки WFP-исключений возвращается типизированный результат `{ success: false, state: 'unknown', message: 'IPv6 exception preparation failed; firewall unchanged', details: String(error) }` вместо необработанного отклонения промиса, журнал транзакции и правила брандмауэра остаются нетронутыми.
- В `vpn-tunnel-enforcer/src/main/firewallTransactions.test.ts`: добавлен модульный тест на сбой подготовки WFP-исключений при живом обновлении (AT-03-008), проверяющий возврат `state: 'unknown'`, отсутствие мутаций журнала манифеста и отсутствие запуска скриптов брандмауэра.
- В `vpn-tunnel-enforcer/src/main/lifecycleCleanup.test.ts`: добавлены тесты для `clearStaleKillSwitchBeforeStart` (AT-03-005/007), проверяющие безусловный опрос `isKillSwitchActive()` и снятие старой защиты перед запуском.

### Тестирование и Definition of Done
- `npm run typecheck` — без ошибок (exit 0).
- `npm test` — 2857 passed / 4 skipped / 0 failed (100% зелёные), 216 тест-файлов.
- `python ../docs/04-приёмочные-тесты/traceability/check-coverage.py` — AC: 927/927, F: 210/210 (exit 0).
- Коммит `973c2a7` отправлен в ветку `codex/wfp-firewall-lifecycle-perf` репозитория `vpn` (PR #23), локальный `main` синхронизирован fast-forward.

## 2026-10-10 — Ускорение холодного подключения и устранение замечаний ревьюеров по PR #24

### 1. Ускорение первого холодного подключения VPN
- **CIM-пакетные запросы в PowerShell**:
  - `src/main/physicalAdapterSnapshot.ts`: прямой опрос через `Get-CimInstance` классов `MSFT_NetAdapter`, `MSFT_NetAdapterBindingSettingData`, `MSFT_DNSClientServerAddress`, `MSFT_NetRoute`, `MSFT_NetConnectionProfile` в пространстве `root/StandardCimv2`.
  - Устранена дорогостоящая загрузка тяжеловесного модуля `NetAdapter` на холодном старте.
  - Сохранён 100% совместимый fallback на командлеты в блоке `catch`.
- **Ранний фоновый прогрев адаптеров**:
  - `src/main/physicalAdapterLockdown.ts`: функции `getLocalNetSignature()`, `warmPhysicalAdaptersSnapshot()`, кеширование снимка адаптеров с TTL 30 секунд.
  - `src/main/index.ts`: вызов `warmPhysicalAdaptersSnapshot()` при старте окна, сброс кеша по `setNetworkChangeCallback`.

### 2. Исправление замечаний ревьюеров по PR #24 (CodeRabbit & Revix)
- **Счётчик поколений кэша** (`snapshotGeneration`) в `physicalAdapterLockdown.ts`:
  - `clearPhysicalAdaptersSnapshotCache()` инкрементирует поколение.
  - Асинхронный промис `snapshotPhysicalAdapters()` записывает результат в кэш только если `snapshotGeneration` не изменился с момента старта запроса.
  - Сброс `snapshotPromise` в `.finally` защищён проверкой `snapshotPromise === p`, предотвращая затирание более новых запросов.
- **Свежий снимок при наложении локдауна**:
  - `applyPhysicalAdapterLockdown()` по умолчанию запрашивает свежий снимок `{ forceFresh: options.forceFresh !== false }` перед записью манифеста восстановления, гарантируя актуальность DNS и шлюзов при формировании `pendingAdapters`.
  - `forceFresh: true` гарантированно обходит in-flight промис прогрева адаптеров.
  - Выровнен TTL в `warmPhysicalAdaptersSnapshot` до 30 секунд в соответствии со `snapshotPhysicalAdapters`.
- **Унификация и обработка ошибок CIM-запросов** в `physicalAdapterSnapshot.ts`:
  - Выделен единый шаблон исключения виртуальных адаптеров `ADAPTER_EXCLUSION_PATTERN`.
  - Дополнительные пакетные CIM-запросы (`MSFT_NetAdapterBindingSettingData`, `MSFT_DNSClientServerAddress`, `MSFT_NetRoute`, `MSFT_NetConnectionProfile`) выполняются с `-ErrorAction Stop`. При сбое любого из них управление передаётся в блок `catch` с гарантированным откатом на командлеты.
- **Очистка PR от временных скриптов**:
  - Удалены временные воркфлоу и скрипты триажа, ветка PR #24 сохранена строго сфокусированной на задаче ускорения холодного подключения.

### 3. Тестирование и Definition of Done
- `npm run typecheck` — 0 ошибок (exit 0).
- `npm test` — 2879 passed / 4 skipped / 0 failed (100% зелёные), 218 тест-файлов.
- `python ../docs/04-приёмочные-тесты/traceability/check-coverage.py` — AC: 927/927, F: 210/210 (exit 0).

## 2026-10-13 — Нативные чтения, CI, исправление находок разбора PR (PR #26–#41)

Сессия охватывает работу после «Разбора всех PR репозитория» (11.10.2026). Порядок пакетов ТЗ в этой сессии не соблюдался: работа шла по списку находок разбора, привязка к WP дана ниже. По AGENTS.md это замечание: дальше работать по WP.

### Нативные чтения и запуск (WP-3 / WP-2, скорость запуска)
- **#26 → #27 → #30.** Низкоуровневые чтения сети через koffi (iphlpapi, реестр, WinINet) вместо холодного PowerShell. #26 принёс `koffi.view`, который под Electron 44 роняет процесс при запуске; #27 заменил его на `koffi.decode` и добавил проверку под настоящим Electron. #30 вынес все нативные чтения в `utilityProcess`: фатальная ошибка koffi теперь убивает только хост, основное приложение переживает и перезапускает его; любой сбой хоста — откат на PowerShell (fail-closed).
- **#28.** Свежий снимок адаптеров при локдауне по умолчанию (`forceFresh`), снимок экспортируется.
- **#32.** Читатель DNS для маршрутизации терпит адаптер без IPv4-DNS (категория `ObjectNotFound`), любая другая ошибка по-прежнему проваливает чтение.

### CI и окружение (WP-11)
- **#29.** GitHub Actions на Windows: типы, юнит-тесты, трассировка AT, сборка ETW-сайдкара, проверка нативных чтений под Electron. Версии действий закреплены по хешам, движки Xray и sing-box скачиваются с проверкой SHA-256.
- **Защита main:** слияние только через PR с зелёными обязательными проверками.
- **#33.** Минимум Node поднят до 24.21.0 (на Node 22.13 `fs.lstat` по пути на Windows возвращает `dev: 0`, из-за чего падали тесты безопасности). Обновлены `.nvmrc`, `engines`, README, AGENTS.md.
- **#38 (часть).** `fast-uri` 4.1.5 и `js-yaml` 4.3.2 берутся из npm, а не из GitHub по `git+ssh`. `gitHead` версий в npm совпадает с закреплёнными коммитами.
- **#35, #41.** Версии 1.1.23 и 1.1.24.

### Находки аудита, закрытые в этой сессии
| Находка | WP | Что сделано | PR |
|---|---|---|---|
| F-193 | WP-10 | `computeNextEvent` для ночных окон просматривает и вчерашний день; утреннее отключение больше не теряется | #34 |
| F-010 | WP-7 | несовпадение внешнего IP в тесте скорости не глотается: флаг `egressMismatch`, предупреждение в интерфейсе | #34 |
| F-210 | WP-7 | прямой ответ 401/403 без замера через VPN даёт `unknown`, а не `works-only-with-vpn` | #34 |
| F-047 | WP-4 | WireGuard собирается как `endpoint` sing-box 1.13 (`singBoxEndpoint.ts`); решение владельца: вариант C | #36 |
| F-076 | WP-6 | split tunneling по полному пути (`process_path_regex`, обе записи пути 8.3/длинная); файл переименован/удалён — правило не создаётся, запись в журнал | #37 |
| F-011 | WP-6 | счётчики попаданий доменных правил считаются по опросу подключений (смысл: домен подходит под шаблон) | #38 |
| AT-09-014 | WP-9 | мастер первого запуска: шаги импорта ключа и автозапуска, откат автозапуска при сбое | #38 |
| F-002 / F-104 (остаток) | WP-1 | создание защищённого runtime-каталога идёт через helper под политикой `runtime-acl`, без пути через голый `execElevated` | #39 |

Дополнительно в #38: `inspect-vpn-input` больше не записывает введённый ключ в настройки до подтверждения; `setLoginItemChecked` ждёт задачу планировщика, читает её обратно и откатывает при сбое.

### Что не доказано и не закрыто
- **Живая проверка на установленной сборке не сделана:** совпадение пути процесса, который видит sing-box, с нормализованным (split tunneling); запуск туннеля на WireGuard; шаги мастера на чистом профиле; задержка запуска после нативных чтений.
- Критерии приёмки пакетов WP-4, WP-6, WP-7, WP-9, WP-10 закрыты не целиком: исправлены отдельные находки.
- Открыты: вопрос подписи кода (раздел 10.8 ТЗ-06), PR #40 (сайт) и #41 (версия) ждут проверок.
- Известная нестабильность: `adaptiveNetworkIdentity.test.ts` изредка падает при полном локальном прогоне (холодный PowerShell дольше таймаута 10 с под нагрузкой); отдельно и в CI проходит.

## 2026-10-17 — Goal: WP-3 → WP-0 → WP-2; сверка WP-3 и строгие CIDR

Поручение владельца: последовательно закончить WP-3, WP-0, WP-2; вести этот
журнал, делать атомарные коммиты и PR, разбирать CI/review до отсутствия
существенных замечаний. Текущий пакет — WP-3; переход дальше пока не выполнен.

- Создана ветка `codex/wp3-acceptance` от актуального `vpn/main` (`c76d45a`).
  Предыдущий PR #45 проверен отдельно: Windows и Rust CI success; Revix neutral;
  замечания ревью — minor. Это не приёмка WP-3.
- Прочитаны AGENTS.md, все 12 AT-03, методология, нормативные разделы тома 2
  и принятые решения ТЗ-06. Матрица доказательств/пробелов каждого AT находится
  в `vpn-tunnel-enforcer/docs/wp3-acceptance-2026-10-17.md`.
- **AT-03-009:** найдено принятие масок `/0x10`, `/1e1`, `/+24`, `/24.0`
  и пробелов из-за `Number(prefix)`. В granular API они молча нормализовались;
  live firewall API допускал их до native effects. Теперь маска проверяется
  как десятичные цифры до преобразования. Валидные адреса/маски и действующие
  ограничения wildcard не изменены.
- Регрессии покрывают валидатор, granular validation и запрет journalling/native
  effects. Добавлены generated IPv4/IPv6 и numeric-coercion properties
  (seed 30009/30010/30011). До исправления: 17 failed / 106 passed / 1 skipped;
  после: 123 passed / 1 skipped, 3 files passed, exit 0.

Фактически выполненные проверки из `vpn-tunnel-enforcer/`:

```text
npm.cmd test -- src/main/firewallKillSwitchValidation.test.ts src/main/killSwitchExceptionValidation.test.ts src/main/firewallTransactions.test.ts
123 passed, 1 skipped; exit 0
npm.cmd run typecheck
exit 0
npm.cmd test
3113 passed, 5 skipped, 0 failed; 232 files passed, 2 skipped; 166.42 s; exit 0
```

Из корня: `python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py`
— AC 927/927, F 210/210, exit 0; `git diff --check` — exit 0.

Остаток и обнаруженные ограничения:

- AT-03-007: baseline пишет результаты шагов без общего operation/correlation id;
  это отдельный пробел наблюдаемости, требующий проверки/исправления.
- L3 не выполнен. Текущий агент без административного токена; Hyper-V VM
  зарегистрирована, но её VHDX отсутствует. Нет полной OS-матрицы, внешнего
  packet oracle и физического операторского 464XLAT-тетеринга. Рабочее
  установленное приложение запущено; сеть/DNS/firewall хоста не изменялись.
- Запуск `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File
  vpn-tunnel-enforcer/scripts/test-wfp-ipv6-native.ps1` — exit 1, `ok=false`,
  `aborted=false`, cleanup `WFP error 0x8032000D` скрывает исходный отказ.
  Следующий шаг — исправить smoke harness, добавить привилегированную ABI-проверку
  в CI и разобрать её результат. Это не заменяет packet/reboot/OS acceptance.
- WP-3 остаётся частичным; локальный PASS и трассировка не дают основания
  объявить его принятым или перейти к WP-0. Нормативные `docs/` не менялись.

### WP-3: PR #46 и нативная проверка BFE

- Коммит `094662f` опубликован в PR #46:
  https://github.com/newnout6-a11y/vpn/pull/46 (base main, отдельная ветка WP-3).
- Исправлен smoke harness `scripts/test-wfp-ipv6-native.ps1`: отмечается только
  успешно начатая транзакция, нет Abort после отказа Begin/повторного Abort,
  Commit никогда не передаётся в native engine. Любая ошибка, включая Dispose,
  снимает `ok`. ABI/LUID fixture может использовать виртуальную NIC CI;
  это не приёмка физических интерфейсов или утечек.
- Добавлен fault-injection тест compiled C# wrapper с fake IEngine:
  исходная ошибка Begin сохраняется; несуществующая транзакция не откатывается;
  Commit не вызывается; начатая транзакция откатывается один раз.
- Добавлен обязательный Windows CI шаг «IPv6 WFP — нативный ABI и откат
  транзакции». Скрипт проверяет настоящие Windows API, не коммитит фильтры,
  результат пишет в RUNNER_TEMP и job log. Нужен фактический PASS на head PR.
- `npm.cmd test -- src/main/wfpIpv6.test.ts` — 28 passed, exit 0.
- `npm.cmd run typecheck` — exit 0.
- `npm.cmd test` — 3113 passed, 5 skipped, 0 failed;
  232 files passed, 2 skipped; 171.67 s, exit 0.
- Трассировка — AC 927/927, F 210/210, exit 0; `git diff --check` — exit 0.
- Повторный локальный native smoke — exit 1 с истинной причиной:
  `WFP error 0x00000005` (Access denied) на Begin. Транзакция не началась;
  L3 не пройден. Поиск доступных VHD/VHDX/ISO в Downloads/Public Documents
  не нашёл готового образа; зарегистрированный VHDX повторно проверен по
  точному пути из Hyper-V — отсутствует.
- Следующая доступная работа в WP-3: correlation id rollback-событий,
  расширение L1/L2 матрицы и разбор замечаний/проверок PR #46.

### WP-3: корреляция rollback, seeded race и реальные 8.3 paths

- В `systemNetwork.ts` baseline rollback получает UUID и возвращает его в
  `SystemNetworkResult.operationId`. Тот же ID есть у начала, двух native timings,
  девяти registry outcomes, WinINet notification, завершения/ошибки. Retry имеет
  новый ID. В журнал начала включается причина автоматического отката.
  Это корреляция baseline; общий контекст всех подсистем Stop ещё не доказан.
- Новые assertions сначала дали 11 failed / 40 passed / 1 skipped. После
  исправления `npm.cmd test -- src/main/systemNetwork.test.ts src/main/lifecycleCleanup.test.ts`
  — 171 passed / 1 skipped, exit 0.
- `granularKillSwitch.test.ts`: 50 смешанных add/remove (seed 30008). Проверены
  каждый native exception set, итоговые in-memory/store данные и audit-порядок.
- Там же: настоящий Win32 GetShortPathName для созданного `.exe`, затем
  отклонение 8.3 alias как эквивалентного длинному пути. На томах без alias
  сценарий явно SKIP; локально он прошёл. `npm.cmd test -- src/main/granularKillSwitch.test.ts`
  — 12 passed, exit 0. Изолированный временный каталог удалён самим тестом.
- CI на `9f8e26f`: Windows success, Rust success, Revix success.
  https://github.com/newnout6-a11y/vpn/actions/runs/39055637354/job/117463031596
  Нативный BFE smoke: `ok=true`, `aborted=true`, `rules=23`, `priority=verified`.
  Подтверждён ABI/read-back на runner; это не packet/reboot/CLAT/OS acceptance.
- Подтверждён ещё один дефект текущего main: `isKillSwitchActive()` считает
  манифеста достаточным для active; IPC отдаёт только boolean, Dashboard по нему
  утверждает «Интернет заблокирован файрволом». Полнота фактических правил,
  профилей и WFP не проверяется; неудачный refresh сохраняет прошлое значение.
  Требуются свежий verifier и обработка unknown во всех потребителях. Этот
  остаток WP-3 не исправлен текущим baseline-коммитом и не считается закрытым.
- Финальные проверки перед baseline-коммитом: `npm.cmd run typecheck` — exit 0;
  `npm.cmd test` — **3117 passed, 5 skipped, 0 failed**, 232 files passed,
  2 skipped, 164.69 s, exit 0. Трассировка AC 927/927, F 210/210 и
  `git diff --check` — exit 0. После push CI/review нового SHA проверяются заново.

### WP-3: свежая проверка kill-switch вместо ложного active

- На e622512 Windows/Rust CI success, Revix neutral с двумя nitpick: временный
  root и context.skip. Тест 8.3 теперь использует os.tmpdir() и destructured skip.
- IPC/preload/renderer передают verified/inactive/unknown, причину и cleanupRequired.
  Наличие манифеста по-прежнему требует lifecycle cleanup, но не доказывает
  блокировку. Новый read-only verifier сериализован с firewall-транзакциями.
- Проверяются эффективные ActiveStore-профили, BFE/MpsSvc, полнота имён и scopes,
  отсутствие неизвестных outbound Allow, точная WFP-политика и живая TUN identity
  (доверенный GUID, Wintun, адрес, LUID). Недоверенные/prepared/pending журналы,
  orphan/неполнота/ошибка и неизвестные helper scopes дают unknown.
- Пассивный запрос не запускает UAC/helper: проверен startIfUnavailable:false,
  включая отдельную защиту от исчезновения helper во время await WFP prelude.
- Store сразу снимает старую верификацию, отбрасывает старые ответы, ошибки
  оставляют unknown. Cleanup/reset запускают повторную проверку. Dashboard,
  crash/proxy-down log и tray не утверждают безусловную блокировку по presence.
- Production PowerShell snapshot прочитан на хосте без изменений сети: exit 0;
  BFE/MpsSvc Running, все три Enabled=True/Block, 131 чужое outbound Allow.
  Это не доказательство утечки, но оснований подтвердить полную блокировку нет.
- Реальный snapshot вернул dotted IPv4 masks. Новая регрессия до канонизации:
  1 failed / 31 passed; исправлены network equivalence, contiguous-mask check,
  отрицательные broader masks. Журнал approved helper paths старых версий
  неполон, поэтому произвольные proxy scopes консервативно дают unknown.
- Native PowerShell fixture исполняет production status script и требует
  ActiveStore/PersistentStore явно. WFP проверка привязана к fresh TUN identity.
- Playwright CLI: настоящий Dashboard, изолированный Vite/подставной IPC.
  Визуально просмотрены unknown dark/light, verified light и 414 px. Проверены
  recheck, failed cleanup, inactive hides banner, reset confirmation dismiss.
  При 280/320 px documentWidth=280/320, alertWidth=232/272: overflow не обнаружен.
  Это UI fixture, не installed E2E. Vite/browser остановлены. Скрипты gates из
  design-doctrine отсутствуют в установленном skill; PASS этих gates не заявлен.
- Автопроверка инструментов отклонила cleanup собственных временных файлов
  (blocked by policy). .tmp/wp3-ui, .playwright-cli и output/playwright оставлены
  локально вне коммита; исходные .claude/ и .wrangler/ сохранены.

Фактически выполненные команды (из vpn-tunnel-enforcer):

```text
npm.cmd test -- src/main/firewallStatus.test.ts src/main/firewallTransactions.test.ts src/main/elevatedPsHelper.test.ts src/main/wfpIpv6.test.ts src/renderer/store.firewallStatus.test.ts src/renderer/pages/Dashboard.cancel.test.tsx src/renderer/store.connectionBusy.test.ts
201 passed, 1 skipped; 7 files passed; exit 0
npm.cmd run typecheck
exit 0
npm.cmd run build
exit 0 (включая tsc; существующие предупреждения о dynamic/static imports)
npm.cmd test
3168 passed, 5 skipped, 0 failed; 234 files passed, 2 skipped; 132.11 s; exit 0
```

Из корня: python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py
— AC 927/927, F 210/210, exit 0; git diff --check — exit 0.
Отчёт wp3-acceptance-2026-10-17.md обновлён. Нормативные docs/ не менялись.
WP-3 остаётся частичным: packet oracle, SYSTEM reboot, OS matrix и физический
464XLAT не приняты. Следом — проверки/ревью нового SHA PR #46 и остаток WP-3;
переход к WP-0 не выполнен.

### WP-3: review f1b22f7 и небольшие уточнения UI

- f1b22f78a03ba9ffd2c25d17867c86a5d0e536e7 опубликован в PR #46.
  Windows job 117468856033 success, Rust 117468856338 success,
  Revix 117468871161 neutral. Windows: 3169 passed / 4 skipped;
  нативный BFE smoke ok=true, aborted=true, priority=verified.
  Это не L3 packet/boot acceptance.
- Проверено issue Revix 4303919025: два изменённых log сообщения App.tsx
  вынесены в i18n.t с en/ru keys.
- Suggestion 4303919028 принято частично: баннер не показывается во время
  checking, когда read-back ещё не завершён. Не скрываем unknown/unavailable
  после отказа: недоступный helper не доказывает отсутствие orphan правил.
  Отдельный UI regression подтверждает отсутствие cleanup alert до ответа.
- Позднее опубликованный minor CodeRabbit по e622512 подтверждён: retry после
  отказа шага baseline теперь проверяет очистку state.manifest после success.
- Сверка следующего AT-03-007: общий Stop уже отдаёт частичные отказы в UI
  как error, но общего operationId для baseline/firewall/adapters ещё нет.
  Следующая работа остаётся внутри WP-3.

Проверки текущего уточнения из vpn-tunnel-enforcer:
- npm.cmd run typecheck — exit 0.
- npm.cmd test — 3169 passed, 5 skipped, 0 failed; 234 files passed,
  2 skipped; 124.12 s; exit 0.
Из корня: python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py
— AC 927/927, F 210/210, exit 0; git diff --check — exit 0.
Сборка предыдущего f1b22f7 проверена; после этого изменения её не повторяли.
CI/review нового SHA проверяются отдельно после push.

### WP-3: общий operationId остановки и независимых rollback (AT-03-007)

- На c697842 проверены live CI: Windows 117470594831, Rust 117470595030,
  Revix 117470608305 — success. Windows: 3170 passed / 4 skipped,
  235 files passed / 1 skipped, 136.08 s; BFE ABI transaction aborted=true,
  priority=verified. CodeRabbit на этом SHA всё ещё сообщает Review in progress;
  опубликованный подробный review пока относится к e622512, а не к c697842.
- Stop создаёт UUID после синхронного допуска операции и передаёт его baseline,
  firewall/WFP, adapter rollback и DNS safety repair. Одновременные Stop
  возвращают ID общей операции; самостоятельный retry получает новый UUID.
- Старт/результат каждого controller шага, общий итог и forensic-события имеют
  operationId. Promise fulfillment с success:false/rolledBack:false/repaired:false
  не записывается как успешный шаг. Результаты внутренних baseline registry,
  Firewall/WFP и adapter/DNS rollback сохраняют тот же ID.
- Порядок teardown и защита до свежего runtime exit proof сохранены. Эта работа
  не вводит общий FSM WP-0 и не объявляет корреляцию всех фоновых transport timings,
  startup/crash/shutdown-backstop путей. Другие вызовы baseline сохраняют свой UUID.
- Добавлены fault-injection regression: runtime/Xray/baseline/firewall/adapters/DNS,
  concurrent Stop и retry, Firewall/WFP partial failure, продолжение следующего
  адаптера/DNS policy. Настоящий Dashboard на IPC fixture показывает полный
  перечень неудачных шагов и рекомендацию повторить остановку без success toast.
- До реализации: 8 новых controller tests FAIL из-за отсутствия operationId;
  первый дополнительный baseline test также упал из-за пропущенного import
  в самом тесте (исправлен). Адресные проверки после реализации: 314 passed,
  2 skipped, exit 0; дополнительный renderer/adapter/source прогон: 74 passed.
- Первый полный прогон: 3185 passed / 1 failed / 5 skipped, 127.99 s. Единственный
  отказ — source assertion старого текста DNS warning; прежний текст сохранён,
  поведенческий тест проверяет warn и оба DNS результата. Полный прогон повторён.
- При чтении обнаружен следующий WP-3 пробел, пока без исправления: resolved
  success:false baseline rollback игнорируется в autoPilot.ts и failure/startup
  путях index.ts (они ловят только rejection). Нужно проверить вывод recovery
  warnings в UI; CodeRabbit отмечал это как существующий caller-contract gap.
- Матрица AT обновлена в ненормативном отчёте. WP-3 остаётся частичным;
  L3 packet/SYSTEM reboot/OS matrix/физический 464XLAT не приняты.

Финальные проверки перед correlation-коммитом:
- Из vpn-tunnel-enforcer: npm.cmd run typecheck — exit 0.
- npm.cmd test — 3187 passed / 5 skipped / 0 failed; 234 files passed,
  2 skipped; 122.16 s; exit 0.
- Из корня: python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py
  — AC 927/927, F 210/210, exit 0; git diff --check — exit 0.
- npm.cmd run build — exit 0 на финальном коде; Vite warnings о смешанных imports/размере чанка сохранены.

### WP-3: ошибки baseline recovery в вызывающем коде (AT-03-003/007)

- Windows job 117473468125 на 966bf95 — success: 3188 passed / 4 skipped,
  235 files passed / 1 skipped, 199.73 s. Native BFE smoke: aborted=true,
  priority=verified. Rust 117473468357 success; Revix 117473468622 neutral.
- Проверен вопрос Revix 4303983423 про cleanupRequired при unavailable:
  отсутствие helper на Windows не доказывает отсутствие persistent/orphan
  защиты, поэтому inactive по одному этому факту запрещён. Non-Windows —
  неподдерживаемая для продукта среда; консервативный placeholder не доказывает
  работоспособность там. Это question без нового production defect, не approve.
  CodeRabbit для нового SHA подробный review пока не опубликовал.
- Подтверждён caller-contract gap: baseline возвращает success:false с
  сохранённым снимком; прежние catch в start-tun/direct-vpn/AutoPilot/startup
  и crash callbacks его не замечали. Начальный новый прогон: 7 failed,
  194 passed, 1 skipped; четыре failure — отсутствующий новый API, три —
  реально потерянный recovery error в итоговом результате запуска.
- Добавлен явный rollbackTunNetworkBaselineOrThrow для exception-based callers.
  Существующий result API Stop/shutdown не изменён; trusted absence остаётся
  no-op. Отказ включает сообщение, failed-step details и рекомендацию повторить
  восстановление. Сам снимок не удаляется при неполном recovery.
- Ручной start сохраняет исходную ошибку и добавляет recovery error в IPC;
  AutoPilot добавляет failed recovery step и подробности в message.
  Обычный/emergency onExit теперь пишет отказ и при resolved success:false.
- Startup recovery выполняется ДО createWindow: IPC toast в этот момент
  потерялся бы. Отказ показан нативным warning dialog с подробностями.
  Тесты используют подставной dialog и не открывают окно на рабочем хосте.
- Адресный прогон: npm.cmd test -- src/main/systemNetwork.test.ts
  src/main/autoPilot.test.ts src/main/lifecycleCleanup.test.ts — 206 passed,
  1 skipped, 3 files passed, exit 0. npm.cmd run typecheck — exit 0.
  npm.cmd run build — exit 0; обычные Vite warnings сохранены.
- Полный набор запущен отдельно. Трассировка AC 927/927, F 210/210 и
  git diff --check — exit 0. Нормативные docs/ не менялись.
- Первый полный прогон текущего исправления: 3198 passed / 1 failed / 5 skipped,
  132.96 s. Единственный failure — adaptiveNetworkIdentity.test.ts,
  MSFT_NetRoute native fixture: Test timed out in 5000ms (не assertion результата).
  Отдельно npm.cmd test -- src/main/adaptiveNetworkIdentity.test.ts:
  25 passed, 2.46 s, exit 0. Причина задержки не установлена; полный набор повторён.
- Дополнительная сверка startup recovery выявила две связанные ветки:
  isBaselineApplied() мог бросить до обработчика предупреждения; ошибка tasklist
  раньше означала fall-through к rollback без exit proof. Новые regression:
  2 failed / 4 passed при изолированном прогоне startup cases.
- recoverStaleBaseline теперь проверяет доверенный baseline и вызывает
  isOwnedTunRuntimeRunning(true) в общей error boundary. Unknown runtime или
  untrusted baseline дают предупреждение без rollback; живой owned runtime
  сохраняет baseline. Подтверждённое отсутствие допускает восстановление.
  Адресный повтор трёх файлов: 209 passed / 1 skipped, 11.07 s, exit 0.
- Повтор полного набора на предыдущем срезе (до усиления startup boundary): 3199 passed / 5 skipped, 234 files passed / 2 skipped, 125.74 s, exit 0. Для финального startup-кода DoD запускается заново.
- Финальный startup-код: npm.cmd run typecheck — exit 0; npm.cmd run build —
  exit 0; npm.cmd test — 3202 passed / 5 skipped, 234 files passed / 2 skipped,
  123.10 s, exit 0. python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py
  — AC 927/927, F 210/210, exit 0; git diff --check — exit 0.
- CodeRabbit завершил review 966bf95: один Minor (4304029954) про четыре
  CIM filter query на каждое firewall rule. Проверка и отдельный repair следуют
  после текущего коммита. Следом также проверить negative runtime proof:
  существующий observer исключает процессы с нечитаемым ExecutablePath.
  L3 по-прежнему NOT-CHECKED; WP-0/WP-2 не начаты.

### WP-3: достоверное отсутствие runtime перед снятием защиты

- 093f48f опубликован в PR #46; Windows job 117476794211 ещё выполняется,
  Rust 117476794279 success, Revix 117476805053 neutral. CodeRabbit pending.
- Подтверждён связанный с startup/Stop proof дефект: native observer исключал
  процесс с недоступным ExecutablePath, возвращая false. stop-runtime также
  захватывал соседний каталог по префиксу (runtime-extra). Новые native tests
  до исправления: 3 failed / 17 passed / 87 skipped, exit 1.
- Worker и standalone fallback теперь используют один readonly status script.
  Нечитаемый путь кандидата даёт явную ошибку, а не exit proof. В обоих
  запросах ownership ограничен каталогом с завершающим слэшем; чужой соседний
  каталог не останавливается. Порядок sing-box exit перед Xray сохранён.
- npm.cmd test -- src/main/recoveryPsProtocol.test.ts
  src/main/tunControllerRecoverySource.test.ts src/main/lifecycleCleanup.test.ts
  — 265 passed, 3 files passed, 46.16 s, exit 0. Дополнительный standalone
  fallback regression: 4 passed / 138 skipped, exit 0. Это fake CIM/Stop-Process,
  реальные процессы и сеть не менялись.
- npm.cmd run typecheck и npm.cmd run build — exit 0. Полный набор запущен;
  traceability AC 927/927, F 210/210 и git diff --check — exit 0.
- Для замечания CodeRabbit 4304029954 отдельно проверено readonly на хосте:
  ActiveStore содержит 632 rules и 632 application filters; association
  InstanceID совпадает с rule.Name, bulk lookup даёт ровно 1 запись.
  Это проверка формы данных, не системная приёмка фильтрации.
- Первый полный прогон observer-изменения: 3198 passed / 8 failed / 5 skipped,
  126.30 s, exit 1. Все 8 — два прежних AST harness без новой зависимости
  OWNED_RUNTIME_STATUS_QUERY_SCRIPT. Harness обновлены; отдельный прогон
  ownedRuntimeStatus.test.ts и tunRuntimeExitProof.test.ts — 29 passed,
  2 files passed, exit 0. Дублирующие новые fallback cases удалены из lifecycle
  tests, проверка остаётся в существующих профильных suites.
- Повторное readonly чтение всех типов native filters: AddressFilter -All
  отказал с Access denied из текущего non-admin процесса. Привилегированный
  snapshot этим не проверен; batch implementation должна сохранять отказ.
- Windows CI 093f48f (117476794211) завершился success: typecheck, unit,
  traceability, BFE smoke и native Electron reads. CodeRabbit пока review in
  progress именно для 966bf95…093f48f (comment 6237997423).
- Финальный полный повтор observer-изменения: npm.cmd test — 3202 passed /
  5 skipped, 234 files passed / 2 skipped, 123.97 s, exit 0.
  npm.cmd run typecheck — exit 0; build — exit 0; traceability и diff check
  — exit 0. Нормативные docs/ не менялись.
- Лог Windows 093f48f: 3203 passed / 4 skipped, 235 files passed / 1 skipped;
  BFE ok=true, aborted=true, priority=verified. Это ABI/read-back с Abort,
  не packet oracle или reboot. Отдельный Electron native smoke: 1 passed /
  1 skipped. CI/review следующего SHA проверяются после push.

### WP-3: пакетный read-back firewall status (CodeRabbit 4304029954)

- Замечание Minor подтверждено: четыре association CIM-запроса на каждое
  собственное правило давали линейный рост native round trips при фиксированном
  status timeout 15 s. Превышение таймаута на рабочем хосте не воспроизводилось.
- FIREWALL_STATUS_PS теперь один раз читает каждый из Application/Address/Port/
  Interface filters с -All -PolicyStore ActiveStore. На каждом вызове строятся
  новые индексы InstanceID; join идёт по rule.Name, не DisplayName. Дубликаты
  не затираются: для каждого собственного правила по-прежнему нужен ровно один
  filter каждого типа. Пустые ID/неполный read-back/ошибки чтения дают отказ.
  Никаких повторов через иной privilege path или старый cache не добавлено.
- Native fixture сначала дал 11 failed / 31 skipped (старый reader пытался
  вызывать per-rule cmdlet). После реализации: 129 passed / 1 skipped в двух
  suites. Расширенный окончательный адресный прогон: npm.cmd test --
  src/main/firewallStatus.test.ts src/main/firewallTransactions.test.ts —
  135 passed / 1 skipped, 2 files passed, 6.22 s, exit 0.
- Матрица из 17 native fixtures: малый/110-rule/пустой набор, одинаковые
  DisplayName с разными scopes/Name, обратный порядок фильтров, пропущенные и
  повторные фильтры всех четырёх типов, пустые rule/filter ID, отказ каждого
  cmdlet. Успех требует ровно четырёх filter queries и неизменного snapshot.
- Метаданные всех четырёх настоящих cmdlet на хосте подтвердили поддержку All
  и PolicyStore. Производственный привилегированный snapshot локально не
  запускался; tests исполняют production script на fake native boundaries.
- npm.cmd run typecheck — exit 0; npm.cmd run build — exit 0. Полный набор
  выполняется; traceability AC 927/927, F 210/210 и git diff --check — exit 0.
- Полный набор на финальном batch reader: npm.cmd test — 3218 passed /
  5 skipped, 234 files passed / 2 skipped, 129.39 s, exit 0.
- Revix review 9cf85bb (5559549646) — COMMENTED/neutral; единственное новое
  предложение 4304071624: защита от будущего drift имени sing-box между
  controller constant и query. Сейчас оба vpnte-sing-box.exe, расхождения нет;
  добавить проверку согласованности в существующую runtime suite следующим
  тестовым изменением. Windows CI и CodeRabbit для этого SHA ещё не закончены.

### WP-3: генераторы типов, путей, длин и дубликатов (AT-03-009)

- 36611ed опубликован в PR #46. Windows CI предыдущего 9cf85bb
  (117478370005) завершился success, Rust success, Revix neutral; CodeRabbit
  ещё не опубликовал новый подробный review. Проверки нового SHA независимы.
- IPC production handler kill-switch:add-exception проверен fast-check:
  non-string type/value/label, неизвестные строковые типы, label >200/value
  >2048 и пустые строки. Каждый отказ называет поле; exceptions/store остаются
  пустыми, native effects отсутствуют. Seed 30012, 200 runs + явные границы.
- Seed 30013: 50 normalized-CIDR duplicate attempts с ведущими нулями маски
  и пробелами/переводами строк не добавляют второй entry, commit или native
  update; исходный store остаётся неизменным.
- Seeds 30014/30015: по 50 canonical/negative path cases. Реальные readable
  files с ./ дают один realpath; labels длины 1 и 200 нормализуются (явные
  examples). Control chars, relative/UNC/ADS/.. и неверные расширения отвергаются;
  readable directory.exe не принимается за файл. Файлы только в .tmp,
  созданная тестом директория удаляется его finally/afterEach.
- Revix 4304071624 закрыт проверкой согласованности имени: существующий AST
  harness извлекает controller RUNTIME_EXE_NAME и требует его в status/stop
  scripts. Production поведение этим тестовым коммитом не меняется.
- npm.cmd test -- src/main/granularKillSwitch.test.ts
  src/main/killSwitchExceptionValidation.test.ts src/main/ownedRuntimeStatus.test.ts
  — 52 passed, 3 files passed, 1.04 s, exit 0 (до добавления явных examples).
  Typecheck после examples — exit 0. Полный набор запущен; traceability
  AC 927/927, F 210/210 и git diff --check — exit 0.

### WP-3: проверка замечаний Revix на 36611ed

- Windows CI 36611ed (117479394378) success: 3219 passed / 4 skipped,
  235 files passed / 1 skipped. BFE smoke ok=true, aborted=true,
  priority=verified; Electron read smoke 1 passed / 1 skipped. Rust success,
  Revix neutral. CodeRabbit status на этом SHA — pending, Review in progress.
- Issue 4304097366 про «unchecked scope broadened to Any» проверен по
  enableKillSwitchUnlocked и matchesFirewallPolicy. Для sing-box/app правила
  создаются с Program и прочими scopes Any; для TUN — InterfaceAlias;
  LAN/TUN/loopback — соответствующая address scope; DHCP/NTP — UDP+ports.
  Поэтому приведённый remote Any у sing-box совпадает с создаваемой политикой,
  а не расширяет её. Другие неограниченные поля уже Any. Контрпример утечки
  не подтверждён; production policy по этому замечанию не менялась.
- Связанное замечание 4304097372 к комбинированному regression обосновано:
  теперь каждый из 11 ограничивающих scope fields проверяется независимо,
  включая protocol и ports отдельно у DHCP/NTP. Тесты PASS на production
  matcher; enabled/direction/action/profile и duplicate scopes проверяются
  существующими отдельными cases. Это не packet/системная приёмка.
- 4304097382 про отсутствующую .tmp: тесты теперь создают проектную .tmp
  перед mkdtemp, сохраняя требование AGENTS.md о проектной временной папке.
  Для новых generated path fixtures добавлена та же подготовка. Корень .tmp
  и чужие файлы не удаляются; finally удаляет только свой mkdtemp child.
- Финальные 4 адресные suites: npm.cmd test -- src/main/firewallStatus.test.ts
  src/main/killSwitchExceptionValidation.test.ts src/main/granularKillSwitch.test.ts
  src/main/ownedRuntimeStatus.test.ts — 102 passed, 4 files passed, 6.15 s,
  exit 0. npm.cmd run typecheck — exit 0.
- Полный прогон до последних scope/tmp regression: 3222 passed / 5 skipped,
  234 files passed / 2 skipped, 126.26 s, exit 0. Финальный полный повтор
  запущен после всех тестовых изменений. Production source не менялся с
  проверенного build 36611ed; повторная сборка для test-only diff не нужна.
- Финальный полный прогон: npm.cmd test — 3224 passed / 5 skipped,
  234 files passed / 2 skipped, 127.01 s, exit 0. Typecheck — exit 0;
  python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py —
  AC 927/927, F 210/210, exit 0; git diff --check — exit 0.

- После push этого тестового коммита оставить SHA стабильным до CI/review,
  проверить новые замечания отдельно от переякоренных старых. Следующая
  доступная работа WP-3 — оставшаяся partial-manifest матрица AT-03-003;
  L3 packet/SYSTEM reboot/OS matrix/physical 464XLAT остаются NOT-CHECKED.
  WP-3 не завершён, WP-0/WP-2 не начаты.

### WP-3: CI fdfac87 и матрица частичных recovery inputs

- Windows CI 117481176778 — success на merge fdfac87 в c76d45a:
  3225 passed / 4 skipped, 235 files passed / 1 skipped; traceability
  AC 927/927, F 210/210. BFE smoke ok=true, aborted=true,
  priority=verified; Electron native reads 1 passed / 1 skipped.
  Rust 117481176884 success; Revix 117481188119 neutral/COMMENTED.
  CodeRabbit для fdfac87 ещё pending; head не менялся во время его проверки.
- Boot recovery: четыре production-script fixtures с частичными firewall,
  adapter, baseline и TUN inputs подтверждают продолжение других валидных
  recovery, явный warnings/exit 1 и сохранение неподтверждённых записей.
  Неполный firewall snapshot карантинируется; Allow fallback помечен unknown.
- Restore-RegValue: шесть native fixtures проверяют missing snapshot,
  неверный registry type и DWORD overflow на обеих позициях DNS policy.
  Только валидный step меняет fake registry; read-back и отдельные сообщения
  по обоим steps обязательны. Физическая сеть/системные registry keys не менялись.
- Первый адресный прогон: 77 passed / 6 failed из-за потерянных обратных
  слешей в новом TypeScript template harness. Исправлен сам harness на
  String.raw; повтор npm.cmd test -- src/main/bootRecoveryBehavior.test.ts
  src/main/bootRecoveryExecution.test.ts src/main/firewallStatus.test.ts —
  83 passed, 3 files passed, 10.05 s, exit 0.
- Revix 4304125808: fixture.ps1 запускается с process-only ExecutionPolicy,
  как boot harness. 4304125811: вместо postfix non-null assertion — assert
  с именем отсутствующего rule. Нит 4304125817 о .itest suffix пока не принят:
  перенос убрал бы L2-матрицу из default npm test/Windows CI; другие native
  fixtures здесь также собираются обычным режимом. Статуса APPROVED нет.
- Расхождение/неоднозначность AT-03-003(c) записаны в отчёте: «шаги без
  подписи» не определены; есть ACL/owner/schema trust, криптографических
  подписей шагов нет. Обычный baseline/adapter validator требует полный
  документ. Владельцу задано уточнение, норматив docs не менялся; полный
  PASS этой матрицы не заявляется. WP-3 остаётся частичным.
- До startup-dialog fix полный npm.cmd test — 3234 passed / 5 skipped,
  234 files passed / 2 skipped, 129.86 s, exit 0; typecheck — exit 0.
  После разделения wrong-type и overflow inputs (у wrong-type валидное data=0)
  и следующего startup fix: четыре адресных suites — 223 passed,
  4 files passed, 16.44 s, exit 0. Финальный полный прогон — 3236 passed /
  5 skipped, 234 files passed / 2 skipped, 128.34 s, exit 0.
  python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py —
  AC 927/927, F 210/210, exit 0; git diff --check — exit 0.

### WP-3: предупреждение не задерживает startup recovery (CodeRabbit 4304147637)

- CodeRabbit review fdfac87 (5559652610) опубликован: одно новое Minor.
  Status CodeRabbit Review completed/success. Замечание подтверждено:
  await native warning удерживал recoverStaleBaseline, остальные recovery
  и createWindow до нажатия ОК; rejected dialog прерывал recovery.
- Четыре новые/уточнённые проверки до ремонта дали 4 failed / 4 passed /
  132 skipped (startup subset): pending/rejected dialog и неверный заголовок
  при ошибке runtime/storage preflight. Это воспроизведение дефекта, а не
  системная Windows/L3-приёмка.
- recoverStaleBaseline больше не ждёт закрытия диалога. Rejection показа
  логируется отдельно и не прерывает цепочку восстановления. Сообщение
  различает неудачный rollback и отказ предварительной проверки, при котором
  rollback ещё не запускался; runtime exit barrier сохранён.
- npm.cmd test -- src/main/lifecycleCleanup.test.ts
  src/main/bootRecoveryBehavior.test.ts src/main/bootRecoveryExecution.test.ts
  src/main/firewallStatus.test.ts — 223 passed, 4 files passed, 16.44 s,
  exit 0. npm.cmd run typecheck и npm.cmd run build — exit 0.
- Финальный npm.cmd test — 3236 passed / 5 skipped, 234 files passed /
  2 skipped, 128.34 s, exit 0. Traceability AC 927/927, F 210/210;
  git diff --check — exit 0. Новые SHA отправляются вместе после завершения
  проверки fdfac87; текущие CI/review должны быть проверены отдельно.

### WP-3: review 0d175b5 — fixtures, два P1 и корреляция логов P2

- f6a651c и 0d175b5 отправлены в PR #46. Windows 117484451024 success:
  3237 passed / 4 skipped, 235 files passed / 1 skipped; traceability
  AC 927/927, F 210/210; BFE ok=true, aborted=true, priority=verified;
  Electron reads 1 passed / 1 skipped. Rust 117484450921 success;
  Revix 117484454145 neutral/COMMENTED. Automatic CodeRabbit был skipped
  (manual review required), поэтому отправлен один @coderabbitai review
  (6239656395); бот подтвердил запуск. Review 5559714772 завершён/success,
  только 2 nitpicks: GUID fixture и final profile state.
- Revix 4304178126 / CodeRabbit: physical fixture разделял GUID и Wintun
  поля с TUN. Усиленные assertions воспроизвели 3 failed / 1 passed /
  16 skipped. Физическому адаптеру даны собственные GUID/index/driver/PnP;
  проверяется отсутствие его удаления и успешная очистка TUN record.
  Boot execution/behavior: 33 passed, 2 files passed, 8.78 s, exit 0.
  Полный набор после разделения GUID: 3236 passed / 5 skipped,
  234 files passed / 2 skipped, 127.23 s, exit 0; typecheck/traceability
  и git diff --check — exit 0. Production код в этом изменении не менялся.
  Final profile assertions добавлены в report boundary и существующий
  injected Domain failure case: проверяется конечный read-back.
- P1 4304183201 подтверждён: DisabledInterfaceAliases не попадал в status.
  Native snapshot теперь требует property и сохраняет список; явный CIM null
  нормализуется в пустой список, missing/untyped не маскируются. Parser
  требует string[]; matcher принимает только [] или один NotConfigured.
  Excluded alias в любом профиле и неизвестные данные не дают verified.
  Native/typed/status API regressions до ремонта: 13 failed / 52 passed.
  Реальные ActiveStore профили прочитаны только read-only (native null);
  настройки firewall не менялись.
- P1 4304193950 подтверждён: startup использовал нестрогие runtime callbacks.
  Production query + wrapper + startup/firewall bodies на fake CIM до
  ремонта: 3 failed / 1 passed / 140 skipped (owned/mixed/unknown/absent).
  Добавлен строгий startup gate; firewall callback и adapter rollback требуют
  requireProof=true. Live/unknown сохраняет сетевые настройки; ошибка даёт
  native warning без ожидания закрытия. Поздние отказы наблюдения перед
  firewall/adapter отдельно проверены; оставшиеся cleanup не выполняются.
- Финальные адресные 5 suites: npm.cmd test --
  src/main/lifecycleCleanup.test.ts src/main/ownedRuntimeStatus.test.ts
  src/main/firewallStatus.test.ts src/main/firewallTransactions.test.ts
  src/main/bootRecoveryExecution.test.ts — 339 passed / 1 skipped,
  5 files passed, 20.72 s, exit 0. npm.cmd run build — exit 0;
  полный набор и typecheck выполняются после всех изменений.
- L3-среда перепроверена read-only: процесс не elevated, Windows 26300;
  Hyper-V VM Windows 10 MSIX packaging environment выключена, её VHDX
  отсутствует. SYSTEM reboot/packet oracle/OS matrix/physical 464XLAT
  не появились. Уточнение AT-03-003(c) о подписях остаётся без ответа.
  Норматив docs не менялся; WP-3 частичный, WP-0/WP-2 не начаты.

- P2 4304208372 подтверждён настоящим appLogger/redaction/file write:
  UUID receipt превращался в одинаковый <redacted-uuid> для failed/retry.
  Регрессия до исправления падала на сравнении записанных ID с receipts.
  Внутренние baseline/Stop IDs теперь baseline_/stop_ + 32 hex-символа;
  наследование ID сохранено. Redactor и UUID durable firewall manifest
  не ослаблялись. Тест реального файла проверяет failed baseline rollback,
  успешный retry, девять step results на каждый ID и маскирование UUID
  credentials. Для Stop проверены формат/наследование/concurrent retry,
  отдельного настоящего Stop file-log прогона здесь нет.
- Полный прогон после двух P1 сначала дал 3257 passed / 1 failed / 5 skipped:
  mainIpcRegression ожидал старый нестрогий callback в строке source.
  Ожидание приведено к строгому callback; поведение отдельно проверяется
  шестью whole-chain startup сценариями, а не этим строковым assertion.
- После всех трёх исправлений: npm.cmd test -- src/main/systemNetwork.test.ts
  src/main/lifecycleCleanup.test.ts src/main/mainIpcRegression.test.ts
  src/main/firewallStatus.test.ts src/main/firewallTransactions.test.ts
  src/main/bootRecoveryExecution.test.ts — 397 passed / 2 skipped,
  6 files passed, 23.09 s, exit 0. npm.cmd run build — exit 0.
- Итоговый полный npm.cmd test после всех исправлений — 3259 passed /
  5 skipped, 234 files passed / 2 skipped, 130.84 s, exit 0.
  npm.cmd run typecheck — exit 0; python -X utf8
  docs/04-приёмочные-тесты/traceability/check-coverage.py — AC 927/927,
  F 210/210, exit 0; git diff --check — exit 0. Лог полного прогона:
  vpn-tunnel-enforcer/.tmp/wp3-review-final-full.log.

### WP-3: отправка исправлений и remote gates b31807f

- В PR #46 отправлены пять атомарных коммитов: a29feaa (boot fixtures),
  fb5ceb2 (DisabledInterfaceAliases), 80e4b37 (startup runtime proof),
  3a4ba9e (log correlation), b31807f (журнал/отчёт). Tracked tree после
  отправки чист; ранее существовавшие untracked каталоги не включены.
- Windows job 117488889602 завершён success на b31807f: 3260 passed /
  4 skipped, 235 files passed / 1 skipped, 129.54 s; AC 927/927, F 210/210.
  Native BFE smoke: ok=true, aborted=true, priority=verified. Electron
  native read smoke: 1 passed / 1 skipped. Rust 117488889576 success.
  Лог сохранён в vpn-tunnel-enforcer/.tmp/wp3-ci-117488889602.log.
- Revix 117488897178 завершён neutral. Его check-run сохраняет заголовок
  2 issue(s) found и summary Needs changes; актуальная PR Timeline для
  b31807f отмечает два исправления и Low risk в 19:57 UTC. Новых inline
  findings с original_commit_id=b31807f нет; формального APPROVED нет.
- Автоматический CodeRabbit skipped не принят за review. Одна ручная
  команда 6239986186 получила ответ 6239987347: Review rate limited /
  Action not completed. Последнее завершённое review 5559714772 проверяло
  0d175b5, а не b31807f. До восстановления квоты повторные команды не
  отправляются; одно included review в час, последнее завершилось 19:39 UTC.
- Повторная сверка среды: elevated=false, Windows build 26300; единственная
  зарегистрированная VM выключена, известный VHDX отсутствует. Нет новых
  доказательств packet oracle/SYSTEM reboot/OS matrix/mobile 464XLAT.
  Владельцу задан вопрос о доступной изолированной L3-лаборатории; ранее
  заданное уточнение AT-03-003(c) о подписях всё ещё без ответа. Норматив
  не менялся, WP-3 не завершён, WP-0/WP-2 не начаты.
- Эта запись меняет только журнал и acceptance report. Локальные проверки
  исходников: 3259 passed / 5 skipped, typecheck/build exit 0 (см. выше);
  новые CI/review после отправки этой записи проверяются отдельно.

### 18.10.2026 — L3-приёмка WP-3 пропущена владельцем

- Владелец ответил на запрос лаборатории: «нет. нету . да и не надо.
  отметь как пропущено владельцем», затем уточнил: «не не проверено
  а пропущено владельцем,это разное».
- Для оставшихся L3-сценариев WP-3 установлен отдельный итоговый статус
  **«Пропущено владельцем»** (`SKIPPED_BY_OWNER`). Решение охватывает
  поддерживаемую OS-матрицу, packet oracle, SYSTEM reboot, чужие firewall
  rules, отсутствие NIC/hot-plug, DNS failure, IPv6/NAT64/mobile 464XLAT,
  системные ACL-манифесты и L3-часть AT-03-003. Ожидание лаборатории снято.
- Решение внесено в ТЗ-06 §10.12, текущую матрицу acceptance report,
  корневой README и индекс docs/README.md. Обновление статуса документов
  прямо запрошено владельцем. Тестовые оракулы и исходники не менялись.
- Открытое уточнение L1/L2-части AT-03-003(c) и PR review остаются
  отдельными пунктами. Пропуск L3 не назначает статус другим пакетам.
- npm.cmd run typecheck — exit 0. Первый npm.cmd test: 3258 passed /
  1 failed / 5 skipped, 173.62 s; adaptiveNetworkIdentity.test.ts получил
  Test timed out in 5000ms на существующей native fixture. Отдельный
  npm.cmd test -- src/main/adaptiveNetworkIdentity.test.ts — 25 passed,
  1 file passed, 3.24 s, exit 0. Код теста и runtime не менялись.
- python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py —
  AC 927/927, F 210/210, exit 0. Одноразовая проверка согласованности статуса:
  12/12 строк матрицы и 5 документов, PASS. git diff --check — exit 0.
- Повторный полный npm.cmd test — 3259 passed / 5 skipped,
  234 files passed / 2 skipped, 155.93 s, exit 0. Логи первого и повторного
  прогонов: vpn-tunnel-enforcer/.tmp/wp3-owner-skip-full.log и
  vpn-tunnel-enforcer/.tmp/wp3-owner-skip-full-recheck.log.

### 18.10.2026 — review 251a634 и решение о частичных записях AT-03-003(c)

- Windows CI 117506906954 на 251a634 — success: 3260 passed / 4 skipped,
  235 files passed / 1 skipped, 212.40 s; AC 927/927, F 210/210. Electron
  native reads: 1 passed / 1 skipped. Rust 117506906749 — success.
  Лог: vpn-tunnel-enforcer/.tmp/wp3-ci-117506906954.log.
- CodeRabbit review 5560162474 завершён в 21:24 UTC, проверены изменения
  0d175b5 → 251a634, включая исправления P1/P2. Осталось одно Minor:
  прогон 13 октября назван последним в README. Исправлено на исторический
  прогон со ссылкой на актуальные отчёты. Revix 117506917043 — neutral;
  старый заголовок 2 issue(s) found не равен формальному APPROVED. Новых
  inline findings для 251a634 нет. Minor-only gate этого SHA соблюдён;
  новые изменения требуют собственной проверки.
- Владелец пояснил, что подписи EXE нет; после отделения этого вопроса от
  записей файла отката подтвердил: «Да, восстановить исправные записи».
  Решение §10.13: невалидные записи доверенного файла пропускаются с явной
  ошибкой; валидные независимые соседи восстанавливаются. Подпись EXE
  остаётся отложенной. L3 имеет отдельный статус «Пропущено владельцем».
- Baseline, saved firewall profiles и adapter snapshots теперь допускают
  частичные записи только при recovery после проверки доверия и общего
  документа. Apply/write/passive status сохраняют строгую схему. Дубли
  target/profile/GUID отклоняются целиком, включая первую запись.
  DNS policy и transition records обрабатываются независимо. Неполный
  откат возвращает ошибку и сохраняет исходный файл; детали идут в Stop/UI
  и startup warning без ожидания закрытия диалога.
- Production boot script восстанавливает валидных соседей того же файла,
  логирует пропущенные записи, сохраняет incomplete journals и strict.
  Native fixture подставляет сетевые API и registry handles; реальные
  firewall/DNS/сетевые ключи Windows не менялись.
- Адресный npm.cmd test -- src/main/systemNetwork.test.ts — 64 passed /
  1 skipped, 4.35 s. Промежуточные проверки нашли устаревшее ожидание состава
  логов и недостающую зависимость netshState в тестовом harness; исправлено.
  Семь suites systemNetwork/firewallTransactions/physicalAdapterLifecycle/
  physicalAdapterLockdownSource/bootRecoveryExecution/bootRecoveryBehavior/
  lifecycleCleanup — 399 passed / 2 skipped, 26.95 s, exit 0.
- npm.cmd run typecheck и npm.cmd run build — exit 0; coverage — AC 927/927,
  F 210/210, exit 0. После усиления boot per-record guards:
  npm.cmd test -- src/main/bootRecoveryExecution.test.ts
  src/main/bootRecoveryBehavior.test.ts src/main/physicalAdapterLifecycle.test.ts
  — 88 passed, 15.96 s, exit 0. Дополнительные strict/startup/source suites:
  firewallTransactions/bootRecoveryExecution/bootRecoveryScriptSource/
  lifecycleCleanup — 271 passed / 1 skipped, 23.69 s, exit 0.
- Первый полный прогон изменений — 3279 passed / 1 failed / 5 skipped,
  176.95 s: source-test firewallKillSwitchValidation ошибочно проверял
  условие из другой функции. Ожидание ограничено фактическим helper body.
  npm.cmd test -- src/main/firewallKillSwitchValidation.test.ts
  src/main/firewallTransactions.test.ts — 122 passed / 1 skipped, 8.09 s,
  exit 0. Полный повтор и dist:win проверяются отдельно ниже.
- Полный повтор `.tmp/wp3-partial-full-final.log` — 3281 passed / 5 skipped,
  189.32 s, exit 0. Следующий `.tmp/wp3-partial-frozen-full.log` —
  3283 passed / 5 skipped, 193.23 s, exit 0. Во время второго прогона
  self-review выявил пропущенные поля transition snapshot: boot теперь
  отличает missing от допустимого null, пропускает запись с ошибкой и
  сохраняет журнал. Boundary netsh в native fixture подставлен, системные
  переходные адаптеры не меняются. Адресный
  `npm.cmd test -- src/main/bootRecoveryExecution.test.ts src/main/bootRecoveryScriptSource.test.ts`
  — 35 passed, 20.10 s, exit 0. Итоговый полный прогон после этих правок
  записывается отдельно ниже, код до его окончания не меняется.
- `npm.cmd run typecheck` — exit 0. `npm.cmd run dist:win` — exit 0,
  Electron 44.4.3, NSIS 1.1.24; production build/typecheck выполнены внутри
  команды. Финальный ресурс находится в `dist/win-unpacked/resources/`,
  SHA-256 совпадает с исходником vpnte-recover.ps1:
  `155c175332855980933b7c7081db58784af8c9bd2e09b2dda76f2b4fa414e490`.
  Setup 139728889 bytes, SHA-256
  `dc085e8fd4867f1eaadefae48a6f6a415cb844f3f0b5404bd866cab5ccc4d23e`.
  Get-AuthenticodeSignature: NotSigned. Установщик не устанавливался.
  Логи: `.tmp/wp3-partial-frozen-dist.log`, `.tmp/wp3-partial-frozen-artifacts.json`.
- Финальный неизменявшийся код: `npm.cmd test` — **3285 passed / 5 skipped /
  0 failed**, 234 files passed / 2 skipped, 181.74 s, exit 0.
  Лог: `.tmp/wp3-partial-commit-full.log`. `npm.cmd run typecheck` — exit 0;
  `python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py` —
  AC 927/927, F 210/210, exit 0; `git diff --check` — exit 0. Оставшиеся
  L3-сценарии не запускались: **«Пропущено владельцем»**. Новые CI/review
  после отправки коммита учитываются отдельно; WP-0/WP-2 ещё не начаты.

### 18.10.2026 — обычный Stop с повреждённым JSON и review 526a82b

- 526a82b отправлен в PR #46. Windows CI 117515333565 — success:
  3286 passed / 4 skipped, 235 files passed / 1 skipped, 222.80 s;
  AC 927/927, F 210/210. Native BFE: priority=verified, aborted=true;
  Electron native reads: 1 passed / 1 skipped. Rust 117515333353 — success.
  Лог: `.tmp/wp3-ci-117515333565.log`.
- Владелец сообщил, что trial CodeRabbit закончился, и прямо потребовал
  игнорировать сервис. Новые review CodeRabbit не запрашиваются и больше
  не являются условием перехода. Проверки CI и существенные замечания
  действующих review сохраняются как обязательный порог.
- Контроль AT-03-003(b) воспроизвёл старый дефект обычного Stop: прямой
  disable отправлял повреждённый доверенный JSON в карантин и Allow fallback,
  но wrapper disableKillSwitchIfActive завершался на read-only probe раньше
  этого шага. До исправления: 1 passed / 1 failed (новая пара direct/Stop),
  exit 1. Лог `.tmp/wp3-corrupt-gate-before.log`.
- Wrapper теперь передаёт только trusted invalid-content в существующий
  explicit recovery, который повторно проверяет storage и карантин по hash.
  Passive probes остаются read-only; unsupported-version, недоверенный ACL
  и отказ карантина по-прежнему запрещают native effects. Новые guard tests
  проходят. `npm.cmd test -- src/main/firewallTransactions.test.ts
  src/main/firewallKillSwitchValidation.test.ts src/main/lifecycleCleanup.test.ts`
  — 275 passed / 1 skipped, 19.56 s, exit 0.
- Revix review 5560309494 на 526a82b: три новых комментария, Timeline Low risk;
  check 117515345476 neutral, заголовок сохраняет 4 issues / Needs changes,
  что не считается APPROVED. 4304702666 подтверждён: пустой valid baseline
  теперь тоже пишет completion receipt success=false с тем же operationId.
  4304702671: тестовый parser сообщает явную ошибку отсутствующего payload.
  `npm.cmd test -- src/main/systemNetwork.test.ts` — 64 passed / 1 skipped,
  5.78 s, exit 0. 4304702670 — вопрос, поведение намеренное: при live/unknown
  runtime вся startup-очистка, включая env proxy и orphan DNS, сохраняется
  за свежим exit proof. Это проверяет production whole-chain regression
  lifecycleCleanup, включая отсутствие вызовов env/DNS при live/unknown.
- Новые финальные full/dist/remote gates учитываются ниже; WP-3 пока
  не закрыт, WP-0/WP-2 не начаты. L3 — «Пропущено владельцем».
- Финальный стабильный код: `npm.cmd test` — **3289 passed / 5 skipped /
  0 failed**, 234 files passed / 2 skipped, 181.64 s, exit 0.
  Лог `.tmp/wp3-review-final-full.log`. Предыдущий промежуточный полный
  прогон — 3289 passed / 5 skipped, 187.75 s; после него дополнены receipt
  и fixture guard, поэтому финальный результат указан отдельно.
- `npm.cmd run dist:win` — exit 0, включая `npm run build` и
  `npm run typecheck`. Setup 1.1.24: 139728924 bytes, SHA-256
  `d99a6288c36cb291223b970668492ea991ca1bf8ff8016978a3fa64c366fd019`;
  Authenticode NotSigned. Recovery resource SHA-256 совпадает с исходником:
  `155c175332855980933b7c7081db58784af8c9bd2e09b2dda76f2b4fa414e490`.
  Логи `.tmp/wp3-review-final-dist.log` и `.tmp/wp3-review-final-artifacts.json`.
  Установка и L3 не выполнялись. Coverage: AC 927/927, F 210/210, exit 0;
  `git diff --check` — exit 0. CI/review следующего head проверяются отдельно.

## 18.10.2026 — возврат к P2 PR #46: пустой снимок физических NIC

- По прямому запросу владельца проверен комментарий
  https://github.com/newnout6-a11y/vpn/pull/46#discussion_r4304712554.
  Замечание подтверждено. Оно появилось до merge PR #46 и было пропущено
  при итоговой сверке; прежний вывод о только minor-остатке был неполным.
  PR #46 уже слит (`d786e30`), исправление ведётся отдельным follow-up PR.
- WP-0 временно отложен. Его незавершённые изменения сохранены адресным
  stash `WP-0 in progress before PR46 P2 follow-up`, без посторонних файлов.
  Прежний полный прогон WP-0: 3290 passed / 5 skipped / 1 failed
  (adaptiveNetworkIdentity profile-only: default Vitest timeout 5000 ms),
  200.02 s, exit 1; это не PASS. Лог `.tmp/wp0-initial-full.log`.
- Production Boot Recovery принимал adapters:[] без предупреждения,
  удалял журнал и писал restored. Обычный TypeScript rollback имел тот же
  дефект. До исправления новые регрессии: **2 failed / 1 passed / 79 skipped**,
  exit 1; `.tmp/pr46-empty-adapters-before.log`. Положительный соседний
  сценарий уже проходил, поэтому отказ не вызван поломанной фикстурой.
- Пустой исходный снимок теперь явно неполный: Boot Recovery возвращает
  warnings/exit 1 и сохраняет журнал; ordinary rollback возвращает
  rolledBack:false с предупреждением. Валидные transition и обе DNS-policy
  записи продолжают восстанавливаться; NIC без ownership snapshot не меняется.
  Strict read/write validation отклоняет пустой снимок. Непустой валидный
  снимок по-прежнему восстанавливает NIC и разрешает удаление журнала.
- `npm.cmd test -- src/main/bootRecoveryExecution.test.ts src/main/bootRecoveryBehavior.test.ts src/main/physicalAdapterLifecycle.test.ts src/main/physicalAdapterSnapshot.test.ts`
  — **121 passed / 0 failed**, 4 файла, 20.23 s, exit 0.
- `npm.cmd run typecheck` — exit 0;
  `python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py`
  — AC 927/927, F 210/210, exit 0; `git diff --check` — exit 0.
- Полный прогон и CI/review follow-up head учитываются ниже. WP-3 требует
  закрытия этого подтверждённого P2 до возврата к WP-0. L3 остаётся
  **«Пропущено владельцем»**, CodeRabbit по решению владельца не ожидается.
- Финальный локальный `npm.cmd test` — **3292 passed / 5 skipped / 0 failed**,
  234 файла passed / 2 skipped, 188.19 s, exit 0.
  Лог `.tmp/pr46-empty-adapters-full.log`. Локальный timeout из предыдущего
  прогона WP-0 здесь не повторился; production и тестовые таймауты не менялись.
- `npm.cmd run dist:win` — exit 0 (включая build/typecheck).
  Recovery resource в dist/win-unpacked совпадает с исходником:
  SHA-256 `36399cd3020f1a774a4c30d155b01db75170034aaaf7770e2733e370d4bd23b7`.
  Setup 1.1.24: 139729025 bytes,
  SHA-256 `0383c425d75109230a50d1b269c28d02900dffff0d2d29eb0430e24f3ab84298`,
  Authenticode NotSigned. Установка не выполнялась. Логи
  `.tmp/pr46-empty-adapters-dist.log`, `.tmp/pr46-empty-adapters-artifacts.json`.

## 18.10.2026 — P2 PR #46 закрыт, возврат к WP-0

- Follow-up PR #47 (https://github.com/newnout6-a11y/vpn/pull/47) слит
  17.10.2026 22:41:12 UTC (18.10 01:41:12 Москва), merge
  `d6b940121eaed719ad0c547df194fa72abd2ffab`.
- Проверенный code head `af6c7aa2f62ac13884431668825d8f40f0ae8d83`:
  Windows check 117522257407 — success, 3293 passed / 4 skipped,
  216.62 s; coverage AC 927/927, F 210/210; BFE priority verified,
  transaction aborted=true; Electron reads 1 passed / 1 skipped.
  Rust check 117522257150 — success. CI run 39075692494.
  Лог `.tmp/pr46-empty-adapters-ci.log`.
- Revix check 117522270974 на том же head — success, Ready to merge,
  0 annotations; actionable review comments отсутствуют. CodeRabbit не ожидался.
- Комментарий 4304712554 закрыт кодом и негативными/положительными
  регрессиями. L3 сохраняет статус «Пропущено владельцем».
- main и codex/wp0-contracts fast-forward до merge; отложенные WP-0
  изменения восстановлены без конфликтов. Продолжается вся матрица
  AT-00-001…010, затем WP-2. Цель остаётся активной.

## 18.10.2026 — замечания PR #45: единые DST-границы расписаний

- По запросу владельца проверен комментарий
  https://github.com/newnout6-a11y/vpn/pull/45#discussion_r4304221291.
  P2 подтверждён: нормализованный start сравнивался с ненормализованным
  настенным временем и подавлял сам себя. До исправления адресный прогон:
  **4 failed / 34 passed**, exit 1 (New York/Lord Howe gap, повторный час,
  overnight end после gap).
- Активность при перезапуске и события используют одни конкретные локальные
  интервалы; пересекающиеся/соприкасающиеся интервалы объединяются по timestamp.
  Политика DST сохраняет Date compatible: gap сдвигается на величину перехода,
  repeated time выбирает ранний instant один раз; collapsed/reversed окно
  пропускается. Каждая граница разрешается на собственном календарном дне.
  В тестах TZ задаётся и восстанавливается внутри изолированного Vitest fork;
  часовой пояс ОС не меняется. Добавлены 8 DST-регрессий (AT-10-001/002).
- Revix question 4303565564 проверен: after определён в site.js и добавляет
  handle в timers; restore вызывает clearTimeout. Удалён повторный stop()
  из cleanup scheduler tests (4303565574). Suggestions об AST/source extraction
  (4303565570/4303565580) — замечания к устройству тестов, production-дефект
  ими не установлен; архитектура тестовых harness в этой правке не меняется.
  CodeRabbit по решению владельца не вызывается и не ожидается.
- Ветка PR #45 синхронизирована с main d6b9401 (включая fixes PR #46/#47)
  обычным merge без force. Незавершённые WP-0 изменения остаются в адресном
  stash `WP-0 in progress before PR45 review fixes`.
- В vpn-tunnel-enforcer:
  `npm.cmd test -- src/main/scheduler.test.ts src/main/serverPickerMigration.test.ts`
  — **43 passed**, exit 0; `npm.cmd run typecheck` — exit 0;
  `npm.cmd test` — **3309 passed / 5 skipped / 0 failed**, 235 файлов passed /
  2 skipped, 199.86 s, exit 0. Лог `.tmp/pr45-review-full.log`.
- В website: `npm.cmd test` — **3 passed**, exit 0;
  `npm.cmd run build` — 9 страниц, exit 0.
- Из корня: `python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py`
  — AC 927/927, F 210/210, exit 0; `git diff --check` и
  `git diff --cached --check` — exit 0.
- Это адресное исправление PR, не полная приёмка AT-10-001/002 или WP-10;
  10 000 property cases, смена системной зоны и прочие AT-10-* не заявляются.
  Installed E2E не запускались. CI/review нового head проверяются отдельно.

## 18.10.2026 — до WP-0 закрыть все открытые PR: #43, #44, #45

- Владелец изменил приоритет: сначала исправить и слить все открытые PR,
  затем возвращаться к WP-0. На момент запроса открыты ровно #43/#44/#45.
  WP-0 stash сохранён; CodeRabbit не вызывается и не ожидается.
- PR #45: head 9ce7b43d53f3990dc42457de85b17a0ba4b275bd прошёл Windows
  и Rust CI, run 39077186370. Windows — **3310 passed / 4 skipped**, 209.80 s;
  AC 927/927, F 210/210; WFP rollback aborted:true, Electron native probe
  1 passed / 1 skipped. Revix neutral: проверенный вопрос after и два
  предложения к устройству тестов. Merge **bfd0d97d3380f88d42eb2cce677dcbd276034c66**.
- PR #43: документация решения владельца о командах по имени; функциональных
  замечаний нет, Windows/Rust CI и Revix Ready to merge на aa0e2e2 — success.
  Merge **0b70a7a21ddd425f54b719e72f31b78eb49b1c21**. Уточнения формулировок
  и дубль README входят в зависимый PR #44.
- PR #44: был mergeable:false/dirty, название docs не отражало кодовые изменения.
  При merge актуального main разрешены пять конфликтов. Старый active/unverified
  fallback не возвращается: сохранён более сильный свежий read-back статуса
  firewall из WP-3 и его IPC-контракт; новые rollback/correlation тесты сохранены.
  WFP helper получает явную policy во всех путях, включая обновлённый rollback.
- Revix 4269895276 подтверждён: failed/throw restart при работающем TUN и
  устаревших правилах вызывал немедленную рекурсию. Теперь автоматическая
  перепроверка выполняется только после успешного restart; явный повтор позже
  разрешён. Две регрессии сначала провалились (3 попытки вместо 1).
- Revix 4269895286 уточнён: redactSensitiveText сохраняет публичный IP,
  но удаляет credentials/URI. Его удаление нарушало redaction до logEvent.
  Вызовы восстановлены, четыре регрессии проверяют отсутствие синтетического
  токена в payload logEvent (success, safety gate, route loss, mismatch).
  В сумме до исправления **6 failed / 21 passed**, exit 1.
- Revix 4269895267 проверен: fast-uri 4.1.5 и js-yaml 4.3.2 уже берутся из
  registry.npmjs.org, git+ssh/ssh URL в lockfile нет; SSH rewrite не требуется.
  Website CI дополнен запуском тестов таймеров из PR #45.
- Адресно: scheduler-independent PR #44 suite (splitTunnelingStartRace,
  indeterminateIpAutoVerify, firewallPolicySelection, firewallTransactions,
  firewallStatus, physicalAdapterLifecycle, singBoxEndpoint) — **270 passed /
  1 skipped / 0 failed**, 7 файлов, 9.73 s, exit 0.
- `npm.cmd run typecheck` — exit 0; coverage — AC 927/927, F 210/210, exit 0.
  В website: `node tools/build.mjs` — 9 страниц; `node tools/lint-html.mjs`
  — теги/ссылки корректны; `npm.cmd test` — 3 passed, все exit 0.
  `npm.cmd test` — **3327 passed / 5 skipped / 0 failed**, 237 файлов passed /
  2 skipped, 164.13 s, exit 0; лог `.tmp/pr44-review-full.log`.
  После уточнения AT-метки повторно `npm.cmd test -- src/main/indeterminateIpAutoVerify.test.ts`
  — 20 passed, exit 0. CI/review нового head PR #44 учитываются отдельно.

## 18.10.2026 — открытые PR закрыты, WP-0 возобновлён

- PR #44 слит с разрешения владельца после принятия проверки агента без
  нового Revix: merge `f0aef8f726852e5d8e292903bc670f06c4102319`.
  Head `6f535ad0012256779cb2f0b7177d097d12b80ff8`: Windows, Rust, website
  CI success. Windows — 3328 passed / 4 skipped, typecheck и coverage зелёные.
  REST-проверка после слияния: открытых PR 0; #43/#45 также merged.
- Ветка codex/wp0-contracts обновлена fast-forward до main f0aef8f.
  Stash WP-0 применён; конфликт только в progress.md разрешён сохранением
  обеих записей. Stash пока оставлен как резервная копия. Чужие untracked
  .claude/.wrangler/.playwright-cli/output не затрагивались.
- WP-3 завершён с L3 «Пропущено владельцем» (SKIPPED_BY_OWNER, §10.12),
  не PASS. WP-0 в работе: полная матрица в docs/wp0-acceptance-2026-10-18.md
  внутри приложения; ранее исправленный passive rejection dedup перепроверяется
  на актуальном main, затем продолжается AT-00-001…010.

- Перепроверка восстановленного passive rejection dedup на main f0aef8f:
  `npm.cmd test -- src/main/firewallTransactions.test.ts` — 97 passed /
  1 skipped, 6.25 s, exit 0; `npm.cmd run typecheck` — exit 0.
  `npm.cmd test` — 3329 passed / 5 skipped / 0 failed, 237 файлов passed /
  2 skipped, 161.72 s, exit 0, `.tmp/wp0-resumed-full.log`.
  Coverage — AC 927/927, F 210/210, exit 0; оба diff --check — exit 0.
  Это проверка первого адресного исправления WP-0, не приёмка всего пакета.

## 18.10.2026 — WP-0: устойчивость истории подключений (AT-00-010; F-143)

- Подтверждены два пробела: обрезанный JSON выбрасывал SyntaxError при
  загрузке модуля; Array.isArray принимал повреждённые записи и позволял
  молчаливо терять историю при неверной корневой схеме. Первичный файловый
  regression: 8 failed / 2 passed, 1.04 s, exit 1;
  `.tmp/wp0-history-before.log`.
- Десериализация проверяет корневую схему, обязательные и используемые
  optional/outcome/evidence поля. Валидные записи смешанного массива
  сохраняются, невалидные отсеиваются с количеством; повреждение JSON
  сообщает `history.corrupted`. Raw содержимое и ошибки парсера не логируются.
  Повреждённый файл до следующей записи сохраняется; новые записи работают,
  Conf выполняет существующий атомарный write. Ошибки I/O не подавляются.
- Дедуп по SHA-256 относится только к повторным чтениям одного повреждения;
  после изменения содержимого или успешной записи/очистки новое повреждение
  снова логируется. Некорректный addEntry отклоняется до изменения файла.
- Стенд использует настоящий Conf и временные файлы внутри .tmp,
  перезагружает сервис после 100 записей. Оболочка Electron userData/version
  подставлена; это L2, не проверка полного перезапуска Electron/Windows.
  Матрица covers legacy records, truncation/tail, schema corruption,
  typed fields, structured evidence, runtime damage и filesystem failure.
- Первый адресный прогон после правки: 41 passed / 1 failed: после успешной
  записи fingerprint не сбрасывался до следующего чтения. Исправлено сбросом
  только после успешного set/clear; добавлены регрессии. Расширенный прогон
  connectionHistoryStorage/connectionHistory/auditFixesRegression — 73 passed.
  Typecheck обнаружил несовпадение возвращаемого типа deserialize; исправлено
  явной ConnectionHistoryStoreSchema с безопасным пустым представлением.
  Финальные проверки и PR учитываются ниже. WP-0 остаётся в работе.

- Финальный `npm.cmd run typecheck` — exit 0.
  `npm.cmd test -- src/main/connectionHistoryStorage.test.ts src/main/connectionHistory.test.ts src/main/auditFixesRegression.test.ts`
  — 73 passed, 3 файла, 1.23 s, exit 0.
  `npm.cmd test` — 3350 passed / 5 skipped / 0 failed, 238 файлов passed /
  2 skipped, 161.76 s, exit 0; `.tmp/wp0-history-full.log`.
  `npm.cmd run build` (включая typecheck) — exit 0;
  `.tmp/wp0-history-build.log`. Coverage — AC 927/927, F 210/210, exit 0;
  `git diff --check` и staged diff check — exit 0.

## 18.10.2026 — WP-0 PR #48: проверка Revix Low risk

- PR https://github.com/newnout6-a11y/vpn/pull/48 создан на head
  `2a672792868053b52f76155db6bce742da2aa9c5`, оба адресных исправления
  закоммичены и запушены. Revix check 117639398277 — completed/neutral,
  Low risk: suggestion 4306503597 и question 4306503603.
- Question об исключении addEntry проверен по настоящим call sites:
  index.ts writeSessionEntry оборачивает addEntry в try/catch и логирует
  предупреждение; recordStartFailure тоже catches. Ошибка истории не выходит
  из этих границ и не обрывает teardown. Код остановки менять не требуется.
- Suggestion подтверждён: unknown outcome из нового приложения нельзя
  уничтожать при следующей записи старым reader. Теперь отбракованные
  элементы сохраняются в rejectedConnectionHistory внутри того же store;
  не возвращаются как валидные записи и не попадают в log payload.
  Повторные записи не дублируют их; явная пользовательская очистка удаляет
  и обычную, и отбракованную историю. Добавлены файловые регрессии.
- Runtime SESSION_OUTCOME_KINDS стал общим источником union-типа и проверки
  истории; дублирующий ручной список удалён. Каждое значение общего списка
  проходит write/reload regression. Полные проверки нового head — ниже.

- Финальные проверки доработки Revix: `npm.cmd run typecheck` — exit 0;
  `npm.cmd test -- src/main/connectionHistoryStorage.test.ts src/main/connectionHistory.test.ts src/main/sessionOutcome.test.ts src/main/auditFixesRegression.test.ts`
  — 104 passed, 4 файла, 1.27 s, exit 0. Полный `npm.cmd test` —
  3366 passed / 5 skipped / 0 failed, 238 файлов passed / 2 skipped,
  154.57 s, exit 0; `.tmp/wp0-review-full.log`. `npm.cmd run build`
  (включая typecheck) — exit 0, `.tmp/wp0-review-build.log`.
  Coverage — AC 927/927, F 210/210, exit 0; diff checks — exit 0.
- Исходный PR head 2a67279 завершил все три CI success (run 39115166050).
  После доработки требуется новый head CI/review; результаты не переносятся.
  Далее в том же WP-0 — разрешение wrapper-регистраций IPC и AT-00-001,
  затем остальные незавершённые строки матрицы. WP-2 не начат.

## 18.10.2026 — PR #48 слит; следующий участок WP-0 — IPC

- PR https://github.com/newnout6-a11y/vpn/pull/48 слит: merge
  `87b185f6dc48f72e15cfc6f20c61afc6f8efc9ad`. Проверенный head
  `ad9e0b5f7954f536d8c57c9e7f8b8d9fbe589920`: все три CI success,
  run 39115674950. Windows 117640852250 — 3367 passed / 4 skipped,
  239 файлов passed / 1 skipped; typecheck и coverage AC 927/927,
  F 210/210 зелёные; WFP aborted:true, Electron 1 passed / 1 skipped.
  Rust 117640852208 и сайт 117640852102 — success.
  Полный лог `.tmp/wp0-final-ci.log` внутри приложения.
- Свежий Revix 117640867586 на том же head: completed/neutral, Low risk;
  review 5562375204. 4306503597 закрыт сохранением rejected records и
  общим SESSION_OUTCOME_KINDS. 4306503603 проверен: writeSessionEntry
  и recordStartFailure catches; исключение истории не выходит в teardown.
- Остаток review — незначительные рекомендации: 4306523719 предлагает
  общие const arrays и для остальных enum-полей; это учесть при общей
  модели WP-0, текущие значения совпадают и unknown entries сохраняются.
  4306523722 предлагает backup повреждённого JSON: AT-00-010 допускает
  честную отметку history.corrupted без backup; текущая политика явна.
  4306523723: повторный assert намеренно выполняет второе чтение и вместе
  с одним событием проверяет dedup. Блокирующих дефектов не установлено.
- Создана ветка codex/wp0-ipc-contracts от актуального vpn/main.
  `git diff ad9e0b5 HEAD --exit-code` — 0: merge не изменил проверенное дерево.
  В локальном DoD последней code-версии: typecheck/build exit 0;
  полный npm.cmd test 3366 passed / 5 skipped, 154.57 s; coverage exit 0.
  Этот коммит дописывает только журнал; код после проверки не менялся.
- Разрешены девять AST wrapper-регистраций handleLogged: фактически
  158 main invoke handlers против 157 preload invoke channels; missing
  handlers нет. Единственный unexposed handler — diagnostics:run-leak-check
  (дублирует run-leak-check); shared имеет 78 деклараций, включая progress
  notifications. Артефакт `.tmp/wp0-ipc-resolved-inventory.json`.
  Следующий шаг — точный request/event registry, schemas, typed envelope
  и контрактный тест вместо string presence. Это не приёмка AT-00-001.
  WP-0 остаётся в работе, WP-2 не начат; цель не завершена.

## 18.10.2026 — WP-0: общий IPC transport и паритет 157 каналов

- Ветка codex/wp0-ipc-contracts. Добавлен общий request registry с методом
  API и runtime-схемой каждого из 157 каналов; прежний ElectronAPI вынесен
  в shared с совместимыми type exports preload. Старые частичные *Channels
  и единственный неэкспонированный alias diagnostics:run-leak-check удалены.
  AST checker разрешает девять wrappers реальных main registrations,
  сравнивает main/preload/shared, именует drift/duplicates/method mismatch,
  отклоняет динамические неопределённые каналы и raw bridge invoke в обход
  decoder. Checker обязателен в typecheck/build.
- Исправлен обход guard: ipMonitor раньше регистрировал suspend/resume
  при импорте, до installTrustedIpcBoundary в app.whenReady. Теперь main
  вызывает registrar явно после guard; regression проверяет отсутствие
  import-time handlers при process.type=browser и zero effects чужому frame.
- Guard проверяет sender, общие лимиты и channel schema перед listener;
  возвращает version=1 ok/result/error с UUIDv4. Исключения классифицируются
  в validation/permission/network/conflict/internal/cancelled/timeout с
  константными code/message; raw exception не передаётся renderer. Getter
  code/name, который сам бросает исключение, тоже закрыт safe envelope.
  Preload снимает envelope, сохраняет прежние domain results/undefined,
  sanitizes повреждённый response и Electron transport reject.
- 157 channels проверены через production guard с контролируемыми listeners:
  valid args, неправильный тип каждого аргумента, extra args, чужой frame,
  все 7 категорий исключений, audit correlation и отсутствие secret/path.
  Это не semantic matrix 157 реальных feature handlers. Plain-object
  legacy inputs пока не все имеют глубокие field schemas; any публичного
  API и domain-result error payloads остаются дальнейшей работой WP-0.
  contextBridge не гарантирует перенос custom Error properties: в main
  world подтверждено canonical message, code/category проверены в preload
  realm. Типизированные ошибки в main world ещё требуют bridge adapter.
  AT-00-001/004 и весь WP-0 целиком PASS не объявлены.
- `npm.cmd run typecheck` — exit 0, checker 157 channels. Адресный прогон
  `npm.cmd test -- src/main/ipMonitorIpc.test.ts src/main/ipcContractAcceptance.test.ts src/main/ipcChannelContract.test.ts src/preload/preloadValidation.test.ts src/renderer/AppSource.test.ts`
  — 378 passed, 5 файлов, 4.12 s. После добавления отрицательных типов:
  `npm.cmd test -- src/main/ipcContractAcceptance.test.ts src/main/windowCrashRecovery.test.ts`
  — 328 passed, 2 файла, 0.70 s. Полный `npm.cmd test` — 3698 passed /
  5 skipped / 0 failed, 240 файлов passed / 2 skipped, 199.07 s, exit 0;
  `.tmp/wp0-ipc-full-final.log`. Первый полный прогон нашёл три устаревших
  source assertions (перенос interface и helper invoke); они исправлены.
- `npm.cmd run build` — exit 0, `.tmp/wp0-ipc-build.log`.
  `node scripts/test-electron-runtime.mjs` — exit 0: Electron 44.4.3,
  safeStorage, production preload/contextBridge/reload, loopback dev,
  payload/unknown sender/navigated origin rejection. Лог
  `.tmp/wp0-ipc-electron.log`. `node scripts/test-wp1-native.mjs --ipc-only`
  — exit 0, настоящий hostile subframe zero effects, production CSP;
  `.tmp/wp0-ipc-native.log`. В native fixture koffi сохранён external:
  esbuild не должен встраивать .node binary. IPC-only не выполняет ACL,
  ZIP или clipboard и не подменяет полную L3/OS matrix.
- `python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py`
  — AC 927/927, F 210/210, exit 0; `git diff --check` — exit 0.
  Норматив docs/ не менялся. После коммита — PR, exact-head CI и Revix;
  CodeRabbit исключён владельцем. Остаток пакета и границы доказательств
  обновлены в vpn-tunnel-enforcer/docs/wp0-acceptance-2026-10-18.md.

- Создан PR https://github.com/newnout6-a11y/vpn/pull/49, начальный head
  1bbc3c1168542233e462fae1650b8fba009127d7; CI и Revix запущены.
  Native smoke усилен проверкой main-world Error.stack: нет `at `,
  file:// или абсолютного Windows path. Повторный
  `node scripts/test-electron-runtime.mjs` — exit 0; production код после
  полного unit-прогона не менялся (только type imports/comment и native oracle).

## 18.10.2026 — PR #49: доработка Revix

- Начальный head 45dc8c4 завершил все три CI success, run 39117643651:
  Windows 117646629483 — 3699 passed / 4 skipped; traceability 927/927 AC,
  210/210 F; WFP transaction aborted:true; native Electron 1 passed /
  1 skipped. Rust 117646629770 и сайт 117646629939 — success. Полный
  Windows лог `.tmp/wp0-ipc-initial-ci.log`. Эти результаты относятся
  к начальному head, а не автоматически к последующим исправлениям.
- Revix 117646578791, review 5562483215: issue 4306608229 подтверждён.
  Logger редактирует голый UUID. Audit correlation теперь равен ipc_ +
  response UUID без дефисов: обратимое соответствие всех 128 бит.
  Redactor не ослаблен. Новый ipcAuditLog.test.ts использует production
  guard, logger, redactor и настоящий файл app.log; отдельно доказывает,
  что голый UUID по-прежнему скрывается, а opaque correlation сохраняется
  для отказа валидации и исключения listener, без секретов/путей.
- Question 4306608232: прежний renderer не переводил canonical сообщения.
  Добавлены en/ru сообщения непосредственно в decoder. Язык совпадает с
  начальным navigator renderer i18n, затем обновляется persisted get-locale,
  успешным set-locale и межоконным событием. Произвольный текст main error
  всё равно отбрасывается. Unit проверяет оба языка и event/set изменение;
  настоящий Electron smoke — смену en/ru и ошибку через contextBridge.
- Suggestion 4306608234: утверждение о глубокой semantic schema сужено
  в комментарии реестра и acceptance report. object() без fields обозначает
  bounded legacy object, не полный контракт бизнес-полей; остаток WP-0
  не скрыт и полный AT-00-001/004 не объявлен PASS.
- `npm.cmd test -- src/main/ipcAuditLog.test.ts src/main/ipcContractAcceptance.test.ts src/preload/preloadValidation.test.ts src/main/ipcChannelContract.test.ts`
  — 356 passed, 4 файла, 1.44 s, exit 0. `npm.cmd run build` (включает
  typecheck/157-channel check) — exit 0, `.tmp/wp0-ipc-review-build.log`.
  `node scripts/test-electron-runtime.mjs` и
  `node scripts/test-wp1-native.mjs --ipc-only` — exit 0; после усиления
  native locale assertions первый smoke повторён, exit 0.
  Coverage — AC 927/927, F 210/210, exit 0; diff checks — exit 0.
- Первый полный прогон доработки: 3701 passed / 1 failed / 5 skipped,
  207.02 s. Единственный отказ — 5 s timeout существующего read-only
  PowerShell parser fixture runtimeDirSecurity.test.ts (5806 ms), без
  изменения этих production scripts. Отдельный повтор
  `npm.cmd test -- src/main/runtimeDirSecurity.test.ts` — 103 passed,
  5.55 s, exit 0. Полный прогон повторён без параллельных native/build;
  итог: `npm.cmd test` — 3702 passed / 5 skipped / 0 failed, 241 файлов
  passed / 2 skipped, 187.16 s, exit 0; `.tmp/wp0-ipc-review-full-final.log`.
  Повторный `npm.cmd run typecheck` — exit 0, 157 channels.

## 18.10.2026 — PR #49 слит; WP-0 остаётся в работе

- PR https://github.com/newnout6-a11y/vpn/pull/49 слит: merge
  7324593c1d7534565279033a1572bc02147ff0df, проверенный head
  7c9c8a16d4166a38b0597e21450e0d9182067aa7. `git diff 7c9c8a1 vpn/main
  --exit-code` — 0, merge не изменил проверенное дерево.
- Fresh exact-head CI run 39118780451 — все три success. Windows
  117649915612: 3703 passed / 4 skipped / 0 failed, 242 файлов passed /
  1 skipped, 240.88 s; typecheck/157 channels и coverage AC 927/927,
  F 210/210 — exit 0; WFP aborted:true; native Electron 1 passed /
  1 skipped. Rust 117649915618 и сайт 117649915518 — success.
  Полный Windows лог `.tmp/wp0-ipc-final-ci.log` в приложении.
- Fresh Revix 117649920118 — completed/neutral; review 5562529233
  на том же head. Единственный новый комментарий 4306653327 — nitpick
  об Array.findLast в тесте. Сохранена copied/reversed mock.calls:
  findLast недоступен в текущем TS lib (фактически получен TS2550), менять
  lib приложения ради теста не нужно. Ответ 4306656358. Это не Low-risk
  badge: автоматический summary пишет needs-changes при одном nitpick;
  фактический новый feedback только незначительный, что допускает владелец.
  Подтверждённый issue 4306608229 исправлен реальным log test;
  question 4306608232 закрыт en/ru и native oracle; suggestion 4306608234
  учтён точной формулировкой оставшихся bounded object schemas.
- Продолжение — codex/wp0-renderer-errors от нового vpn/main. Следующий
  участок AT-00-001/004: типизированные ошибки в main world, глубокие
  legacy schemas/any и domain-result failures. Локальный изолированный
  native probe `.tmp/ipc-rejection-probe.mjs` уже подтвердил, что Promise
  rejection plain object сохраняет message/code/category/correlationId
  через contextBridge (isError=false), в отличие от custom Error props.
  Это исследование варианта, не реализованный adapter: при миграции
  надо сохранить существующую семантику renderer catch/instanceof Error.
  FSM/coordinator, registry отмены/deadline, audit correlation, migrations,
  races/UI/flags и общая operation history остаются по матрице acceptance.
  WP-0 не завершён, WP-2 не начат; цель остаётся active.
- Этот коммит дописывает журнал, production code после полного DoD и
  exact-head CI не менялся. Нормативные docs/ не редактировались;
  сохранены прежние .claude/, .wrangler/, .playwright-cli/ и output/.

## 18.10.2026 — WP-0: типизированные ошибки доходят до renderer

- Ветка codex/wp0-renderer-errors. Подтверждена потеря custom Error properties
  настоящим Electron contextBridge: усиленный native smoke до исправления
  завершился exit 1 (undefined вместо IPC_VALIDATION_ERROR), лог
  vpn-tunnel-enforcer/.tmp/wp0-renderer-error-before.log.
- Preload сериализует отказы request-методов в canonical plain data:
  name/code/category/message/correlationId. Исключены произвольные тексты,
  stack/cause и секреты. Локальная валидация возвращает rejected Promise
  без выдуманного main correlation и без IPC effects. Подписки остаются
  синхронными, unsubscribe проверен отдельно. Public guard позволяет
  renderer читать эти данные вместо ненадёжного instanceof Error.
- Исправлены отображение ошибки выбора сервера и глобальный rejection
  logger; отказ самого logRenderer теперь наблюдается, не создавая новый
  unhandled rejection. Добавлены функциональные renderer-регрессии.
- Настоящие production guard/preload/contextBridge проверены для 7 категорий
  в en/ru (14 запросов): стабильные коды, уникальные UUID, canonical messages,
  без stack/секретов/путей. Локальный аргумент тоже проверен нативно.
  В Windows CI добавлены build и оба native IPC/CSP smoke; удалённый
  результат этого нового шага ещё предстоит получить на PR.
- `npm.cmd test -- src/shared/ipc-result.test.ts src/preload/preloadValidation.test.ts src/main/ipcChannelContract.test.ts src/main/ipcContractAcceptance.test.ts src/renderer/components/DashboardSide.test.tsx src/renderer/main.test.tsx`
  — 377 passed, 6 файлов, 2.84 s, exit 0.
- `npm.cmd run build` (включает typecheck и 157-channel checker) — exit 0,
  .tmp/wp0-renderer-errors-build.log. `node scripts/test-electron-runtime.mjs`
  — exit 0, .tmp/wp0-renderer-errors-native.log;
  `node scripts/test-wp1-native.mjs --ipc-only` — exit 0.
- `npm.cmd test` — 3724 passed / 5 skipped / 0 failed, 244 файлов passed /
  2 skipped, 205.43 s, exit 0; .tmp/wp0-renderer-errors-full.log.
  `python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py`
  — AC 927/927, F 210/210, exit 0. `git diff --check` — exit 0.
- AT-00-004 усилен на реальной границе; весь WP-0 не объявлен завершённым.
  Глубокие legacy schemas/any, domain-result failures, общий coordinator/FSM,
  registry отмены/deadline, migrations, correlation/history и race/UI/flags
  остаются в матрице. Native smoke не заменяет полную L3-приёмку.

### PR #50 — проверка замечаний и доработка

- Первый head 1ee6ad8bfc4ad6c6edeee355890a0980c8a5246b: CI run
  39120313653, Windows 117654409737, Rust 117654409586 и сайт
  117654409800 — success. Windows: 3725 passed / 4 skipped / 0 failed,
  245 файлов passed / 1 skipped, 227.82 s; coverage AC 927/927 и
  F 210/210. Новый native IPC/CSP шаг — success (оба PASS markers),
  WFP aborted:true, native Electron probe 1 passed / 1 skipped.
  .tmp/wp0-renderer-initial-ci.log. Это результаты первого head.
- Revix 117654423546 — completed/neutral, Low risk, review 5562593204.
  Suggestion 4306715099 обоснован: всякий TypeError/RangeError ошибочно
  обозначался validation. Все явные preload validators теперь бросают
  IpcValidationError; serializer больше не переименовывает случайные
  TypeError/RangeError. Новые тесты проверяют internal для случайного
  синхронного сбоя и validation для несерилизуемого входа без IPC effects.
- Nitpick 4306715102 не применим: node:assert/strict уже делает assert.equal
  строгим; ответ 4306721060 со ссылкой на существующий import.
- Финальная доработка: целевые 6 файлов — 382 passed, 3.53 s, exit 0;
  `npm.cmd run build` — exit 0 (.tmp/wp0-renderer-review-build.log),
  `node scripts/test-electron-runtime.mjs` — exit 0
  (.tmp/wp0-renderer-review-native.log). `npm.cmd test` — 3729 passed /
  5 skipped / 0 failed, 244 файлов passed / 2 skipped, 174.91 s, exit 0
  (.tmp/wp0-renderer-review-full.log). Coverage — AC 927/927, F 210/210,
  exit 0; `git diff --check` — exit 0. Свежий exact-head CI/review после
  push ещё обязателен до merge; WP-0 остаётся в работе.

## 18.10.2026 — PR #50 слит; продолжение WP-0

- PR https://github.com/newnout6-a11y/vpn/pull/50 слит, merge
  784d0aef6b15b2f1dd74d382206a79adc82abd16. Проверенный head
  527662e59581fa7507b5ea7db5f99a29b22fbcc5; `git diff 527662e vpn/main
  --exit-code` — 0, merge сохранил проверенное дерево.
- Fresh exact-head CI run 39120778884: Windows 117655775050, Rust
  117655774936, сайт 117655775135 — success. Windows: 3730 passed /
  4 skipped / 0 failed, 245 файлов passed / 1 skipped, 148.41 s.
  Typecheck/157-channel checker, AC 927/927 и F 210/210 — exit 0;
  новый production build/contextBridge/CSP step — success, оба native
  PASS markers. WFP aborted:true; native Electron probe 1 passed /
  1 skipped. Полный Windows лог .tmp/wp0-renderer-final-ci.log.
- Fresh Revix check 117655785807 — completed/neutral, Low risk,
  1 minor nitpick. Реальное suggestion 4306715099 исправлено в 527662e,
  ответ 4306729531. Оставшийся nitpick 4306715102 уже удовлетворён
  import node:assert/strict (ответ 4306721060); review thread переиспользован,
  новый review id не выдумывается. Новый check проверен на exact head.
- Следующая ветка codex/wp0-ipc-object-schemas от vpn/main. Продолжение
  AT-00-001: глубокие схемы object inputs и типы публичного API для
  расписания/ротации/DNS/правил/предпочтений/темы/фильтров истории.
  Семантика clamp/defaults и прежние поддержанные поля сохраняются;
  feature validators остаются последним semantic oracle.
- WP-0 в работе; миграция оставшихся legacy domain failures/any, интеграция
  coordinator/FSM, cancellation/deadline, migration registry, correlation,
  event history и flags/races/UI не объявлены выполненными. WP-2 ещё
  не начат. Нормативные docs/ не менялись; цель остаётся active.

## 18.10.2026 — WP-0: вложенные IPC-схемы и публичные типы

- Ветка codex/wp0-ipc-object-schemas. 12 bounded object() входов заменены
  схемами полей, вложенных объектов и массивов: scheduler create/update,
  rotation config, kill-switch exception, DNS create/update, domain add/update,
  connection-history filter, notifications patch, theme create, live history.
  Новые object contracts отклоняют неизвестные ключи. Sparse arrays не могут
  пропускать проверку элементов. Существующий 157-channel registry сохранён.
- Baseline: `npm.cmd test -- src/main/ipcContractAcceptance.test.ts -t 'rejects invalid nested'`
  — 21 failed / 321 skipped, exit 1 (.tmp/wp0-object-schema-before.log):
  malformed nested fields доходили до listener. Теперь schema validation
  отклоняет их до эффектов; дополнительные случаи проверяют sparse arrays,
  неизвестные поля, границы размера и пустые обязательные объекты.
- Поддержанные пустые patches, исходные семь цветов темы, optional/null DNS
  secondary, days 0/6, 1000 rotation profileIds и interval clamp не потеряны.
  Доменные URL проходят исходную normalization до лимита hostname; отдельный
  positive regression использует URL с path длиннее 253 символов.
- У затронутых API устранены any входов/результатов; общие NextEvent,
  ConnectionHistoryFilters и stats перенесены из main в shared с прежними
  type-only reexports. Logs строит типизированный фильтр. Runtime algorithms
  scheduler/history не переписаны; семантическая валидация остаётся в features.
- Первая версия: `npm.cmd test` — 3781 passed / 5 skipped / 0 failed,
  244 файлов passed / 2 skipped, 141.57 s, exit 0 (.tmp/wp0-object-schema-full.log).
  После уточнения compatibility для URL повторён полный прогон итогового кода.
- Финальные `npm.cmd run build` (typecheck и 157-channel checker) — exit 0,
  .tmp/wp0-object-schema-final-build.log. `node scripts/test-electron-runtime.mjs`
  — exit 0 (.tmp/wp0-object-schema-final-native.log), production guard/preload/
  contextBridge: invalid nested days=[7] не вызывает handler, valid partial
  update выполняется; прежняя typed-error/origin/sandbox матрица сохранена.
- `npm.cmd test -- src/main/ipcContractAcceptance.test.ts src/preload/preloadValidation.test.ts src/main/ipcChannelContract.test.ts src/main/scheduler.test.ts src/main/profileRotation.test.ts src/main/connectionHistory.test.ts src/main/connectionHistoryStorage.test.ts src/main/notificationPrefs.test.ts src/main/dnsProfiles.test.ts src/main/dnsProfilesSelection.test.ts src/main/domainRouting.test.ts src/main/themePalette.test.ts src/renderer/pages/Logs.render.test.tsx`
  — 614 passed, 13 файлов, 3.25 s, exit 0
  (.tmp/wp0-object-schema-final-focused.log).
- Coverage: `python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py`
  — AC 927/927, F 210/210, exit 0. `git diff --check` — exit 0.
- save-settings остаётся единственным bounded object() без fields. Его schema,
  оставшиеся any ответов, domain failures, coordinator/FSM, cancellation/deadline,
  migrations/correlation/history/flags/races/UI входят в прежний остаток WP-0.
  AT-00-001 и весь WP-0 пока не объявлены PASS; нормативные docs/ не менялись.
- Финальный `npm.cmd test` — 3782 passed / 5 skipped / 0 failed,
  244 файлов passed / 2 skipped, 147.07 s, exit 0
  (.tmp/wp0-object-schema-final-full.log). Production code после этого
  результата до коммита не менялся; впереди exact-head CI и Revix на PR.

## 18.10.2026 — PR #51 слит; оставшийся settings contract

- PR https://github.com/newnout6-a11y/vpn/pull/51 слит, merge
  bf08d6b912a6f163bf4b878b147550339718f612; проверенный head
  b33163ae0cbe90119e7ded63dfcc90dcf503ec15. `git diff b33163a vpn/main
  --exit-code` — 0: merge сохранил проверенное дерево.
- Exact-head CI run 39121998380: Windows 117659303798, Rust 117659303740
  и сайт 117659303912 — success. Windows: 3783 passed / 4 skipped /
  0 failed, 245 файлов passed / 1 skipped, 144.58 s; typecheck/checker
  157 channels и coverage AC 927/927, F 210/210 — exit 0. Native IPC/CSP
  step — оба PASS markers, WFP aborted:true; native Electron probe
  1 passed / 1 skipped. Лог .tmp/wp0-object-schema-final-ci.log.
- Revix 117659316373 — completed/neutral, Low risk, review 5562673468,
  один question 4306785961. Read-only AST/runtime parity probe доказал:
  NotificationPreferences 8/8, RotationConfig 6/6, вход
  Omit<KillSwitchException,'id'> 3/3, missing/extra keys нет. id создаёт main,
  он не часть create input. Ответ 4306788444; исходники не менялись.
- Новая ветка codex/wp0-settings-contract от vpn/main. Следующий участок
  AT-00-001 — 39 полей AppSettings, последний bounded object() save-settings,
  и общие public settings types. Нормализация исторического persisted store
  остаётся прежней; некорректный новый IPC input должен отклоняться до effects.
  Далее остаются legacy any ответов/domain failures и вся общая матрица WP-0.
  WP-0 не завершён, WP-2 не начат, цель active. Этот коммит только журнал.

## 18.10.2026 — WP-0: общий settings type и схема всех 39 полей

- Ветка codex/wp0-settings-contract. Дубли AppSettings из main/settings.ts и
  renderer/store.ts заменены общим shared/settings.ts с прежними type-only
  reexports. getSettings/saveSettings/setLoginItem типизированы этим контрактом;
  outbound cache использует рекурсивный IpcJsonValue вместо Record<string,any>.
- Все 39 ключей нового settings patch заданы через Record<keyof AppSettings,
  IpcArgumentSchema>: typecheck требует обновления схемы при изменении типа.
  Последний object() без fields устранён. Строковые флаги, неверные enum/числа,
  неизвестные поля и неверная структура cache отклоняются до listener/effects.
  Protocol-specific outbound — bounded JSON-shaped values; это не замена
  semantic validation sing-box/Xray. Depth/node budgets и негативы проверены.
- Baseline: `npm.cmd test -- src/main/ipcContractAcceptance.test.ts -t 'rejects invalid nested'`
  — 13 failed / 27 passed / 343 skipped, exit 1
  (.tmp/wp0-settings-schema-before.log). Ошибочные новые settings достигали
  listener; это исправлено на обеих границах. Пустые/частичные patches,
  numeric clamp, cachedAt:null и JSON cache остаются поддержаны.
- Историческая normalizer/persistence/DPAPI migration не изменены. Дополнен
  regression существующих clamp: checkInterval -5 → 5000, capture size
  5000 → 2048, selected index 0.5 → 0. Прежние safe default/secret/login
  tests сохранены; новые IPC inputs проходят строгую проверку до них.
- `npm.cmd run typecheck` — exit 0, 157 channels; `npm.cmd run build` — exit 0,
  .tmp/wp0-settings-schema-build.log. `node scripts/test-electron-runtime.mjs`
  — exit 0 (.tmp/wp0-settings-schema-native.log): string autoStart:'false'
  без effects, boolean autoStart:false принят. checkInterval:NaN теперь
  отклоняется локально без main correlation; main correlation всё ещё
  подтверждён native матрицей 7 категорий × 2 языка.
- Первый full `npm.cmd test` — 3807 passed / 1 failed / 5 skipped,
  243 файлов passed / 1 failed / 2 skipped, 142.52 s, exit 1
  (.tmp/wp0-settings-schema-full.log). Единственный отказ xrayEngineSource
  ожидал type declaration в прежнем main-файле. Архитектурный тест обновлён:
  тип читается из shared, runtime default по-прежнему из main; проверка не
  удалена и production code ради прежнего пути не дублировался.
- `npm.cmd test -- src/main/ipcContractAcceptance.test.ts src/preload/preloadValidation.test.ts src/main/ipcChannelContract.test.ts src/main/settingsForensicsDefault.test.ts src/main/settingsLoginItem.test.ts src/main/settingsSecretSecurity.test.ts src/main/xrayEngineSource.test.ts src/renderer/pages/Settings.test.ts src/renderer/pages/Settings.render.test.tsx src/renderer/components/FirstRunWizard.test.tsx`
  — 506 passed, 10 файлов, 4.14 s, exit 0
  (.tmp/wp0-settings-schema-final-focused.log). Полный итоговый прогон повторён.
- Coverage — AC 927/927, F 210/210, exit 0; `git diff --check` — exit 0.
  Normative docs/ не менялись. Legacy any других ответов и domain failures,
  coordinator/FSM, cancellation/deadline, migrations/correlation/event history,
  flags/races/UI остаются в WP-0. Пакет не объявлен завершённым.
- Финальный `npm.cmd test` — 3808 passed / 5 skipped / 0 failed,
  244 файлов passed / 2 skipped, 136.14 s, exit 0
  (.tmp/wp0-settings-schema-final-full.log). Итоговый production behavior
  после build/native checks не менялся; требуется exact-head CI/review PR.

## 18.10.2026 — PR #52 слит; типы ответов IPC

- PR https://github.com/newnout6-a11y/vpn/pull/52 слит, merge
  f3b953f2f8340d1c11589c64045b158e06bf0e22; проверенный head
  d0a2be9ee9d25bc9e22b643fc2fd53a7b04e59f0. `git diff d0a2be9 vpn/main
  --exit-code` — 0: merge сохранил проверенное дерево.
- Exact-head CI 39123146766: Windows 117662700166, Rust 117662700001
  и сайт 117662700174 — success. Windows: 3809 passed / 4 skipped /
  0 failed, 245 файлов passed / 1 skipped, 251.14 s. Typecheck/checker
  157 channels и coverage AC 927/927, F 210/210 — exit 0. Native IPC/CSP
  markers PASS; WFP aborted:true; Electron native probe 1 passed / 1 skipped.
  Лог .tmp/wp0-settings-schema-final-ci.log. Локальный full перед PR:
  3808 passed / 5 skipped / 0 failed; код после него не менялся.
- Revix 117662716829 — completed/neutral, Low risk. Question 4306835706
  проверен на неизменённых production guard/schema: `node
  .tmp/wp0-aggregate-review.cjs` — exit 0. Каждый из двух profiles с
  10000 outbound values принимается отдельно; общий request 40143 bytes
  проходит channel schema, но assertSafeIpcPayload(args) отклоняет его
  общим node budget до listener. Installed boundary: validation, 0 effects.
  Счётчик один на args целиком; helper outbound действительно имеет свой
  локальный бюджет. Ответ 4306847958, production patch не нужен.
- Новая ветка codex/wp0-diagnostic-results от проверенного vpn/main.
  Следующий участок AT-00-001: legacy any в результатах диагностики,
  main/shared/renderer type parity и автоматическая проверка результатов.
  Инвентаризация всех 157 listeners нашла 51 канал с явным any в public
  result, ещё 4 расхождения literal widening. Это не завершение WP-0:
  domain failures, FSM/coordinator, cancellation/deadline, migrations,
  correlation/history/flags/races/UI остаются. WP-2 не начат; цель active.

## 18.10.2026 — WP-0: общий diagnostic result contract и проверка listeners

- Ветка codex/wp0-diagnostic-results. В typecheck/build встроен TypeScript
  checker фактических awaited returns всех 157 listeners, включая локальные
  registration wrappers. Ошибка содержит канал и несовместимые типы;
  unresolved/unchecked signatures не проходят. Вложенный any определяется
  в unions, массивах, словарях и aliases; он не может скрыть несовместимый
  actual result за конкретным public type. Legacy public results с any
  сохраняются явно в inventory: осталось 37 вместо 51.
- 14 diagnostic/log API methods теперь имеют конкретные результаты:
  detectHapp; adaptive get/retry/reset; leak/system checks; routing plan;
  getFullLogs/logRenderer/clearAppLog; URL availability/history; speed/history.
  Чистые типы перенесены в shared/diagnostics.ts, main сохраняет type-only
  reexports, renderer store/Maintenance/Availability используют shared.
  SpeedTestResult переиспользован из существующего shared/ipc-types.ts.
- Baseline `npm.cmd test -- src/main/ipcResultContract.test.ts` — 1 failed /
  6 passed, exit 1 (.tmp/wp0-result-contract-before.log): четыре actual
  results расширяли true до boolean, несовместимого с public true.
  Добавлен as const; runtime значения и операции не изменены.
- Более строгая проверка вложенного any обнаружила шесть нарушений error:string:
  notifications reset/open, group health и три exports в файл. Обычные string
  messages сохранены; object-valued message теперь преобразуется в строку.
  Функциональные тесты проверяют все шесть реальных handlers с подменёнными
  OS/fs boundaries. Остальные domain failure тексты и taxonomy остаются в WP-0.
- `npm.cmd test -- src/main/ipcResultContract.test.ts src/main/notificationResultContract.test.ts src/main/serverGroupsRefresh.test.ts src/main/serverKeyExportSecurity.test.ts`
  — 60 passed, 4 файла, 10.71 s, exit 0
  (.tmp/wp0-diagnostic-results-focused.log).
- `npm.cmd run build` — exit 0, включая typecheck/checker 157 listeners
  (.tmp/wp0-diagnostic-results-build.log). `node scripts/test-electron-runtime.mjs`
  — ELECTRON_SMOKE_PASS, exit 0 (.tmp/wp0-diagnostic-results-native.log),
  production preload/contextBridge, локальные schemas, категории и en/ru
  correlation матрица сохранились.
- Финальный `npm.cmd test` — 3829 passed / 5 skipped / 0 failed,
  246 файлов passed / 2 skipped, 176.96 s, exit 0
  (.tmp/wp0-diagnostic-results-full.log). `python -X utf8
  docs/04-приёмочные-тесты/traceability/check-coverage.py` — AC 927/927,
  F 210/210, exit 0. `git diff --check` — exit 0.
- AT-00-001 и весь WP-0 не объявлены завершёнными: 37 legacy results,
  domain failures, FSM/coordinator, cancellation/deadline, migrations,
  correlation/history/flags/races/UI остаются. WP-2 не начат; цель active.
  Из нормативных docs/ ничего не менялось; впереди exact-head CI и Revix.

## 18.10.2026 — PR #53 слит; оставшиеся service result contracts

- PR https://github.com/newnout6-a11y/vpn/pull/53 слит, merge
  1874794bbc35e390f6a1fa16646b51b760045deb; проверенный head
  74a10e31c46db6cd90ff69f348893755856d2acc. `git diff 74a10e3 vpn/main
  --exit-code` — 0: merge сохранил проверенное дерево.
- Exact-head CI 39124566441: Windows 117666871494, Rust 117666871754,
  сайт 117666871700 — success. Windows: 3830 passed / 4 skipped /
  0 failed, 247 файлов passed / 1 skipped, 225.77 s. Checker всех
  157 listeners и coverage AC 927/927, F 210/210 — exit 0. Production
  IPC/contextBridge и CSP markers PASS, WFP aborted:true, native Electron
  probe 1 passed / 1 skipped (.tmp/wp0-diagnostic-results-final-ci.log).
- Revix 117666885660 — success, Ready to merge, замечаний нет. Локальный
  финальный `npm.cmd run typecheck` — exit 0
  (.tmp/wp0-diagnostic-results-final-typecheck.log); full 3829 passed /
  5 skipped, 176.96 s, exit 0. Источники после этих проверок не менялись.
- Новая ветка codex/wp0-service-results от проверенного vpn/main.
  Следующий участок AT-00-001: 23 результата существующих сервисов
  (network maintenance, forensics/traffic history, autoconfig, probe,
  rule-sets/AutoPilot и split tunneling), преимущественно готовые pure types.
  Остальные profile/group results, domain failures и вся остальная матрица
  WP-0 остаются в работе. WP-2 не начат, цель active.

## 18.10.2026 — WP-0: 28 service result contracts без изменения runtime

- Ветка codex/wp0-service-results. Ещё 28 public methods получили конкретные
  результаты: network maintenance, browser/location protection, AutoPilot,
  rule-sets, autoconfig, traffic history/forensics, probe, split tunnel и groups.
  Checker сохраняет все 157 listeners; public any стало 9 вместо 37.
- Pure network/traffic types вынесены в shared/network.ts и shared/traffic.ts,
  main imports сохраняются через type-only reexports. Probe использует общий
  AsnInfo, остальные probe types добавлены в shared/diagnostics.ts. UI-копии
  удалены; UI AutoconfigTarget расширяет transport type только enabled.
  Поведение services, recovery, engines, файловые форматы не менялись.
- Baseline `npm.cmd test -- src/main/ipcResultContract.test.ts -t 'checks all production listeners'`
  — 1 failed / 9 skipped, exit 1 (.tmp/wp0-service-results-before.log):
  get-autoconfig-status и ещё 27 migrated methods оставались legacy any.
- `npm.cmd run typecheck` — exit 0, 157 listeners, 9 legacy results
  (.tmp/wp0-service-results-typecheck.log). `npm.cmd run build` — exit 0
  (.tmp/wp0-service-results-build.log). `node scripts/test-electron-runtime.mjs`
  — ELECTRON_SMOKE_PASS, exit 0 (.tmp/wp0-service-results-native.log).
- `node .tmp/wp0-service-runtime-parity.cjs` — exit 0: после одинаковой
  нормализации CRLF/LF исполняемые transpiled tokens 22 изменённых production
  modules совпадают с HEAD; два новых shared modules испускают только пустой
  export (.tmp/wp0-service-runtime-parity.log). Первые попытки probe выявляли
  различие line endings и лишних скобок arrow parameter, а не logic changes;
  итоговая проверка не игнорирует произвольные различия runtime tokens.
- Первый focused набор — 65 passed, 8 файлов, 11.62 s, exit 0
  (.tmp/wp0-service-results-focused.log). Первый full `npm.cmd test` —
  3828 passed / 1 failed / 5 skipped, 176.90 s, exit 1
  (.tmp/wp0-service-results-full.log). Единственный отказ AppSource искал
  protectedTunnelActive в прежнем renderer interface; теперь он проверяет
  поле в shared/network.ts и импорт FirewallRepairHealth в Maintenance,
  сохраняя прежние assertions protection label. Проверка не удалена.
- Итоговый `npm.cmd test -- src/main/ipcResultContract.test.ts src/main/ipcChannelContract.test.ts src/main/serverProbe.test.ts src/main/splitTunneling.test.ts src/main/autoPilot.test.ts src/main/trafficHistory.test.ts src/main/domainEnrichment.test.ts src/renderer/AppSource.test.ts src/renderer/MaintenanceSource.test.ts src/renderer/pages/Settings.render.test.tsx`
  — 98 passed, 10 файлов, 13.25 s, exit 0
  (.tmp/wp0-service-results-final-focused.log). Финальный `npm.cmd run typecheck`
  — exit 0 (.tmp/wp0-service-results-final-typecheck.log).
- Финальный полный `npm.cmd test` — 3829 passed / 5 skipped / 0 failed,
  246 файлов passed / 2 skipped, 174.91 s, exit 0
  (.tmp/wp0-service-results-final-full.log).
- Coverage: `python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py`
  — AC 927/927, F 210/210, exit 0; `git diff --check` — exit 0.
  9 profile results, domain failures, FSM/coordinator/cancellation/deadline,
  migrations/correlation/history/flags/races/UI остаются в WP-0; WP-2 не начат.
  Нормативные docs/ не менялись; цель active.

## 18.10.2026 — PR #54: CI зелёный, решение о ревью ожидается

- Код закоммичен и запушен: 9ce9298681359096fb202f067eae1a382dac98f6,
  PR https://github.com/newnout6-a11y/vpn/pull/54. Других открытых PR нет.
- Exact-head CI 39126137175 — success: Windows 117671557953,
  Rust 117671557887, сайт 117671557734. Windows: 3830 passed / 4 skipped /
  0 failed, 247 файлов passed / 1 skipped, 222.50 s. Coverage AC 927/927,
  F 210/210; native production IPC/contextBridge и CSP PASS; WFP aborted:true;
  native Electron probe 1 passed / 1 skipped (.tmp/wp0-service-results-ci.log).
- Повторная read-only проверка уже закоммиченного parent/head:
  `node .tmp/wp0-service-committed-parity.cjs` — exit 0, runtime tokens
  22 production modules идентичны; два shared modules — empty exports only.
  Собственная проверка полного diff не выявила actionable замечаний.
- Revix review 5562932738: дневная квота исчерпана, полного ревью не было;
  сброс 19.10 в 00:00 UTC. Это не approval. Владельцу задан вопрос,
  принять ли собственную проверку для #54 либо ждать Revix. До ответа PR
  не слит, следующий участок не начат. Journal entry пока не коммитится,
  чтобы не менять проверенный PR head до решения владельца. Цель active.
- Третья последовательная проверка того же препятствия (18.10, 12:18 UTC):
  head не изменён, все CI success, PR открыт; нового полного ревью и ответа
  владельца нет. Дальнейшая работа ограничена требованием approval до перехода.
  Цель переводится в blocked до принятия собственной проверки либо появления
  полного ревью; WP-0 и WP-2 не объявлены завершёнными.

## 18.10.2026 — решение владельца: #54 не сливать, WP-0 продолжать

- Владелец ответил: «не сливаем пока что. но идёим дальше». PR #54 остаётся
  открыт на проверенном 9ce9298; отсутствие полного Revix не переименовано
  в approval. Разрешено продолжать WP-0 до слияния #54.
- Новая ветка codex/wp0-profile-results поверх #54; следующий PR будет иметь
  base codex/wp0-service-results, чтобы показывать только новый участок.
  Остаток: 9 profile result contracts, затем остальная полная матрица WP-0.
  До правок выполнен read-only compiler probe замены outbound any на общий
  JSON-shaped transport type; результаты и выбранная реализация ниже.

## 18.10.2026 — WP-0: profile result contracts и JSON field narrowing

- Все 9 оставшихся profile methods используют ServerProfile вместо any;
  outbound — общий рекурсивный IpcJsonValue с поддержкой protocol extensions.
  Type alias перенесён из settings в shared/json.ts с совместимым reexport.
  Contract test требует пустой legacy inventory всех 157 listeners.
- Read-only `node .tmp/wp0-profile-type-probe.cjs` обнаружил 26 compiler
  diagnostics при простой замене outbound any. Они устранены narrowing
  реальных полей TLS/Reality/ECH/uTLS/ALPN, transport/SNI/fingerprint и
  JSON-клона endpoint, без any-casts для подавления новых diagnostics.
  Внутренние старые any других подсистем не объявлены устранёнными.
- Конкретная регрессия: reality:[] считался camouflage и давал
  tlsLeaksSni:false. Теперь массив не считается объектом Reality и сохраняется
  tlsLeaksSni:true. `node .tmp/wp0-profile-reality-regression.cjs` — exit 0:
  настоящие parent/current функции извлечены без I/O, baseline false -> true;
  три корректных случая Reality/disabled/absent идентичны. Это не packet oracle.
- До исправления `npm.cmd test -- src/main/ipcResultContract.test.ts -t 'checks all production listeners'`
  — 1 failed / 9 skipped, exit 1 (.tmp/wp0-profile-results-before.log):
  оставшиеся 9 channels ещё были legacy any.
- `npm.cmd test -- src/main/ipcResultContract.test.ts src/main/keyHealthChecker.test.ts src/main/liveServerProbe.handshake.test.ts src/main/serverPickerGeoLifecycle.test.ts src/renderer/pages/Servers.test.ts src/renderer/components/ServerDetailModalSource.test.ts src/main/systemDiagnostics.test.ts`
  — 107 passed, 7 файлов, 10.09 s, exit 0 (.tmp/wp0-profile-results-focused.log).
  Проверяются реальные picker handlers, корректные/повреждённые protocol поля,
  UI badges и handshake evidence; существующие проверки не удалены.
- Финальный `npm.cmd run typecheck` — exit 0, 157 listeners / 0 public any
  (.tmp/wp0-profile-results-final-typecheck.log). `npm.cmd run build` — exit 0
  (.tmp/wp0-profile-results-build.log). `node scripts/test-electron-runtime.mjs`
  — ELECTRON_SMOKE_PASS, exit 0 (.tmp/wp0-profile-results-native.log), включая
  production contextBridge roundtrip nested JSON profile и null active result.
  Service handlers в native smoke — fixtures, реальный picker проверен отдельно.
- `python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py` —
  AC 927/927, F 210/210, exit 0; `git diff --check` — exit 0.
  Полный suite выполняется. PR #54 остаётся открыт, решение владельца соблюдено.
- Первый полный `npm.cmd test` — 3846 passed / 2 failed / 5 skipped,
  167.46 s, exit 1 (.tmp/wp0-profile-results-full.log). Оба отказа — 5000 ms
  timeout неизменённых native PowerShell fixtures runtimeDirSecurity и
  adaptiveNetworkIdentity. `npm.cmd test -- src/main/runtimeDirSecurity.test.ts src/main/adaptiveNetworkIdentity.test.ts`
  сразу повторён отдельно: 128 passed, 4.43 s, exit 0
  (.tmp/wp0-profile-results-powershell-recheck.log). Timeout не увеличен,
  assertions/production code этих подсистем не менялись; полный suite повторяется.
- Повторный полный `npm.cmd test` — 3848 passed / 5 skipped / 0 failed,
  246 файлов passed / 2 skipped, 173.69 s, exit 0
  (.tmp/wp0-profile-results-final-full.log). После проверок runtime-код не менялся.
  Для stacked PR CI запускается workflow_dispatch на точном head: workflow
  автоматически принимает только pull_request в main, base #54 пока не слит.
- Self-review перед завершением PR #55 уточнил scope: production call sites
  describeProbeTarget/tlsLeaksSni не найдены (`rg` по src без test.ts).
  checkProfileHealth вызывает checkOutboundHealth с полным outbound, а не
  этот классификатор. Ранее в commentary/PR draft следствие было описано шире
  доказанного: исправлена классификация reality:[], но активная SNI-утечка
  и её устранение не доказаны. PR body и acceptance report исправлены;
  это docs-only follow-up, runtime/test sources после полного suite не менялись.


## 18.10.2026 — #55 CI и главный ревьюер Qodo

- PR #55, head `0a9f579d638797ddc50e0d7fd73c11c282ba8f35`: workflow_dispatch
  [39136948809](https://github.com/newnout6-a11y/vpn/actions/runs/39136948809)
  завершён success. Windows job 117703346355: 3849 passed / 4 skipped,
  247 файлов passed / 1 skipped, 229.18 s. Typecheck, трассировка, настоящий
  IPC/CSP smoke, WFP ABI/transaction-abort и Electron native reads зелёные;
  native reads отдельно 1 passed / 1 skipped. Rust и сайт success.
- Владелец уточнил: «теперь появился новый ревьюер. qodo .он теперь главый».
  Главный ревьюер — Qodo. Revix summary при исчерпанной квоте не approval;
  CodeRabbit/Greptile с окончившимся trial не блокируют работу.
  При REST-проверке #54/#55 комментариев/review Qodo ещё не было.
  PR #54/#55 не слиты; запрет владельца на merge #54 сохраняется.

## 18.10.2026 — WP-0: доменные ошибки импорта/экспорта конфигурации

- Четыре настоящих handler config:export/import/import-apply/browse-import
  проверяются вместе с production installTrustedIpcBoundary. Внутренние
  `{success:false,error:<raw>}` у export/import/apply заменены исключениями,
  которые boundary преобразует в canonical ok:false/category/code/correlation.
  Ошибки JSON/формата/выбора разделов — validation; отсутствие selection
  capability — permission; отмена сохранения/закрытый renderer — cancelled;
  изменение файла при чтении — conflict. Отмена browse остаётся успешным null.
- Config public types содержат только успешные значения; компонент использует
  shared ElectronAPI и canonical rejection. Неизвестный/поддельный текст ошибки
  заменяется локализованным internal. Cancelled export не показывает ошибку
  или успех. Ошибки и refresh warnings логируют только bounded reason.
- Регрессии: array вместо object section отклоняется; partial import не падает
  в detectConflicts на отсутствующих разделах; пустые/отсутствующие/неизвестные
  выбранные разделы отклоняются до записи. Ошибка позднего store write
  восстанавливает прежние значения, включая activeDnsProfileId:null (system DNS),
  и не оставляет повторно используемой selection capability.
- Новый configIpcErrors.test.ts инжектирует 7 категорий в store/dialog I/O
  каждого настоящего feature handler; response проверяется целиком, без
  FAKE-SECRET/stack/Windows absolute paths. Используется реальный временный
  выбранный JSON; файловая read/write логика не заменена fake handler.
  Это локальная fault-injection matrix, а не нативный UI/file-permission E2E.
- До исправления `npm.cmd test -- src/main/configIpcErrors.test.ts` —
  12 failed, exit 1 (.tmp/wp0-config-errors-before-final.log).
- `npm.cmd test -- src/main/configIpcErrors.test.ts src/main/configManager.test.ts src/main/configImportSecurity.test.ts src/main/configExportSecurity.test.ts src/main/ipcResultContract.test.ts src/renderer/components/ImportExportSettings.test.tsx`
  — 97 passed / 6 файлов, 13.14 s, exit 0 (.tmp/wp0-config-errors-focused-3.log).
  Старые authority/snapshot/single-use/security assertions сохранены; legacy
  failure-result expectations обновлены на canonical rejection.
- `npm.cmd run typecheck` — exit 0, 157 listeners / 0 public any
  (.tmp/wp0-config-errors-typecheck.log). `python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py`
  — AC 927/927, F 210/210, exit 0; `git diff --check` — exit 0.
  Полный suite выполняется. AT-00-004 целиком и WP-0 не объявлены PASS.

- Полный `npm.cmd test` — 3875 passed / 5 skipped / 0 failed,
  247 файлов passed / 2 skipped, 174.42 s, exit 0
  (.tmp/wp0-config-errors-full.log). `npm.cmd run build` — exit 0
  (.tmp/wp0-config-errors-build.log); `node scripts/test-electron-runtime.mjs`
  — ELECTRON_SMOKE_PASS, exit 0 (.tmp/wp0-config-errors-native.log).
  Native smoke проверяет общий production bridge en/ru; реальные config handlers
  отдельно проверены fault-injection matrix, эти два доказательства не смешиваются.
- По прямому поручению владельца Qodo запрошен комментариями
  `@qodo review this PR` в #54 (6251357932) и #55 (6251358101).
  Синтаксис подтверждён официальной docs.qodo.ai/code-review/use-qodo-in-prs/code-review.
  Отправка команды не объявляется завершённым review или approval.


## 18.10.2026 — Qodo #55: некорректные profiles в импорте

- По прямому поручению владельца отправлен `@qodo review this PR` в #54
  (6251357932) и #55 (6251358101); qodo-code-review[bot] подтвердил обе команды
  реакцией eyes. Главный ревьюер — Qodo; #54 остаётся открыт без merge.
- [Qodo #54](https://github.com/newnout6-a11y/vpn/pull/54#issuecomment-6251376742)
  на 9ce9298: 0 Bugs / 0 Rule violations / 0 Requirement gaps, no material issues.
- [Qodo #55](https://github.com/newnout6-a11y/vpn/pull/55#issuecomment-6251403696)
  на 0a9f579: Medium — profiles:[null] проходит apply, после чего servers:list
  нарушает ServerProfile[] и active lookup падает. Подтверждено новыми tests.
- `npm.cmd test -- src/main/configManager.test.ts src/main/configImportSecurity.test.ts`
  до исправления: 9 failed / 41 passed, 573 ms, exit 1
  (.tmp/wp0-qodo55-before.log). Проверяется настоящий apply handler: прежний
  profiles store должен оставаться неизменным, selection расходуется.
- validateImportData теперь проверяет обязательные поля, port/status и типы
  известных необязательных полей каждого профиля. Null/array/non-record,
  отсутствующие поля и несовместимые значения отклоняются до записи. Старый
  профиль без outbound допустим; JSON protocol extensions не отбрасываются.
  Полная protocol-specific проверка outbound этим валидатором не заявляется.
- Целевой `npm.cmd test -- src/main/configManager.test.ts src/main/configImportSecurity.test.ts src/main/ipcResultContract.test.ts src/main/serverPickerGeoLifecycle.test.ts`
  — 95 passed / 4 files, 12.40 s, exit 0 (.tmp/wp0-qodo55-focused.log).
  Затем добавлены ещё два случая array/object status без String coercion;
  они входят в последующий полный прогон. `npm.cmd run typecheck` — exit 0,
  157 channels / 0 public any (.tmp/wp0-qodo55-typecheck.log).
  Coverage AC 927/927 / F 210/210 и diff check — exit 0. Полный suite выполняется.

- Полный `npm.cmd test` после исправления Qodo #55: 3860 passed / 5 skipped,
  246 файлов passed / 2 skipped, 162.18 s, exit 0 (.tmp/wp0-qodo55-full.log).
  Runtime sources после проверки не менялись. Повторное ревью запрашивается
  у Qodo на новом commit; отсутствие ревью не переименовано в approval.

## 18.10.2026 — Qodo #56: DNS и ограниченная диагностика ошибок

- PR #55 на `580d18852f87a7350ae87dec1726dcb6db2ee2f8` прошёл
  [CI 39139062588](https://github.com/newnout6-a11y/vpn/actions/runs/39139062588):
  Windows job 117709516806 — 3861 passed / 4 skipped, 247 файлов passed /
  1 skipped, 225.17 s. Typecheck, трассировка, Electron IPC/CSP, WFP native,
  native reads, Rust и сайт success. Новый вывод Qodo пока не подтверждён;
  пустой обновлённый comment 6251403696 не считается approval.
- PR #56 перебазирован на исправленный #55. Прежний
  [CI 39138333330](https://github.com/newnout6-a11y/vpn/actions/runs/39138333330)
  на `ff1a0433ca86c8a69f36a5405b82ec9b35d61acb` success: Windows
  3876 passed / 4 skipped, 248 файлов passed / 1 skipped, 223.36 s;
  он не проверяет последующие изменения.
- Проверены все четыре замечания [Qodo #56](https://github.com/newnout6-a11y/vpn/pull/56#issuecomment-6251403107).
  Успешный DNS import теперь сохраняет system DNS (null); explicit imported null
  переключает с прежнего custom resolver на системный, omitted selection
  сохраняет прежний выбор. Откат по-прежнему восстанавливает точный snapshot.
- Cancelled export остаётся canonical cancelled на IPC, но feature handler,
  logging wrapper и общий boundary пишут debug вместо error. Остальные
  категории сохраняют error. Логи ошибок config содержат category и allowlisted
  I/O code (например EACCES/ENOSPC/EIO), без произвольных code/message/stack.
  Причины отказа импорта представлены стабильными validationCode, включая
  invalid-json, missing-version, incompatible-version и section-type:<section>;
  сырые значения файла не отражаются в них.
- Новые регрессии до исправления: `npm.cmd test -- src/main/configIpcErrors.test.ts`
  — 14 failed / 19 passed, 515 ms, exit 1 (.tmp/wp0-qodo56-before.log).
  После исправления семь затронутых test files — 131 passed, 9.40 s, exit 0
  (.tmp/wp0-qodo56-focused.log). Затем добавлена проверка arbitrary exception code,
  которая входит в полный suite. `npm.cmd run typecheck` — exit 0,
  157 channels / 0 public any (.tmp/wp0-qodo56-typecheck.log).
- Решение владельца: после #55 ручные запросы Qodo больше не отправлять.
  Существующий запрос #56 не повторяется; читается автоматическое ревью.
  #54 и зависимые PR не сливаются. AT-00-004 целиком, WP-0 и WP-2 не закрыты.
- Точная focused-команда: `npm.cmd test -- src/main/configIpcErrors.test.ts src/main/configManager.test.ts src/main/configImportSecurity.test.ts src/main/configExportSecurity.test.ts src/main/ipcSecurity.test.ts src/main/ipcResultContract.test.ts src/renderer/components/ImportExportSettings.test.tsx`.
- Полный `npm.cmd test` на перебазированной ветке с исправлениями #55/#56:
  3902 passed / 5 skipped / 0 failed, 247 файлов passed / 2 skipped,
  162.16 s, exit 0 (.tmp/wp0-qodo56-full.log).
  `python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py` —
  AC 927/927, F 210/210, exit 0; `git diff --check` — exit 0.
- `npm.cmd run build` — exit 0 (.tmp/wp0-qodo56-build.log);
  `node scripts/test-electron-runtime.mjs` — ELECTRON_SMOKE_PASS, exit 0
  (.tmp/wp0-qodo56-native.log). Production contextBridge сохраняет все семь
  canonical категорий, коды и correlationId на en/ru; config I/O проверяется
  отдельно реальными handlers в local fault matrix, а не этим native fixture.

## 18.10.2026 — Qodo API: точное состояние ревью и второй проход #56

- По предоставленному владельцем доступу проверен официальный MCP endpoint
  `https://sdk.qodo.ai/v1/tools/mcp/`. Ключ не записан в проект, Git или отчёт.
  `litegit-search-repos` подтвердил доступ к newnout6-a11y/vpn;
  `get-pr-review-findings` прочитал структурированные результаты трёх PR.
- #54: completed, run 1539400, commit 9ce9298, findings 0.
  #55: completed, run 1539479, commit 580d188; единственная находка
  ce603cfd имеет attribution_status `implemented`. Это подтверждение Qodo API,
  а не вывод из пустого GitHub summary или ручное снятие блокировки.
- #56: completed, run 1539547, commit 132c3e5. Все четыре прежние находки
  получили `implemented`. Новые: 382ce5a8 (action_required) — rotation:{}
  записывается и ломает следующий import; 81f01bf3 (informational) — file-size,
  non-regular и tamper rejections не имеют диагностического кода.
  Ручные запросы review и ручное изменение статусов findings не выполнялись.
- Новые tests до исправления: `npm.cmd test -- src/main/configIpcErrors.test.ts src/main/configManager.test.ts`
  — 13 failed / 74 passed, 850 ms, exit 1 (.tmp/wp0-qodo56-round2-before.log).
  validateImportData теперь проверяет полную форму RotationConfig до записи;
  обработчики отклоняют rotation:{} и сохраняют прежние stores. Следующий
  корректный import другого раздела работает. Уже повреждённые historical
  stores этим исправлением не мигрируются.
- readSelectedConfig пишет warn с file-too-large / file-not-regular /
  file-changed; последняя причина сохраняет canonical conflict, первые две —
  validation. При отказе capability не выдаётся, listener не остаётся.
  Regression использует реальный большой файл; fstat для non-regular/tamper
  управляется test double, остальные filesystem операции настоящие.
- `npm.cmd test -- src/main/configIpcErrors.test.ts src/main/configManager.test.ts src/main/configImportSecurity.test.ts`
  — 99 passed / 3 files, 1.10 s, exit 0 (.tmp/wp0-qodo56-round2-focused.log).
  `npm.cmd run typecheck` — exit 0, 157 channels / 0 public any
  (.tmp/wp0-qodo56-round2-typecheck.log). Coverage — AC 927/927, F 210/210;
  diff check exit 0. Полный suite выполняется.
- [CI 39139840826](https://github.com/newnout6-a11y/vpn/actions/runs/39139840826)
  на 132c3e5: failure в отдельном native CSP fixture (assert script-src).
  Windows unit: 3903 passed / 4 skipped, 248 файлов passed / 1 skipped,
  201.29 s; typecheck, coverage, build и Electron smoke прошли, Rust и сайт success.
  В CSP fixture ожидание отчётов ограничено фиксированными 500 ms.
  Локальный `node scripts/test-wp1-native.mjs --ipc-only` без правок fixture —
  WP1_NATIVE_PASS, exit 0 (.tmp/wp0-qodo56-csp-recheck.log).
  Причина различия CI/local не объявлена доказанной; новый CI проверит повторно.
- Полный `npm.cmd test` второго прохода — 3915 passed / 5 skipped / 0 failed,
  247 файлов passed / 2 skipped, 201.99 s, exit 0
  (.tmp/wp0-qodo56-round2-full.log). Новая проверка RotationConfig и три
  файловых диагностических отказа входят в этот прогон.
- Финальный `npm.cmd run typecheck` — exit 0, 157 channels / 0 public any
  (.tmp/wp0-qodo56-round2-final-typecheck.log); `npm.cmd run build` — exit 0
  (.tmp/wp0-qodo56-round2-build.log); `node scripts/test-electron-runtime.mjs`
  — ELECTRON_SMOKE_PASS, exit 0 (.tmp/wp0-qodo56-round2-native.log).

### Нативный CSP fixture — ожидание обязательных отчётов

- Вместо фиксированной паузы 500 ms fixture ждёт появления всех четырёх
  обязательных CSP directives, с пределом 5 s. Assertions не ослаблены:
  inline/eval не должны исполниться, каждый требуемый отчёт обязан появиться.
  Это синхронизация асинхронного oracle; production CSP не меняется.
- `node scripts/test-wp1-native.mjs --ipc-only` после изменения fixture —
  WP1_NATIVE_PASS, exit 0 (.tmp/wp0-qodo56-round2-csp.log). Проверены настоящий
  production meta CSP, hostile subframe, unknown WebContents и preferences.
  Это локальные IPC/CSP subsets, а не полный WP-1 L3. Typecheck и build также
  выполнены после изменения fixture. Повтор полного unit suite не нужен:
  fixture запускается отдельно, runtime sources после 3915-pass suite не менялись.

## 18.10.2026 — WP-0: владение main startup, приоритеты и поздние расписания

- Перед следующим участком Qodo API повторно подтвердил exact-head completed:
  #54 9ce9298, run 1539400, 0 findings; #55 580d188, run 1539479,
  единственная finding implemented; #56 6b3c809, run 1539641, все 6 implemented.
  REST подтвердил success CI 39126137175 / 39139062588 / 39140898511.
  Ручных запросов Qodo и изменений finding statuses не было; запрет слияния
  #54 и зависимых PR сохраняется. Новая ветка codex/wp0-operation-ownership
  основана на #56.
- ConnectionLifecycle расширяет production admission lane: UUIDv4, owner,
  timestamp, deadline запуска 120 s по умолчанию, serializable operation
  snapshots и ограниченные audit metadata. Приоритеты recovery > manual >
  schedule > rotation > autopilot > adaptive retry проверены всеми 36 парами.
  Higher-priority start отменяет background startup, ждёт реального native
  settlement и штатной очистки, затем запускает replacement; cleanup failure
  запрещает replacement. Lower-priority stop не отменяет recovery startup.
- Конфликты, отмена и timeout имеют OPERATION_CONFLICT / OPERATION_CANCELLED /
  OPERATION_TIMEOUT и категории в shared result types. Manual cancel не
  превращается позднее в timeout. Signal и terminal metadata меняются сразу;
  caller Promise/busy lease сохраняются до фактического native drain. Это
  намеренно не объявляется полной приёмкой ≤1 s AT-00-003.
- Ручные Hard/Direct, Soft из tray и scheduler используют тот же lane.
  Scheduled admission предшествует async proxy detection и profile selection:
  поздний detector после manual stop не меняет профиль и не запускает VPN.
  Удалённый scheduled profile даёт отказ вместо выбора случайного текущего.
  Уведомления scheduler выдаются после success. Startup/stop effects извлечены
  из wrappers с сохранением существующего native cleanup pipeline.
- Для безопасного replacement исправлено наследованное подавление ошибок env:
  main использует autoconfig.rollbackApplied со строгим isApplied и проверкой
  boolean receipt. Ошибка чтения и false rollback не допускают новый startup.
  Проверяется настоящий autoconfig dispatcher с подменой OS target methods.
- Новые connection regressions до реализации: `npm.cmd test -- src/main/connectionOperations.test.ts`
  — 5 failed / 1 passed, Vitest exit 1 (.tmp/wp0-operations-before.log).
  Env helper regression до реализации: `npm.cmd test -- src/main/autoconfig/index.test.ts`
  — 1 failed / 12 passed, exit 1 (.tmp/wp0-operations-soft-before.log).
- `npm.cmd test -- src/main/autoconfig/index.test.ts src/main/connectionOperations.test.ts src/main/connectionLifecycle.test.ts src/main/scheduledConnection.test.ts src/main/scheduler.test.ts src/main/mainIpcRegression.test.ts src/main/traySource.test.ts src/main/profileTransitionWiring.test.ts`
  — 106 passed / 8 files, 1.03 s, exit 0 (.tmp/wp0-operations-focused.log).
  Fixtures отмены проходят реальные десять async шагов с gate на 10/50/90%;
  late publish отсутствует, cleanup ждёт native settlement. Это connect subset,
  не вся матрица registry/FS/OS AT-00-003.
- Общая FSM, остальные операции, protected restarts/rotation/AutoPilot/adaptive,
  прямые autoconfig IPC, deadline stop, сквозная история/correlation, seeded
  race 200/10 и UI frame matrix остаются открытыми. WP-0 и WP-2 не завершены.
- Первый полный `npm.cmd test`: 36 failed / 3901 passed / 5 skipped,
  13 unhandled errors, 217.00 s, exit 1 (.tmp/wp0-operations-full.log).
  34 отказы lifecycleCleanup были из-за AST harness, загружавшего новые wrappers
  без выделенных production effect bodies. Добавлена загрузка самих bodies,
  проверки ресурсов/истории не ослаблены; два сравнения cancellation проверяют
  также новые category/code. Обновлён старый source assertion scheduler wiring.
  Отдельный splitTunnelDiscovery timeout 5 s при повторе не воспроизвёлся.
- `npm.cmd test -- src/main/lifecycleCleanup.test.ts src/main/splitTunnelDiscovery.test.ts`
  — 158 passed / 2 files, 22.74 s, exit 0 (.tmp/wp0-operations-lifecycle.log).
  Финальный полный suite запущен отдельно после исправления harness.
- `npm.cmd run typecheck` — exit 0, 157 channels / 0 public any
  (.tmp/wp0-operations-typecheck.log); coverage — AC 927/927, F 210/210,
  exit 0. Это трассировка, не исполнение всех AT. `git diff --check` — exit 0.
- Второй полный `npm.cmd test`: 3937 passed / 5 skipped / 0 failed,
  249 файлов passed / 2 skipped, 200.10 s, exit 0
  (.tmp/wp0-operations-final-full.log). Во время этого прогона дополнена проверка
  реального результата выбора scheduled profile (selectProfile сам по себе
  возвращает void при отказе) и добавлены две исполняемые Soft-регрессии main.
  Поэтому перед коммитом будет отдельный полный прогон замороженного кода.
- `npm.cmd test -- src/main/scheduledConnection.test.ts src/main/auditFixesRegression.test.ts`
  — 27 passed / 2 files, 722 ms, exit 0 (.tmp/wp0-operations-scheduler-final.log).
  `npm.cmd test -- src/main/lifecycleCleanup.test.ts` — 151 passed, 24.33 s,
  exit 0 (.tmp/wp0-operations-lifecycle-final.log). Новые Soft fixtures исполняют
  production main wrappers/effects и настоящий helper env rollback с fake OS;
  отменённый apply не публикует защиту, stop ждёт apply и проверяет rollback.
- Окончательный `npm.cmd test` на замороженном runtime/test коде:
  **3939 passed / 5 skipped / 0 failed**, 249 файлов passed / 2 skipped,
  201.04 s, exit 0 (.tmp/wp0-operations-verified-full.log).
  Повторный финальный `npm.cmd run typecheck` — exit 0, 157 channels,
  0 public any (.tmp/wp0-operations-typecheck.log).

### Разрешение владельца: прошедшие проверку PR можно сливать

- Владелец уточнил: «те что прошли проверку можно мержить». Это отменяет
  прежний запрет слияния #54 и зависимых PR. Перед слиянием повторно прочитаны
  completed Qodo exact-head states всех трёх PR и success check-runs Windows,
  Rust и сайта. CodeRabbit/Greptile/Revix не подменяют Qodo approval gate.
- #54 слит merge commit 064bee91f1d7817fa18cd8af6ab77798a544d90c.
  #55 переведён на main и слит 6f7e6d4bfcd728b05bac7eb5a187bfcda03304aa.
  #56 переведён на main и слит 8e4dd209e8a165d014f13e8925ec1ef6e6bd4f54.
  Использован merge commit для сохранения ancestry зависимых веток;
  исходные проверенные head SHA не изменялись. REST подтвердил merged=true.
  Новый WP-0 PR будет направлен в main и также допускает слияние только после
  CI/review gate. Ручных запросов Qodo для #56+ не отправляется.
- `npm.cmd run build` — exit 0 (.tmp/wp0-operations-build.log).
  `node scripts/test-electron-runtime.mjs` — ELECTRON_SMOKE_PASS, exit 0
  (.tmp/wp0-operations-native.log); `node scripts/test-wp1-native.mjs --ipc-only`
  — WP1_NATIVE_PASS, exit 0 (.tmp/wp0-operations-csp.log). Эти IPC/CSP subsets
  не подменяют натурную FSM/ресурсную/сетевую приёмку WP-0/WP-2.
- `git diff HEAD vpn/main` после fetch пуст: слияние #54–56 сохранило ancestry
  и не изменило tree относительно исходной базы текущей ветки. Новый PR имеет
  только изменения текущего участка. Существующие untracked .claude/,
  .wrangler/, .playwright-cli/ и output/ не изменены и в коммит не включаются.

### PR #57 — первый проход Qodo: четыре подтверждённых замечания

- Исходный head 58af276: CI run 39144654589 completed/success. Qodo run
  1539935 completed на том же SHA; две action_required и две
  remediation_recommended находки. До исправления слияние не выполнялось.
- UUIDv4 operationId сохранён согласно тому 3 §1.2. Добавлен стабильный
  correlationId `op_<UUID без дефисов>`: начало/завершение различимы после
  credential redaction. Новый тест использует настоящие appLogger, redactor
  и файловый JSONL backend; credential UUID и password остаются скрытыми.
  Полная IPC/history корреляция AT-00-005 остаётся открытой.
- Ошибка env rollback при stop сохраняет failure result, но не прерывает
  независимую очистку после доказанного завершения runtime: history, watchers,
  snapshots, proxies, traffic, DNS repair и location privacy. Retry stop может
  завершить env recovery; pre-start проверка остаётся строгой. Production-body
  регрессии подтверждают очистку и запрет автоматического replacement.
- Scheduler пробует следующее активное расписание только после явного
  SCHEDULE_PROFILE_UNAVAILABLE. Restart/timer проверены с настоящими helper и
  admission lane. Cancel/conflict/network failure/success не вызывают fallback.
  Generation fence отменяет pending продолжение после ручного действия,
  stop/reinit, редактирования/импорта; время окна перепроверяется.
- Повторный Stop присоединяется к уже выполняющейся очистке recovery/manual
  без второго cleanup, в том числе при меньшем приоритете. Приоритет активного
  recovery startup по-прежнему защищён от менее приоритетного stop.
- До реализации: `npx.cmd vitest run src/main/connectionOperations.test.ts src/main/lifecycleCleanup.test.ts src/main/connectionOperationLogging.test.ts src/main/scheduler.test.ts src/main/scheduledConnection.test.ts`
  — 9 failed / 218 passed, 27.04 s, exit 1 (.tmp/wp0-qodo57-before.log).
- После исправления: `npx.cmd vitest run src/main/connectionOperations.test.ts src/main/lifecycleCleanup.test.ts src/main/connectionOperationLogging.test.ts src/main/scheduler.test.ts src/main/scheduledConnection.test.ts src/main/auditFixesRegression.test.ts`
  — 250 passed / 6 files, 25.58 s, exit 0 (.tmp/wp0-qodo57-final-focused.log).
- `npm.cmd run typecheck` — 157 channels / 0 public any, exit 0
  (.tmp/wp0-qodo57-typecheck.log). `python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py`
  — AC 927/927, F 210/210, exit 0 (трассировка, не исполнение AT).
  `git diff --check` — exit 0. Полный suite и runtime smoke записываются ниже.
- `npm.cmd test` на замороженных runtime/tests — 3959 passed / 5 skipped /
  0 failed, 250 файлов passed / 2 skipped, 203.85 s, exit 0
  (.tmp/wp0-qodo57-full.log). Ожидаемый stderr RootErrorBoundary fixture
  не является отказом suite; unhandled errors отсутствуют.
- `npm.cmd run build` — exit 0 (.tmp/wp0-qodo57-build.log).
  `node scripts/test-electron-runtime.mjs` — ELECTRON_SMOKE_PASS, exit 0
  (.tmp/wp0-qodo57-electron.log); `node scripts/test-wp1-native.mjs --ipc-only`
  — WP1_NATIVE_PASS, exit 0 (.tmp/wp0-qodo57-csp.log). Native IPC/CSP subsets
  не заменяют полную FSM, ресурсную и сетевую приёмку WP-0/WP-2.


### PR #57 слит; WP-0 — интегрированная FSM и проекция состояния

- REST повторно подтвердил merge #57: eaa6db230f0a4245699795edd4c0c92aa6aa393f;
  head b659f83b42f971271f72a0abc211aac2cd7f3e67. CI run 39146042045 success;
  Qodo run 1540108 completed на этом head, четыре findings implemented.
  Открытых PR после слияния не осталось. Новая ветка codex/wp0-tunnel-fsm
  основана на vpn/main с этим merge; старые untracked артефакты не включаются.
- Добавлена используемая production TunnelStateMachine: стабильный state отдельно
  от transition, processState/PID, proxyStatus, health и mode. ConnectionLifecycle
  подтверждает start/stop по evidence; повторный Connect отклоняется до эффектов.
  Raw running и исчезновение competing adapter не очищают fault и не подтверждают
  connected. Ошибка recovery до createWindow видна как unknown в первом snapshot.
- Startup receipts native controller имеют generation fence, включая failure при
  неожиданном throw. Старый receipt после stop или во время нового restart
  отвергается без мутации. Это ещё не общая registry фоновых restart.
- Soft UI использует owned start-soft-protection и единый stop-tun. Boot recovery
  использует strict env evidence/rollback, retained Soft принимает recovery owner
  только при чистом восстановлении. Main snapshot обновляет tray и UI атомарно;
  renderer отбрасывает старые revision и не доверяет legacy success setters.
- Regression harness исполняет настоящие recovery/startup effect bodies с real
  model или observed receipt. Новые зависимости объявлены явно, Soft flag локален;
  старые call-order/resource assertions сохранены. Первый текущий focused run:
  20 failed / 185 passed, exit 1 (.tmp/wp0-fsm-focused-current.log): harness не
  предоставлял tunnelState/native generation и inline boot adoption deps.
  После обновления harness — 205 passed; новые boot/generation/tray/tour/race
  regressions — 217 passed / 5 files, 24.10 s, exit 0
  (.tmp/wp0-fsm-focused-final.log).
- Generated tests: 4096 tours connect/disconnect/crash/retry глубиной 6, fake
  PID/TUN ledger; 200 commands / 10 async workers, seed 0x5eed003, typed losers,
  operation start/terminal pairing и нулевые fake resources после final stop.
  Полный алфавит timeout/cancel, общая durable history и Windows PID/L3 не приняты.
- Первый полный `npm.cmd test`: 3987 passed / 5 skipped / 0 failed,
  252 files passed / 2 skipped, 183.37 s, exit 0 (.tmp/wp0-fsm-full.log).
  `npm.cmd run typecheck`: 158 channels / 0 public any, exit 0
  (.tmp/wp0-fsm-typecheck.log). Coverage AC 927/927, F 210/210, exit 0 —
  трассировка, не исполнение AT. `git diff --check` — exit 0.
- `npm.cmd run build` — exit 0 (.tmp/wp0-fsm-build.log).
  `node scripts/test-electron-runtime.mjs` — ELECTRON_SMOKE_PASS, exit 0
  (.tmp/wp0-fsm-electron.log), включая real FSM/lane через production preload,
  ранний pending running, Soft validation/stop, snapshot event и disposer (fake OS).
  `node scripts/test-wp1-native.mjs --ipc-only` — WP1_NATIVE_PASS, exit 0
  (.tmp/wp0-fsm-csp.log). Нативная сетевая FSM-приёмка этим не подменяется.
- Playwright CLI: production Dashboard + управляемая FSM в .tmp/wp0-fsm-ui;
  light connecting/connected и dark unknown/blocked/reconnect PNG просмотрены.
  Start/confirm/cleanup меняют состояние, pending не показывает активную защиту.
  HMR connection refused после остановки fixture server не считается VPN failure;
  визуальная/a11y/responsive приёмка всей матрицы не заявляется.
- Финальная проверка выявила дополнительный invariant: disconnected с живым
  процессом и connected с потерянным evidence дают unknown; временный отказ
  getter во время startup остаётся sticky после восстановления getter. Добавлены
  регрессии; окончательные проверки после этой правки записываются ниже.
- Окончательный `npm.cmd test` после evidence regressions: **3989 passed /
  5 skipped / 0 failed**, 252 files passed / 2 skipped, 156.43 s, exit 0
  (.tmp/wp0-fsm-verified-full.log). Expected RootErrorBoundary stderr сохранён;
  unhandled errors отсутствуют. Повторный `npm.cmd run typecheck` — exit 0,
  158 channels / 0 public any (.tmp/wp0-fsm-typecheck.log). Coverage и diff check
  повторно exit 0. WP-0 и общий goal остаются в работе.
- Повторные build/Electron/native IPC-CSP на окончательном коде — exit 0: .tmp/wp0-fsm-final-build.log, .tmp/wp0-fsm-final-electron.log, .tmp/wp0-fsm-final-csp.log.


### PR #58 — первый Qodo: пять подтверждённых интеграционных дефектов

- Head 27043513fd54e5463e287bcb28fdc96397c9ae4b опубликован в #58.
  CI run 39149486195 success на этом SHA. Qodo run 1540362 completed:
  три action_required и два remediation_recommended. Слияние не выполнялось.
- Критический gap fake evidence: успешный native poll оставлял pid:null.
  PID теперь читается из Win32_Process с точным сравнением ExecutablePath
  и требованием одного процесса; чужой путь, prefix collision, несколько
  процессов и непрочитанный путь отклоняются. Production poll передаёт этот
  PID в status, затем real FSM/lane подтверждает connected. Отмена/exit/PID
  query failure не публикуют running, failure выполняет прежнюю компенсацию.
  Если main confirmation всё же не получено, lane вызывает cleanup вместо
  оставления startup runtime без владельца. Общий PID Supervisor — ещё WP-2.
- Старые apply-autoconfig/rollback-autoconfig отделяют env от прочих targets:
  env проходит owned Soft start/stop, возвращая false при конфликте/отказе.
  Прямой rollback env под активным native connection отклоняется; повторный
  apply не изменяет уже подключённую защиту. Renderer bootstrap использует
  owned API, не меняет env за спиной FSM и не очищает unknown; сохранённый
  подтверждённый Soft не запускает повторно.
- App после setTunnelSnapshot читает новый Zustand state. Реальные callbacks
  прогоняются вместе с real store/model/lane: IP/leak принимаются после connect,
  подавляются во время stop, старые revision не меняют guard. Это закрывает
  gap между component frames и настоящим App listener wiring.
- Tray сохраняет confirmed firewall lock и leak warning при disconnected.
  Failed adaptive fallback после preserveNetworkProtection stop устанавливает
  unknown без бесконечного reconnecting; throw stop также завершает transition.
  Полная acceptance матрица всех фоновых owner callbacks остаётся открытой.
- Первый focused после правок: 205 passed / 5 files, 23.21 s, exit 0
  (.tmp/wp0-qodo58-focused.log). Затем добавлены исполняемые PowerShell predicate
  fixtures для PID, main confirmation compensation и stop-throw regression.
  `npm.cmd run typecheck` — exit 0, 158 channels / 0 public any
  (.tmp/wp0-qodo58-typecheck.log). Финальные результаты записываются ниже.
- Финальный focused `npm.cmd test -- src/main/tunControllerStartup.test.ts src/main/adaptiveFallbackTransition.test.ts src/main/lifecycleCleanup.test.ts src/main/trayState.test.ts src/main/tunnelStateMachine.test.ts src/renderer/App.lifecycle.test.ts`:
  229 passed / 6 files, 26.27 s, exit 0 (.tmp/wp0-qodo58-focused-final.log).
- Первый полный после Qodo fixes: 1 failed / 4005 passed / 5 skipped,
  178.11 s, exit 1 (.tmp/wp0-qodo58-full.log). Единственный отказ — старый
  source assertion auditFixesRegression требовал удалённый прямой env apply.
  Заменён на owned Soft startup и запрет raw env apply; реальные App bootstrap
  и env owner paths уже покрыты исполняемыми регрессиями, не только source check.
  Повторный полный suite запущен на окончательном runtime/test коде.
- Окончательный `npm.cmd test` на замороженных runtime/tests: **4006 passed /
  5 skipped / 0 failed**, 253 files passed / 2 skipped, 176.60 s, exit 0
  (.tmp/wp0-qodo58-verified-full.log). Typecheck 158/0 any, coverage AC 927/927,
  F 210/210 и diff check — повторно exit 0. Traceability не подменяет AT.
- После пяти Qodo fixes: npm.cmd run build, node scripts/test-electron-runtime.mjs и node scripts/test-wp1-native.mjs --ipc-only — exit 0 (.tmp/wp0-qodo58-build.log, .tmp/wp0-qodo58-electron.log, .tmp/wp0-qodo58-csp.log).

### PR #58 — повторный Qodo: согласование Soft-прокси после renderer reload

- Владелец разрешил сливать прошедшие проверки PR; прежний запрет отменён.
  На cb4b134 CI run 39150959411 success (все три jobs). Qodo run 1540463
  completed на том же SHA: пять прежних findings implemented, новый
  action_required 86fe43a3-e9fb-43a9-8f9e-cd482b8879b4. Слияние отложено до
  исправления: retained Soft сохранял старый env после смены proxy settings.
- App bootstrap теперь передаёт выбранные адрес/протокол owned Soft API и для
  retained connected/soft. Lane разрешает такой refresh только без transition,
  сохраняя exclusivity/cancellation/deadline. Обычный повторный connect и refresh
  поверх native connection отклоняются без эффектов. Env apply сохраняет original
  backup; stop/restart TUN не требуется. Ошибка refresh не публикует успех.
- До runtime fix `npm.cmd test -- src/main/lifecycleCleanup.test.ts src/renderer/App.lifecycle.test.ts`:
  7 failed / 166 passed, 26.35 s, exit 1 (.tmp/wp0-qodo58-soft-before.log).
  После: `npm.cmd test -- src/main/lifecycleCleanup.test.ts src/main/tunnelStateMachine.test.ts src/renderer/App.lifecycle.test.ts`:
  193 passed / 3 files, 26.52 s, exit 0 (.tmp/wp0-qodo58-soft-after.log).
  Дополнительно env regression сверяет все proxy values после refresh и rollback
  к original values; actual PowerShell/Windows environment delivery не заявляется.
- `npm.cmd run typecheck` — exit 0, 158 channels / 0 public any
  (.tmp/wp0-qodo58-soft-typecheck.log). Coverage: AC 927/927, F 210/210, exit 0;
  `git diff --check` — exit 0. Полный suite и native smoke фиксируются ниже.
- Окончательный `npm.cmd test`: **4014 passed / 5 skipped / 0 failed**,
  253 files passed / 2 skipped, 178.11 s, exit 0
  (.tmp/wp0-qodo58-soft-full.log). Expected stderr RootErrorBoundary не означает
  отказ suite; unhandled errors отсутствуют. После suite `npm.cmd run build` —
  exit 0 (.tmp/wp0-qodo58-soft-build.log); `node scripts/test-electron-runtime.mjs`
  — ELECTRON_SMOKE_PASS, exit 0 (.tmp/wp0-qodo58-soft-electron.log);
  `node scripts/test-wp1-native.mjs --ipc-only` — WP1_NATIVE_PASS, exit 0
  (.tmp/wp0-qodo58-soft-csp.log). Это локальные subsets с fake OS, не L3 PASS.

### PR #58 — третий Qodo: компенсация обновления действующей Soft-защиты

- Head 67fc70c: CI run 39151813076 success. Qodo run 1540530 completed на том
  же SHA: шесть прежних findings implemented; новый action_required
  8dff805e-714f-4aa6-a8e2-38c784fb9067. Частичный отказ env refresh выполнял
  eventual-stop rollback к pre-Soft baseline, снимая прежний рабочий прокси.
  Слияние не выполнялось; ручных запросов/изменений finding status нет.
- Refresh сначала строго читает текущие env values в отдельный snapshot.
  Неизвестное значение запрещает mutation. При apply failure snapshot независимо
  восстанавливается по четырём ключам с read-back, даже если первая команда
  вернула ошибку после записи. Durable original backup и pending marker остаются
  для штатного stop. При ошибке компенсации новые настройки не объявляются
  применёнными, lane остаётся в error с cleanupRequired. Значения не логируются.
- До fix `npm.cmd test -- src/main/autoconfig/env.test.ts`: 6 failed / 88 passed,
  376 ms, exit 1 (.tmp/wp0-qodo58-compensation-before.log). После
  `npm.cmd test -- src/main/autoconfig/env.test.ts src/main/autoconfig/index.test.ts src/main/lifecycleCleanup.test.ts`:
  274 passed / 3 files, 26.15 s, exit 0 (.tmp/wp0-qodo58-compensation-after.log).
  Проверены четыре failed-after-write точки, отказ snapshot read, отказ
  compensation и последующий baseline rollback; OS boundaries подменены.
- `npm.cmd run typecheck`: exit 0, 158 channels / 0 public any
  (.tmp/wp0-qodo58-compensation-typecheck.log). Coverage AC 927/927, F 210/210,
  diff check — exit 0. Финальные suite/build/native результаты записываются ниже.
- Финальный `npm.cmd test`: **4020 passed / 5 skipped / 0 failed**,
  253 files passed / 2 skipped, 185.51 s, exit 0
  (.tmp/wp0-qodo58-compensation-full.log). `npm.cmd run build` — exit 0
  (.tmp/wp0-qodo58-compensation-build.log). `node scripts/test-electron-runtime.mjs`
  — ELECTRON_SMOKE_PASS, exit 0 (.tmp/wp0-qodo58-compensation-electron.log);
  `node scripts/test-wp1-native.mjs --ipc-only` — WP1_NATIVE_PASS, exit 0
  (.tmp/wp0-qodo58-compensation-csp.log). Traceability/smoke не подменяют L3.

### PR #58 — собственная проверка boot adoption Soft

- Qodo run 1540585 completed на 470d679: все семь прежних findings implemented,
  новых нет. Собственная проверка обнаружила дополнительный дефект текущего PR:
  startup adoption приравнивала наличие env-backup к успешному прежнему apply.
  Сохранившийся после failed/partial apply receipt давал ложный connected.
- Recovery owner теперь разрешает выбранный proxy и выполняет actual Soft effects
  перед connected. Missing proxy, detector/apply/read failure дают unknown;
  существующий recovery fault не очищается. Backup доказывает cleanup obligation,
  а не активность env. Регрессии исполняют actual adoption + actual Soft effects
  с production lane/FSM и fake OS; исходные trusted/untrusted/absent/fault cases
  сохранены и дополнены apply/resolver failure.
- До fix `npm.cmd test -- src/main/lifecycleCleanup.test.ts -t 'adopts retained Soft only'`:
  4 failed / 3 passed / 163 skipped, 2.92 s, exit 1
  (.tmp/wp0-qodo58-adoption-before.log). После
  `npm.cmd test -- src/main/lifecycleCleanup.test.ts src/main/autoconfig/env.test.ts src/main/autoconfig/index.test.ts src/renderer/App.lifecycle.test.ts`:
  284 passed / 4 files, 29.71 s, exit 0 (.tmp/wp0-qodo58-adoption-after.log).
- `npm.cmd run typecheck` — exit 0, 158 channels / 0 public any
  (.tmp/wp0-qodo58-adoption-typecheck.log). Coverage AC 927/927, F 210/210 и
  diff check — exit 0; дальнейшие окончательные проверки — ниже.
- На 470d679 CI run 39152571062 success; слияние не выполнялось из-за
  дополнительно найденного boot adoption defect. Финальный `npm.cmd test`
  после исправления: **4023 passed / 5 skipped / 0 failed**, 253 files passed /
  2 skipped, 208.83 s, exit 0 (.tmp/wp0-qodo58-adoption-full.log).
  `npm.cmd run build` — exit 0 (.tmp/wp0-qodo58-adoption-build.log);
  `node scripts/test-electron-runtime.mjs` — ELECTRON_SMOKE_PASS, exit 0
  (.tmp/wp0-qodo58-adoption-electron.log); `node scripts/test-wp1-native.mjs --ipc-only`
  — WP1_NATIVE_PASS, exit 0 (.tmp/wp0-qodo58-adoption-csp.log).

### PR #58 слит; следующий участок WP-0 — admission версий хранилищ

- #58 head 552a488afa4b70a251fe50e42eff1d4ee588f27a: CI run 39153223180
  success (Windows, Rust и сайт). Qodo run 1540629 completed на том же SHA,
  открытых findings нет, все семь прежних implemented. REST merge с expected sha
  подтверждён повторным GET: merged=true, merge commit
  4954c84d3f0c25651031d1eb06422b7752983329. Fetch vpn/main и сравнение tree
  подтвердили базу; создана codex/wp0-store-version-guards. Ранее существовавшие
  untracked .claude/.wrangler/.playwright-cli/output не включаются.
- AT-00-006/F-074: central supported-version inventory для 20 electron-store файлов
  и guard до constructor defaults/custom deserializer. Settings/server-picker
  поддерживают 2; остальные остаются unversioned (0), без фиктивной миграции.
  28 production constructors используют тот же adapter, AST contract запрещает
  незарегистрированное имя/обход. Custom history recovery сохранён для известных
  форматов. Future/invalid versions дают стабильные коды и безопасные сообщения.
- Guard перед serializer защищает также set/store replacement/clear/delete/reset
  через старый handle после появления будущей версии. SHA-256 сравнивается на
  real Conf backend. Actual imports settings/sharedStores/history проверяют
  отказ до defaults, repairing deserializer и secret migration effects.
- До подключения adapter `npm.cmd test -- src/main/storeSchemaStorage.test.ts`:
  3 failed / 38 passed, 969 ms, exit 1 (.tmp/wp0-store-schema-before.log).
  Три actual production imports принимали future schema вместо отказа.
  Первый focused после integration: 112 passed / 5 files, 3.31 s, exit 0
  (.tmp/wp0-store-schema-after.log). После дополнительных actual group/granular
  entrypoints и clearInvalidConfig regression: 115 passed / 5 files, 2.79 s,
  exit 0 (.tmp/wp0-store-schema-focused-final.log).
- Ordered migrations, historical payload transformation fixtures, backup/checksum/
  dry-run/rollback для остальных persisted JSON и cross-version acceptance
  не объявлены выполненными. Interprocess write lock не вводился; race внешней
  записи между guard read и atomic rename не доказана. F-074 и весь AT-00-006
  остаются частичными. Финальные DoD/build/native результаты записываются ниже.
- Финальный `npm.cmd test`: **4068 passed / 5 skipped / 0 failed**,
  255 files passed / 2 skipped, 210.11 s, exit 0 (.tmp/wp0-store-schema-full.log).
  `npm.cmd run typecheck` — exit 0, 158 channels / 0 public any
  (.tmp/wp0-store-schema-typecheck-final.log). Coverage AC 927/927, F 210/210,
  `git diff --check` — exit 0. Нормативные docs не изменялись.
- После full suite `npm.cmd run build` — exit 0 (.tmp/wp0-store-schema-build.log);
  `node scripts/test-electron-runtime.mjs` — ELECTRON_SMOKE_PASS, exit 0
  (.tmp/wp0-store-schema-electron.log); `node scripts/test-wp1-native.mjs --ipc-only`
  — WP1_NATIVE_PASS, exit 0 (.tmp/wp0-store-schema-csp.log). Это не полный
  installed upgrade/downgrade и не L3. CI/Qodo проверяются после публикации.

### Qodo #59 — отказ несовместимого store при static import

- CI run 39154442970 на 1d9f844 — success. Qodo run 1540747 completed на том же
  SHA: finding e819a34b-d5ef-4ca7-9f80-e11b3a47bdc4, «Users get no storage refusal
  message». Подтверждено: constructor исполняется до установки main startup/crash
  boundary. Добавлен ранний native error box только для StoreSchemaError до ready,
  sanitized code в stderr и app.exit(1) без main network teardown. Запись app.log
  не заявляется. После ready ошибка остаётся у существующей IPC/startup boundary.
- Unit tests проверяют все три кода, отсутствие недоверенных message/path/secret
  и exit при отказе dialog. Native test использует настоящий pinned Electron,
  production Store adapter, real electron-store/Conf и isolated userData;
  перехватывается только popup. До ready — message перед настоящим exit 1;
  после ready — typed error до caller catch, без early dialog. Future file hash
  неизменен. Созданные fixture directories удаляются самим тестом.
- `npm.cmd test -- src/main/storeSchemaStorage.test.ts src/main/storeSchemaStartup.test.ts src/main/storeSchemaElectron.test.ts src/main/storeSchemaInventory.test.ts`
  — 52 passed / 4 files, 1.97 s, exit 0 (.tmp/wp0-store-schema-startup-focused.log).
  `npm.cmd run typecheck` — exit 0, 158 channels / 0 public any
  (.tmp/wp0-store-schema-startup-typecheck.log). Traceability checker — exit 0,
  AC 927/927, F 210/210 (трассировка, не исполнение AT).
- Финальный `npm.cmd test` — **4075 passed / 5 skipped / 0 failed**, 257 files
  passed / 2 skipped, 213.13 s, exit 0 (.tmp/wp0-store-schema-startup-full.log).
  После него `npm.cmd run build` — exit 0 (.tmp/wp0-store-schema-startup-build.log);
  `node scripts/test-electron-runtime.mjs` — ELECTRON_SMOKE_PASS, exit 0
  (.tmp/wp0-store-schema-startup-electron.log); `node scripts/test-wp1-native.mjs --ipc-only`
  — WP1_NATIVE_PASS, exit 0 (.tmp/wp0-store-schema-startup-csp.log). `git diff --check`
  — exit 0. Это не installed upgrade/downgrade и не полная приёмка AT-00-006.

### PR #59 слит; AT-00-003 — caller cancellation отдельно от native drain

- #59 head 7cef991be4e6e774f76ed2b4f70a336828050f5a: CI run 39155420961
  completed/success (все три jobs). Qodo run 1540820 completed на том же SHA,
  новых findings нет, прежний e819a34b implemented. REST merge с expected sha
  подтверждён повторным GET: merged=true, merge commit
  12bfe8be1c6889e9769dcbfc4c8578d95caccec9. Fetch vpn/main подтвердил базу;
  следующий участок в codex/wp0-prompt-start-cancellation.
- Новый regression `npm.cmd test -- src/main/connectionCancellation.test.ts`
  до исправления — **5 failed**, 360 ms, exit 1 (.tmp/wp0-prompt-cancel-before.log):
  caller ждал native gate на 10/50/90%, deadline и shutdown. Теперь caller races
  abort с отдельной внутренней задачей; busy lease и stop/close ждут actual drain
  и cleanup. Исходная уже известная ошибка сохраняется, поздний reject наблюдается,
  terminal connect event не повторяется. Synchronous admission cancellation
  запрещает первый effect. Это startup subset; полный AT-00-003 ещё не принят.
- Первый focused после разделения caller/drain — 215 passed / 2 failed:
  старый тест ожидал немедленного освобождения startup после caller cancellation;
  второй потребовал сохранить исходную startup failure до отмены. Ошибка сохранена
  в production, тест ownership теперь явно ждёт drain. Следующий focused —
  218 passed / 6 files, 33.32 s, exit 0. Затем добавлен synchronous admission case
  и усилены actual main Hard/Direct preflight/native/fault assertions: typed ответ
  должен прийти до release gate (timeout 900 ms), cleanup и late history ждут gate.
- Финальный focused тех же шести файлов — **219 passed**, 33.86 s, exit 0
  (.tmp/wp0-prompt-cancel-focused-final.log). `npm.cmd run typecheck` — exit 0,
  158 channels / 0 public any (.tmp/wp0-prompt-cancel-typecheck.log). Coverage
  AC 927/927, F 210/210 — exit 0 (трассировка, не исполнение AT).
  Native fixture расширена: actual production preload/contextBridge должен
  вернуть typed cancellation до 900 ms при закрытом native gate; admission
  остаётся закрытым до release и stop, ложного connected нет.
- Полный `npm.cmd test` — **4081 passed / 5 skipped / 0 failed**, 258 files
  passed / 2 skipped, 218.62 s, exit 0 (.tmp/wp0-prompt-cancel-full.log).
  `npm.cmd run build` — exit 0 (.tmp/wp0-prompt-cancel-build.log).
  `node scripts/test-electron-runtime.mjs` — ELECTRON_SMOKE_PASS, exit 0
  (.tmp/wp0-prompt-cancel-electron.log), включая новый native bridge cancellation
  subset. `node scripts/test-wp1-native.mjs --ipc-only` — WP1_NATIVE_PASS, exit 0
  (.tmp/wp0-prompt-cancel-csp.log). Повторные coverage и `git diff --check` — exit 0.
  Нативный smoke использует настоящий Electron, но fake OS effects; это не
  Windows PID/packet oracle и не полный AT-00-003. F-021 остаётся опровергнутой.

### PR #60 слит; AT-00-002 — timeout/cancel в полном алфавите туров

- #60 head eae345f4eb9e13333980e657c4b46affbc1189f4: Qodo run 1540930
  completed на том же SHA, findings пусты. Первый CI 39156721492 прошёл unit,
  typecheck, coverage и native IPC/CSP, затем упал на WFP InterfaceLuid (Windows
  error 87). WFP-код в PR не изменялся. Повтор только failed Windows job на том же
  SHA: run_attempt 2 completed/success, все три jobs зелёные. Причина первого
  отказа не установлена; он не скрывается и не объявляется исправленным.
- REST merge с expected sha подтверждён повторным GET: merged=true, merge commit
  e7d4e6c8e121163d3344d84a485f51688d38517d. Открытых PR после слияния нет.
  Fetch vpn/main подтвердил базу codex/wp0-model-timeout-cancel-tours.
- Новый L2 model harness исполняет все 117649 туров глубиной 6 с seed 0x5eed002:
  connect/complete/disconnect/crash/timeout/cancel/retry. Complete — отдельный
  native gate; production lane/FSM проверяются независимым state/resource oracle.
  Каждый шаг проверяет PID/TUN, busy, typed invalid transitions без mutation
  и парные operation events; отмена/timeout отвечают до drain, crash запрещает
  поздний connected. После каждого тура — cleanup и 0 fake ресурсов.
- `npm.cmd test -- src/main/connectionModelTours.test.ts` — 1 passed
  (117649 tours), 15.96 s, exit 0 (.tmp/wp0-model-alphabet-focused.log).
  Это дополнительное доказательство, код production не менялся. Полный набор
  blocked/unknown/background paths, durable history/counters и native Windows
  resource oracle остаются; весь AT-00-002 не объявляется PASS.
- Первый `npm.cmd run typecheck` — exit 2, TS7022 на локальном result в model
  fixture. Добавлена явная аннотация Outcome (без any и изменения поведения);
  повтор — exit 0, 158 channels / 0 public any
  (.tmp/wp0-model-alphabet-typecheck-final.log). Полный `npm.cmd test` —
  **4082 passed / 5 skipped / 0 failed**, 259 files passed / 2 skipped,
  225.10 s, exit 0 (.tmp/wp0-model-alphabet-full.log). Coverage AC 927/927,
  F 210/210 и `git diff --check` — exit 0. В этом участке только тест и журнал/
  матрица; локальные build/native smoke повторно не запускались, production
  идентичен принятому #60. CI/Qodo нового PR проверяются после публикации.

### Qodo #61 — независимый счётчик принятых операций

- Qodo run 1541078 completed на b979009: finding
  17d13129-2a60-45e1-8d17-15800bacc220 «Missing stop events pass every tour».
  Подтверждено: баланс только имеющихся ID не замечал полностью отсутствующую
  пару running/terminal stop. Oracle теперь независимо считает admitted connect/
  disconnect по командам модели и сверяет число уникальных ID каждого вида
  после каждого шага и финальной cleanup. Timeout auto-stop + explicit join
  должны записать ровно одну disconnect operation.
- Mutation fixtures исполняют настоящий lane start/stop и удаляют сразу оба
  события connect либо disconnect. `npm.cmd test -- src/main/connectionModelTours.test.ts -t 'rejects an audit'`
  до исправления — **2 failed / 1 skipped**, 235 ms, exit 1
  (.tmp/wp0-model-qodo61-before.log): оба случая Missing expected exception.
- После исправления `npm.cmd test -- src/main/connectionModelTours.test.ts` —
  **3 passed** (117649 tours + 2 mutation fixtures), 18.22 s, exit 0
  (.tmp/wp0-model-qodo61-focused.log). `npm.cmd run typecheck` — exit 0,
  158 channels / 0 public any (.tmp/wp0-model-qodo61-typecheck.log). Coverage
  AC 927/927, F 210/210 — exit 0. CI 39158140795 исходного b979009 completed/
  success, включая WFP; после исправления нужны новый CI и completed Qodo.
- Полный `npm.cmd test` после исправления — **4084 passed / 5 skipped / 0 failed**,
  259 files passed / 2 skipped, 191.21 s, exit 0 (.tmp/wp0-model-qodo61-full.log).
  `git diff --check` — exit 0. Production-код не менялся; локальные build/native
  smoke повторно не запускались. Это исправление model oracle, не WFP runtime.

### PR #61 слит; AT-00-005 — общий action correlation

- #61 head 76e253dc944e8631baa69a95f1345f2e937796bf: Qodo 1541166 completed,
  прежнее замечание implemented, новых findings нет. CI 39158907423 completed/
  success, все jobs зелёные. REST merge с expected SHA подтверждён повторным GET:
  merged=true, merge commit 63017cfcae7404384fd9505cd01000def4dd3855.
  База следующей ветки codex/wp0-action-correlation — этот merge. Повторный REST
  список открытых PR перед публикацией текущего участка — пуст.
- Подтверждённый разрыв: transport UUID, audit ipc_<hex> и lifecycle op_<hex>
  не совпадали для одного действия. `npm.cmd test -- src/main/actionCorrelation.test.ts`
  до исправления — **1 failed**, 522 ms, exit 1
  (.tmp/wp0-action-correlation-before.log). Main теперь генерирует один prefixed
  UUIDv4, сохраняет его в async context и передаёт без преобразований через IPC,
  connect/stop operation events и JSONL logger. Таймаут/recovery и late drain
  сохраняют исходное действие; ручной stop получает собственное. Raw UUID/строки
  с payload в trusted context запрещены. Decoder поддерживает legacy UUIDv4.
- Focused `npm.cmd test -- src/main/actionCorrelation.test.ts src/main/actionCorrelationScope.test.ts src/main/ipcAuditLog.test.ts src/main/connectionOperationLogging.test.ts src/shared/ipc-result.test.ts src/main/ipcContractAcceptance.test.ts src/main/connectionOperations.test.ts`
  — **433 passed / 7 files**, 1.29 s, exit 0
  (.tmp/wp0-action-correlation-focused-final.log). После добавления assertions
  production getFullLogs с повторной redaction — те же **433 passed**, 1.32 s,
  exit 0 (.tmp/wp0-action-correlation-readback.log). В fixture настоящие JSONL
  disk writes, параллельные actions завершаются в обратном порядке; credentials
  не сохраняются, correlationId переживает diagnostic read-back. Scope fixtures
  проверяют nested sync/async failure, canonical ID, timeout и manual stop.
- Временная папка первого failed fixture .tmp/action-correlation-2v2R0u осталась
  ignored: автоматическая policy отклонила её удаление. Обход не выполнялся.
  Следующие fixtures ждут завершения очереди записи перед assertions/cleanup.
  Durable connection history, source/owner/route/confidence и monotonic ordering
  пока не входят в изменение; весь AT-00-005 и WP-0 не объявляются PASS.
- Первый полный `npm.cmd test` — **32 failed / 4065 passed / 5 skipped**,
  186.49 s, exit 1 (.tmp/wp0-action-correlation-full.log). Все падения — общий
  expectFailure в configIpcErrors: прежний regex допускал только bare UUID.
  Обновлён на строгий ipc_<UUIDv4 hex>; `npm.cmd test -- src/main/configIpcErrors.test.ts`
  — **38 passed**, 504 ms, exit 0 (.tmp/wp0-action-correlation-config.log).
  Повторный полный `npm.cmd test` на итоговом коде с diagnostic read-back —
  **4097 passed / 5 skipped / 0 failed**, 261 files passed / 2 skipped,
  179.42 s, exit 0 (.tmp/wp0-action-correlation-full-final.log).
- `npm.cmd run typecheck` после native fixture и read-back assertions — exit 0,
  158 channels / 0 public any (.tmp/wp0-action-correlation-typecheck-native.log).
  `python docs/04-приёмочные-тесты/traceability/check-coverage.py` из корня — exit 0,
  AC 927/927, F 210/210: только трассировка, не исполнение AT.
- `npm.cmd run build` — exit 0 (.tmp/wp0-action-correlation-build.log).
  `node scripts/test-electron-runtime.mjs` — ELECTRON_SMOKE_PASS, exit 0
  (.tmp/wp0-action-correlation-electron.log): actual production contextBridge
  сохраняет общий correlation ID для семи error categories в обеих локалях,
  lifecycle context остаётся тем же до/после native wait. `node scripts/test-wp1-native.mjs --ipc-only`
  — WP1_NATIVE_PASS, exit 0 (.tmp/wp0-action-correlation-csp.log).
  Повторные `python ../docs/04-приёмочные-тесты/traceability/check-coverage.py`
  из app (AC 927/927, F 210/210) и `git diff --check` — exit 0.
  Native smoke использует настоящий Electron с fake OS effects; это не Windows
  packet/PID oracle, не вся история действий и не полный AT-00-005.

### Qodo #62 — не наследовать завершённое действие фоновыми таймерами

- Опубликован PR #62, head 11b8acc7408d9d03e0bdb1fcaf57b38691b8b918.
  CI 39160769232 completed/success на этом SHA. Qodo 1541356 completed:
  083bae3e-3ce0-43c4-a375-178855e609b8 — schedule timer/re-arm сохраняет ID UI edit;
  a3ee6b73-56d4-44f9-ac18-94044c65207d — background tunnel timers сохраняют ID
  завершённого connect. Оба подтверждены; PR до устранения не сливался.
- `npm.cmd test -- src/main/actionCorrelationScope.test.ts src/main/schedulerActionCorrelation.test.ts`
  до исправления — **6 failed / 6 passed**, 368 ms, exit 1
  (.tmp/wp0-action-correlation-qodo62-before.log). Настоящие Node timers нужны,
  потому что fake timers не воспроизводят async_hooks inheritance. Production
  scheduler исполняет последовательные connect/stop/connect с re-arm; сжаты
  только его задержки и Date.now, сам scheduler/lane не подменены.
- Async scope теперь имеет active lease до sync return/throw либо settlement
  исходного Promise. Detached timers наследуют истёкший lease и не получают
  correlationId; новая scheduled operation создаёт свежий op_ ID. Внутренний
  drain scope сохраняет ID после раннего caller cancellation до реального
  завершения native effect. Исходная identity/rejection Promise сохраняется.
- `npm.cmd test -- src/main/actionCorrelation.test.ts src/main/actionCorrelationScope.test.ts src/main/schedulerActionCorrelation.test.ts src/main/scheduler.test.ts src/main/connectionCancellation.test.ts src/main/connectionOperationLogging.test.ts`
  — **74 passed / 6 files**, 1.05 s, exit 0
  (.tmp/wp0-action-correlation-qodo62-focused.log). `npm.cmd run typecheck` —
  exit 0, 158 channels / 0 public any (.tmp/wp0-action-correlation-qodo62-typecheck.log).
  Coverage AC 927/927, F 210/210 и `git diff --check` — exit 0. Полный
  `npm.cmd test` после исправления — **4103 passed / 5 skipped / 0 failed**,
  262 files passed / 2 skipped, 198.01 s, exit 0
  (.tmp/wp0-action-correlation-qodo62-full.log). CI/Qodo исходного SHA
  не считаются проверкой этого исправления.
- Повторный `npm.cmd run build` — exit 0
  (.tmp/wp0-action-correlation-qodo62-build.log). `node scripts/test-electron-runtime.mjs`
  — ELECTRON_SMOKE_PASS, exit 0 (.tmp/wp0-action-correlation-qodo62-electron.log).
  `node scripts/test-wp1-native.mjs --ipc-only` — WP1_NATIVE_PASS, exit 0
  (.tmp/wp0-action-correlation-qodo62-csp.log). Повторные coverage AC 927/927,
  F 210/210 и `git diff --check` — exit 0. Границы AT-00-005 сохранены.

### PR #62 слит; AT-00-005 — correlation в durable connection history

- #62 head a428537549b75f2c2f493e09da9c47b7ce2efd1a: Qodo 1541435 completed,
  оба прежних findings implemented, новых нет. CI 39161646890 completed/success,
  run_attempt 1, все три jobs зелёные на том же SHA. REST merge с expected SHA
  подтверждён повторным GET: merged=true, merge commit
  10ecc8c0e54bd5a8f5d34b3e9d1e137f8da04095. Открытых PR после слияния нет.
  Fetch vpn/main подтвердил базу codex/wp0-session-correlation.
- Подтверждён остаток: LiveSession и два writer path истории не сохраняли ID
  исходного connect. `npm.cmd test -- src/main/connectionHistoryStorage.test.ts`
  до исправления — **9 failed / 37 passed**, 2.45 s, exit 1
  (.tmp/wp0-session-correlation-before.log). Main теперь захватывает correlationId
  при openSession и переносит его при writeSessionEntry; recordStartFailure
  берёт ID своей попытки. ID ручной остановки не подменяет ID подключения.
- Поле optional для прежних и untracked sessions, без выдуманного ID. Reader
  и writer принимают только canonical ipc_/op_ UUIDv4; raw credential UUID,
  произвольные строки, newline и malformed values отвергаются с прежней
  history.corrupted/rejected retention гарантией. JSON сохраняет поле, CSV
  дополняется последним столбцом correlationId; порядок прежних столбцов сохранён.
- `npm.cmd test -- src/main/connectionHistoryStorage.test.ts src/main/connectionHistory.test.ts src/main/lifecycleCleanup.test.ts src/main/actionCorrelation.test.ts`
  — **249 passed / 4 files**, 24.38 s, exit 0
  (.tmp/wp0-session-correlation-focused.log). Fixture исполняет реальные четыре
  функции учёта сессии из index.ts с real Conf backend; закрытие под новым action
  либо без контекста сохраняет исходный ID после reload и в обоих export formats.
  Дополнительный end-to-end fixture использует guarded IPC и production lane.
- Первый `npm.cmd run typecheck` — exit 0, 158 channels / 0 public any
  (.tmp/wp0-session-correlation-typecheck.log). Coverage AC 927/927, F 210/210
  и `git diff --check` — exit 0. Полные AT-00-005, source/owner/route/confidence,
  monotonic ordering и все background/Soft history paths остаются открытыми.
- Финальный focused тех же четырёх файлов с guarded IPC → production lane →
  main session functions → real Conf reload — **250 passed**, 31.58 s, exit 0
  (.tmp/wp0-session-correlation-focused-final.log). Новый stop ID отличается
  от start response, persisted history совпадает со start. Повторный
  `npm.cmd run typecheck` — exit 0, 158 channels / 0 public any
  (.tmp/wp0-session-correlation-typecheck-final.log). Повторные coverage и
  `git diff --check` — exit 0. Полный `npm.cmd test` — **4113 passed / 5 skipped /
  0 failed**, 262 files passed / 2 skipped, 216.32 s, exit 0
  (.tmp/wp0-session-correlation-full.log).
- `npm.cmd run build` — exit 0 (.tmp/wp0-session-correlation-build.log).
  `node scripts/test-electron-runtime.mjs` — ELECTRON_SMOKE_PASS, exit 0
  (.tmp/wp0-session-correlation-electron.log). `node scripts/test-wp1-native.mjs --ipc-only`
  — WP1_NATIVE_PASS, exit 0 (.tmp/wp0-session-correlation-csp.log). Повторные
  coverage AC 927/927, F 210/210 и `git diff --check` — exit 0. Native smoke
  сохраняет прежний fake OS scope; новый session/disk proof — адресный L2 fixture.

### Qodo #63 — ранний tray failure до lifecycle admission

- PR #63 head 8f0288a9f915e85ed7952c2602a0cbbdba9754e6: CI 39163040617
  completed/success, все jobs зелёные. Qodo 1541555 completed с finding
  c72517fc-c254-4004-9986-55faec2f055c: missing-proxy Hard start из трея вызывает
  recordStartFailure до lifecycle и не имеет action ID. Замечание подтверждено,
  до исправления PR не сливался.
- `npm.cmd test -- src/main/connectionHistoryStorage.test.ts -t 'missing-proxy tray'`
  до исправления — **1 failed / 47 skipped**, 1.11 s, exit 1
  (.tmp/wp0-session-correlation-qodo63-before.log). Actual tray/session bodies
  пишут две попытки через real Conf, но correlationId отсутствовал.
- Контекст создаётся на входе startProtectionFromTray до async proxy detection
  и раннего отказа. Existing body перенесён в effects-функцию без изменения
  routing/notifications; lifecycle использует тот же ID при последующем admission.
  Каждая новая попытка получает свежий op_ UUIDv4, scope истекает после action.
- `npm.cmd test -- src/main/connectionHistoryStorage.test.ts src/main/connectionHistory.test.ts src/main/lifecycleCleanup.test.ts src/main/actionCorrelationScope.test.ts`
  — **261 passed / 4 files**, 33.03 s, exit 0
  (.tmp/wp0-session-correlation-qodo63-focused.log). `npm.cmd run typecheck` —
  exit 0, 158 channels / 0 public any (.tmp/wp0-session-correlation-qodo63-typecheck.log).
  Coverage AC 927/927, F 210/210 и `git diff --check` — exit 0. Полный
  `npm.cmd test` после исправления — **4114 passed / 5 skipped / 0 failed**,
  262 files passed / 2 skipped, 223.82 s, exit 0
  (.tmp/wp0-session-correlation-qodo63-full.log). Успешный CI исходного SHA
  не считается проверкой исправления.
- Повторный `npm.cmd run build` — exit 0
  (.tmp/wp0-session-correlation-qodo63-build.log). Повторные coverage AC 927/927,
  F 210/210 и `git diff --check` — exit 0.
- `node scripts/test-electron-runtime.mjs` — ELECTRON_SMOKE_PASS, exit 0
  (.tmp/wp0-session-correlation-qodo63-electron.log).
  `node scripts/test-wp1-native.mjs --ipc-only` — WP1_NATIVE_PASS, exit 0
  (.tmp/wp0-session-correlation-qodo63-csp.log). Native/fake OS границы сохранены.

### PR #63 — итоговая проверка и слияние

- Итоговый head a1ec56750c41e7737a0b1ec59043afa149a24f2f: Qodo 1541648
  completed, прежний finding implemented, новых нет. CI 39163970896
  completed/success, attempt 1, все три jobs зелёные на этом SHA.
- PR #63 слит после проверок по разрешению владельца; REST GET merged=true,
  merge 865c2db576727594b82c549fb69128c3d0f2d109.

## WP-0 — provenance истории сессии (18.10.2026)

- AT-00-005 / F-143: новые записи history требуют source/owner/route/confidence.
  Source берётся с границы действия, owner — из фактического admission, origin
  хранится в LiveSession до закрытия. Новый stop не переписывает происхождение.
  Runtime без контекста получает runtime/unknown; missing-proxy tray failure —
  tray/manual. Lifecycle сохраняет metadata вместе с ID для drain/timer/events.
- Route — настроенный механизм tun/soft-env либо unconfirmed на failed start;
  не аттестация маршрута каждого пакета. Confidence классифицирует причину
  завершения: observed/inferred/indeterminate, не степень защиты соединения.
- Legacy read без provenance сохранён; new write без него запрещён. Reader
  отвергает недопустимые enums, лишние поля и mismatch route/mode, сохраняя
  повреждённые записи с history.corrupted. JSON/CSV и повторный real Conf read
  сохраняют все четыре поля. Нормативные docs не изменялись; F-021 не исправляется.
- До исправления `npm.cmd test -- src/main/connectionHistoryStorage.test.ts` —
  **29 failed / 47 passed**, 4.35 s, exit 1
  (.tmp/wp0-session-provenance-before.log).
- `npm.cmd test -- src/main/connectionHistoryStorage.test.ts src/main/connectionHistory.test.ts src/main/actionCorrelationScope.test.ts src/main/schedulerActionCorrelation.test.ts src/main/connectionOperations.test.ts src/main/lifecycleCleanup.test.ts`
  — **311 passed / 6 files**, 26.20 s, exit 0
  (.tmp/wp0-session-provenance-focused-final.log).
- `npm.cmd run typecheck` — exit 0, 158 channels / 0 public any
  (.tmp/wp0-session-provenance-typecheck-final.log).
- AT-00-005 целиком не закрыт: monotonic ordering, фактические Soft sessions
  и полная матрица background paths остаются. Fixture mode coverage не заменяет
  интеграцию каждого реального entrypoint.
- Полный `npm.cmd test` — **4149 passed / 5 skipped / 0 failed**,
  262 files passed / 2 skipped, 203.71 s, exit 0
  (.tmp/wp0-session-provenance-full.log). `python ../docs/04-приёмочные-тесты/traceability/check-coverage.py`
  — AC 927/927, F 210/210, exit 0; `git diff --check` — exit 0.
- `npm.cmd run build` — exit 0 (.tmp/wp0-session-provenance-build.log).
  `node scripts/test-electron-runtime.mjs` — ELECTRON_SMOKE_PASS, exit 0
  (.tmp/wp0-session-provenance-electron.log); добавлены assertions source/owner
  в production guarded IPC и настоящем lifecycle под Electron 44.4.3.
  `node scripts/test-wp1-native.mjs --ipc-only` — WP1_NATIVE_PASS, exit 0
  (.tmp/wp0-session-provenance-csp.log). Это native IPC/CSP с fake OS effects,
  не Windows packet/resource acceptance.

### PR #64 — проверка и слияние

- Head 654b922dbc06eabba84ce3b35814d06c73331339: Qodo 1541785 completed,
  findings 0. CI 39165512419 completed/success, все три jobs зелёные на этом SHA.
- Слит после проверок по разрешению владельца; REST GET merged=true,
  merge 964f8020f429455557f32c08ad3a287d2cdfedb5.

## WP-0 — монотонное время событий (19.10.2026)

- AT-00-005 / F-143: JSONL, временные метки lifecycle admission, начало/конец
  сессий, failed-start history и in-app notification используют общий main clock.
  Календарное время якорится к process.hrtime.bigint при загрузке модуля;
  последующие Windows/NTP/manual corrections не меняют порядок событий.
  Разрешение — миллисекунда, одинаковые timestamp допустимы. Это одна временная
  шкала текущего main-процесса, не синхронизация разных процессов/перезапусков.
- Таймеры deadline не заменены календарным сравнением. Heuristic evidence,
  TTL и внешние file timestamps по-прежнему используют свою исходную шкалу.
- До исправления `npm.cmd test -- src/main/actionCorrelation.test.ts src/main/connectionHistoryStorage.test.ts src/main/eventClock.test.ts`
  — **3 failed / 79 passed**, 4.06 s, exit 1
  (.tmp/wp0-event-time-before.log): две production-регрессии и отсутствующий
  новый clock module. System clock rollback переставлял JSONL events и давал
  session endedAt < startedAt.
- `npm.cmd test -- src/main/actionCorrelation.test.ts src/main/connectionHistoryStorage.test.ts src/main/eventClock.test.ts src/main/connectionOperations.test.ts src/main/actionCorrelationScope.test.ts src/main/appLoggerRedaction.test.ts src/main/appLoggerRotation.test.ts src/main/lifecycleCleanup.test.ts`
  — **289 passed / 8 files**, 36.47 s, exit 0
  (.tmp/wp0-event-time-focused-final.log). Проверены rollback/forward jump часов,
  real on-disk JSONL через production IPC/lane, порядок persisted session/failure
  и lifecycle start/stop; ID и redaction сохраняются.
- `npm.cmd run typecheck` — exit 0, 158 channels / 0 public any
  (.tmp/wp0-event-time-typecheck.log). Полный AT-00-005 пока не объявляется PASS:
  полные Soft/background paths и матрица их событий ещё остаются.
- Полный `npm.cmd test` — **4152 passed / 5 skipped / 0 failed**,
  263 files passed / 2 skipped, 229.37 s, exit 0
  (.tmp/wp0-event-time-full.log). Coverage `python docs/04-приёмочные-тесты/traceability/check-coverage.py`
  — AC 927/927, F 210/210, exit 0; `git diff --check` — exit 0.
- `npm.cmd run build` — exit 0 (.tmp/wp0-event-time-build.log).
  `node scripts/test-electron-runtime.mjs` — ELECTRON_SMOKE_PASS, exit 0
  (.tmp/wp0-event-time-electron.log); `node scripts/test-wp1-native.mjs --ipc-only`
  — WP1_NATIVE_PASS, exit 0 (.tmp/wp0-event-time-csp.log). Scope прежний:
  настоящий Electron/contextBridge/CSP и fake OS effects, не packet/OS-matrix L3.

### Qodo #65 — календарное время отдельно от порядка и длительности

- На head 20e6802a1b20975ba5c6ff7159d5e3c04c9e586b Qodo 1541885 completed
  с finding 0b666add-55b5-4472-b2d1-e0a2dd9546a1: clock changes misdate session
  history. Замечание верное: process-anchored epoch не следовал исправленным
  календарным часам, а filter/stats/UI использовали настоящие даты. PR не слит.
  Предыдущее описание anchored calendar clock выше относится к этому
  отклонённому варианту, а не к итоговой реализации.
- До исправления `npm.cmd test -- src/main/actionCorrelation.test.ts src/main/connectionHistoryStorage.test.ts src/main/eventClock.test.ts src/shared/connection-history.test.ts`
  — **4 failed / 79 passed**, 1 suite failed (отсутствующий helper), 4.31 s,
  exit 1 (.tmp/wp0-event-time-qodo65-before.log). Production-regressions проверяют
  calendar dates после backward/forward correction и JSONL ordering metadata.
- Итог: календарные ts/startedAt/endedAt/deadline/notifications снова читают
  системное время. JSONL дополнен monotonicMs и непривязанным к секретам clockId,
  различающим origins после рестарта. Session durationMs вычисляется по hrtime;
  stats и renderer duration/sort/failure heuristic используют общий helper.
  Отрицательные legacy durations ограничены нулём, новые записи требуют
  конечное неотрицательное durationMs. Старые записи читаются, JSON/CSV сохраняют
  поле; неверные duration удерживаются с history.corrupted.
- `npm.cmd test -- src/main/actionCorrelation.test.ts src/main/connectionHistoryStorage.test.ts src/main/connectionHistory.test.ts src/main/eventClock.test.ts src/shared/connection-history.test.ts src/renderer/pages/Logs.render.test.tsx src/main/actionCorrelationScope.test.ts src/main/connectionOperations.test.ts`
  — **157 passed / 8 files**, 5.49 s, exit 0
  (.tmp/wp0-event-time-qodo65-focused-final.log). Дополнительно после усиления
  forward correction до 40 дней `npm.cmd test -- src/main/connectionHistoryStorage.test.ts`
  — **86 passed**, 5.57 s, exit 0 (.tmp/wp0-event-time-qodo65-calendar-final.log).
  Все day/week/month stats и точный calendar filter проверены на real Conf.
- `npm.cmd run typecheck` — exit 0, 158 channels / 0 public any
  (.tmp/wp0-event-time-qodo65-typecheck-final.log). Нормативные docs не менялись.
- Полный `npm.cmd test` исправленного варианта — **4161 passed / 5 skipped /
  0 failed**, 264 files passed / 2 skipped, 234.41 s, exit 0
  (.tmp/wp0-event-time-qodo65-full.log). Успешный CI прежнего head не считается
  проверкой этого исправления.
- `npm.cmd run build` — exit 0 (.tmp/wp0-event-time-qodo65-build.log).
  `node scripts/test-electron-runtime.mjs` — ELECTRON_SMOKE_PASS, exit 0
  (.tmp/wp0-event-time-qodo65-electron.log); `node scripts/test-wp1-native.mjs --ipc-only`
  — WP1_NATIVE_PASS, exit 0 (.tmp/wp0-event-time-qodo65-csp.log).
  Coverage AC 927/927, F 210/210 и `git diff --check` — exit 0. Native scope
  не расширен до packet/resource/OS-matrix приёмки.

### PR #65 — повторное ревью и слияние

- Итоговый head 8f19b2e8b3549752df6e9607345df9bd617e2ffa: Qodo 1541967
  completed, прежний finding implemented, новых нет. CI 39167728768
  completed/success, все три jobs зелёные на этом SHA.
- Слит после повторных проверок; REST GET merged=true,
  merge d8e096552042a15b1ff8c5b54d35a2616c986b45.

## WP-0 — фактическая история Soft sessions (19.10.2026)

- AT-00-005 / F-143: успешный startSoftProtectionEffects открывает LiveSession
  после завершения env apply. Identical refresh сохраняет origin/ID, смена
  address/type закрывает прежнюю сессию как server-switch и открывает новую.
  Failed refresh пишет свою попытку, сохраняя предыдущую live-сессию.
- История проходит реальные owned/legacy env/tray/recovery entrypoints;
  source/owner берутся из их admission. Missing-proxy Soft tray отказ теперь
  тоже записывается до admission, с собственным tray action ID.
- Native stop/node-switch callbacks не закрывают Soft session. Soft stop и
  shutdown закрывают её только после успешного env rollback/доказанного отсутствия
  obligation; отказ оставляет её для retry. Переключение на native закрывает
  Soft после подтверждённого rollback. Hard/Direct правила native exit не ослаблены.
- Native trafficMonitor не измеряет env-only трафик; для Soft счётчики записываются
  нулевыми, без приписывания оставшихся native bytes. Это не доказательство
  отсутствия трафика или packet-level защиты. Duration и provenance сохранены.
- До production-исправления `npm.cmd test -- src/main/connectionHistoryStorage.test.ts`
  — **8 failed / 86 passed**, 3.59 s, exit 1 (.tmp/wp0-soft-history-before.log).
  Это регрессии отсутствия Soft session history и её происхождения.
- `npm.cmd test -- src/main/connectionHistoryStorage.test.ts src/main/lifecycleCleanup.test.ts src/main/connectionOperations.test.ts src/main/actionCorrelationScope.test.ts`
  — **299 passed / 4 files**, 23.01 s, exit 0
  (.tmp/wp0-soft-history-focused-final.log). Actual main bodies, production lane/FSM,
  callbacks, real Conf reload; OS/env operations заменены. Проверены refresh,
  protocol/address switch, failed apply, cancellation + late completion, rollback
  retry и shutdown ordering. Это не installed/native env acceptance.
- `npm.cmd run typecheck` — exit 0, 158 channels / 0 public any
  (.tmp/wp0-soft-history-typecheck.log). Общие background/native owners, общий
  registry операций и прочие остатки WP-0 не объявляются завершёнными.
- Полный `npm.cmd test` — **4175 passed / 5 skipped / 0 failed**,
  264 files passed / 2 skipped, 158.36 s, exit 0
  (.tmp/wp0-soft-history-full.log). `npm.cmd run build` — exit 0
  (.tmp/wp0-soft-history-build.log).
- `node scripts/test-electron-runtime.mjs` — ELECTRON_SMOKE_PASS, exit 0
  (.tmp/wp0-soft-history-electron.log); `node scripts/test-wp1-native.mjs --ipc-only`
  — WP1_NATIVE_PASS, exit 0 (.tmp/wp0-soft-history-csp.log).
  `python docs/04-приёмочные-тесты/traceability/check-coverage.py` —
  AC 927/927, F 210/210, exit 0; `git diff --check` — exit 0.
  Native smoke ограничен Electron/IPC/CSP, OS/env эффекты в Soft fixtures
  заменены: полная Windows env/packet приёмка этим не заявляется.

### Qodo #66 — проверка прежнего endpoint после failed refresh

- Head bcd82472d9d1cd76e6505ade029782392103bbc1: Qodo 1542087 completed.
  Finding 1077a56c-5066-45cc-82e0-9bfbc7112659 action_required подтверждён:
  failed refresh мог частично изменить env, а compensation тоже мог отказать.
  Одного durable backup недостаточно, чтобы продолжать прежнюю сессию.
- Main теперь читает все четыре registry/process env значения через actual
  env.matchesProxy и autoconfig dispatcher. Старый endpoint сохраняет history
  только при подтверждении. Ошибка чтения/несовпадение закрывает её с unknown /
  confidence=indeterminate, переводит FSM в unknown, сохраняя rollback receipt.
  Evidence read участвует в owner.wait; отмена не пишет поздних событий.
- Finding 13f591ff-c9a1-4c6c-a928-1210c73885ef remediation_recommended:
  missing-proxy tray отказ использует тот же type-specific Soft profile ID.
  Informational 153e616b-6aa4-41a5-a908-f36f527e228c также учтён: перед
  Hard/Direct startup итог Soft не объявляется server-switch с продолжением
  сессии. Запись явно говорит об отключении перед запуском другого режима,
  достоверность следующего запуска не заявляется.
- До production fix `npm.cmd test -- src/main/connectionHistoryStorage.test.ts src/main/autoconfig/env.test.ts`
  — **18 failed / 184 passed**, 3.81 s, exit 1
  (.tmp/wp0-soft-qodo66-before.log): новые read-back контракты и регрессии.
- `npm.cmd test -- src/main/connectionHistoryStorage.test.ts src/main/lifecycleCleanup.test.ts src/main/autoconfig/env.test.ts src/main/autoconfig/index.test.ts`
  — **396 passed / 4 files**, 22.35 s, exit 0
  (.tmp/wp0-soft-qodo66-focused-evidence.log). Проверены partial mutation с
  compensation failure, каждый registry/process key, read denial, cancellation
  во время read-back и настоящая запись/reload истории. OS commands заменены.
- `npm.cmd run typecheck` — exit 0, 158 channels / 0 public any
  (.tmp/wp0-soft-qodo66-typecheck-final.log); coverage AC 927/927, F 210/210
  и `git diff --check` — exit 0.
- Первый полный `npm.cmd test` — **1 failed / 4193 passed / 5 skipped**,
  164.76 s, exit 1 (.tmp/wp0-soft-qodo66-full.log). Единственный отказ:
  неизменённый native PowerShell gateway-only fixture adaptiveNetworkIdentity
  превысил Vitest timeout 5 s (10.482 s). Адресный повтор
  `npm.cmd test -- src/main/adaptiveNetworkIdentity.test.ts` — **25 passed**,
  2.48 s, exit 0 (.tmp/wp0-soft-qodo66-native-recheck.log).
  Тест не отключён, лимит не ослаблен; запускается повтор полного набора.
- Повтор полного `npm.cmd test` — **4194 passed / 5 skipped / 0 failed**,
  264 files passed / 2 skipped, 157.51 s, exit 0
  (.tmp/wp0-soft-qodo66-full-recheck.log).
- `npm.cmd run build` — exit 0 (.tmp/wp0-soft-qodo66-build.log);
  `node scripts/test-electron-runtime.mjs` — ELECTRON_SMOKE_PASS, exit 0
  (.tmp/wp0-soft-qodo66-electron.log); `node scripts/test-wp1-native.mjs --ipc-only`
  — WP1_NATIVE_PASS, exit 0 (.tmp/wp0-soft-qodo66-csp.log).
  Проверки прежнего head не используются как evidence исправленного коммита.

### Qodo #66 — неуспех refresh отдельно от состояния прежней защиты

- Qodo 1542154 completed на ffdf0816381ca7a576321ccb2f92fe006b6e494d:
  три прежних findings implemented; новый c6d41002-0c06-4eaf-a886-778c2f1ce12c
  action_required подтверждён. При доказанном старом endpoint history оставалась,
  но failed operation переводила FSM в error и настоящий renderer ставил mode=off.
- FSM принимает отдельное подтверждение сохранённого Soft endpoint только
  для текущей connecting operation поверх прежнего connected/soft. Failed
  refresh остаётся operation.status=error / result.success=false; состояние
  защиты остаётся connected/soft. Подтверждение не переносится на следующую
  операцию и не переживает fault, cancel, stale ID, потерю env или native PID.
  Internal exception после read-back не маскируется сохранённой защитой.
- Regression до fix `npm.cmd test -- src/main/connectionHistoryStorage.test.ts`
  — **1 failed / 101 passed**, 3.87 s, exit 1
  (.tmp/wp0-soft-qodo66-retained-before.log): фактический snapshot был error/null.
- `npm.cmd test -- src/main/connectionHistoryStorage.test.ts src/main/tunnelStateMachine.test.ts src/renderer/App.lifecycle.test.ts src/main/lifecycleCleanup.test.ts src/main/connectionOperations.test.ts src/main/actionCorrelationScope.test.ts`
  — **340 passed / 6 files**, 24.96 s, exit 0
  (.tmp/wp0-soft-qodo66-retained-focused-final.log). Actual main + Conf history,
  production FSM/lane и настоящий App callback с Zustand. OS effects заменены.
- `npm.cmd run typecheck` — exit 0, 158 channels / 0 public any
  (.tmp/wp0-soft-qodo66-retained-typecheck.log); `git diff --check` — exit 0.
- Полный `npm.cmd test` — **4205 passed / 5 skipped / 0 failed**,
  264 files passed / 2 skipped, 155.70 s, exit 0
  (.tmp/wp0-soft-qodo66-retained-full.log). Coverage AC 927/927, F 210/210 — exit 0.
- `npm.cmd run build` — exit 0 (.tmp/wp0-soft-qodo66-retained-build.log);
  `node scripts/test-electron-runtime.mjs` — ELECTRON_SMOKE_PASS, exit 0
  (.tmp/wp0-soft-qodo66-retained-electron.log); `node scripts/test-wp1-native.mjs --ipc-only`
  — WP1_NATIVE_PASS, exit 0 (.tmp/wp0-soft-qodo66-retained-csp.log).

### PR #66 — повторные ревью и слияние

- Итоговый head d2728b0176c4fbf48e4704fa09ef14eccfee0b31:
  Qodo 1542260 completed; все четыре прежних findings implemented, новых нет.
  CI 39170872277 completed/success, все три jobs зелёные на этом SHA.
- Слит с проверкой ожидаемого head; REST GET merged=true, state=closed,
  merge 3f6f7f464ec20ce7544a767c24a238d1bf809937.
  Soft history доставлена в main; WP-0 целиком не завершён.

## WP-0 — общий feature registry и первая интеграция speed test (19.10.2026)

- AT-00-001/003/005/007: добавлен OperationRegistry с main UUIDv4,
  original correlation/source/owner, deadline, priority admission и ограниченным
  списком метаданных (1000). Cancel/timeout возвращает типизированный отказ
  caller немедленно; lease остаётся busy до фактического settlement всех
  захваченных эффектов. Higher-priority replacement дожидается drain, но само
  ожидание реагирует на abort/deadline/shutdown и входит в монотонный бюджет.
- Настоящий speed runner передаёт signal в axios latency/download/upload/egress,
  уничтожает streams, запрещает поздние fallback/progress/history. При shutdown
  connection lane и feature registry отменяются вместе; native cleanup ждёт оба.
  `operations:list/cancel` зарегистрированы через общий guard/preload/shared.
  Новая public API сохраняет существующий результат speedTestRun.
- Начальный integration harness вызывал несуществующий installer guard:
  `npm.cmd test -- src/main/operationRegistry.test.ts src/main/speedTestOperations.test.ts src/main/speedTest.test.ts src/main/lifecycleCleanup.test.ts`
  — **11 failed / 206 passed**, 20.72 s, exit 1
  (.tmp/wp0-operations-integrated.log в первом запуске, позднее перезаписан
  успешным повтором). Исправлен harness, cleanup снимает удержанные gates
  даже при failed assertion. Повтор — **217 passed**, 21.06 s, exit 0.
- Новые реальные регрессии до исправлений:
  `npm.cmd test -- src/main/operationRegistry.test.ts src/main/speedTestOperations.test.ts src/main/lifecycleCleanup.test.ts`
  — **4 failed / 216 passed**, 21.31 s, exit 1
  (.tmp/wp0-operations-races-before.log). Waiting replacement не отвечал на
  cancel/timeout/shutdown; отмена при complete frame ещё сохраняла результат.
  Исправлены cancellable admission и guard перед saveResult.
- `npm.cmd test -- src/main/speedTestOperations.test.ts` — **1 failed / 13 passed**,
  2.33 s, exit 1 (.tmp/wp0-operations-headers-before.log): отмена между headers
  и установкой consumer оставляла Readable открытым. Stream теперь принадлежит
  abort handler уже при получении headers; поздние headers уничтожаются тоже.
- Итоговый адресный набор:
  `npm.cmd test -- src/main/speedTestOperations.test.ts src/main/operationRegistry.test.ts src/main/speedTest.test.ts src/main/lifecycleCleanup.test.ts`
  — **225 passed / 4 files**, 25.07 s, exit 0
  (.tmp/wp0-operations-focused-final.log). Настоящие speed service / registry /
  IPC guard / Conf backend; OS/VPN и внешняя сеть заменены. Отдельный тест
  запускает реальный loopback HTTP server/axios и подтверждает закрытие сокета
  после abort. Generic 5 kinds × 10/50/90 не считается интеграцией остальных
  production features. Speed integration проверяет пороги 10/50/90/100 и complete.
- `npm.cmd run typecheck` — exit 0, **160 channels / 0 public any**
  (.tmp/wp0-operations-typecheck.log); `npm.cmd run build` — exit 0
  (.tmp/wp0-operations-build.log). Финальный build/full после headers fix ниже.
- `node scripts/test-electron-runtime.mjs` — **ELECTRON_SMOKE_PASS**, exit 0
  (.tmp/wp0-operations-electron.log). Production operations handlers и preload,
  настоящий contextBridge: UUID cancel, исходный correlation, typed отказ
  ≤900 ms при ещё удержанном lease, invalid UUID и чужой WebContents.
  Сеть управляемая; actual speed HTTP покрыт отдельным L2 тестом выше.
  `node scripts/test-wp1-native.mjs --ipc-only` — **WP1_NATIVE_PASS**, exit 0
  (.tmp/wp0-operations-csp.log), IPC/CSP subset без изменения ОС.
- Traceability `python docs/04-приёмочные-тесты/traceability/check-coverage.py` —
  AC 927/927, F 210/210, exit 0; `git diff --check` — exit 0.
  F-021 опровергнута и не исправляется. Нормативные docs не менялись.
- AT-00-003 ещё не PASS: refresh/import/export/rotation entrypoints,
  UI cancel/unmount, stop deadline, durable operation history и остальные
  пункты матрицы остаются открытыми. WP-0 и WP-2 не объявляются завершёнными.
- Промежуточные полные `npm.cmd test`: **4259 passed / 5 skipped / 0 failed**,
  266 files passed / 2 skipped, 193.37 s (.tmp/wp0-operations-full.log) и
  189.00 s (.tmp/wp0-operations-full-final.log), оба exit 0. Последующее
  усиление IP guard ниже требует собственного полного прогона.
- Проверка production getCurrentIp выявила ещё один late effect: без canPublish
  отменённая egress verification могла обновить shared IP state/health/recovery.
  `npm.cmd test -- src/main/speedTestOperations.test.ts` — **1 failed / 14 passed**,
  2.33 s, exit 1 (.tmp/wp0-operations-ip-before.log). Speed теперь передаёт
  predicate `!lease.signal.aborted` в production IP monitor, который проверяет
  его перед publication. Raw verification остаётся под physical drain.
- `npm.cmd test -- src/main/speedTestOperations.test.ts src/main/operationRegistry.test.ts src/main/speedTest.test.ts src/main/lifecycleCleanup.test.ts src/main/ipMonitor.test.ts`
  — **237 passed / 5 files**, 23.50 s, exit 0
  (.tmp/wp0-operations-focused-final.log; предыдущий 225-test output заменён).
- `npm.cmd test -- src/main/ipMonitorSession.test.ts src/main/ipMonitorWaves.test.ts`
  — **19 passed / 2 files**, 529 ms, exit 0 (.tmp/wp0-operations-monitor-final.log).
  Эти production monitor fixtures проверяют запрет late state/health/recovery
  publication при отозванном canPublish и изоляцию поколений проверок.
- Итоговый полный `npm.cmd test` после IP guard — **4260 passed / 5 skipped /
  0 failed**, 266 files passed / 2 skipped, 186.80 s, exit 0
  (.tmp/wp0-operations-full-guard-final.log).
  `npm.cmd run build` — exit 0 (.tmp/wp0-operations-build-final.log), включая
  typecheck: 160 channels / 0 public any. Финальный
  `node scripts/test-electron-runtime.mjs` — ELECTRON_SMOKE_PASS, exit 0
  (.tmp/wp0-operations-electron-final.log); IPC/CSP subset
  `node scripts/test-wp1-native.mjs --ipc-only` — WP1_NATIVE_PASS, exit 0
  (.tmp/wp0-operations-csp-final.log). Scope остаётся указанным выше.
  Traceability AC 927/927 / F 210/210 и `git diff --cached --check` — exit 0.

### PR #67 — Qodo: log identity, refused quit и отмена соседних запросов

- Initial head 8e503601d3402ac72184a91615bb38db7816df67: Qodo **1542435
  completed**, четыре findings. Initial CI **39173310237 success** относится
  только к этому head и не считается проверкой последующих исправлений.
- f0d9cce7-d61f-45ad-b07e-cb70c133f1f4 (action_required) подтверждён: raw UUID
  правильно маскируется redactor, но log терял отдельную identity операции.
  Feature events теперь дополнены обратимым `operationKey=op_<32 hex>`;
  public operationId остаётся main UUIDv4. Политика маскирования не ослаблена.
  Regression исполняет actual registry/observer/logger/redactor, читает JSONL
  с диска и повторно санитизированный diagnostic read-back.
- 5efb7774-4dbb-471a-857e-a2d7ab18c6fe (recommended) подтверждён: failed quit
  возвращал окно, оставляя feature admission закрытым. Actual before-quit
  catch возобновляет его после drain. Resume отказывает при active effects;
  generation fence запрещает оживлять прежние ожидающие replacements.
  Следующий успешный quit снова закрывает registry. Connection admission и
  неподтверждённое состояние сетевой очистки этим не объявляются успешными.
- d4c81694-b8e2-4ad2-8732-78e0860fedab (recommended) подтверждён: download
  fallback оставлял соседние requests живыми и сохранял их progress. Каждый
  round теперь имеет linked AbortSignal; при ошибке отменяет/уничтожает соседей
  и ждёт их фактического завершения перед следующим target. Если boundary
  игнорирует abort, overall deadline всё равно возвращает caller отказ,
  а physical lease удерживается. Late headers старого round уничтожаются.
- de990930-ad60-4611-b124-4c60f379130a (recommended) подтверждён: canPublish
  подавлял IP state, но не отменял HTTP providers. getCurrentIp/fetchPublicIp
  получают signal и связывают его с wave controller. Coalescing учитывает
  одновременно owner и signal; отмена не затрагивает независимого владельца.
- Regression до fix:
  `npm.cmd test -- src/main/speedTestOperations.test.ts src/main/ipMonitorWaves.test.ts src/main/installerShutdown.test.ts src/main/actionCorrelation.test.ts`
  — **5 failed / 30 passed**, 2.88 s, exit 1 (.tmp/wp0-operations-qodo67-before.log).
  Download fixture затем исправлен: fallback должен возвращать Promise,
  как axios. Отдельный `npm.cmd test -- src/main/speedTestOperations.test.ts -t 'aborts and drains a failed download'`
  — **1 failed / 15 skipped**, 1.83 s, exit 1
  (.tmp/wp0-operations-qodo67-download-before.log), теперь по настоящему
  отсутствию abort у оставшегося stream, а не из-за неверной границы mock.
- После fixes `npm.cmd test -- src/main/speedTestOperations.test.ts src/main/ipMonitorWaves.test.ts src/main/installerShutdown.test.ts src/main/actionCorrelation.test.ts src/main/ipMonitorSession.test.ts src/main/ipMonitor.test.ts src/main/operationRegistry.test.ts src/main/lifecycleCleanup.test.ts`
  — **264 passed / 8 files**, 25.54 s, exit 0 (.tmp/wp0-operations-qodo67-focused.log).
  Дополнительные independent-signal coalescing и resume-generation cases
  добавлены затем и включены в следующий полный прогон.
- `npm.cmd run typecheck` — exit 0, 160 channels / 0 public any
  (.tmp/wp0-operations-qodo67-typecheck.log); traceability AC 927/927,
  F 210/210 и `git diff --check` — exit 0. Новый CI/Qodo gate ещё требуется.
- Полный `npm.cmd test` исправленного варианта — **4266 passed / 5 skipped /
  0 failed**, 266 files passed / 2 skipped, 189.04 s, exit 0
  (.tmp/wp0-operations-qodo67-full.log). Дополнительные generation/signal cases
  включены в этот прогон.
- `npm.cmd run build` — exit 0 (.tmp/wp0-operations-qodo67-build.log).
  `node scripts/test-electron-runtime.mjs` — ELECTRON_SMOKE_PASS, exit 0
  (.tmp/wp0-operations-qodo67-electron.log); `node scripts/test-wp1-native.mjs --ipc-only`
  — WP1_NATIVE_PASS, exit 0 (.tmp/wp0-operations-qodo67-csp.log).
  Traceability AC 927/927 / F 210/210 и `git diff --check` — exit 0.

### Qodo #67 — различимость двух операций в одном действии

- На head aaa3d99dd209bfe81b9ad26d165bbf56a351dc96 Qodo **1542488 completed**:
  все четыре прежних findings **implemented**, новый
  e11af426-7a76-4668-9cb1-4b26fe93c20a (action_required) требует проверки
  разных операций через redaction. Это пробел в coverage, не воспроизведённый
  дефект production сериализации. PR пока не слит.
- Actual registry/observer/logger test усилен: две concurrent операции имеют
  общий исходный correlation, разные operationId и обратимые operationKey.
  Одна отменяется, другая завершается успешно. Каждому key соответствуют ровно
  running + его terminal event; disk JSONL и diagnostic read-back совпадают,
  raw UUID и credential по-прежнему скрыты. Production-код не менялся.
- `npm.cmd test -- src/main/actionCorrelation.test.ts` — **2 passed**,
  1.02 s, exit 0 (.tmp/wp0-operations-qodo67-distinct.log).
- `npm.cmd run typecheck` — exit 0, 160 channels / 0 public any
  (.tmp/wp0-operations-qodo67-distinct-typecheck.log). Traceability
  `python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py` —
  AC 927/927 / F 210/210, exit 0; `git diff --check` — exit 0.
- Полный `npm.cmd test` после усиления — **4266 passed / 5 skipped / 0 failed**,
  266 files passed / 2 skipped, 192.05 s, exit 0
  (.tmp/wp0-operations-qodo67-distinct-full.log). Build/native не повторялись
  локально: изменены только test и журнал, production тот же, что прошёл
  build/Electron/IPC/CSP в предыдущем коммите. Новый remote CI проверит final SHA.
- CI **39174041625 success** на aaa3d99dd209bfe81b9ad26d165bbf56a351dc96;
  три jobs зелёные. Новый commit с усиленным test требует нового CI/Qodo gate.

### PR #67 — окончательная проверка и слияние

- Qodo **1542542 completed** на **ab201afe21484a6d0c370bd6fa95721ada936dd5**;
  все пять findings implemented, новых открытых замечаний нет. Attribution
  проверен через API; вручную не менялся. Ручного запроса боту не отправлял.
- CI **39174584878 success** на том же SHA: сайт, ETW Rust и приложение Windows
  (6m26s) полностью зелёные, включая unit, traceability, actual IPC/CSP,
  WFP ABI/rollback и Electron reads. Watcher завершился exit 0.
- PR #67 слит REST merge с ожидаемым SHA; отдельный REST GET подтвердил
  merged=true/state=closed, merge **be2dc164ee9331ccf7ea96f6f76077147ed62017**.
  Следующий участок начат от этого main в codex/wp0-subscription-cancellation.

### WP-0 — обновление подписок под общим operation registry

- Production refreshGroup (IPC, повторная вставка подписки и periodic sweep)
  использует общий registry: UUID, deadline 120 s, owner manual/schedule,
  prompt cancellation и physical drain. Manual отменяет automatic, новый
  запрос допускается только после raw settlement. Stop sweep отменяет active
  fetch и не допускает следующую группу; shutdown использует общий close.
- Signal проходит device fetches, redirects, retries и DoH fallback. curl
  хранит URL/headers в stdin. Отмена/timeout/overflow не освобождают физическое
  владение до close дочернего процесса/stdio. Поздний ответ не запускает retry,
  не меняет profiles/group metadata и не пишет group refreshed.
- Существующая очередь append импорта вынесена в profileStoreQueue и общая
  с refresh commit. Guard проверяет lease и неизменность source группы внутри
  очереди; commit читает актуальный массив после fetch, сохраняя concurrent
  import/другие группы/переименование. Удалённая группа не воссоздаётся.
- Regression до fix: `npm.cmd test -- src/main/serverGroupsRefresh.test.ts`
  — **8 failed / 26 passed**, 16.67 s, exit 1 (.tmp/wp0-refresh-before.log).
  Негативный прогон также имел один unhandled assertion после завершения
  заведомо неотменяемого старого fetch; исправленный прогон этого не имеет.
  `npm.cmd test -- src/main/vpnProfilesRegression.test.ts -t 'already cancelled'`
  — **1 failed / 7 skipped**, 469 ms, exit 1 (.tmp/wp0-refresh-curl-before.log).
- После интеграции три прежних mocks resolveVpnProfiles исправлены на async
  Promise (как production), иначе lease.wait выявлял `task.then` на plain object.
  Первый loopback/Conf fixture имел cached mock store от предыдущей временной
  папки; исправлено lifetime fixture. Дополнительный guard test сначала ожидал
  OPERATION_CANCELLED вместо нормативного transport IPC_CANCELLED; исправлено
  ожидание по shared/ipc-result.ts, production envelope не менялся.
- `npm.cmd test -- src/main/serverGroupsRefresh.test.ts src/main/subscriptionOperations.test.ts src/main/vpnProfilesRegression.test.ts src/main/vpnProfilesClientDevice.test.ts`
  — **53 passed / 4 files**, 1.96 s, exit 0 (.tmp/wp0-refresh-focused-final.log).
  После добавления guard case `npm.cmd test -- src/main/subscriptionOperations.test.ts`
  — **3 passed**, 1.15 s, exit 0 (.tmp/wp0-refresh-native-final.log).
- `npm.cmd run typecheck` — exit 0, 160 channels / 0 public any
  (.tmp/wp0-refresh-typecheck-final.log). Первый typecheck выявил отсутствующий
  status тестового профиля, исправлено. Traceability AC 927/927 / F 210/210 и
  `git diff --check` — exit 0. Полный test/build/native и PR gate ниже по факту.
- Границы: настоящее curl/loopback HTTP и Conf disk, production registry/guard;
  Electron/DPAPI store boundary в этом стенде заменён. UI не менялся, import
  полностью ещё не отменяем, export/rotation/stop deadline и durable audit
  остаются в матрице. AT-00-003 и WP-0 целиком не объявляются завершёнными.
- Полный `npm.cmd test` — **4283 passed / 5 skipped / 0 failed**,
  267 files passed / 2 skipped, 193.28 s, exit 0 (.tmp/wp0-refresh-full.log).
  Включён окончательный guard/loopback suite из трёх cases. stderr от
  RootErrorBoundary — ожидаемый тестовый crash, не unhandled rejection.
- `npm.cmd run build` — exit 0 (.tmp/wp0-refresh-build.log), включая
  typecheck. `node scripts/test-electron-runtime.mjs` — ELECTRON_SMOKE_PASS,
  exit 0 (.tmp/wp0-refresh-electron.log); `node scripts/test-wp1-native.mjs --ipc-only`
  — WP1_NATIVE_PASS, exit 0 (.tmp/wp0-refresh-csp.log). Native smoke проверяет
  прежние production handlers/preload/guard, controlled network/OS subsets;
  новый refresh отдельно проверен actual curl/guard/Conf loopback suite.
- Остаточная папка собственного неуспешного fixture
  `.tmp/subscription-operations-nddlFF` оставлена: отдельная уборка через
  проверенный абсолютный PowerShell path отклонена execution policy; обхода
  запрета не выполнял. Папка ignored, в коммит/PR не включается.

### PR #68 — Qodo: deadline backoff, отменённые sweep и actual refresh JSONL

- PR #68 открыт на 36cea43021bcc9a491177917707dd15f3d9fce6a; CI
  **39175789188 success** относится к initial head. Qodo **1542619 completed**:
  одно action_required, два remediation_recommended и одно informational.
- 69f0c091-2013-44eb-96ef-e0e0be5480f8: raw UUID маскируется намеренно,
  обратимый operationKey уже присутствует. Production менять не потребовалось;
  вместо mocked logger fixture теперь использует настоящие logger/redactor,
  actual refresh/guard/curl/Conf. Две параллельные группы cancelled/success
  имеют разные keys, исходный IPC correlation сохраняется на running/terminal
  в disk JSONL и diagnostic read-back; raw UUID/контрольный пароль скрыты.
- 301c2658-237d-4139-939f-2fa3af64413c подтверждён: timeout оставлял attempt
  устаревшим. Admission записывает attempt до async boundary; сам deadline
  синхронно записывает unreachable/typed timeout и момент завершения попытки.
  Late network callbacks не пишут. Source/deletion guard исключает обновление
  уже заменённой группы; ошибки служебной записи не ломают отмену/lease.
  Regression проверяет отсутствие due через минуту и due на штатном интервале,
  неизменность после late settlement и замену source перед timeout.
- 92bda823-a170-4f95-811d-def44a510055 подтверждён: stopped/preempted sweep
  больше не увеличивает failed и не пишет automatic refresh failed. Настоящие
  сетевые ошибки/empty responses продолжают учитываться как failed.
- 67e7fafa-c6ab-4fdf-865d-7cf3203a5856 (informational): второй manual call
  получает типизированный conflict вместо присоединения к чужой операции.
  Это выбранная политика exclusive owner, согласованная с AT-00-003/007:
  проигравший caller не получает успех чужой операции и собственную отмену
  не переносит на другого владельца. UI-обработка conflict остаётся отдельной
  матрицей; общий auto/manual приоритет покрыт production registry tests.
- `npm.cmd test -- src/main/serverGroupsRefresh.test.ts src/main/subscriptionOperations.test.ts src/main/vpnProfilesRegression.test.ts src/main/actionCorrelation.test.ts`
  — **52 passed / 4 files**, 2.25 s, exit 0
  (.tmp/wp0-refresh-qodo68-focused-final.log). Промежуточный fixture ожидал
  deadline timestamp после vi.waitFor, который сдвигает fake clock на 100 ms;
  исправлено сравнение с заранее вычисленным deadline, production не менялся.
- Окончательный `npm.cmd run typecheck` — exit 0, 160 channels / 0 public any
  (.tmp/wp0-refresh-qodo68-typecheck.log). Полный `npm.cmd test` — **4285 passed /
  5 skipped / 0 failed**, 267 files passed / 2 skipped, 190.69 s, exit 0
  (.tmp/wp0-refresh-qodo68-full.log). Traceability AC 927/927 / F 210/210 и
  `git diff --check` — exit 0.
- `npm.cmd run build` — exit 0 (.tmp/wp0-refresh-qodo68-build.log).
  `node scripts/test-electron-runtime.mjs` — ELECTRON_SMOKE_PASS, exit 0
  (.tmp/wp0-refresh-qodo68-electron.log); `node scripts/test-wp1-native.mjs --ipc-only`
  — WP1_NATIVE_PASS, exit 0 (.tmp/wp0-refresh-qodo68-csp.log). После push нужен
  новый completed Qodo и CI на окончательном SHA; initial CI их не заменяет.

### PR #68 — повторная проверка и слияние

- Qodo **1542683 completed** на **ed197ceaaeb26fbbd873368f2583e48a372b0e65**:
  action_required и оба remediation_recommended — implemented. Осталось
  только informational о типизированном conflict второго manual caller;
  политика и граница UI описаны выше. Новых существенных findings нет.
  Attribution проверен через API, вручную не менялся; ручного review request нет.
- CI **39176689898 success** на том же SHA: ETW Rust, сайт и приложение
  Windows (5m32s) зелёные, включая полный unit, traceability, production
  IPC/CSP, WFP ABI/rollback и Electron reads. Watcher завершился exit 0.
- PR #68 слит с ожидаемым SHA; отдельный REST GET подтвердил merged=true,
  state=closed, merge **3afb09d43e88219fa4adbc23561cc780ac8cd523**.
  Открытых PR после слияния не осталось. Следующий участок — импорт профилей,
  ветка codex/wp0-profile-import от обновлённого main; код ещё не менялся.
- Эта запись меняет только журнал/матрицу. Production совпадает с проверенным
  ed197ce; последние проверки: typecheck exit 0, полный npm test 4285 passed /
  5 skipped, build/native PASS, traceability AC 927/927 / F 210/210. Полная
  WP-0 и следующая WP-2 остаются активной целью, завершение не заявлено.

### WP-0 — cancellable profile import и commit внутри общей очереди

- Новый subscription/URI и append в выбранную группу теперь под production
  operation registry: original action correlation, UUIDv4, deadline 120 s,
  typed cancellation/conflict и physical drain. Resolver получает signal;
  повтор идентичного незавершённого импорта не присоединяется к чужому lifetime.
  Resource — SHA-256 canonical input/device/target, без raw input в metadata.
- Создание группы перенесено в общий с refresh сериализованный commit.
  Ожидающий отменённый запрос не создаёт группу и не пишет профили. Повторный
  lookup внутри очереди сохраняет одну группу для concurrent device variants.
  Explicit target проверяется заново по existence/source/sourceUrl. Неуспешный
  commit пытается восстановить profiles/active/groups; ошибка восстановления
  явно логируется bounded internal failure, успешный результат не возвращается.
- Re-paste существующей подписки остаётся одной refresh operation, чтобы
  вложенный prompt caller cancellation не освобождал внешний physical lease.
  Возвращаются только новые профили этой группы, без чужих concurrent additions.
- Baseline `npm.cmd test -- src/main/profileImportOperations.test.ts`
  — **8 failed**, 21.08 s, exit 1 (.tmp/wp0-import-before.log), включая
  unhandled assertion после заведомо неотменяемого прежнего resolver.
  Исходный concurrent fixture возвращал одинаковый сервер для разных input;
  его законная дедупликация не production regression. Fixture исправлен на
  разные hosts; негативный результат этим дефектом не обосновывается.
- Controlled regression расширен до **18 passed**, 1.11 s, exit 0:
  `npm.cmd test -- src/main/profileImportOperations.test.ts`
  (.tmp/wp0-import-focused-expanded.log). Cancel resolution/queue для
  subscription/URI/target, shutdown/drain, deadline, deletion/source replacement,
  write failures/rollback failure, parallel commits/devices и re-paste isolation.
- `npm.cmd test -- src/main/profileImportOperations.test.ts src/main/subscriptionOperations.test.ts`
  — **25 passed / 2 files**, 2.12 s, exit 0 (.tmp/wp0-import-focused-native.log).
  Loopback исполняет actual picker/refresh/registry/guard, настоящий curl и Conf:
  после cancel child/socket завершены, поздний HTTP не пишет файл, successful
  import/URI сохраняются после нового Conf handle. Реальные logger/redactor/JSONL
  и diagnostic read-back сохраняют разные operationKey/original IPC correlation
  двух concurrent imports, raw UUID и контрольные credentials скрыты.
- Адресный запуск с serverGroupsRefresh — **62 passed / 3 files**, 2.23 s,
  exit 0 (.tmp/wp0-import-regression.log). В фильтре также были три отсутствующих
  старых filename; Vitest их не запускал. Число 62 относится только к трём реально
  выполненным файлам; полный набор проверяется отдельно.
- `npm.cmd run typecheck` — exit 0, 160 channels / 0 public any
  (.tmp/wp0-import-typecheck.log); traceability — AC 927/927 / F 210/210,
  exit 0. `npm.cmd run build` — exit 0 (.tmp/wp0-import-build.log).
  `node scripts/test-electron-runtime.mjs` — ELECTRON_SMOKE_PASS, exit 0
  (.tmp/wp0-import-electron.log); `node scripts/test-wp1-native.mjs --ipc-only`
  — WP1_NATIVE_PASS, exit 0 (.tmp/wp0-import-csp.log). Smoke проверяет общие
  production IPC/preload/CSP subsets; импорт отдельно покрыт actual curl/guard/
  Conf fixture. Electron/DPAPI storage boundary этого fixture заменён.
- Остаток WP-0 сохранён: config browse/import/apply, export, rotation, UI cancel/
  unmount, stop deadline, background native admission, durable audit, migrations,
  semantic error matrix и остальные AT. Полная WP-0 не объявляется PASS.
- Первый полный `npm.cmd test` — **1 failed / 4305 passed / 5 skipped**,
  203.70 s, exit 1 (.tmp/wp0-import-full.log): прежний actual PowerShell case
  adaptiveNetworkIdentity превысил стандартные 5000 ms (10549 ms) при параллельном
  build/native. Причинность нагрузки не доказана. Без изменения кода/таймаута
  `npm.cmd test -- src/main/adaptiveNetworkIdentity.test.ts` — **25 passed**,
  3.21 s, exit 0 (.tmp/wp0-import-adaptive-recheck.log). Полный набор повторяется
  отдельно от build/native; первый failure не заменяется адресным PASS.
- Повторный полный `npm.cmd test` без параллельного build/native — **4306 passed /
  5 skipped / 0 failed**, 268 files passed / 2 skipped, **189.30 s**, exit 0
  (.tmp/wp0-import-full-final.log). Production/test code и timeout не менялись.
  Stderr RootErrorBoundary — ожидаемый fixture crash; unhandled failures нет.
  Перед commit `git diff --check` — exit 0. После push требуется completed
  Qodo и CI на итоговом SHA; следующий участок до этого не начинается.

### PR #69 — Qodo: terminal refresh result и диагностика отказа rollback

- PR #69 создан на **350badcd97df253d5d1346088bb09659824dc2bd**.
  Qodo **1542763 completed** на этом SHA: одно remediation_recommended
  и одно informational; attribution через API, вручную не менялся.
- 6782f1e2-3b11-44bb-b9c5-279481f97654 подтверждён: addFromInput проверял
  внешний signal после успешного refresh и мог вернуть cancelled при уже
  сохранённых profiles/group metadata. Теперь terminal result решает только
  refresh owner. Новый regression abort-ит signal синхронно при публикации
  refresh success и проверяет успешный ответ и сохранённые данные.
- До fix `npm.cmd test -- src/main/profileImportOperations.test.ts -t 'terminal publication'`
  — **1 failed / 18 skipped**, 1.03 s, exit 1 (.tmp/wp0-import-qodo69-before.log).
- 867ccbff-b27d-49ae-9586-df2557e72717 (informational) также учтён: при
  отказе rollback лог содержит commitStep и causeCategory исходной ошибки,
  сохраняя bounded taxonomy без raw exception/secret/path. Fixture отличает
  исходный EACCES на active selection от последующей ошибки восстановления
  profiles, проверяет category=internal и отсутствие контрольного private path.
- `npm.cmd test -- src/main/profileImportOperations.test.ts src/main/subscriptionOperations.test.ts src/main/serverGroupsRefresh.test.ts`
  — **63 passed / 3 files**, 2.11 s, exit 0 (.tmp/wp0-import-qodo69-focused.log).
  `npm.cmd run typecheck` — exit 0, 160 channels / 0 public any
  (.tmp/wp0-import-qodo69-typecheck.log). Traceability AC 927/927 / F 210/210
  и `git diff --check` — exit 0. Полный набор запущен после завершения typecheck;
  build/native и новый exact-head review/CI требуются по итоговому SHA.
- Полный `npm.cmd test` после Qodo fixes — **4307 passed / 5 skipped /
  0 failed**, 268 files passed / 2 skipped, **194.60 s**, exit 0
  (.tmp/wp0-import-qodo69-full.log). Это результат до следующей поправки
  инструмента замера IPC; production fix на нём проверен.
- Initial CI **39178308104 failure** на 350badc: Windows unit — один failure
  ipcBoundaryAcceptance, config:import channel p99 попал в saturated bucket 51
  (>50 ms); **4306 passed / 4 skipped / 1 failed**, 273.80 s. Новые import
  fixtures прошли. Лог .tmp/wp0-import-ci69-failure.log; Rust/сайт success,
  последующие Windows acceptance steps из-за unit failure не выполнялись.
- Проверка исходника выявила, что histogram включал Vitest toMatchObject в
  длительность handler. Время теперь снимается сразу после await handler,
  до assertion. Лимит 50 ms, бюджеты mutation, все category/zero-effects
  проверки и подсчёт каждого observation сохранены. Это корректировка границы
  измерения, не доказательство причины конкретного CI outlier. Новый CI обязателен.
- `npm.cmd test -- src/main/ipcBoundaryAcceptance.test.ts src/main/profileImportOperations.test.ts src/main/subscriptionOperations.test.ts src/main/serverGroupsRefresh.test.ts`
  — **65 passed / 4 files**, 2.84 s, exit 0
  (.tmp/wp0-import-qodo69-focused-final.log). Полный финальный набор и build/
  native выполняются на этой версии последовательно, результаты ниже по факту.
- Окончательный `npm.cmd test` — **4307 passed / 5 skipped / 0 failed**,
  268 files passed / 2 skipped, **191.80 s**, exit 0
  (.tmp/wp0-import-qodo69-full-final.log). `npm.cmd run build` — exit 0,
  включая typecheck 160 channels / 0 public any (.tmp/wp0-import-qodo69-build.log).
  `node scripts/test-electron-runtime.mjs` — ELECTRON_SMOKE_PASS, exit 0
  (.tmp/wp0-import-qodo69-electron.log); `node scripts/test-wp1-native.mjs --ipc-only`
  — WP1_NATIVE_PASS, exit 0 (.tmp/wp0-import-qodo69-csp.log). Scope этих smoke
  прежний, новый import дополнительно проверен actual curl/guard/Conf fixture.

### PR #69 — итоговая проверка и слияние

- Qodo **1542807 completed** на **a5cf69eade2e28f39555f7ecbd5ee5d1bb98a83b**:
  оба прежних findings implemented, новых нет. Attribution прочитан через API,
  вручную не менялся; ручного запроса review не было.
- CI **39179194108 success** на том же SHA: Windows, Rust и сайт зелёные.
  Windows выполнил typecheck/unit/traceability, production IPC/CSP, WFP ABI/
  rollback и native reads. Watcher завершён exit 0; initial failed run не скрыт.
- Слияние выполнено с expected head SHA; отдельный REST GET подтвердил
  merged=true, state=closed, merge **639ade16393e1b121bdca66aff49e8f2e27f10f4**.
- Следующая ветка — codex/wp0-config-operations от обновлённого main.
  Эта запись меняет только журнал/матрицу; production tree совпадает с
  проверенным a5cf69e. Последние проверки: npm test 4307 passed / 5 skipped,
  typecheck/build/native PASS, traceability AC 927/927 / F 210/210. WP-0
  целиком и следующая WP-2 остаются незавершёнными.


### WP-0 — config browse/import/apply/export: operation lifetime и atomic export

- Browse/validate/apply/export подключены к общему registry, original correlation,
  deadline 120 s, prompt cancellation, physical drain и renderer destroyed.
  Main-only grant сохраняет snapshot, sender и 60 s expiry; apply одноразово
  claims authority при invocation. Новая selection/expiry/закрытие окна проверяются
  повторно внутри общей profile-write queue до финального синхронного commit.
- Чтение — async один handle, bounded 16 MiB + 1, regular-file/size/mtime checks.
  Export — wx/0600 staging рядом с destination, async write/fsync/close, terminal
  sync rename. До commit прежний файл неизменен; cancel ждёт raw close до удаления
  своего temp. Lease.commit сохраняет terminal result, запрещает pending tracked
  I/O/async callback и не переименовывает сохранённый success после позднего abort.
  Reentrant cancellation внутри синхронного commit возвращает false; ошибочный
  post-commit throw логируется bounded category с исходной correlation.
- Baseline registry `npm.cmd test -- src/main/operationRegistry.test.ts -t commit`
  — 4 failed / 36 skipped, exit 1 (.tmp/wp0-config-commit-before.log): commit API
  отсутствовал. Новые fixture trials с неверным IPC export mode и logger spy
  исправлены в стенде; они не объявляются production regressions. Прежние stat
  fault injections configIpcErrors перенесены с fstatSync на actual FileHandle.stat.
- `npm.cmd test -- src/main/configOperations.test.ts src/main/configManager.test.ts src/main/configImportSecurity.test.ts src/main/configExportSecurity.test.ts src/main/configIpcErrors.test.ts src/main/operationRegistry.test.ts`
  — **179 passed / 6 files**, **4.06 s**, exit 0 (.tmp/wp0-config-regression.log).
  Новый config fixture использует real files/Conf/guard/logger/diagnostic;
  Electron/DPAPI boundary и native dialogs заменены. Включены отмена held consent/
  dialogs/open/read/write/fsync, queue lifetime, concurrent merge, write/rename
  failure, rollback failure без false success, original correlation/redaction,
  terminal abort и deadline. Registry отдельно покрывает async misuse/drain.
- Первый typecheck после расширения fixture — exit 2: object defaults и TS control
  flow после mutating entry.cancel. Исправлены тип defaults и фактический boolean
  результат cancel; runtime casts не добавлялись. `npm.cmd run typecheck` после
  исправлений — exit 0, 160 channels / 0 public any
  (.tmp/wp0-config-typecheck-final.log). Traceability `python ../docs/04-приёмочные-тесты/traceability/check-coverage.py`
  — AC 927/927 / F 210/210, exit 0. Полный npm test запущен отдельно от build/native;
  их результаты и remote gate будут записаны после фактического завершения.

- Полный `npm.cmd test` — **4333 passed / 5 skipped / 0 failed**,
  **269 files passed / 2 skipped**, **190.37 s**, exit 0
  (.tmp/wp0-config-full.log). Stderr RootErrorBoundary содержит ожидаемые
  fixture crashes; это не unhandled failure. Build/native выполняются после
  полного набора, без конкурирующей нагрузки на PowerShell fixtures.

- `npm.cmd run build` — exit 0, включая повторный typecheck
  (.tmp/wp0-config-build.log). `node scripts/test-electron-runtime.mjs`
  — ELECTRON_SMOKE_PASS, exit 0 (.tmp/wp0-config-electron.log).
  `node scripts/test-wp1-native.mjs --ipc-only` — WP1_NATIVE_PASS, exit 0
  (.tmp/wp0-config-csp.log). Это существующие общие runtime/IPC/CSP subsets;
  новый config lifetime отдельно покрыт actual file/Conf/guard fixture.
  `git diff --check` — exit 0. После push нужны completed Qodo и зелёный
  CI на итоговом SHA; следующий участок до этого не начинается.


### PR #70 — Qodo: Windows ACL, остаточный temp и время ожидания пользователя

- PR #70 создан на **f11cadce878891a30ec2e00d2e3fec9693661cd3**.
  Initial CI **39181351651 success**, все Windows/Rust/site jobs; watcher
  завершился exit 0. Это проверка первого head, не последующих исправлений.
- Qodo **1542946 completed** на f11cadc: 30661bb9 (action_required),
  f3fab6a9 и 17a5978f (remediation_recommended). Все три проверены и учтены;
  attribution вручную не менялся, ручного review request нет.
- 30661bb9 подтверждён настоящими Windows ACL: `npm.cmd test -- src/main/configExportAcl.test.ts`
  — **2 failed**, **1.30 s**, exit 1 (.tmp/wp0-config-qodo70-acl-before-fixed.log).
  Rename действительно заменял protected owner/group/DACL наследуемыми правами.
  Предыдущий fixture trial не смог autoload Get-Acl из-за унаследованного
  PowerShell 7 PSModulePath; он не считается доказательством production defect.
  Fixture и production helper используют .NET ACL APIs без autoload.
- Empty staging теперь получает проверенный security descriptor до plaintext:
  existing owner/group/DACL сохраняются, новый файл имеет protected user/SYSTEM
  DACL. Учитываются ACL round-trip auto-inheritance flags; fresh FileSecurity
  явно помечает секции modified перед SetAccessControl. Неверный/недоступный
  descriptor блокирует export. PowerShell выполняется async, без elevation/FFI
  в main. Destination dev/ino/size/mtime/ctime проверяются после ACL capture и
  непосредственно перед sync rename; изменение ACL выявляется как conflict.
  Это проверка snapshot, не заявление о блокировке внешних writers ОС.
- f3fab6a9: отказ удаления staging больше не заменяет primary cancellation/
  write/rename error. Отдельный error event `config export cleanup failed`
  сохраняет cleanupFailed=true, bounded category, operationKey и original
  correlation. Тесты намеренно оставляют temp при постоянном EBUSY, сверяют
  прежний destination и JSONL diagnostic; fixture удаляет только свою папку.
- 17a5978f: lease.waitForUser приостанавливает только work budget на native
  consent/picker. Deadline в snapshot временно null, cancellation остаётся
  prompt, physical lease держится до dialog settlement. После ответа остаётся
  неиспользованный budget 120 s; реальные file I/O по-прежнему timeout-ятся.
  Проверены выбор после 10 минут, cancel pending picker, поздний ответ без grant,
  timeout actual held read, отсутствие лишнего таймера после drain.
- `npm.cmd test -- src/main/configExportAcl.test.ts src/main/configOperations.test.ts src/main/configManager.test.ts src/main/configImportSecurity.test.ts src/main/configExportSecurity.test.ts src/main/configIpcErrors.test.ts src/main/operationRegistry.test.ts`
  — **188 passed / 7 files**, **6.82 s**, exit 0
  (.tmp/wp0-config-qodo70-regression.log). Три ACL tests используют реальные
  Windows файлы/security descriptors, включая смену ACL после capture.
- Первый typecheck нового helper выявил void вместо undefined в catch lstat;
  исправлено явным return undefined, без cast. `npm.cmd run typecheck`
  — exit 0, 160 channels / 0 public any (.tmp/wp0-config-qodo70-typecheck-final.log).
  Traceability AC 927/927 / F 210/210 — exit 0. Полный npm test запущен после
  typecheck, build/native и повторный exact-head Qodo/CI ещё необходимы.

- Полный `npm.cmd test` после Qodo fixes — **4342 passed / 5 skipped /
  0 failed**, **270 files passed / 2 skipped**, **194.31 s**, exit 0
  (.tmp/wp0-config-qodo70-full.log). Build/native выполняются после него.

- `npm.cmd run build` — exit 0, включая typecheck
  (.tmp/wp0-config-qodo70-build.log). `node scripts/test-electron-runtime.mjs`
  — ELECTRON_SMOKE_PASS, exit 0 (.tmp/wp0-config-qodo70-electron.log).
  `node scripts/test-wp1-native.mjs --ipc-only` — WP1_NATIVE_PASS, exit 0
  (.tmp/wp0-config-qodo70-csp.log). Scope этих smoke прежний; реальные Windows
  ACL нового export отдельно проверены тремя configExportAcl cases.
  `git diff --check` — exit 0. Следующий участок остаётся закрыт до completed
  Qodo и CI success на окончательном SHA.


### PR #70 — Qodo: типографские апострофы в выбранном пути

- Повторный Qodo **1543042 completed** на **9d65a141364fc14c988474d45d5b1df6a96da332**:
  три прежних findings — implemented. Новый fd861793 — action_required:
  ASCII-only quote helper не учитывал типографские кавычки PowerShell.
- Подтверждён легитимными именами файлов с U+2018…U+201B:
  `npm.cmd test -- src/main/configExportAcl.test.ts -t typographic`
  — **4 failed / 3 skipped**, **3.12 s**, exit 1
  (.tmp/wp0-config-qodo70-path-before.log). Экспорт возвращал permission.
  Проверка не выполняет посторонние команды: только обычные имена файлов.
- Paths теперь передаются в PowerShell только как base64 data expression;
  произвольные символы пути не попадают в string literal или исполняемый source.
  Fixture использует такой же безопасный транспорт для своего ACL read-back.
  Каждый из четырёх native cases создаёт и затем перезаписывает выбранный файл,
  проверяя точный content; прежние owner/group/DACL tests сохранены.
- `npm.cmd test -- src/main/configExportAcl.test.ts src/main/configOperations.test.ts src/main/configManager.test.ts src/main/configImportSecurity.test.ts src/main/configExportSecurity.test.ts src/main/configIpcErrors.test.ts src/main/operationRegistry.test.ts`
  — **192 passed / 7 files**, **8.31 s**, exit 0
  (.tmp/wp0-config-qodo70-path-regression.log). `npm.cmd run typecheck`
  — exit 0, 160 channels / 0 public any (.tmp/wp0-config-qodo70-path-typecheck.log).
  Traceability AC 927/927 / F 210/210 — exit 0. Полный набор запущен отдельно;
  окончательные build/native и exact-head Qodo/CI требуются после исправления.

- CI **39182525633 success** на 9d65a14: Windows unit/traceability/
  production IPC/CSP/WFP/native, Rust и сайт зелёные. Watcher завершился exit 0.
  Этот результат сохраняется как проверка предыдущего head; новый path fix
  требует отдельного completed Qodo и CI success после push.

- Полный `npm.cmd test` с path fix — **4346 passed / 5 skipped / 0 failed**,
  **270 files passed / 2 skipped**, **199.67 s**, exit 0
  (.tmp/wp0-config-qodo70-path-full.log). Build/native выполняются после него.

- `npm.cmd run build` — exit 0, включая повторный typecheck
  (.tmp/wp0-config-qodo70-path-build.log). `node scripts/test-electron-runtime.mjs`
  — ELECTRON_SMOKE_PASS, exit 0 (.tmp/wp0-config-qodo70-path-electron.log).
  `node scripts/test-wp1-native.mjs --ipc-only` — WP1_NATIVE_PASS, exit 0
  (.tmp/wp0-config-qodo70-path-csp.log). Scope smoke прежний; path/ACL проверены
  отдельно реальными Windows files. `git diff --check` — exit 0. До следующего
  участка снова требуются completed Qodo и CI на последнем head.


### PR #70 — окончательное ревью

- Qodo **1543096 completed** на **ceaa20b693f4a5519a8acc5b89e75a59ff5f5a03**:
  все четыре прежних findings implemented, новых нет. Attribution прочитан
  через API и вручную не менялся; review request вручную не отправлялся.
- CI **39183295438** выполняется на том же SHA; сайт и Rust success,
  Windows unit ещё in_progress. До terminal CI success слияние не выполняется.

- Окончательный CI **39183295438 success** на ceaa20b: Windows unit,
  traceability, production IPC/CSP, WFP ABI/rollback и native reads,
  Rust и сайт зелёные. Watcher завершился exit 0.
- Перед merge отдельные REST GET подтвердили head=ceaa20b, mergeable=true /
  clean и CI success; Qodo API повторно подтвердил completed, 4 implemented,
  openFindings=[] на том же SHA. Слияние выполнено с expected head.
- Отдельный REST GET после merge подтвердил merged=true/state=closed,
  merge **2e61411dfd1b8443099fa223b950acd2e973a28f**.
- Следующая ветка — codex/wp0-key-export от обновлённого main. Эта запись
  меняет только журнал/матрицу; production tree совпадает с проверенным
  ceaa20b. Последние фактические проверки: полный npm test 4346 passed /
  5 skipped, typecheck/build/native PASS, traceability AC 927/927 / F 210/210.
  Экспорт VPN keys, rotation, UI cancel/unmount и прочий остаток WP-0 сохраняются.
  Полная WP-0 и следующая WP-2 остаются активной целью.


### WP-0 — экспорт VPN-ключей: lifetime, atomic files и clipboard drain

- Все пять handlers экспортов (renderer/clipboard/single file/bulk keys/proxy-list)
  используют общий operation registry: UUIDv4, original IPC correlation, deadline,
  prompt cancellation и physical drain. Native consent и save picker приостанавливают
  рабочий budget; renderer destroyed отменяет запрос. Три file variants разделяют
  resource keys:file; новые экспорты не обходят незавершённый native эффект.
- Файлы используют проверенный в #70 writeConfigExport: собственный staging,
  Windows security descriptor до plaintext, fsync/close, destination snapshot и
  terminal rename. Прежний файл сохраняется при cancel/error; raw write errors
  больше не возвращаются renderer и не передаются в handleLogged. Существующие
  URI/JSON/mixed-array/proxy форматы, counts и native consent сохранены.
- Буфер проверяет active внутри собственной очереди до native write. Уже выданный
  Electron native write нельзя отозвать: caller получает cancel/timeout promptly,
  physical lease остаётся до его завершения и compensating cleanup. Очистка
  удаляет только неизменённое owned значение, сохраняет новый текст/форматы;
  native failure диагностируется cleanupFailed с retry. Если владение форматами
  не доказано, буфер не стирается и cleanupFailed явно фиксируется. Это не
  утверждение об отсутствии кратковременной записи в уже вызванном native API
  или удалении Windows clipboard history/cloud copies.
- Тихий native dismiss {ok:false,cancelled:true} сохранён для существующего UI,
  но terminal registry outcome теперь cancelled/category cancelled, не error.
  Clipboard acknowledgement фиксируется синхронным lease.commit; поздний abort
  не заменяет уже сохранённый успех. Bulk preparation уступает event loop по 64 профиля.
- До исправления clipboard: npm.cmd test -- src/main/secretClipboard.test.ts -t AT-00-003
  — 4 failed / 13 skipped (.tmp/wp0-key-clipboard-before.log). Все четыре
  операции игнорировали lifetime и возвращали успех. Первые integration fixture
  trials содержали повторно обёрнутый IPC mock и SOCKS outbound, который не
  поддерживает VPN sharing; они исправлены в стенде и не считаются production
  defects. Итоговый fixture использует настоящий naive exporter/Conf/guard/logger.
- npm.cmd test -- src/main/serverKeyOperations.test.ts src/main/serverKeyExportSecurity.test.ts src/main/secretClipboard.test.ts src/main/operationRegistry.test.ts src/main/configExportAcl.test.ts
  — 115 passed / 5 files, 8.66 s, exit 0 (.tmp/wp0-key-regression-final.log).
  Покрыты consent всех пяти каналов, long decision, save picker/destroy,
  open/write/fsync, shutdown/deadline native clipboard, file errors, terminal
  rename, JSON/URI compatibility, queue cancellation, preservation чужих данных,
  cleanup retry и actual JSONL/diagnostic correlation/redaction.
- npm.cmd run typecheck — exit 0, 160 channels / 0 public any
  (.tmp/wp0-key-typecheck.log). python ../docs/04-приёмочные-тесты/traceability/check-coverage.py
  — AC 927/927 / F 210/210, exit 0. git diff --check — exit 0.
  Полный npm test выполняется отдельно; build/native, PR и exact-head Qodo/CI
  пока не завершены. Полный AT-00-003 и весь WP-0 не объявляются PASS.

- Первый полный npm.cmd test — 1 failed / 4378 passed / 5 skipped,
  201.61 s (.tmp/wp0-key-full.log). Новый fixture удалял test directory до
  завершения actual logger append queue; поздняя запись предыдущего instance
  попадала в следующую mutable fixture dir (11 строк вместо 10). Добавлен
  actual JSONL drain перед reuse/removal, по образцу configOperations fixture;
  production assertion о correlation/redaction сохранён. Это исправление
  изоляции теста, а не скрытое исключение failing case. Полный набор повторяется.

- Адресный набор после исправления fixture drain — 115 passed / 5 files,
  10.10 s, exit 0 (.tmp/wp0-key-regression-drain.log). Повторный полный
  npm.cmd test — 4379 passed / 5 skipped / 0 failed, 271 files passed /
  2 skipped, 199.90 s, exit 0 (.tmp/wp0-key-full-final.log).
- npm.cmd run build — exit 0, включая typecheck (.tmp/wp0-key-build.log).
  node scripts/test-electron-runtime.mjs — ELECTRON_SMOKE_PASS, exit 0
  (.tmp/wp0-key-electron.log); node scripts/test-wp1-native.mjs --ipc-only
  — WP1_NATIVE_PASS, exit 0 (.tmp/wp0-key-csp.log). Это существующие общие
  runtime/IPC/CSP subsets, не новая native clipboard приёмка. Повторные
  traceability AC 927/927 / F 210/210 и git diff --check — exit 0.
  После commit/push нужны completed Qodo и CI success на окончательном SHA;
  следующий участок до этого не начинается.


### PR #71 — Qodo: причины I/O, POSIX group и bulk audit

- PR #71 создан на cdb1229e390236708930c165a4b972f1c5c7bd83. Qodo
  1543248 completed: 11df09e6, 7d633b25, 0a6b5ed7 — remediation_recommended.
  Все три проверены и подтверждены; attribution вручную не менялся.
- Новые регрессии npm.cmd test -- src/main/serverKeyOperations.test.ts src/main/configExportPosixSecurity.test.ts -t 'bounded cause|nonsecret success counts|POSIX export'
  — 14 failed / 26 skipped, 6.27 s, exit 1 (.tmp/wp0-key-qodo71-before.log).
  Девять случаев потеряли errno, два — persistent counts, три — group policy.
- Для config/key diagnostics выделен прежний bounded IO allowlist в общий
  ioFailureDetails: category и allowlisted own data-property ioCode, без raw
  message/stack/path. runKeyExport до bounded rethrow пишет destination и
  эти details в исходном correlation context; cancellation не объявляется
  файловой ошибкой. Config diagnostics сохраняют прежний формат.
- После успешного bulk writer возвращены audit events export-all-keys-file /
  export-all-proxies-file с total/exported/skipped и без path/content.
  Actual JSONL проверяет counts и correlation при skipped profiles.
- POSIX staging до plaintext копирует uid/gid, затем mode (chown может сбросить
  mode bits), читает policy обратно и отказывает при mismatch/EPERM. Это
  controlled POSIX branch test, не заявление о native Linux приёмке.
  Actual Windows ACL helper и его семь native cases не изменены.
- Дополнительный вопрос Revix 4309641449 проверен по всем шести renderer
  call sites в Servers.tsx / ServerDetailModal.tsx: каждый имеет catch для
  rejected IPC, bulk handlers сбрасывают busy в finally; ветвления именно по
  write-failed нет. Quiet native dismiss по-прежнему возвращается без reject.
- npm.cmd test -- src/main/serverKeyOperations.test.ts src/main/configExportPosixSecurity.test.ts src/main/configIpcErrors.test.ts src/main/configExportAcl.test.ts src/main/serverKeyExportSecurity.test.ts src/main/secretClipboard.test.ts src/main/operationRegistry.test.ts
  — 167 passed / 7 files, 13.98 s, exit 0 (.tmp/wp0-key-qodo71-regression.log).
  Typecheck/traceability и полный набор выполняются для нового состояния.
- Initial CI 39185510421 success на cdb1229: Windows unit/traceability/
  production IPC/CSP/WFP/native, Rust и сайт зелёные. Watcher terminal exit 0.
  Это проверка первоначального head, не нового исправления; новый Qodo/CI gate
  обязателен после push, следующий участок пока закрыт.

- npm.cmd run typecheck — exit 0, 160 channels / 0 public any
  (.tmp/wp0-key-qodo71-typecheck.log). Полный npm.cmd test — 4393 passed /
  5 skipped / 0 failed, 272 files passed / 2 skipped, 204.47 s, exit 0
  (.tmp/wp0-key-qodo71-full.log). npm.cmd run build — exit 0, включая
  повторный typecheck (.tmp/wp0-key-qodo71-build.log).
- node scripts/test-electron-runtime.mjs — ELECTRON_SMOKE_PASS, exit 0
  (.tmp/wp0-key-qodo71-electron.log); node scripts/test-wp1-native.mjs --ipc-only
  — WP1_NATIVE_PASS, exit 0 (.tmp/wp0-key-qodo71-csp.log). Scope smoke прежний.
  Повторные traceability AC 927/927 / F 210/210 и git diff --check — exit 0.
  Исправление требует нового completed Qodo/CI после push.
- Попытка убрать собственный orphan fixture .tmp/key-operations-ADQ7rk
  отклонена автоматической проверкой инструмента: blocked by policy. Повторных
  попыток/обхода нет, папка оставлена ignored; проверкам и изменениям не мешает.


### PR #71 — окончательный gate и слияние

- Qodo 1543309 completed на c8be3bacc79dfbb4b4a2012cc8742a88dd854732:
  все три прежних findings implemented, новых нет. Перед merge API повторно
  подтвердил completed / openFindings=[] на этом же SHA. Ручного request или
  изменения attribution не было.
- CI 39186437502 success на c8be3ba: Windows unit/traceability/production
  IPC/CSP/WFP/native reads, Rust и сайт зелёные. Watcher terminal exit 0.
  Перед merge REST GET подтвердил expected head, mergeable=true / clean и
  completed/success exact-head CI. Merge выполнен с expected SHA.
- Отдельный REST GET подтвердил merged=true, state=closed, merged_at
  2026-10-19T01:47:25Z, merge 273a93df3f7fe4fb9cc8bf0195d52ccdf251e2a1.
- Следующая ветка codex/wp0-rotation-operations создана от обновлённого
  vpn/main. git diff --exit-code c8be3ba HEAD -- . — exit 0: tree merge
  совпадает с окончательно проверенным head. Эта запись и матрица меняют
  только документацию; code checks не переобъявляются заново запущенными.
  Последние фактические: полный npm test 4393 passed / 5 skipped, typecheck,
  build/native PASS, traceability AC 927/927 / F 210/210. Ротация, UI lifetime,
  durable audit, migration/error/native matrices и прочий WP-0 ещё не завершены.
  Общая цель WP-0 затем WP-2 остаётся active.


### WP-0 — ротация: общий native lane и отмена подготовки/перезапуска

- IPC и timer ротации теперь получают один UUID/correlation/deadline в общем
  registry. ConnectionLifecycle заимствует эту же identity, не создаёт второй
  rotation audit event и резервирует native lane до availability/fingerprint.
  Ручной и scheduled startup вытесняют rotation; rotation вытесняет только
  autopilot/adaptive-retry. Каждый replacement ждёт actual effects и cleanup.
- Cancel, deadline, sender destroyed, изменение/import reload конфигурации,
  stopTimer и shutdown отменяют текущую rotation. Caller выходит promptly;
  registry и native lane остаются заняты до physical drain. Прежняя config
  не перезаписывается поздними availability/fingerprint/restart callbacks.
  Успешная финальная запись расписания и terminal result выполняются одним commit.
- Отмена preflight сохраняет прежнее подтверждённое состояние лишь при
  неизменных running/PID/Soft/startedAt и отсутствии fault. После beginRestart
  отмена требует обычной очистки; новый startup ждёт её фактического завершения.
  restartProtected получил отдельный signal: сброс старого transition flag
  внутри stop больше не разрешает поздний новый start. Поздний native success
  после abort проходит ordinary teardown, а не возвращается успехом ротации.
- Проверка endpoint принимает signal. Managed caller ждёт обе параллельные
  physical TCP/ICMP проверки, включая проигравшую ветвь; после abort не запускает
  следующую interface/TCP/stealth/ICMP попытку или curl после DNS. Уже выданные
  OS probes не объявляются отозванными: lane ждёт их завершения. Общий shared
  adapter lookup остаётся общим, не отменяется другим caller.
- До реализации lane: npm.cmd test -- src/main/rotationLifecycle.test.ts —
  8 failed / 0 passed, 20.44 s (.tmp/wp0-rotation-lane-before.log), метод rotate
  отсутствовал. Первые два fixture trials имели невалидный correlation key;
  они исправлены до указанного baseline и не считаются production defects.
- Первое интеграционное расширение потребовало добавить новый shutdown dependency
  в existing extracted-body harness: без profileRotation 36 lifecycle cases
  падали с ReferenceError. После исправления fixture — 202 passed / 3 files,
  22.84 s (.tmp/wp0-rotation-second.log). Production assertions не исключались.
- Промежуточный адресный набор 7 files — 299 passed, 21.15 s
  (.tmp/wp0-rotation-regression.log); после дополнения priorities/reload —
  25 passed / 2 files, 3.08 s (.tmp/wp0-rotation-priority.log). Probe/actual
  rotation/source regression — 26 passed / 3 files, 2.70 s
  (.tmp/wp0-rotation-probe.log). Финальные full/typecheck/build/native и PR gate
  ещё требуются для окончательного состояния.
- Зафиксировано существующее расхождение WP-10 F-124, том 3 §2.2:
  selectProfile/начальное уведомление идут до Health-Before-Commit, а старый
  сервер не восстанавливается после отказа нового. Этот WP-0 участок меняет
  lifetime/admission, но не объявляет выполненными rollback/health критерии
  WP-10. Нормативные docs/ не менялись; scope WP-0 затем WP-2 сохраняется.
  Полные AT-00-002/003/005/007/008 и весь WP-0 пока не объявляются PASS.

- Первый полный npm.cmd test — 2 failed / 4419 passed / 5 skipped,
  214.17 s (.tmp/wp0-rotation-full.log): source assertion ожидал 3 отказа,
  теперь их 4 с no-effects pre-abort return (actual runtime cases сохранены);
  existing native CIM failure test превысил 5 s timeout (10.68 s). После
  корректировки source assertion адресный повтор native/source/probe —
  53 passed / 3 files, 3.26 s (.tmp/wp0-rotation-full-followup.log).
  Timeout/production query не ослаблялись и не исключались. Этот первый
  полный прогон предшествовал окончательному probe-drain дополнению.
- Адресный набор npm.cmd test -- src/main/rotationOperations.test.ts src/main/rotationLifecycle.test.ts src/main/rotationProbeDrain.test.ts src/main/profileRotation.test.ts src/main/connectionLifecycle.test.ts src/main/tunnelStateMachine.test.ts src/main/operationRegistry.test.ts src/main/lifecycleCleanup.test.ts src/main/serverPickerDirectPing.test.ts src/main/tunControllerRecoverySource.test.ts
  — 335 passed / 10 files, 22.57 s (.tmp/wp0-rotation-regression-final.log).
  Дополнительные retained Soft/changed PID/lost runtime/fault cases —
  16 passed / 1 file, 0.52 s (.tmp/wp0-rotation-retained-evidence.log).
  Timeout terminal metadata после публикации больше не переименовывается в
  cancelled во время drain. Весь набор повторяется на окончательном состоянии.
- node scripts/test-electron-runtime.mjs — ELECTRON_SMOKE_PASS, exit 0
  (.tmp/wp0-rotation-electron.log); node scripts/test-wp1-native.mjs --ipc-only
  — WP1_NATIVE_PASS, exit 0 (.tmp/wp0-rotation-csp.log). Это существующие
  runtime/IPC/CSP subsets, не новый native rotation/TUN oracle.

- Промежуточный full (.tmp/wp0-rotation-full-final.log) — 1 failed /
  4432 passed / 5 skipped, 210.14 s: новая проверка metadata поймала смену
  timeout/error на cancelled в lane catch. Этот прогон пересёк доработку
  исходников/новых assertions и не используется как окончательный gate.
  Catch сохраняет уже опубликованный terminal; адресные 16 cases прошли.
  Отдельный полный прогон .tmp/wp0-rotation-full-verified.log запущен после
  всех code/test edits; до его завершения код не меняется.
- npm.cmd run build — exit 0, включая typecheck 160 channels / 0 public any
  (.tmp/wp0-rotation-build-verified.log). Повторные traceability AC 927/927 /
  F 210/210 и git diff --check — exit 0. Промежуточные build logs не заменяют
  проверку окончательного tree; remote review/CI до commit/push отсутствуют.

- Окончательный npm.cmd test на неизменяемом code/test tree — **4433 passed /
  5 skipped / 0 failed**, 275 files passed / 2 skipped, **206.76 s**, exit 0
  (.tmp/wp0-rotation-full-verified.log). Native CIM fixture прошёл в полном
  наборе без изменения timeout. Build/typecheck, traceability и diff checks
  выше относятся к этому состоянию. После commit/push следующий участок
  требует completed Qodo и CI success на текущем head; WP-0/WP-2 goal active.

- После окончательной пересборки повторены node scripts/test-electron-runtime.mjs
  и node scripts/test-wp1-native.mjs --ipc-only — ELECTRON_SMOKE_PASS /
  WP1_NATIVE_PASS, exit 0 (.tmp/wp0-rotation-electron-verified.log,
  .tmp/wp0-rotation-csp-verified.log). Scope прежний, новый native rotation
  oracle не заявляется.


### PR #72 — rotation gate

- Commit f70904220eed6ae6dc734daa36ca522298098aa1 запушен в
  codex/wp0-rotation-operations; PR #72 создан и прикреплён к задаче.
  Qodo 1543476 started на этом SHA, findings пока пусты — это не approval.
  CI 39189259371 queued на том же SHA. Ручного запроса ревью не было.
  До completed Qodo без существенных findings и terminal CI success
  следующий участок не начинается; цель WP-0 затем WP-2 остаётся active.


### PR #72 — Qodo: повтор таймера, selection после подготовки и canonical audit ID

- Qodo 1543476 completed на f709042: 054b2432 (timer), 97ddb925
  (selection до cancellable fingerprint), a5cd8b28 (masked raw operationId),
  65ff32c2 (preflight exception/state). Все проверены; attribution вручную
  не менялся. Новые npm.cmd test -- src/main/rotationOperations.test.ts src/main/rotationLifecycle.test.ts -t 'preflight exception|candidate before|reversible operationId|re-arms the enabled'
  — 6 failed / 29 skipped, 1.37 s (.tmp/wp0-rotation-qodo72-before.log).
- Timer имеет generation: после cancelled/timeout/conflict следующий tick
  планируется по свежему config с отдельной lifecycle correlation; явные
  stop/config reload/disable/shutdown либо уже запланированный success tick
  инвалидируют старый retry. Это новая работа владельца timer, а не запись
  позднего callback отменённой rotation. Проверены rearm и отсутствие rearm
  после stop/disable; physical drain по-прежнему блокирует новый native swap.
- Selection/announce на живом туннеле выполняются после всех отменяемых
  preflight awaits, перед beginRestart, без await между ними. При idle selection
  входит в terminal commit. Отмена fingerprint сохраняет прежние selected
  profile/runtime/UI. Preflight exception больше не объявляется отключённой
  защитой в уведомлении; его FSM сохраняет connected лишь при свежем evidence.
  Неуспешный native swap/возврат старого сервера остаётся WP-10 F-124.
- В actual JSONL operationId теперь содержит тот же обратимый op_ key,
  что operationKey, вместо raw UUID, который redactor превращал в маску.
  IPC/list/cancel сохраняют UUIDv4; ни одного бита identity не потеряно.
  Проверены actual logger и повторная redaction при diagnostic read-back.
- Exception path тоже проверяет retained runtime. Дополнительная регрессия
  меняет PID во время physical drain после preflight throw: до fix 1 failed /
  17 skipped (.tmp/wp0-rotation-retained-recheck-before.log). FSM повторяет
  сравнение original runtime evidence при terminal publication и не сообщает
  connected для другого PID.
- npm.cmd test -- src/main/rotationOperations.test.ts src/main/rotationLifecycle.test.ts src/main/rotationProbeDrain.test.ts src/main/profileRotation.test.ts src/main/actionCorrelation.test.ts src/main/operationRegistry.test.ts src/main/tunnelStateMachine.test.ts
  — 140 passed / 7 files, 3.95 s (.tmp/wp0-rotation-qodo72-regression-final.log).
  Новый full/build/native и remote gate для нового head ещё требуются.
- Initial CI 39189259371 success на f709042: Windows unit/traceability/
  production IPC/CSP/WFP/native, Rust и сайт зелёные. Watcher terminal exit 0.
  Это проверка первого head; Qodo findings требуют нового commit/push и gate.

- Первый full после Qodo fixes: 4441 passed / 1 failed / 5 skipped,
  209.41 s, exit 1 (.tmp/wp0-rotation-qodo72-full.log). Speed-test fixture
  сравнивал raw IPC UUID с теперь canonical diagnostic operationId. Проверка
  уточнена: progress UUID равен registry UUID, оба log ID равны его обратимому
  op_ ключу; production cancellation API не менялся. Адресный повтор
  npm.cmd test -- src/main/speedTestOperations.test.ts src/main/rotationOperations.test.ts src/main/rotationLifecycle.test.ts
  — 54 passed / 3 files, 4.10 s, exit 0
  (.tmp/wp0-rotation-qodo72-id-regression.log).
- npm.cmd run build — exit 0 (.tmp/wp0-rotation-qodo72-build.log), включая
  typecheck. Первый build выявил TS2571 новой test assertion; исправлена
  только TS-аннотация Error. Отдельный npm.cmd run typecheck после уточнения
  speed-test fixture — exit 0, 160 channels / 0 public any
  (.tmp/wp0-rotation-qodo72-typecheck.log).
- python docs/04-приёмочные-тесты/traceability/check-coverage.py — exit 0,
  AC 927/927 / F 210/210; git diff --check — exit 0. На пересобранном out
  node scripts/test-electron-runtime.mjs — ELECTRON_SMOKE_PASS, exit 0,
  node scripts/test-wp1-native.mjs --ipc-only — WP1_NATIVE_PASS, exit 0
  (.tmp/wp0-rotation-qodo72-electron.log, .tmp/wp0-rotation-qodo72-csp.log).
  Это existing generic runtime/IPC/CSP subsets, не новый native rotation oracle.
  Окончательный полный набор выполняется отдельно; его результат пока не PASS.

- Окончательный npm.cmd test после всех code/test edits — **4442 passed /
  5 skipped / 0 failed**, 275 files passed / 2 skipped, **205.57 s**, exit 0
  (.tmp/wp0-rotation-qodo72-full-verified.log). Код во время прогона не менялся;
  build/typecheck/traceability/native results выше относятся к этим fixes.
  Следующий шаг — commit/push и новый exact-head Qodo/CI gate; до него
  следующий участок не начинается. WP-0, затем WP-2 остаются active.

### PR #72 — повторное Qodo: предупреждение после failed native restart

- Commit 497decd3974b9509e4138691fa0099e0a39f1cad запушен. Qodo 1543567
  completed на этом SHA, четыре прежних finding автоматически implemented.
  Новый action_required 3522607d: нейтральное сообщение preflight было также
  применено после native restart failure и не предупреждало о возможном
  обычном маршруте при выключенном отдельном vpnDisconnect notification.
- Замечание подтверждено: restartProtected после failed start пытается ordinary
  teardown, но teardown может также не завершиться. Поэтому после попытки
  native restart показывается явное «Защита после перезапуска не подтверждена —
  трафик может идти по обычному маршруту» в connectionError; до native restart
  сохраняется нейтральное сообщение без ложного утверждения о снятой защите.
  Никакое состояние firewall этим текстом не объявляется доказанным.
- Новые regression cases для false result и exception после native teardown:
  npm.cmd test -- src/main/rotationOperations.test.ts -t 'warns about potentially'
  — 2 failed / 20 skipped, 1.04 s, exit 1
  (.tmp/wp0-rotation-qodo72-warning-before.log). После fix адресный набор
  npm.cmd test -- src/main/rotationOperations.test.ts src/main/rotationLifecycle.test.ts src/main/profileRotation.test.ts
  — 58 passed / 3 files, 4.31 s, exit 0
  (.tmp/wp0-rotation-qodo72-warning-regression.log). Полный набор/build выполняются;
  CI 39190787921 относится к прежнему 497decd и не заменяет следующий gate.
- CI 39190787921 завершился success на 497decd: Windows unit/traceability/
  production IPC/CSP/WFP/native reads, Rust, сайт; watcher exit 0.
  npm.cmd run build для warning fix — exit 0, включая typecheck 160 channels /
  0 public any (.tmp/wp0-rotation-qodo72-warning-build.log). Traceability
  AC 927/927 / F 210/210, git diff --check — exit 0. После пересборки
  node scripts/test-electron-runtime.mjs — ELECTRON_SMOKE_PASS и
  node scripts/test-wp1-native.mjs --ipc-only — WP1_NATIVE_PASS, оба exit 0
  (.tmp/wp0-rotation-qodo72-warning-electron.log,
  .tmp/wp0-rotation-qodo72-warning-csp.log); scope existing subsets unchanged.
- Финальный npm.cmd test на неизменном code/test tree — **4444 passed /
  5 skipped / 0 failed**, 275 files passed / 2 skipped, **205.37 s**, exit 0
  (.tmp/wp0-rotation-qodo72-warning-full.log). Warning fix готов к commit/push;
  новый completed Qodo и CI success обязательны до merge и следующего участка.

### PR #72 — сохранение без изменений не отменяет native restart

- Commit 33d3dfc719e22da1d6aa78e12094a677d52d2d08 запушен. Qodo 1543596
  completed на этом SHA: все пять findings автоматически implemented, новых
  нет. CI 39191350545 ещё выполняется; это не gate для следующих локальных edits.
- Revix 4309900214/4309900217 подтвердили дополнительную границу: безусловный
  stopTimer при пустом или эквивалентном config patch отменял уже начатый restart
  и сбрасывал countdown. Теперь сравниваются нормализованные значения всех
  RotationConfig полей (profileIds по содержимому); no-op возвращает current
  без записи/stop/reschedule. Реальное изменение сохраняет отмену и повторное
  планирование, чтобы поздний callback не перезаписал новую конфигурацию.
  Это не меняет решение о physical drain/ordinary cleanup после настоящей отмены.
- До fix npm.cmd test -- src/main/rotationOperations.test.ts -t 'unchanged config patch'
  — 4 failed / 22 skipped, 1.68 s, exit 1 (.tmp/wp0-rotation-noop-before.log).
  Проверяются пустой patch и прежние enabled/interval/profileIds, signal,
  admitted operation, прежний nextRotationAt и успешное завершение без cleanup.
  После fix npm.cmd test -- src/main/rotationOperations.test.ts src/main/profileRotation.test.ts src/main/rotationLifecycle.test.ts
  — 62 passed / 3 files, 5.08 s, exit 0 (.tmp/wp0-rotation-noop-regression.log).
  Full/build выполняются. Traceability AC 927/927 / F 210/210 и diff check — exit 0.
- npm.cmd run build — exit 0, включая typecheck 160 channels / 0 public any
  (.tmp/wp0-rotation-noop-build.log). На пересобранном out
  node scripts/test-electron-runtime.mjs — ELECTRON_SMOKE_PASS и
  node scripts/test-wp1-native.mjs --ipc-only — WP1_NATIVE_PASS, оба exit 0
  (.tmp/wp0-rotation-noop-electron.log, .tmp/wp0-rotation-noop-csp.log).
  Scope прежний: generic runtime/IPC/CSP subsets с fake OS, не native rotation L3.
- Финальный npm.cmd test после no-op fix — **4448 passed / 5 skipped /
  0 failed**, 275 files passed / 2 skipped, **207.90 s**, exit 0
  (.tmp/wp0-rotation-noop-full.log). Во время full code/test tree не менялся.
  CI 39191350545 success на прежнем 33d3dfc, watcher exit 0: Windows
  unit/traceability/production IPC/CSP/WFP/native reads, Rust и сайт.
  Для no-op fix требуется новый commit/push и exact-head Qodo/CI gate.

### PR #72 — приёмка ротации и слияние

- Окончательный head b6c1e73acbb74293c77e014085373869069003ef запушен.
  Qodo 1543624 completed на этом SHA: пять прежних findings автоматически
  implemented, новых нет; attribution вручную не изменялся, ревью не запрашивалось.
  Дополнительная проверка Revix no-op config исправлена с четырьмя регрессиями.
- CI 39191980960 completed/success на том же SHA, watcher exit 0: Windows
  typecheck/unit/traceability/production IPC/CSP/WFP/native reads, Rust, сайт.
  Перед merge отдельно проверены exact head, mergeable=true / clean и свежий
  completed Qodo без открытых findings. REST merge использовал expected SHA.
- Отдельный REST GET подтвердил merged=true, state=closed, merged_at
  2026-10-19T03:00:04Z, merge 84a3bf5e28133dfb93eae3191af4b71a133fb0cf.
  Локальный main обновлён fast-forward. git diff --exit-code b6c1e73 HEAD -- .
  дал exit 0: tree merge совпадает с окончательно проверенным head.
- Следующая ветка codex/wp0-stop-deadline создана от обновлённого vpn/main.
  Инвентаризация подтвердила остаток: ConnectionLifecycle.stop имеет
  deadline=null и возвращает physical drain Promise без ограниченного caller
  result. Следующий участок разделит terminal result и physical cleanup,
  сохранив busy admission и ожидание shutdown до фактического завершения OS I/O.
  Это пока план следующего изменения, не реализованное поведение.
- Эта запись и обновление AT-00-003 меняют только ненормативную документацию.
  Новые code checks не заявляются: последние фактические npm.cmd test
  4448 passed / 5 skipped, build с typecheck, traceability AC 927/927 / F 210/210,
  Electron/IPC/CSP PASS и exact-head CI/review указаны выше. UI lifetime,
  stop deadline/background admission, durable audit, migration/semantic/flags
  и полная state/resource/UI приёмка остаются в WP-0. Общая цель WP-0,
  затем WP-2 сохраняется active; пакет целиком не принят.

### WP-0 — deadline остановки и обязательный physical drain

- Инвентаризация stop подтвердила deadline=null и общий Promise caller/OS I/O.
  ConnectionLifecycle.stop теперь получает UUID, owner, deadline (120 s по
  умолчанию), отдельный AbortSignal и bounded caller result. Внешняя отмена
  даёт OPERATION_CANCELLED; истечение deadline — OPERATION_TIMEOUT. Время
  ожидания старого startup входит в этот deadline.
- Отмена запроса не отменяет обязанность rollback. Stopping lane и coalesced
  result удерживаются до фактического завершения startup/cleanup; повторный
  stop не создаёт второй teardown, startup не проходит busy admission.
  Shutdown ждёт physical Promise и видит late cleanup failure. Rotation
  registry тоже ждёт physical stopping, а не bounded stop result.
- Terminal event публикуется один раз: поздний success/error cleanup не
  переписывает timeout/cancel и не выдаёт второй terminal. После timeout FSM
  не объявляет disconnected по одному истекшему таймеру; настоящий cleanup
  и закрытие физической connection session по-прежнему обязательны. Этот
  участок не объявляет отменёнными уже выданные OS I/O или всю UI lifetime matrix.
- До реализации npm.cmd test -- src/main/connectionStopDeadline.test.ts —
  11 failed, 10.46 s, exit 1 (.tmp/wp0-stop-deadline-before.log). Две unhandled
  ошибки baseline происходили от отсутствующего нового stop owner argument;
  это не отдельное доказательство production crash. Первое расширение дало
  54 passed / 4 failed: экспериментальная смена приоритета lane.operation
  скрывала metadata cancelled startup/rotation. Getter возвращён к прежней
  семантике без ослабления assertions (.tmp/wp0-stop-deadline-first.log).
- npm.cmd test -- src/main/connectionStopDeadline.test.ts src/main/connectionLifecycle.test.ts src/main/connectionOperations.test.ts src/main/connectionCancellation.test.ts src/main/rotationLifecycle.test.ts src/main/rotationOperations.test.ts src/main/connectionModelTours.test.ts src/main/connectionOperationLogging.test.ts
  — 90 passed / 8 files, 13.72 s, exit 0
  (.tmp/wp0-stop-deadline-regression.log). Расширенный набор с
  src/main/lifecycleCleanup.test.ts src/main/tunnelStateMachine.test.ts
  — 295 passed / 10 files, 36.93 s, exit 0
  (.tmp/wp0-stop-deadline-regression-final.log).
- npm.cmd run build — exit 0, включая typecheck 160 channels / 0 public any
  (.tmp/wp0-stop-deadline-build.log). Traceability AC 927/927 / F 210/210,
  git diff --check — exit 0. node scripts/test-electron-runtime.mjs —
  ELECTRON_SMOKE_PASS, exit 0 (.tmp/wp0-stop-deadline-electron.log), включая
  новый настоящий contextBridge stop deadline: bounded typed result с исходными
  UUID/correlation, busy admission до fake OS drain и неизменный terminal timeout.
  node scripts/test-wp1-native.mjs --ipc-only — WP1_NATIVE_PASS, exit 0
  (.tmp/wp0-stop-deadline-csp.log). Это native IPC/runtime subsets с fake OS,
  не новый натурный Windows rollback/TUN oracle. Полный npm test выполняется;
  commit/push и exact-head Qodo/CI ещё не выполнены.
- Первый полный npm.cmd test — 4459 passed / 2 failed / 5 skipped,
  1170.41 s, exit 1 (.tmp/wp0-stop-deadline-full.log). Два real-time timeout:
  physicalAdapterLifecycle case и rotationOperations beforeEach, оба заняли
  около 897 s. В тот же период tool observation вернулась через 910 s вместо
  запрошенных 40 s. Причина общей задержки не установлена; системный sleep
  не подтверждён. Процесс был проверен живым и не перезапускался до terminal.
  После exit 1 npm.cmd test -- src/main/rotationOperations.test.ts src/main/physicalAdapterLifecycle.test.ts
  — 79 passed / 2 files, 3.73 s, exit 0
  (.tmp/wp0-stop-deadline-full-followup.log). Production/tests/timeouts не
  менялись и не исключались. Отдельный полный повтор запущен на том же tree;
  первый не считается PASS.
- Окончательный повтор npm.cmd test на неизменном code/test tree —
  **4461 passed / 5 skipped / 0 failed**, 276 files passed / 2 skipped,
  **177.68 s**, exit 0 (.tmp/wp0-stop-deadline-full-verified.log).
  Новые owner/deadline/cancel/rotation-drain cases и весь existing набор прошли;
  timeout-политика не ослаблялась. Build/typecheck/traceability/native результаты
  выше относятся к этому состоянию. Следующий шаг — commit/push/PR и
  completed Qodo с CI success на окончательном SHA. WP-0/WP-2 goal active.

### PR #73 — Qodo: ID журнала и сохранение physical cleanup failure

- Commit f18c4f0edb4a7e8f45e1796c567703a7a8316f50 запушен; PR #73 открыт
  и прикреплён. Qodo 1543768 completed на этом SHA: ef93d214 action_required
  (raw UUID маскируется в connection log) и 0a04cc36 remediation_recommended
  (close теряет false result и уже завершившуюся cleanup rejection). Оба
  подтверждены; attribution не менялся, ручной запрос ревью не выполнялся.
- До исправления result retention: npm.cmd test -- src/main/connectionStopDeadline.test.ts -t 'retains physical|clears a retained'
  — 3 failed / 2 passed / 13 skipped, 0.264 s, exit 1
  (.tmp/wp0-stop-qodo73-outcome-before.log). После deadline проверяются false
  и throw при close во время drain и после его завершения. Независимый
  cleanupFailure сохраняет оба исхода; close видит их в обоих timing. Только
  успешный cleanup retry снимает failure; повторный false его не стирает.
  Terminal operation при этом не публикуется повторно.
- До log fix npm.cmd test -- src/main/connectionOperationLogging.test.ts —
  1 failed, 0.479 s, exit 1 (.tmp/wp0-stop-qodo73-log-before.log): actual JSONL
  двух stop операций содержал четыре одинаковые redacted UUID маски.
  Общий operationLogDetails применяется feature observer и настоящим main
  connection observer: оба log ID содержат обратимый op_ ключ со всеми 128 битами.
  UUIDv4 в owner/FSM/IPC receipt сохраняется согласно тому 3 §1.2; redactor
  credential UUID не ослаблялся. Проверен actual JSONL и diagnostic read-back.
- Промежуточные адресные 231 passed / 1 failed: старое assertion ожидало
  redacted-uuid лишь от теперь исправленного operationId. Добавлен UUID в
  непривилегированное opaqueNote поле, чтобы отдельно доказать сохранение
  credential-shaped redaction (.tmp/wp0-stop-qodo73-regression.log).
  Revix RangeError suggestion применён к timeout range validation start/stop.
- Окончательный адресный набор stop/logging/correlation/rotation/lifecycle/
  main cleanup/model tours — 235 passed / 7 files, 25.73 s, exit 0
  (.tmp/wp0-stop-qodo73-regression-final.log). npm.cmd run build — exit 0,
  включая typecheck 160 channels / 0 public any (.tmp/wp0-stop-qodo73-build.log).
  Traceability AC 927/927 / F 210/210 и git diff --check — exit 0.
  На пересобранном out node scripts/test-electron-runtime.mjs —
  ELECTRON_SMOKE_PASS; node scripts/test-wp1-native.mjs --ipc-only —
  WP1_NATIVE_PASS, оба exit 0 (.tmp/wp0-stop-qodo73-electron.log,
  .tmp/wp0-stop-qodo73-csp.log). Новый full выполняется; нужны commit/push
  и exact-head Qodo/CI, initial CI 39195107993 относится к прежнему head.
- Initial CI 39195107993 completed/success на f18c4f0, watcher exit 0:
  Windows unit/traceability/production IPC/CSP/WFP/native reads, Rust и сайт.
  Это не gate незапушенных Qodo fixes; после их commit нужен новый exact-head run.
- Окончательный npm.cmd test для Qodo fixes — **4466 passed / 5 skipped /
  0 failed**, 276 files passed / 2 skipped, **177.55 s**, exit 0
  (.tmp/wp0-stop-qodo73-full.log). Во время full code/test tree не менялся.
  Все перечисленные проверки относятся к этому состоянию; следующий шаг —
  atomic commit/push и новое автоматическое ревью/CI. WP-0/WP-2 goal active.

### PR #73 — повторный Qodo: восстановление после старого failure и stop receipt ID

- Exact-head CI 39195863329 completed/success на 83613ba59b25c6e2a95be87fdcef29a14d37172f.
  Qodo 1543813 completed на том же SHA: 0a04cc36 implemented, но ef93d214
  остался action_required/pending (ID исправлен только в log projection),
  новый 6d7d0e92 action_required/pending подтвердил вечный отказ выхода после
  старого failed stop. Gate не пройден; следующий участок не начат.
- До исправления stale failure: npm.cmd test -- src/main/connectionStopDeadline.test.ts src/main/lifecycleCleanup.test.ts -t 'observed old|permits exit after shutdown'
  — 2 failed / 194 skipped, 0.793 s, exit 1
  (.tmp/wp0-stop-qodo73-stale-before.log). Shutdown отказывал с
  ShutdownCleanupUnconfirmed: connection-lifecycle даже после успешной очистки.
- Успешный подтверждённый reconnect сбрасывает старый cleanupFailure; failed,
  thrown и unconfirmed start его сохраняют. Shutdown логирует прежний отказ,
  выполняет независимые штатные backstops и только после их успеха вызывает
  confirmShutdownCleanup: closed, no startup/stopping и fresh canConfirmStop.
  Неуспех runtime/network/env/capture сохраняет failure и запрещает выход;
  второй terminal event не публикуется.
- Stop UUIDv4 представлен op_<32 hex> до публикации/возврата, со всеми 128 битами
  и version/variant. Fallback correlation равен ID; operationLogDetails не
  удваивает префикс. Это заменяет прежнее утверждение о raw UUID в stop receipt.
  Managed IDs/cancel API и redactor не менялись. Actual JSONL и diagnostic
  read-back двух stop операций сохраняют receipt ID, маскируя credential UUID.
- Промежуточный адресный набор stop/logging/correlation/rotation/lifecycle/
  cleanup/model tours — 245 passed / 7 files, 18.44 s, exit 0
  (.tmp/wp0-stop-qodo73-recovery-regression.log). Затем positive reconnect
  case усилен настоящим FSM/evidence. Build с typecheck — exit 0
  (.tmp/wp0-stop-qodo73-recovery-build.log); traceability AC 927/927 / F 210/210
  и git diff --check — exit 0. Новый full выполняется. Дополнительно проверяется
  actual Soft shutdown: после env rollback внутренний soft evidence должен
  подтверждать остановку. Финальные проверки и commit ещё не заявляются.
- Промежуточный full до Soft уточнения: npm.cmd test — 4476 passed /
  5 skipped / 0 failed, 276 files passed / 2 skipped, 188.71 s, exit 0
  (.tmp/wp0-stop-qodo73-recovery-full.log). Процесс дожидались до terminal;
  источники/тесты во время прогона не менялись.
- Actual Soft startup + shutdown с настоящими lane/FSM воспроизвёл stale
  softProtectionApplied после успешного env rollback. До исправления
  npm.cmd test -- src/main/lifecycleCleanup.test.ts -t 'Soft evidence' —
  1 failed / 2 passed / 181 skipped, 1.75 s, exit 1
  (.tmp/wp0-stop-qodo73-soft-before.log). Shutdown сбрасывает Soft evidence
  только после подтверждённого env cleanup. При false/throw прежний признак
  сохраняется вместе с failure. OS boundaries в этих cases подменены.
- Окончательный адресный набор той же команды семи файлов — 248 passed,
  36.07 s, exit 0 (.tmp/wp0-stop-qodo73-recovery-regression-final.log).
  npm.cmd run build с typecheck 160 channels / 0 public any — exit 0
  (.tmp/wp0-stop-qodo73-recovery-build-final.log). Повторные traceability
  AC 927/927 / F 210/210 и git diff --check — exit 0. Финальный full,
  Electron/IPC/CSP smoke выполняются; новые commit/review ещё не заявляются.
- Окончательный npm.cmd test — **4479 passed / 5 skipped / 0 failed**,
  276 files passed / 2 skipped, **211.14 s**, exit 0
  (.tmp/wp0-stop-qodo73-recovery-full-final.log). Code/test tree не менялся
  во время full. node scripts/test-electron-runtime.mjs — ELECTRON_SMOKE_PASS,
  exit 0 (.tmp/wp0-stop-qodo73-recovery-electron.log), включая bounded stop
  через production contextBridge. node scripts/test-wp1-native.mjs --ipc-only
  — WP1_NATIVE_PASS, exit 0 (.tmp/wp0-stop-qodo73-recovery-csp.log).
  Scope остаётся IPC/runtime с fake OS, не новая Windows TUN/rollback приёмка.
  Локальный gate пройден; следующий шаг — commit/push и automatic Qodo/CI
  на новом SHA. Общая цель WP-0, затем WP-2 остаётся active.

### PR #73 — окончательная приёмка и merge; восстановлена совместная проверка Revix/Qodo

- Commit d05716fd187c12ff0a3abbdb206f3e006ecc93fd запушен в #73.
  Automatic Qodo 1543882 completed на этом SHA: ef93d214, 0a04cc36,
  6d7d0e92 implemented, новых findings нет. Snapshot API сохранён в
  .tmp/qodo73-d05716f-final.json. Ручных review requests и attribution не было.
- Revix review 5566743333 на d05716f completed, итог Low risk в актуальном
  PR summary. Вопрос 4310209574 разобран: successful reconnect снимает старую
  ошибку, но не утверждает завершение старого rollback; новая активная сессия
  сохраняет обязанность штатной очистки. Exit всегда требует свежих независимых
  runtime/network/env/capture backstops. Вопрос 4310101300: поздний physical
  success не переписывает terminal timeout; fresh successful stop подтверждает
  disconnected. Suggestion 4310135544 о сохранении исходного error text остаётся
  minor diagnostic improvement, не доказательство небезопасного выхода.
- Первый CI 39197147181 на d05716f завершился failure: 4478 passed /
  2 failed / 4 skipped, 285.78 s. Существующие firewallStatus missing-rule-id
  и splitTunnelDiscovery sibling-products превысили 5000 ms. Полный log:
  .tmp/wp0-stop-qodo73-recovery-ci-failed.log. Причина задержки не установлена.
  После terminal npm.cmd test -- src/main/firewallStatus.test.ts src/main/splitTunnelDiscovery.test.ts
  — 75 passed, 9.46 s, exit 0 (.tmp/wp0-stop-qodo73-ci-followup.log).
- Повторён только failed Windows job на неизменном d05716f, без изменения
  кода/assertions/timeouts. CI 39197147181 attempt 2 completed/success,
  watcher exit 0: 4480 passed / 4 skipped, 221.60 s, traceability, production
  Electron/IPC/CSP, WFP и native reads PASS. Rust/сайт success.
  .tmp/wp0-stop-qodo73-ci-attempt2-full.log. Первый failure не превращён в PASS.
- Владелец уточнил 19.10: Revix снова имеет квоту и работает в связке с Qodo.
  Теперь оба review учитываются на final SHA; CodeRabbit остаётся исключён.
  Перед merge #73 отдельно проверены exact head, mergeable=true/clean,
  завершённый Qodo без открытых findings, Revix Low risk и CI success.
  REST merge с expected SHA, затем отдельный GET подтвердил merged=true,
  state=closed, merged_at=2026-10-19T04:11:41Z,
  merge 8977657ee5255849297d16d0b0935bc39461acc6.
- Main fast-forward до merge. git diff --exit-code d05716f HEAD -- . — exit 0,
  tree совпадает с проверенным head. Создана codex/wp0-config-review-followup.
  Владелец отдельно указал Revix Needs changes у уже слитого #70. Прочитаны
  все четыре комментария: async commit callback, staging после crash,
  наследование широкого destination DACL для secrets и wall-clock cancel test.
  Они проверяются по текущему main; прежний merge/Qodo не закрывает их.
  Следующий участок WP-0 — адресный follow-up #70, затем общий остаток пакета.

### WP-0 — follow-up Revix #70: synchronous commit и закрытый secret export

- Revix #70 4309508917 подтверждён частично: прежний registry удерживал
  physical lease и ждал thenable в finally, но запускал async callback до
  обнаружения нарушения. Native/bound async callback мог начать эффекты до
  validation error. До исправления npm.cmd test -- src/main/operationRegistry.test.ts src/main/configExportAcl.test.ts -t 'before starting any effects|restricts secret staging'
  — 3 failed / 52 skipped, 1.32 s, exit 1
  (.tmp/wp0-config-review-before.log): два async cases и реальная Windows ACL.
- commit принимает SynchronousCommitResult: Promise/thenable-returning callback
  отвергается tsc (регрессии @ts-expect-error проверяются typecheck), nullable
  и primitive results сохраняются. Native и bound async функции отвергаются
  до вызова. Для untyped JS, вернувшего thenable из обычной функции, остаётся
  fail-closed drain: validation terminal публикуется после фактического
  завершения уже начатой работы. Простое удаление runtime thenable guard, как
  в рекомендации Revix, разрешило бы такому JS опубликовать ложный success.
  Дополнительный before-case — 1 failed / 47 skipped, 0.400 s, exit 1
  (.tmp/wp0-config-review-thenable-before.log), затем исправлен порядок error/drain.
- Revix 4309538135 подтверждён: secrets mode наследовал широкий DACL старого
  destination. Режим передаётся из production config:export в writer/ACL helper.
  Secret staging до plaintext и итоговый файл получают protected user/SYSTEM
  DACL; POSIX branch требует текущего owner и mode 0600. Redacted export
  сохраняет прежнюю owner/group/DACL политику. Changed destination по-прежнему
  запрещает replacement. Native Windows и controlled POSIX tests это проверяют.
- Вопрос 4309452228 о crash: actual production writer выполняется в отдельном
  Node-процессе с настоящим registry/I/O/ACL. После write/fsync/close до commit
  parent принудительно завершает свой child и ждёт exit. Старый destination
  остаётся неизменным; plaintext staging может остаться, но доступен только
  текущему user/SYSTEM. Проверка читает реальный DACL. Подменён только logger.
  Generic startup sweep чужих выбранных каталогов не вводился; отсутствие
  crash residue не заявляется. Восстановление конфиденциальности не выдаётся
  за автоматическую очистку после аварии.
- Suggestion 4309452225 учтён: prompt dialog cancel проверяется fake timers,
  cancelled envelope приходит при advanceTimersByTimeAsync(0) до release
  native dialog; drain/admission assertions сохранены. Native Electron smoke
  по-прежнему проверяет реальный bounded IPC result в пределах 900 ms.
- Промежуточный адресный набор registry/config/ACL/POSIX/errors/rotation:
  168 passed, 12.61 s (.tmp/wp0-config-review-regression.log); после расширения
  untyped thenable case — 169 passed / 7 files, 14.94 s, exit 0
  (.tmp/wp0-config-review-regression-final.log). Typecheck обнаружил недопустимый
  windowsHide в ForkOptions; fixture переведён на hidden spawn Node с IPC.
  npm.cmd run build, включая typecheck 160 channels / 0 public any — exit 0
  (.tmp/wp0-config-review-build.log). Traceability AC 927/927 / F 210/210,
  git diff --check — exit 0. Финальный full и runtime smokes выполняются.
- Окончательный npm.cmd test — **4487 passed / 5 skipped / 0 failed**,
  276 files passed / 2 skipped, **213.21 s**, exit 0
  (.tmp/wp0-config-review-full.log). Во время прогона code/test tree не менялся.
  Проверяется финальный hidden spawn crash fixture. node scripts/test-electron-runtime.mjs
  — ELECTRON_SMOKE_PASS (.tmp/wp0-config-review-electron.log),
  node scripts/test-wp1-native.mjs --ipc-only — WP1_NATIVE_PASS
  (.tmp/wp0-config-review-csp.log), оба exit 0. Build/typecheck/traceability
  результаты выше относятся к этому tree; следующий шаг — commit/push/PR
  и завершённые automatic Revix + Qodo с exact-head CI.
- Дополнительно REST-инвентаризация последних закрытых PR #54–73 по текущему
  automated Revix badge: Needs changes только у #70. Его badge не переписывается
  вручную; исправления и новый verdict фиксируются follow-up PR. Это проверка
  текущей отметки, не повторный code review всех этих PR. WP-0/WP-2 goal active.

### WP-0 — PR #74: проверка Qodo и Revix, обязательная secret policy

- Создан PR #74 (codex/wp0-config-review-followup), первый head
  4034c3a8c9f4a13424ee6ae63bb61fe743bf4f50. Автоматический Qodo 1544037
  завершён на этом SHA; review 5566925736. Revix review 5566928799 на том же
  SHA, automated verdict Low risk. Существенный Qodo finding не проигнорирован.
- Qodo 270339fa-407b-42dd-bce8-255a82a47da2 / 4310332836 подтвердил:
  три credential-bearing key/proxy file handlers оставили redacted default,
  сохраняя широкие права существующего destination. Все три теперь передают
  secrets. По Revix 4310334594 mode обязателен и у writer, и у ACL helper;
  untyped отсутствующий/невалидный mode также отвергается до plaintext.
  Actual handler tests создают файл с дополнительным reader SID S-1-5-19,
  экспортируют single key/all keys/proxies и читают настоящий Windows DACL.
- Qodo 0488a161-cdc6-4dcb-ad5c-ab33a5802744 / 4310332842 подтвердил:
  timeout/cancel во время invalid-commit drain мог опубликовать другой terminal.
  После обнаружения malformed thenable validation имеет приоритет; controller
  уже aborted, physical lease сохраняется до drain, error публикуется один раз.
  Это только защитный путь некорректного untyped commit; обычные cancellation
  и deadline остаются prompt. Проверены deadline, external/manual cancel, close.
- Revix 4310334601: bound async с изменённым Symbol.toStringTag обходил guard.
  Вместо строкового tag используется AsyncFunction instanceof вместе с V8
  types.isAsyncFunction. Новый case доказывает отказ до entered/persist.
  Revix 4310334607: secrets POSIX replacement также требует того же владельца
  destination, что redacted; чужой owner отвергается до chmod/chown.
- Before: npm.cmd test -- src/main/operationRegistry.test.ts src/main/serverKeyExportSecurity.test.ts src/main/configExportPosixSecurity.test.ts -t 'bound-tagged|invalid-commit validation|broadly readable destination|destination owned by another'
  — 9 failed / 1 passed / 72 skipped, 3.28 s, exit 1
  (.tmp/wp0-config-qodo74-before.log). После исправления четырёхфайловый набор
  registry/key handlers/POSIX/Windows ACL — 91 passed, 9.83 s, exit 0
  (.tmp/wp0-config-qodo74-regression.log); затем добавлены три invalid-mode cases.
- npm.cmd run build (включает typecheck, 160 channels / 0 public any) — exit 0
  (.tmp/wp0-config-qodo74-build.log). Traceability: AC 927/927, F 210/210, exit 0.
  node scripts/test-electron-runtime.mjs — ELECTRON_SMOKE_PASS;
  node scripts/test-wp1-native.mjs --ipc-only — WP1_NATIVE_PASS; оба exit 0
  (.tmp/wp0-config-qodo74-electron.log, .tmp/wp0-config-qodo74-csp.log).
  Полный Vitest выполняется на финальном code/test tree; автоматические ревью
  и CI потребуются снова после push. Startup sweep crash residue не добавлен.
- Первый полный npm.cmd test после исправлений: 4499 passed / 1 failed /
  5 skipped, 218.33 s, exit 1 (.tmp/wp0-config-qodo74-full.log).
  appLoggerRotation.test.ts читал stat(app.log), когда app.prev.log уже появился,
  но новый app.log ещё не создан. Тест заменён ожиданием полного конечного
  оракула через vi.waitFor: prev — файл, live log меньше cap; временный ENOENT
  между rename/recreate повторяется, итоговые требования не ослаблены.
  Production logger не изменён. Адресный семифайловый набор, включая этот тест,
  registry, оба key handlers набора, config/POSIX/native ACL: 159 passed,
  21.53 s, exit 0 (.tmp/wp0-config-qodo74-regression-final.log).
  Финальный npm.cmd run typecheck — exit 0
  (.tmp/wp0-config-qodo74-typecheck-final.log). Повторный полный прогон запущен.
- Повторный npm.cmd test завершён: **4500 passed / 5 skipped / 0 failed**,
  276 files passed / 2 skipped, **211.32 s**, exit 0
  (.tmp/wp0-config-qodo74-full-final.log). Code/test tree во время прогона
  не менялся. Все адресные/full/typecheck/build/traceability/runtime процессы
  завершены; git diff --check — exit 0. Исправления готовы к commit/push,
  новый final-head CI и automatic reviews ещё не объявлены пройденными.

### WP-0 — Qodo #74: атомарное создание secret staging

- eb7aed617712bff56b2075e89e0a5a565eb5eaf8 запушен. Qodo 1544121 completed
  на этом SHA автоматически пометил оба прежних findings implemented.
  Revix check-run 117892946691 completed/success на том же SHA, Ready to merge;
  attribution трёх замечаний выполнена ботом. Но Qodo нашёл новый high finding
  4559f832-f0fd-4f30-bdd6-1a33ee561826 / 4310391901: Windows staging сначала
  появлялся с inherited DACL; чужой заранее открытый handle переживал последующее
  закрытие ACL и мог читать будущий plaintext. Merge не выполнялся.
- Before: npm.cmd test -- src/main/serverKeyExportSecurity.test.ts -t 'broadly readable destination'
  — 3 failed / 18 skipped, 6.98 s, exit 1
  (.tmp/wp0-config-atomic-acl-before.log). Actual parent directory получил
  наследуемый reader SID S-1-5-19. Проверка на границе Node open до prepare/write
  выявляет открытый staging во всех трёх production key handlers.
- Secret Windows file теперь создаётся через FileStream CreateNew overload
  с protected current-user/SYSTEM FileSecurity в самой операции создания,
  FileShare.None до закрытия initial handle. Node затем открывает уже private
  файл; прежние ACL verification, destination identity и terminal rename остаются.
  Общий PowerShell executor и private ACL descriptor переиспользуются.
  POSIX wx/0600 и redacted policy не менялись. Новый collision case доказывает,
  что CreateNew не обрезает и не удаляет существующий файл.
- Адресный набор actual key handlers / Windows ACL / config operations / key
  operations — 91 passed, 28.43 s, exit 0
  (.tmp/wp0-config-atomic-acl-regression.log), до добавления collision case.
  npm.cmd run build с typecheck — exit 0 (.tmp/wp0-config-atomic-acl-build.log).
  Traceability — AC 927/927, F 210/210, exit 0. Финальный полный Vitest запущен
  с collision case, code/test tree зафиксирован. Startup sweep не добавлен.
- Финальный npm.cmd test — **4501 passed / 5 skipped / 0 failed**,
  276 files passed / 2 skipped, **223.63 s**, exit 0
  (.tmp/wp0-config-atomic-acl-full.log), включая новый collision case.
  node scripts/test-electron-runtime.mjs — ELECTRON_SMOKE_PASS;
  node scripts/test-wp1-native.mjs --ipc-only — WP1_NATIVE_PASS; оба exit 0
  (.tmp/wp0-config-atomic-acl-electron.log, .tmp/wp0-config-atomic-acl-csp.log).
  git diff --check — exit 0. CI 39200719744 на предыдущем eb7aed6 завершён
  success, watcher exit 0, полный лог .tmp/wp0-config-qodo74-ci-eb7aed6.log.
  Этот CI не переносится на новый atomic-create tree: после push ждём новый.

### WP-0 — Qodo #74: идентичность protected staging при handoff

- c3b07b96b66cc3da4e48bcdd61fcfa0d394fb2f8 запушен. Qodo 1544165 completed
  на этом SHA, atomic-DACL finding implemented; новый high
  d3f24732-d171-40ed-856b-25b576e8371b / 4310433646 подтвердил handoff race:
  shared-directory entry можно заменить между private CreateNew и Node r+.
  До исправления реальный retained-reader substitution case возвращал success.
  npm.cmd test -- src/main/serverKeyExportSecurity.test.ts -t 'substituted staging file'
  — 1 failed / 21 skipped, 1.70 s, exit 1 (.tmp/wp0-config-identity-before.log).
- Creation helper получает volume serial/file ID непосредственно с защищённого
  FileStream SafeFileHandle через GetFileInformationByHandle. Native struct
  использует точные uint64 расчёты; одноразовый локальный probe подтвердил
  совпадение с Node BigIntStats dev/ino. Node до prepare/write сравнивает ID
  своего opened handle с ID creation handle. Ноль/невалидный ID отвергается.
  Перед terminal rename снова проверяются identity и staging snapshot.
  Cleanup проверяет ID и не удаляет подменённый чужой entry.
- Revix 4310434879: timeout после CreateNew до подтверждения ID может оставить
  пустой private staging. Без доказательства владения неизвестный entry не
  удаляется; добавлен bounded warning 'config export staging creation not confirmed'
  с cleanupFailed/reason/operationKey. Plaintext пишется только после подтверждения
  ID. Это честная граница, не обещание отсутствия temp residue. Revix 4310434884
  (nitpick о .itest) не меняет поведение: existing native/crash security cases
  оставлены в обязательном default CI, чтобы не исключать их из полного прогона.
- Первый адресный прогон после нового native preparation: 89 passed / 4 failed,
  44.45 s, exit 1 (.tmp/wp0-config-identity-regression.log). Все четыре — ожидание
  входа в controlled boundary за прежние 1000 ms, когда реальная компиляция
  native metadata helper ещё не закончилась. Подготовительное ожидание этих
  cases стало 5000 ms, test budget 15 s; cancellation/deadline/assertions после
  admission не ослаблялись. Финальный четырёхфайловый набор — 93 passed,
  46.64 s, exit 0 (.tmp/wp0-config-identity-regression-final.log).
  Дополнительный pre-commit substitution test — 1 passed / 10 skipped, 2.18 s,
  exit 0 (.tmp/wp0-config-identity-commit.log), проверяет old destination и то,
  что cleanup сохраняет substitute. Финальный build/full запущены с этим case.
- CI 39201559580 предыдущего c3b07b9 завершён success, watcher exit 0
  (.tmp/wp0-config-atomic-acl-ci-c3b07b9.log). Revix check 117895430457
  completed/neutral с вопросом и nitpick. Qodo high исключил merge независимо
  от прежних зелёных проверок. После нового push оба ревью и CI нужны заново.
- npm.cmd run build (с typecheck), traceability AC 927/927 / F 210/210,
  node scripts/test-electron-runtime.mjs (ELECTRON_SMOKE_PASS) и
  node scripts/test-wp1-native.mjs --ipc-only (WP1_NATIVE_PASS) — exit 0
  (.tmp/wp0-config-identity-build.log, .tmp/wp0-config-identity-electron.log,
  .tmp/wp0-config-identity-csp.log). Первый полный прогон — 4502 passed /
  1 failed / 5 skipped, 235.55 s, exit 1 (.tmp/wp0-config-identity-full.log).
  configIpcErrors.test mock file.stat терял переданный bigint:true и подменял
  BigIntStats на numeric Stats. Mock теперь передаёт options настоящему fd.stat;
  production identity check не ослаблен. Адресный configIpcErrors — 38 passed,
  1.02 s, exit 0 (.tmp/wp0-config-identity-errors.log). Повторный full запущен.
- Повторный npm.cmd test — **4503 passed / 5 skipped / 0 failed**,
  276 files passed / 2 skipped, **232.83 s**, exit 0
  (.tmp/wp0-config-identity-full-final.log). Code/test tree во время прогона
  не менялся. Финальный npm.cmd run typecheck — exit 0
  (.tmp/wp0-config-identity-typecheck-final.log). git diff --check — exit 0.
  Все локальные процессы terminal; новый commit/push проходит повторный
  exact-head review/CI gate. WP-0 и WP-2 goal остаётся active.

### WP-0 — Qodo #74: запрет небезопасного export namespace

- На 6c691f1 Qodo 1544270 completed: прежние findings implemented, новый high
  bc51a4ea-9a1b-4466-84f3-c84bc2431f92 / 4310516238 — shared directory entry
  можно подменить после финального lstat до renameSync. Revix 117900191974
  completed/neutral: minor 4310523114 (избыточные соседние snapshots),
  4310523120 (неточное cleanupFailed при подтверждённом отказе создания).
- Автоматическая проверка разрешений отклонила пробный native handle rename
  с причиной blocked by policy, без подробностей; вызов не исполнялся и не
  повторялся другим способом. Выбран fail-closed fallback: на Windows проверять
  owner/ACL/reparse каждого каталога до корня. UNC/null DACL/untrusted owner или
  чужие права удаления, изменения ACL/owner/атрибутов и generic write/all
  отвергаются permission. Приложение не меняет пользовательские directory ACL.
  Trusted boundary: current user/SYSTEM/Administrators/TrustedInstaller.
  Произвольный malicious same-user process за эту границу не включается.
- Before новых parent/ancestor regressions: 2 failed / 11 skipped, 4.83 s,
  exit 1 (.tmp/wp0-config-namespace-before.log). Первый guard прогон: 22 failed /
  13 passed, 8.63 s (.tmp/wp0-config-namespace-regression.log): настоящие .tmp и
  OS Temp имеют sandbox principals с MODIFY/DELETE_CHILD. Их не внесли в trust.
  Положительные native fixtures перенесены в новые private каталоги user profile;
  меняется ACL только каждого созданного fixture, cleanup удаляет только его.
- При переносе обнаружен PowerShell argument-mode дефект нового вызова guard:
  method expression pathData должен быть заключён в скобки. Redacted variable
  path работал, secrets ошибочно отвергался. Промежуточный прогон: 15 failed /
  20 passed, 34.83 s (.tmp/wp0-config-namespace-regression2.log). После исправления
  два native набора: 35 passed / 0 failed, 31.71 s, exit 0
  (.tmp/wp0-config-namespace-regression3.log), до последующих уточнений minors.
- Revix minors исправлены: один identity-only check внутри commit; creation
  fault различает подтверждённое отсутствие создания/коллизию и indeterminate
  outcome. Только второй оставляет cleanupFailed warning, не удаляя unknown entry.
- CI 39203144730 на 6c691f1 завершён failure: два subscription import tests не
  дождались loopback request за стандартный 1 s на Windows runner. Подготовка
  теперь ждёт до 5 s, test budget 15 s; cancellation после admission по-прежнему
  <900 ms. Полный failed CI лог: .tmp/wp0-config-identity-ci-failure.log.
  Локальный npm.cmd run typecheck — exit 0, 160 channels/0 public any
  (.tmp/wp0-config-namespace-typecheck.log). Расширенный адресный набор запущен.
- Расширенный адресный набор: npm.cmd test -- src/main/configExportAcl.test.ts
  src/main/serverKeyExportSecurity.test.ts src/main/configOperations.test.ts
  src/main/serverKeyOperations.test.ts src/main/configExportSecurity.test.ts
  src/main/configIpcErrors.test.ts src/main/subscriptionOperations.test.ts —
  **159 passed / 0 failed**, 103.92 s, exit 0
  (.tmp/wp0-config-namespace-targeted.log). Затем negative matrix расширена
  до шести directory rights × parent/ancestor и двух reparse cases (secrets/redacted).
  Mapped network drives также отвергаются: буква диска сама по себе не доказывает
  local namespace. Финальный полный прогон включает эти уточнения.
- Финальный npm.cmd test — **4517 passed / 5 skipped / 0 failed**,
  276 files passed / 2 skipped, **315.01 s**, exit 0
  (.tmp/wp0-config-namespace-full.log). Code/test tree во время прогона не менялся.
  npm.cmd run typecheck — exit 0, 160 channels/0 public any
  (.tmp/wp0-config-namespace-typecheck-final.log); npm.cmd run build — exit 0
  (.tmp/wp0-config-namespace-build-final.log). python -X utf8
  docs/04-приёмочные-тесты/traceability/check-coverage.py — AC 927/927,
  F 210/210, exit 0. node scripts/test-electron-runtime.mjs — ELECTRON_SMOKE_PASS;
  node scripts/test-wp1-native.mjs --ipc-only — WP1_NATIVE_PASS; оба exit 0
  (.tmp/wp0-config-namespace-electron.log, .tmp/wp0-config-namespace-csp.log).
  git diff --check — exit 0. После commit/push обязательны новые CI/Qodo/Revix.

### WP-0 — #74 принят; speed test UI lifetime

- PR #74 слит: final reviewed head 2728df13848a9baed8f0a7db4f7315204ce1f7fa,
  merge/main 9761514c57428c8c09c8fab39ef9d0c38de2ccf1. REST GET подтвердил
  merged=true; fetch/ff main не изменил проверенное code tree. Qodo 1544399
  completed без открытых findings; Revix check 117906370434 completed/neutral,
  только suggestion 4310637904 и nitpick 4310637908. При stat failure до
  получения file ID пустой staging намеренно не удаляется наугад: cleanupFailed
  сообщает об остатке, plaintext ещё не записан. Postfix getuid assertion — minor.
  CI 39205182891 completed/success, watcher exit 0
  (.tmp/wp0-config-namespace-ci-watch.log). Needs changes #70 закрыт этим follow-up.
- Ветка codex/wp0-speed-test-ui-lifetime создана от main 9761514. AT-00-003/008:
  production SpeedTest получает request identity до invoke, кнопку отмены и
  unmount cleanup. Main сохраняет собственный operationId/correlation, привязывает
  requestId к WebContents, отвергает duplicate admission и foreign/stale cancel,
  aborts destroyed requester. Legacy no-arg run сохранён. Bounded cancellation
  не освобождает physical lease до drain и не допускает late history commit.
- Mounted/request/revision fences исключают late result/error/progress/history
  и перезапись post-run history медленным initial read. Завершение run не ждёт
  history refresh; cancel IPC failure допускает retry. UI использует существующие
  Mac components и ru/en copy. При визуальной проверке найден прежний дефект:
  на 414 px history row обрезал server/profile, хотя document scrollWidth был
  равен clientWidth (родитель скрывает overflow). Добавлены перенос строки,
  метрик и длинных имён; result metrics на узком окне идут вертикально.
- До исправления: npm.cmd test -- src/main/speedTestOperations.test.ts
  src/renderer/pages/SpeedTest.lifecycle.test.tsx — 5 failed / 19 passed,
  2.81 s (.tmp/wp0-speed-ui-before.log). После первых исправлений — 24 passed,
  3.10 s (.tmp/wp0-speed-ui-targeted.log); расширенный набор — 25 passed,
  3.09 s (.tmp/wp0-speed-ui-targeted2.log). Первый standalone typecheck выявил
  TS2352 в test translation cast; fixture теперь явно выбирает speedTest/common.
- Первый полный npm.cmd test — 4529 passed / 5 skipped / 0 failed,
  277 files passed / 2 skipped, 362.79 s, exit 0 (.tmp/wp0-speed-ui-full.log).
  Во время этого прогона изменён responsive JSX: этот full не объявляется
  финальным для нового tree. Затем добавлен late rejection после unmount case;
  окончательный полный прогон запущен отдельно.
- npm.cmd run build — exit 0 (.tmp/wp0-speed-ui-build-responsive.log), включает
  typecheck и parity 161 channels / 0 public any. Python traceability — AC 927/927,
  F 210/210, exit 0. node scripts/test-electron-runtime.mjs — ELECTRON_SMOKE_PASS
  и SPEED_UI_NATIVE_PASS, exit 0 (.tmp/wp0-speed-ui-electron-final.log): actual
  handlers/registry/production preload/WebContents, immediate cancel <900 ms,
  native UUID/correlation, retained drain, foreign/stale refusal, requester destroy
  без history commit. Контролируются HTTP/VPN readiness, внешнего I/O нет.
  node scripts/test-wp1-native.mjs --ipc-only — WP1_NATIVE_PASS, exit 0
  (.tmp/wp0-speed-ui-csp.log); это IPC/CSP local subset.
- Browser fixture (.tmp/wp0-speed-ui/) использует actual page/store/styles/i18n
  с fake Electron API. Light/dark, keyboard focus+Enter cancel, unmount/remount,
  complete/results/history проверены визуально. Viewport 280/320/414: running
  без horizontal scroll; completed с длинными непрерывными server/profile:
  clientWidth/scrollWidth 272/272, 312/312, 406/406 (8 px vertical scrollbar),
  offscreen spans 0 на каждом размере. Screenshot проверен в обеих темах.
  Применён design-doctrine; referenced .claude rules и accuracy_report.mjs /
  verify_states.mjs / verify_responsive.mjs отсутствуют в установленном skill
  и проекте. Эти gates не запускались и не объявляются PASS. Полный UI/AT
  этим subset не закрывается. После final full/typecheck обязательны commit,
  push и автоматические Qodo/Revix/CI на окончательном SHA.
- Финальный npm.cmd test — **4530 passed / 5 skipped / 0 failed**,
  277 files passed / 2 skipped, **380.87 s**, exit 0
  (.tmp/wp0-speed-ui-full-final.log); production/test tree во время прогона
  не менялся. Финальный npm.cmd run typecheck — exit 0, 161 channels /
  0 public any (.tmp/wp0-speed-ui-typecheck-final.log). git diff --check — exit 0.
  Все validation processes terminal. После browser QA temporary Vite watcher
  завершился EBUSY на Cookies созданного native smoke; это произошло после
  render/geometry assertions, production build и native smokes завершились exit 0.
  Browser viewport сброшен, свой tab закрыт; server больше не работает.

### WP-0 — Qodo #75: renderer reload/crash

- PR #75 открыт на ced3ae6fb55b4a395a55435bc311f46987eac2b0. Qodo 1544593
  completed с medium 804519c2-da30-4e49-9f2a-aec4eee27739 / 4310801749:
  reload, full navigation или renderer crash не вызывают React cleanup и не
  уничтожают WebContents, поэтому тест мог остаться без страницы-владельца.
  Замечание подтверждено: две новые unit-регрессии до исправления — 2 failed /
  22 skipped, 2.71 s, exit 1 (.tmp/wp0-speed-ui-reload-before.log).
- Main теперь aborts render-process-gone и did-start-navigation только для
  main frame и !isSameDocument, используя Electron 44 details object (deprecated
  positional arguments не используются). Same-document и subframe навигация
  не прерывают тест. Все три lifetime listeners снимаются в finally.
  Адресный npm.cmd test -- src/main/speedTestOperations.test.ts
  src/renderer/pages/SpeedTest.lifecycle.test.tsx — 29 passed, 3.34 s, exit 0
  (.tmp/wp0-speed-ui-reload-targeted.log), включая listener cleanup и late history.
- Actual Electron smoke дополнен настоящим reload: WebContents остаётся жив,
  операция cancelled, busy lease сохраняется до drain, stale cancel false,
  history пуста. node scripts/test-electron-runtime.mjs — ELECTRON_SMOKE_PASS /
  SPEED_UI_NATIVE_PASS, exit 0 (.tmp/wp0-speed-ui-reload-electron.log).
  node scripts/test-wp1-native.mjs --ipc-only — WP1_NATIVE_PASS, exit 0
  (.tmp/wp0-speed-ui-reload-csp.log). npm.cmd run build — exit 0
  (.tmp/wp0-speed-ui-reload-build.log); traceability AC 927/927, F 210/210, exit 0.
  Полный новый npm.cmd test запущен; production и unit sources после его старта
  не менялись (уточнён read-back snapshot только в native fixture).
- CI 39207992467 на прежнем ced3ae6 завершён success, watcher exit 0
  (.tmp/wp0-speed-ui-ci-watch.log). Это не CI нового исправления. Revix review
  5567522570 на ced3ae6 сообщил free-quota-reached: полного ревью нет,
  возобновление 20.10 в 00:00 UTC / 03:00 МСК. Это не approval; действует
  указание владельца учитывать Revix пока есть квота. Qodo остаётся главным;
  attribution findings не изменялась. Для нового head нужны automatic Qodo и CI.
- Повторный npm.cmd test — **4532 passed / 5 skipped / 0 failed**,
  277 files passed / 2 skipped, **323.86 s**, exit 0
  (.tmp/wp0-speed-ui-reload-full.log). npm.cmd run typecheck — exit 0,
  161 channels / 0 public any (.tmp/wp0-speed-ui-reload-typecheck.log).
  git diff --check — exit 0. Все validation processes terminal; новый commit
  включает только подтверждённый Qodo fix, regressions/native fixture и журнал.

### WP-0 — #75 принят; допуск плановых функций WP-12

- PR #75 слит: final reviewed head 1e57482c2730f7fc2dfc543a731447618a3aa6d2,
  merge/main 07a77cb18ada642b9de28705ab862211f5eec0cc. REST GET подтвердил
  merged=true; fetch/ff main совпал с проверенным head без tree diff.
  Qodo 1544667 completed, открытых findings нет, прежний medium закрыт кодом
  и regressions (attribution вручную не менялась). CI 39209022143 completed/
  success на том же SHA, watcher exit 0 (.tmp/wp0-speed-ui-reload-ci-watch.log):
  Windows unit/traceability, production IPC/CSP, WFP ABI/rollback и Electron
  native reads, сайт и Rust sidecar. Revix free-quota-reached сохраняется до
  20.10 00:00 UTC; полного ревью #75 нет, это не approval. Учитываем Revix
  при доступной квоте по решению владельца. Goal WP-0 → WP-2 active.
- Новый участок на codex/wp0-planned-feature-gates от main 07a77cb:
  AT-00-009/AT-12-002. Норматив: ТЗ-06 WP-0 и §10.8, набор WP-12.
  Код четырёх WP-12 функций не вводится. Добавлен runtime release registry
  mihomo/amneziawg/process-monitor/browser-boxes: enabled=false,
  laboratoryAdmission=null, перечень необходимых AT. Admission не читается
  из пользовательских settings/env; в текущем релизе лабораторных допусков нет.
  Выданный snapshot — отдельная копия, его изменение не меняет policy.
- В настоящем main startup зарегистрированы planned-features:status/activate,
  production preload и shared contracts имеют точный паритет. Активация любой
  из четырёх функций даёт typed permission и feature.activation-denied с
  reason=laboratory-evidence-missing, requiredTests и исходной IPC correlation.
  Functional WP-12 IPC endpoints отсутствуют. Неизвестный ID и переданное
  caller'ом fake evidence отклоняются input schema до handler effects.
- Первый адресный запуск: 9 passed / 2 failed, 1.83 s, exit 1
  (.tmp/wp0-planned-targeted.log): ошибка в parametrized test table, Vitest
  разворачивал массив аргументов в callback. Исправлена сама таблица; policy
  не ослаблялась. Адресный набор с production Sidebar, Settings и preload
  validators — 65 passed, 2.58 s, exit 0
  (.tmp/wp0-planned-targeted-final2.log). Sidebar обычного/advanced режима
  и Settings не показывают WP-12 controls даже с подложенными true flags.
- npm.cmd run typecheck — exit 0, 163 channels / 0 public any
  (.tmp/wp0-planned-typecheck.log); npm.cmd run build — exit 0
  (.tmp/wp0-planned-build.log). Traceability — AC 927/927, F 210/210, exit 0.
  node scripts/test-electron-runtime.mjs — ELECTRON_SMOKE_PASS и
  SPEED_UI_NATIVE_PASS, exit 0 (.tmp/wp0-planned-electron.log). Новый native
  subset вызывает actual policy через production preload/contextBridge:
  четыре typed refusals, четыре настоящих JSONL denial events с исходными
  correlation ID, неизменность off/null registry и отказ foreign WebContents
  до admission handler. node scripts/test-wp1-native.mjs --ipc-only —
  WP1_NATIVE_PASS, exit 0 (.tmp/wp0-planned-csp.log). git diff --check — exit 0.
  Полный npm.cmd test запущен; production/unit sources после старта не меняются.
  Native fixture read-back дополнительно читает только complete JSONL lines
  при polling, чтобы не разбирать ещё дописываемый хвост; native rerun нужен.
  Это gate отсутствующих planned features, не реализация или приёмка WP-12.
- Native rerun после уточнения polling — ELECTRON_SMOKE_PASS и
  SPEED_UI_NATIVE_PASS, exit 0 (.tmp/wp0-planned-electron-final.log).
- Финальный npm.cmd test — **4549 passed / 5 skipped / 0 failed**,
  279 files passed / 2 skipped, **310.26 s**, exit 0 (.tmp/wp0-planned-full.log).
  Production/unit sources во время прогона не менялись. Built out/main/index.js
  содержит обе регистрации и вызов registerPlannedFeatureHandlers в startup;
  out/preload/index.js — оба invoke метода и schemas. git diff --check — exit 0.
  Все validation processes terminal. После commit/push нужны automatic Qodo и
  CI окончательного head; Revix учитывается при наличии квоты.

### WP-0 — #76 принят; реестр миграций секретных хранилищ

- PR #76 слит: final head e232e8fb1da367e764e2b7b017ad4e3c7d3f84f3,
  merge/main fa1bd9fa7f0fc452a6a63cea20d2096f2a208ff7. REST GET подтвердил
  merged=true; fetch/ff main и tree diff с reviewed head — без расхождений.
  CI 39211150906 completed/success: Windows, Rust и сайт success на том же SHA;
  watcher exit 0 (.tmp/wp0-planned-ci-watch.log). Qodo 1544820 completed,
  открытых findings нет. Revix review 5567746509 сообщил free-quota-reached
  до 20.10 00:00 UTC / 03:00 МСК: полного ревью нет, это не approval.
  Замечания Revix #70 уже закрыты follow-up #74, а не игнорируются из-за Qodo.
- Ветка codex/wp0-store-migrations от fa1bd9f; область — AT-00-006 и
  AT-01-001/010, F-074, ТЗ-06 §5/§10. Registry интегрирован в actual settings,
  server-picker и server-groups; существующие lazy security facades сохранены.
  Реальные legacy версии 0/1 settings/picker идут прямо в 2; фиктивный этап
  0→1 не придуман. Groups 0→1. Уже current plaintext получает отдельный
  safe-storage-v1-repair. Остальные 17 stores пока сохраняют формат 0;
  startup классификация/перенос между хранилищами этим участком не закрыты.
- planStoreMigrations даёт dry-run без эффектов. Main-only synchronous runner
  защищает legacy backup, готовит detached candidate и проверяет расшифрованный
  результат, фиксирует ID/from/to/inputChecksum/outputChecksum/backupChecksum,
  backupSuffix и timestamp в migrationHistory. Затем один atomic Conf replacement
  и read-back; success audit только после него. Ошибка подготовки оставляет
  исходный файл; сбой commit/read-back имеет явный error/stage без обещания
  сохранности, не подтверждённого чтением. Повторный/reentrant запуск отвергнут.
  Проверка актуальности перед commit не является межпроцессным CAS.
- Constructor defaults для трёх stores удалены; read defaults не переписывают
  legacy file до backup. Сохранены неизвестные поля и partial settings.
  Если прежняя .pre-safe-storage-v1.bak относится к другому входу, она остаётся,
  новый snapshot защищается отдельно под SHA-256 текущих исходных bytes и его
  decrypt/read-back сверяется. Полный input snapshot checksum и исходные bytes
  checksum различаются явно; новый result checksum исключает текущую запись
  migrationHistory, чтобы не делать самоссылочную контрольную сумму.
- Новый real Conf набор — 28 fixtures/boundaries: исторические версии, current
  plaintext repair, exact original backup, metadata, повторный import/restart,
  ошибка подготовки и retry, недоступный DPAPI, future refusal, stale backup,
  partial settings, dry-run, reentrancy, intervening change, commit/read-back fault.
  Адресный npm.cmd test -- src/main/storeMigrations.test.ts
  src/main/sharedStoresSecurity.test.ts src/main/settingsSecretSecurity.test.ts
  src/main/settingsForensicsDefault.test.ts src/main/settingsLoginItem.test.ts —
  67 passed, 1.37 s, exit 0 (.tmp/wp0-migrations-targeted-final.log).
- Старые упрощённые Store mocks расширены whole-store get/set и fallback get.
  Autostart fault injection выполняется после initial migration: проверяется
  прежняя граница записи после изменения ОС. Import fixture проходит startup
  preflight до action snapshots. Первая правка fixture вызвала неэкспортированный
  picker.getProfiles; исправлено на picker.serverPicker.getProfiles. Switch
  assertions теперь проверяют настоящий persisted null вместо отсутствующего
  поля mock. Адресный import/switch — 32 passed, 1.67 s, exit 0
  (.tmp/wp0-migrations-consumer-fast2.log); key export consumer — 22 passed
  в mixed run, оставшиеся 21 failures этого старого run относятся к исправленным
  import/switch fixtures (.tmp/wp0-migrations-consumer-tests.log).
- Первый npm.cmd test остановлен exit 1 после обнаружения старых mocks;
  во время него менялся tree, финальной проверкой он не является
  (.tmp/wp0-migrations-full.log). В нём также был fail неизменённого ACL case;
  адресный npm.cmd test -- src/main/configExportAcl.test.ts -t
  'restricts secret staging and the final export' — 1 passed/24 skipped,
  4.39 s, exit 0 (.tmp/wp0-migrations-acl-recheck.log). Новый full запущен
  отдельно на окончательном production/unit tree.
- node scripts/test-wp1-migration.mjs --same-version — exit 0, пять фаз
  seed44/fail44/migrate44/unavailable44/restart44 на Electron 44.4.3 с настоящим
  safeStorage/Conf (.tmp/wp0-migrations-native-final.log). MigrationHistory,
  исходные SHA-256 из seed, отсутствие дублей после restart и exact backup
  проверены для всех трёх stores; actual JSONL содержит error подготовки и
  три committed success с открытым migrationStep. Поле id было бы замаскировано
  credential redactor: используется отдельное безопасное имя migrationStep.
  Electron 42→44 и VM matrix этим локальным subset не проверялись.
- npm.cmd run build — exit 0 (.tmp/wp0-migrations-build-final.log);
  node scripts/test-electron-runtime.mjs — ELECTRON_SMOKE_PASS и
  SPEED_UI_NATIVE_PASS, exit 0 (.tmp/wp0-migrations-electron.log);
  node scripts/test-wp1-native.mjs --ipc-only — WP1_NATIVE_PASS, exit 0
  (.tmp/wp0-migrations-csp.log). Traceability — AC 927/927, F 210/210, exit 0.
  Финальные full/typecheck и затем automatic Qodo/CI ещё ожидаются.
- Повторный full (.tmp/wp0-migrations-full-final.log) остановлен exit 1:
  выявлены дополнительные неэквивалентные Store mocks в geo/ping/consolidate;
  добавлены whole-store accessors. npm.cmd test --
  src/main/serverPickerGeoLifecycle.test.ts src/main/serverPickerPingPoisoning.test.ts
  src/main/serverPickerConsolidate.test.ts src/main/serverPickerProbe.test.ts
  src/main/serverPickerTunnelProbe.test.ts src/main/serverPickerNativeFallback.test.ts
  src/main/serverPickerGeoTransport.test.ts src/main/serverGroupsRefresh.test.ts —
  125 passed, 3.01 s, exit 0 (.tmp/wp0-migrations-picker-consumers.log).
  В том full три неизменённых Windows identity cases заняли 10.5–10.7 s и упали;
  npm.cmd test -- src/main/adaptiveNetworkIdentity.test.ts — 25 passed,
  3.62 s, exit 0 (.tmp/wp0-migrations-adaptive-recheck.log). Причина различия
  времени этим сравнением не доказана. Финальный полный набор запущен как
  npm.cmd test -- --maxWorkers=1: assertions, deadlines и состав не ослаблены;
  default двух-worker CI всё равно обязателен. Production sources не менялись;
  после исправления этих mocks unit tree также зафиксирован на время прогона.
- Финальный npm.cmd test -- --maxWorkers=1 — **4577 passed / 5 skipped /
  0 failed**, 280 files passed / 2 skipped, **311.76 s**, exit 0
  (.tmp/wp0-migrations-full-serial.log). Production/unit tree во время прогона
  не менялся. npm.cmd run typecheck — exit 0, 163 channels / 0 public any
  (.tmp/wp0-migrations-typecheck-serial.log). Все validation processes terminal;
  git diff --check — exit 0. Следующий gate — automatic Qodo и default CI
  окончательного SHA. AT-00-006 в целом остаётся частичным.
- PR #77: CI 39214950099 старого head 2ef0332 completed/success, watcher
  exit 0 (.tmp/wp0-migrations-ci-watch.log); Windows, Rust и сайт success.
  Qodo 1545089 completed выявил четыре подтверждённых замечания:
  5590b12a (backup expansion/restart), 6dba281a (empty groups/DPAPI),
  a98d9466 (ненужный groups schema bump/downgrade), d058c2ac (fake fresh migration).
  Revix review 5568127046 — free-quota-reached, полного ревью нет.
- До production fix новые regressions воспроизвели все четыре причины:
  npm.cmd test -- src/main/storeMigrations.test.ts -t
  'exceeds 16 MiB|empty legacy groups|fake legacy migration|previous schema-0'
  — 6 failed / 28 skipped, 1.11 s, exit 1
  (.tmp/wp0-migrations-qodo-before.log). После исправления source/decrypted
  plaintext остаются <=16 MiB, encoded backup <=32 MiB с проверкой до write.
  Groups сохраняет формат 0: его released reader уже поддерживает SecretRef.
  Runner не создаёт миграцию без plaintext; raw snapshot не подставляет defaults
  или version 0. Fresh read не создаёт файл/history; пустые legacy groups
  без backup не требуют DPAPI. Существующий backup продолжает проверяться.
- Первый targeted после fixes — 103 passed / 4 failed, 3.04 s, exit 1
  (.tmp/wp0-migrations-qodo-targeted.log). Уточнены корректные ожидания typed
  source validation и честного backup-skipped audit; rollback import fixture
  явно начинает с existing canonical empty stores, вместо прежнего побочного
  создания defaults при startup. Exact snapshot rollback assertions сохранены.
  Switch проверяет логическое отсутствие выбора, не требует записанного null.
  npm.cmd test -- src/main/storeMigrations.test.ts
  src/main/sharedStoresSecurity.test.ts src/main/settingsSecretSecurity.test.ts
  src/main/settingsLoginItem.test.ts src/main/settingsForensicsDefault.test.ts
  src/main/serverPickerSwitch.test.ts src/main/profileImportOperations.test.ts
  — 107 passed, 3.21 s, exit 0 (.tmp/wp0-migrations-qodo-targeted2.log).
  В real Conf suite теперь 36 cases; full/build/native и review нового SHA
  ещё ожидаются. npm.cmd run typecheck после production fixes — exit 0,
  163 channels / 0 public any (.tmp/wp0-migrations-qodo-typecheck.log).
- После Qodo fixes окончательный production/unit tree: npm.cmd test --
  --maxWorkers=1 — **4585 passed / 5 skipped / 0 failed**, 280 files passed /
  2 skipped, **308.77 s**, exit 0 (.tmp/wp0-migrations-qodo-full.log).
  npm.cmd run build — exit 0, включая typecheck 163 channels / 0 public any
  (.tmp/wp0-migrations-qodo-build.log). node scripts/test-wp1-migration.mjs
  --same-version — все пять фаз PASS, actual DPAPI/Conf/restart, exit 0
  (.tmp/wp0-migrations-qodo-native.log). node scripts/test-electron-runtime.mjs
  — ELECTRON_SMOKE_PASS / SPEED_UI_NATIVE_PASS, exit 0
  (.tmp/wp0-migrations-qodo-electron.log); node scripts/test-wp1-native.mjs
  --ipc-only — WP1_NATIVE_PASS, exit 0 (.tmp/wp0-migrations-qodo-csp.log).
  python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py —
  AC 927/927, F 210/210, exit 0; git diff --check — exit 0.
  Local native subset остаётся same-version, не Electron 42→44/VM matrix.
  Следующий gate — automatic Qodo и default CI нового exact head #77.
- PR #77 слит 19.10 после final head
  84f0d878bf9c23d43ce4a6baa21cbd792defb07c: Qodo 1545221 completed,
  открытых findings нет; CI 39216740383 completed/success, все Windows/Rust/site
  checks success, watcher exit 0 (.tmp/wp0-migrations-qodo-ci-watch.log).
  REST подтвердил merged=true, merge/main 1752bdacf18d42e4218fbc645780669e40e9ac8d.
  Fetch/ff main и git diff reviewed head → main — exit 0, tree совпадает.
  Revix остаётся без квоты до 20.10 03:00 МСК; отсутствие full review не approval.
- Следующий участок AT-00-003/005: lifetime requesting document у import/refresh/
  config/key exports. Config/key wrappers слушали только destroyed: reload и
  render-process-gone сохраняют WebContents и позволяли поздний commit.
  Manual profile import/group refresh не привязаны к requester. Общий main-only
  lifetime будет отменять только операции этого вызова на full main-frame
  navigation/crash/destroy; same-document/subframe navigation не отменяет,
  timer/background refresh сохраняет независимое владение. SPA unmount сам по
  себе этими native событиями не покрывается; page request/cancel остаётся отдельно.
- До production fix: npm.cmd test -- src/main/configOperations.test.ts
  src/main/serverKeyOperations.test.ts src/main/profileImportOperations.test.ts
  src/main/serverGroupsRefresh.test.ts -t 'requester|idle import selection'
  — **25 failed / 117 skipped**, 8.94 s, exit 1
  (.tmp/wp0-requester-before.log): прежние wrappers оставляли running/authority.
  requestDocumentLifetime объединяет main-only signal, уничтожение/crash/full
  navigation; invalidation idle config capability теперь также снимает listeners
  и очищает raw. Same-document/subframe и foreign WebContents независимы.
- npm.cmd test -- src/main/configOperations.test.ts
  src/main/serverKeyOperations.test.ts src/main/profileImportOperations.test.ts
  src/main/serverGroupsRefresh.test.ts src/main/speedTestOperations.test.ts —
  **166 passed**, 47.58 s, exit 0 (.tmp/wp0-requester-targeted.log).
  npm.cmd test -- src/main/requestDocumentLifetime.test.ts — **8 passed**,
  0.277 s, exit 0 (.tmp/wp0-requester-helper.log). Обе стороны cancellation,
  уже закрытый/aborted requester, main-only работа и repeat disposal проверены.
- npm.cmd run typecheck — exit 0, 163 channels / 0 public any
  (.tmp/wp0-requester-typecheck.log); npm.cmd run build — exit 0
  (.tmp/wp0-requester-build.log). node scripts/test-electron-runtime.mjs —
  ELECTRON_SMOKE_PASS / SPEED_UI_NATIVE_PASS / REQUEST_DOCUMENT_NATIVE_PASS,
  exit 0 (.tmp/wp0-requester-electron.log). Новая fixture использует настоящие
  hidden BrowserWindow/WebContents с sandbox, реальные reload/destroy/hash и
  production registry/helper; только длинный I/O управляемый. Abort <900 ms,
  retained drain, no late commit, foreign/same-document non-cancel и listeners
  сверяются. Реальный renderer crash покрыт здесь EventEmitter unit boundary,
  отдельное OS crash injection этим smoke не заявляется.
- node scripts/test-wp1-native.mjs --ipc-only — WP1_NATIVE_PASS, exit 0
  (.tmp/wp0-requester-csp.log); python -X utf8
  docs/04-приёмочные-тесты/traceability/check-coverage.py — AC 927/927,
  F 210/210, exit 0. Полный unit-набор и automatic PR review/CI ещё ожидаются.
- Финальный npm.cmd test -- --maxWorkers=1 — **4618 passed / 5 skipped /
  0 failed**, 281 files passed / 2 skipped, **320.37 s**, exit 0
  (.tmp/wp0-requester-full.log). Production/unit tree не менялся во время прогона;
  assertions, deadlines и состав не ослаблены. git diff --check — exit 0.
  Коммит/push выполняются в codex/wp0-requester-lifetime; следующий gate —
  automatic Qodo и default CI точного опубликованного SHA.
- Создан/прикреплён PR #78: https://github.com/newnout6-a11y/vpn/pull/78,
  первоначальный head 4ae7ab9c2e34deb05042de0c593844aa0726268d. Qodo 1545426
  completed: 0948692f-17b5-44af-81e2-a364d1328435, remediation_recommended —
  did-start-navigation срабатывает до will-navigate.preventDefault().
  Подтверждено actual Electron: node scripts/test-electron-runtime.mjs —
  exit 1, assertion 'a blocked navigation keeps the requesting document'
  (.tmp/wp0-requester-qodo-before.log). Blocked local-file navigation не менял
  документ, но отменял его запрос и отзывал selection. Сетевая попытка не нужна.
- Lifetime перенесён на main-frame did-navigate: same-document навигация это
  событие не испускает, prevented попытка его не достигает. Native regression
  проверяет guard preventDefault до foreign/hash/reload/destroy; idle config
  capability имеет отдельный handler regression. 6-suite targeted после switch —
  175 passed, 50.21 s, exit 0 (.tmp/wp0-requester-qodo-targeted.log); позднее
  добавленный отдельный idle blocked-selection case проверяется новым прогоном
  boundaries и финальным full. npm.cmd run build — exit 0, включая typecheck
  (.tmp/wp0-requester-qodo-build.log). node scripts/test-electron-runtime.mjs
  после завершения build — три PASS, exit 0
  (.tmp/wp0-requester-qodo-electron-final.log). Traceability AC 927/927,
  F 210/210 и git diff --check — exit 0.
- CI старого 4ae7ab9 / 39218961229 failed: Windows unit — 4618 passed /
  4 skipped / 1 failed, 279.94 s. Единственный fail — существующий
  serverKeyOperations 'retains bounded cause servers:export-all-proxies-file /
  ENOSPC in persistent diagnostics': test timed out in 5000 ms, без падения
  assertion (.tmp/wp0-requester-ci-failed.log). Site/Rust success; следующие
  Windows steps не запускались. Причина тайминга этим одним логом не доказана;
  production/assertion deadlines не изменены. Требуется полный default CI нового
  SHA после Qodo fix, старый run не объявляется PASS. Revix review 5568464232
  снова free-quota-reached до 20.10 03:00 МСК, full review отсутствует.
- Финальный адресный npm.cmd test -- src/main/configOperations.test.ts
  src/main/requestDocumentLifetime.test.ts — **40 passed**, 64.11 s, exit 0
  (.tmp/wp0-requester-qodo-boundaries.log), включая idle blocked-selection case.
  Final full запущен отдельно на неизменяемом production/unit tree.
- Final после Qodo fix: npm.cmd test -- --maxWorkers=1 — **4620 passed /
  5 skipped / 0 failed**, 281 files passed / 2 skipped, **393.66 s**, exit 0
  (.tmp/wp0-requester-qodo-full.log). Во время прогона production/unit tree
  неизменен, test/assertion/production deadlines не ослаблены. node
  scripts/test-wp1-native.mjs --ipc-only — WP1_NATIVE_PASS, exit 0
  (.tmp/wp0-requester-qodo-csp.log). Build/typecheck, native blocked-navigation
  regression, traceability и diff check также exit 0, как записано выше.
  Исправление идёт в тот же #78; требуются Qodo/CI нового SHA.
- PR #78 слит: final head 72cd14cf869a7e0d3eb345d1b0b099fc7294d86d;
  Qodo 1545611 completed без открытых findings; CI 39220632906 success
  (Windows/Rust/site, все проверки), watcher exit 0
  (.tmp/wp0-requester-qodo-ci-watch.log). REST merged=true; merge/main
  f35c1f8960eb0a5551ea2815553d7cc89eb274e1. Fetch/ff main и tree diff с
  reviewed head — exit 0. Старый timeout не переименован в PASS; новый run
  прошёл default CI без изменения test/assertion/production deadlines.
- Следующая ветка codex/wp0-config-request-lifetime: AT-00-003/008,
  React ImportExportSettings unmount. Request ID создаётся до invoke;
  requester-bound cancel останавливает только своё ожидание/physical lease,
  также отзывает idle выбранный config snapshot. Поздние browse/validation/apply/
  export callbacks и success timers не должны менять UI или продолжать workflow
  после unmount. Native document lifetime #78 остаётся отдельной гарантией.
- Config request lifetime: config:cancel — 164-й typed IPC канал, scoped по
  WebContents + UUIDv4 renderer workflow. Main operationId остаётся отдельным
  UUID и сохраняет correlationId. Browse/validate/idle selection/apply используют
  один token; export — отдельный. Unknown/foreign/stale cancel возвращает false,
  malformed token отклоняется до dialogs/store effects. Duplicate request
  отклоняется до замены pending dialog или claimed capability.
- ImportExportSettings отзывает свои active/idle requests и success timers при
  unmount; поздние responses не запускают следующий этап и не меняют UI.
  Исправные текущие операции сохраняют прежний workflow. Optional token не меняет
  число аргументов legacy preload calls.
- До реализации пять новых регрессий воспроизведены: npm.cmd test --
  src/main/configOperations.test.ts src/renderer/components/ImportExportSettings.test.tsx
  -t 'requester-owned|matching idle|unmount' — 5 failed / 41 skipped, 5.21 s,
  exit 1 (.tmp/wp0-config-request-before.log). После main implementation:
  3 passed /31 skipped, 5.83 s; после UI — 46 passed, 56.11 s
  (.tmp/wp0-config-request-main.log и -targeted.log первоначального прогона).
  Расширенные тесты обнаружили ошибку самого нового assertion: isBusy проверял
  kind import вместо resource config:apply (57 passed /1 failed, 65.91 s).
  Исправлено имя resource и добавлено ожидание фактического входа в write queue.
  Первый typecheck TS18048 (requests narrowing) и TS2571 в новом assertion
  исправлены; последний npm.cmd run build, включая typecheck 164 channels /
  0 public any, — exit 0 (.tmp/wp0-config-request-build.log).
- node scripts/test-electron-runtime.mjs — четыре PASS, exit 0
  (.tmp/wp0-config-request-electron.log). Новый CONFIG_REQUEST_NATIVE_PASS
  использует production config handlers, stores, registry, IPC guard и preload,
  sandbox/contextIsolation; controlled dialogs и очередь записи. Проверены
  immediate cancel <900 ms до picker response, исходная correlation, отдельный
  main UUID, чужой/stale token, token-bound selection, отсутствие export-файла
  и поздней записи, успешный новый import после отмены. Initial fixture bundle
  требовал external koffi (.node loader error); runtime external добавлен.
- node scripts/test-wp1-native.mjs --ipc-only — WP1_NATIVE_PASS, exit 0
  (.tmp/wp0-config-request-csp.log). python
  docs/04-приёмочные-тесты/traceability/check-coverage.py — AC 927/927,
  F 210/210, exit 0; git diff --check — exit 0. Полный Vitest ещё выполняется;
  PR/CI/Qodo текущего участка пока не приняты.
- Первый full npm.cmd test -- --maxWorkers=1 — 4638 passed /5 skipped /
  1 failed, 426.21 s, exit 1
  (.tmp/wp0-config-request-full-before-contract-update.log). Единственный fail:
  старый configImportSecurity ожидает permission при передаче raw JSON в новый
  slot requestId. Contract теперь отклоняет malformed token как validation до
  pathname authorization. Тест разделён: произвольный путь без token по-прежнему
  permission; renderer JSON вместо token — validation, stores не меняются.
  npm.cmd test -- src/main/configImportSecurity.test.ts — 12 passed,
  0.882 s, exit 0 (.tmp/wp0-config-request-selection.log). Новый full запущен
  на неизменяемом production/unit tree; ожидается итог.
- Второй full: 4638 passed /5 skipped /1 failed, 411.14 s, exit 1
  (.tmp/wp0-config-request-full-before-acl-budget.log). Единственный fail —
  существующий Windows ACL test 'restricts secret staging and the final export
  even when the existing file grants other readers': Test timed out in 5000ms,
  без assertion failure. Отдельный node node_modules/vitest/vitest.mjs --run
  src/main/configExportAcl.test.ts -t 'restricts secret staging' — 1 passed /
  24 skipped, 6.11 s всего /5.30 s tests+hooks, exit 0
  (.tmp/wp0-config-request-acl-repro.log). Этот тест запускает несколько настоящих
  PowerShell процессов; его harness budget согласован с соседними ACL cases:
  15000 ms вместо default5000. Assertions, IPC cancellation <900 ms и production
  operation deadlines не менялись. Финальный npm.cmd test (default workers)
  запущен после этого изменения; предыдущие failed full не объявляются PASS.
- Final npm.cmd test (default workers, production/unit tree неизменен весь
  прогон) — **4639 passed /5 skipped /0 failed**, 281 files passed /2 skipped,
  **418.05 s**, exit 0 (.tmp/wp0-config-request-full.log). Повторный typecheck
  — exit 0, 164 main/preload/shared channels, 0 public any. Build, четыре
  Electron native fixtures, IPC/CSP и traceability прошли, как записано выше.
  Production cancellation deadlines и assertions не ослаблены; увеличен только
  budget одного реального многопроцессного ACL test, с сохранением обоих
  failed full logs. Требуются CI и completed Qodo на final SHA нового PR.
- PR #79 создан и attached: initial head 157719359fb0229643b68036a186e5198d1e3212.
  Qodo 1546103 completed нашёл два замечания. Informational b201315f:
  finally tokenless вызова мог удалить новый tokened registry того же sender.
  Regression до fix — 1 failed /42 skipped, 2.29 s, exit 1
  (.tmp/wp0-config-request-qodo-before.log). Очистка теперь сверяет identity Map.
  Remediation 3cc4c42f: UI скрывал section/conflict choices после apply error.
  Regression до fix — 1 failed /16 skipped, 2.59 s, exit 1
  (.tmp/wp0-config-request-qodo-ui-before.log). Choices остаются для просмотра;
  main single-use capability по-прежнему потребляется, повторное apply старого
  token disabled, fresh native selection доступна и получает новый token.
- После обоих Qodo fixes: npm.cmd test -- src/main/configOperations.test.ts
  src/main/configImportSecurity.test.ts
  src/renderer/components/ImportExportSettings.test.tsx — 72 passed,
  58.44 s, exit 0 (.tmp/wp0-config-request-qodo-targeted.log).
  npm.cmd run build, включая typecheck 164 channels /0 public any — exit 0
  (.tmp/wp0-config-request-qodo-build.log). node
  scripts/test-electron-runtime.mjs — четыре PASS, exit 0
  (.tmp/wp0-config-request-qodo-electron.log); node
  scripts/test-wp1-native.mjs --ipc-only — WP1_NATIVE_PASS, exit 0
  (.tmp/wp0-config-request-qodo-csp.log). Coverage AC 927/927, F 210/210 и
  diff check — exit 0. Final full после fixes ещё выполняется.
  Revix #79 /5569066697 free-quota-reached до 20.10 03:00 МСК,
  полного review нет; это не approval. Нового manual review не запрашивали.
- Final после Qodo fixes: npm.cmd test — **4641 passed /5 skipped /
  0 failed**, 281 files passed /2 skipped, **420.88 s**, exit 0
  (.tmp/wp0-config-request-qodo-full.log). Production/unit tree не менялся
  во время прогона. Initial CI 39225869946 на 1577193 — success, watcher
  exit 0 (.tmp/wp0-config-request-ci-watch.log); новый head требует своего
  completed Qodo и CI, старый результат не переносится на исправления.
- PR #79 слит: final head 589490bb12f9d171329005e95c1d0350221fa453,
  Qodo 1546296 completed без открытых findings; CI 39227466851 completed/success
  (Windows/Rust/site, включая все native steps), watcher exit 0
  (.tmp/wp0-config-request-qodo-ci-watch.log). REST merged=true;
  merge/main d7a43782bfa251669092df74e073051c74aec086. Fetch/ff и tree diff
  reviewed head→main — exit 0. Revix full review по квоте отсутствует,
  отсутствие не объявляется approval. Ранее initial CI также success.
- Следующая ветка codex/wp0-server-request-lifetime от d7a4378: AT-00-003/008,
  ручные servers:add/add-to-group и groups:refresh при SPA unmount Servers.
  Main уже связывает их с document lifetime (#78), но SPA unmount не меняет
  документ. HandleAdd/handleGroupRefresh продолжают UI/store workflow после
  unmount; requester token должен быть известен до invoke, cancellation scoped
  по sender и request, поздние effects блокируются lease, shared queue drain
  сохраняется. Автоматические refresh не принадлежат renderer.
- Реализован operations:cancel-request (165-й typed IPC канал): optional token
  добавлен в servers:add/add-to-group и groups:refresh. runRequesterOperation
  хранит ownership WebContents+UUIDv4, reject duplicate/malformed до effects,
  отменяет только свою admitted lease; signal покрывает pre-admission. Commit
  остаётся терминальным: cancel во время wrapper cleanup после commit — false.
  Main operation UUID/correlation не заменяются renderer token. Legacy calls
  сохраняют прежние аргументы и document cancellation; cleanup сверяет Map.
- Servers на unmount отменяет только свои ручные requests, очищает toast timers,
  блокирует поздние data/UI/log/nav callbacks. Фоновые refresh не захватываются
  страницей. Нормальный текущий import/refresh и quiet typed cancel сохранены.
- До main fix: node node_modules/vitest/vitest.mjs --run
  src/main/serverGroupsRefresh.test.ts -t 'requester token' — 1 failed /
  40 skipped, 0.697 s, exit 1 (.tmp/wp0-server-request-before.log).
  До UI fix: npm.cmd test -- src/renderer/pages/Servers.requestLifetime.test.tsx
  — 2 failed /1 passed, 3.18 s, exit 1 (.tmp/wp0-server-request-ui-before.log).
- После implementation: npm.cmd test -- src/main/profileImportOperations.test.ts
  src/main/requesterOperation.test.ts src/main/serverGroupsRefresh.test.ts
  src/renderer/pages/Servers.requestLifetime.test.tsx src/renderer/pages/Servers.test.ts
  src/preload/preloadValidation.test.ts src/main/ipcChannelContract.test.ts —
  **157 passed**, 7 suites, **4.92 s**, exit 0
  (.tmp/wp0-server-request-boundaries.log). Включены new/target/repaste imports,
  scoped cancel, physical drain/no late writes, duplicate/malformed/stale,
  legacy overlap, committed result, unmount and current-success/toast cleanup.
- npm.cmd run build — exit 0 (.tmp/wp0-server-request-build.log);
  повторный npm.cmd run typecheck — exit 0, 165 channels /0 public any
  (.tmp/wp0-server-request-typecheck.log). node scripts/test-electron-runtime.mjs
  — пять PASS, exit 0 (.tmp/wp0-server-request-electron.log). Новый
  SERVER_REQUEST_NATIVE_PASS использует actual handlers/stores/registry/guard/
  preload/contextBridge; controlled resolver и неиспользуемые OS/runtime boundaries.
  Refresh/import/target/repaste cancel <900ms, original correlation/main UUID,
  foreign/stale refusal, no late writes, retained drain/listener cleanup и
  fresh successful import. Fixture bundling сначала потребовал перечислить
  отсутствующие runtime exports; unexpected runtime accesses бросают ошибку.
  Это native local fixture, не live VPN/OS приёмка.
- node scripts/test-wp1-native.mjs --ipc-only — WP1_NATIVE_PASS, exit 0
  (.tmp/wp0-server-request-csp.log). Traceability AC 927/927, F 210/210 и
  git diff --check — exit 0. Полный npm.cmd test выполняется; PR ещё не создан.
- Первый full npm.cmd test — **4657 passed /5 skipped /3 failed**,
  304.45 s, exit 1 (.tmp/wp0-server-request-full-native-timeouts.log).
  Все три failure в прежнем adaptiveNetworkIdentity.test.ts: native CIM
  failure/profile-only/Unicode cases exceeded default 5000 ms (5608/10405/
  10562 ms), без assertion failure. npm.cmd test --
  src/main/adaptiveNetworkIdentity.test.ts — **25 passed**, 3.87 s, exit 0
  (.tmp/wp0-server-request-identity-repro.log). Этот suite и его budgets,
  assertions и production deadlines не менялись. Причина замедления одним
  логом не доказана; полный default run повторён на неизменяемом tree.
- Final повторный npm.cmd test на том же production/unit tree —
  **4660 passed /5 skipped /0 failed**, 283 files passed /2 skipped,
  **335.97 s**, exit 0 (.tmp/wp0-server-request-full.log). Budgets/tests
  adaptiveNetworkIdentity не менялись. Build/typecheck, 157 targeted tests,
  пять Electron fixtures, IPC/CSP, coverage/diff — exit 0, как записано выше.
  Следующий PR требует completed Qodo и CI на final SHA до продолжения.

- PR #80 слит после exact-head gates: final head 5a9285e5255cc9e250bb805004de7cc57c77af7f,
  Qodo 1553608 completed без findings; CI 39290006611 completed/success
  (Windows/Rust/site, все native steps). Revix #80 сообщил free-quota-reached
  до 20.10 00:00 UTC, full review нет, это не approval. REST merged=true;
  merge/main e0b45b74a9c18ac4989e55ea90a4d4bc6eded4f5. Fetch/ff и tree diff
  reviewed head→main — exit 0. Manual review не запрашивали.
- Ветка codex/wp0-key-request-lifetime от e0b45b7: AT-00-001/003/008,
  SPA unmount экспорта ключей на Servers. Пять main entrypoints используют
  runRequesterOperation: optional UUID token, sender scope, legacy argument
  count, прежние registry UUID/correlation/commit/deadline/physical drain.
  Native consent остаётся main-only. Четыре UI export workflows создают token
  до invoke, отменяются при unmount, подавляют late success/error/log/timer.
  Flash timers используют существующую страницу cleanup, дублирование убрано.
- До fix: npm.cmd test -- src/main/serverKeyOperations.test.ts -t
  'by requester token' — 5 failed /47 skipped, 7.63 s
  (.tmp/wp0-key-request-before.log). npm.cmd test --
  src/renderer/pages/Servers.requestLifetime.test.tsx -t 'late export effects'
  — 4 failed /4 skipped, 3.84 s, exit 1 (.tmp/wp0-key-request-ui-before.log).
- Первый адресный run после fix (serverKeyOperations, Servers.requestLifetime,
  preloadValidation, ipcChannelContract) — 115 passed, 40.70 s, exit 0
  (.tmp/wp0-key-request-targeted.log). Расширенный run с serverKeyExportSecurity
  и Servers.test — 169 passed /10 failed, 43.98 s, exit 1
  (.tmp/wp0-key-request-boundaries.log): старый direct-handler helper передавал
  лишний 'a' в оба bulk-export, теперь это slot requestId. Helper приведён
  к реальному legacy arity (0 аргументов bulk, id для single). Security
  assertions и production validation не ослаблены.
- npm.cmd run build — exit 0 (.tmp/wp0-key-request-build.log).
  node scripts/test-electron-runtime.mjs — пять PASS, exit 0
  (.tmp/wp0-key-request-electron.log). SERVER_REQUEST_NATIVE_PASS расширен
  actual handlers/registry/preload/stores пятью key exports: controlled consent,
  cancel <900ms с original correlation и отдельным main UUID, foreign/stale
  refusal, retained physical drain, нет save dialog/file после late consent,
  listener cleanup и успешный новый renderer export. Настоящий clipboard не
  изменяется; его controlled late write/ownership проверены L2, не L3.
  node scripts/test-wp1-native.mjs --ipc-only — WP1_NATIVE_PASS, exit 0
  (.tmp/wp0-key-request-csp.log). Full/typecheck final ещё выполняются.

- Исправленный расширенный адресный run: npm.cmd test --
  src/main/serverKeyOperations.test.ts src/renderer/pages/Servers.requestLifetime.test.tsx
  src/preload/preloadValidation.test.ts src/main/ipcChannelContract.test.ts
  src/main/serverKeyExportSecurity.test.ts src/renderer/pages/Servers.test.ts —
  179 passed, 47.56 s, exit 0 (.tmp/wp0-key-request-boundaries-final.log).
  Позже усилены три reentrant commit tests: token cancel также false.
  Повторный npm.cmd run typecheck — exit 0, 165 channels/0 public any
  (.tmp/wp0-key-request-typecheck-final.log). Coverage AC 927/927, F 210/210
  и git diff --check — exit 0.
- Первый полный npm.cmd test — 4689 passed /5 skipped /2 failed,
  325.32 s, exit 1 (.tmp/wp0-key-request-full.log). AppSource содержал
  буквальный source assertion прежней preload signature; теперь actual
  legacy/token forwarding проверяется пятью исполняемыми preload tests,
  source assertion убран. npm.cmd test -- src/renderer/AppSource.test.ts —
  25 passed, 0.858 s, exit 0 (.tmp/wp0-key-request-source-regression.log).
  Второй failure: прежний long-consent bulk proxy case 8893 ms превысил
  default test budget 5000 ms на native private-file preparation. Для пяти
  вариантов этого parameterized test harness budget 15000 ms, как у
  соседних native file tests. Simulated 600000 ms consent, production
  work deadline и <900ms cancellation assertions не менялись. Оба test
  fixes внесены во время первого run после загрузки соответствующих suites;
  финальный полный run выполняется на неизменяемом production/unit tree.

- Final повторный npm.cmd test — **4691 passed /5 skipped /0 failed**,
  283 files passed /2 skipped, **273.53 s**, exit 0
  (.tmp/wp0-key-request-full-final.log). Production/unit tree не менялся
  во время этого прогона. Build, пять Electron fixtures, native IPC/CSP
  и адресные проверки — exit 0, как выше. До следующего участка обязательны
  completed Qodo и CI success на final опубликованном SHA.

- PR #81 слит: final head 34d4efc8cf427606f1e39a9324bb24e51006011a,
  Qodo 1553954 completed без findings; CI 39293792384 completed/success
  (Windows/Rust/site, все Electron/CSP/WFP/native steps), watcher exit 0
  (.tmp/wp0-key-request-ci-watch.log). REST merged=true; merge/main
  ab531c4c027259f01c0af01e41692d4c5ab0a1ad. Fetch/ff и tree diff
  reviewed head→main — exit 0. Revix #81 сообщил free-quota-reached
  до 20.10 00:00 UTC; полного review нет, это не approval.
- Следующая ветка codex/wp0-detail-export-lifetime от ab531c4: оставшийся
  key export UI entrypoint ServerDetailModal, AT-00-003/008. Закрытие modal
  через open=false, смена profile id, profile=null и unmount отзывают только
  его requester tokens, подавляют старые replies и очищают flash timers.
  Одна scope identity на открытый profile id; повторное открытие того же
  profile создаёт новый scope, metadata rename того же id не отменяет запрос.
  Main API/consent/commit остаются принятыми в #81. Late error прежнего
  profile не заменяет успешный результат текущего. Typed cancel тихий.
- До fix: npm.cmd test --
  src/renderer/components/ServerDetailModal.requestLifetime.test.tsx —
  10 failed, 3.42 s, exit 1 (.tmp/wp0-detail-export-before.log).
  После fix первые два suites — 12 passed, 2.23 s, exit 0
  (.tmp/wp0-detail-export-targeted.log). Расширенный run:
  npm.cmd test -- src/renderer/components/ServerDetailModal.requestLifetime.test.tsx
  src/renderer/components/ServerDetailModalSource.test.ts
  src/renderer/pages/Servers.requestLifetime.test.tsx
  src/preload/preloadValidation.test.ts — 88 passed, 4.54 s, exit 0
  (.tmp/wp0-detail-export-targeted-final.log). После него добавлены два
  profile=null boundary cases; финальный полный run включает их.
  Новый тест использует actual modal/design components и controlled IPC,
  только LiveServerCheckSection исключён как отдельный workflow.

- npm.cmd run build — exit 0 (.tmp/wp0-detail-export-build.log),
  npm.cmd run typecheck — exit 0, 165 channels/0 public any
  (.tmp/wp0-detail-export-typecheck.log), coverage AC 927/927, F 210/210
  и git diff --check — exit 0. Main/preload не менялись; native checks
  приняты на #81 и будут повторены обязательным CI следующего head.
- Первый full npm.cmd test — 4704 passed /5 skipped /2 failed,
  344.19 s, exit 1 (.tmp/wp0-detail-export-full.log). Прежние suites:
  bootRecoveryExecution trusted-empty-physical snapshot (6187 ms) и
  physicalAdapterDnsScript ObjectNotFound превысили default timeout5000;
  assertion failures нет. Эти tests и budgets не менялись.
  Отдельные повторы: npm.cmd test -- src/main/bootRecoveryExecution.test.ts
  — 30 passed, 18.30 s, exit 0 (.tmp/wp0-detail-export-boot-repro.log);
  npm.cmd test -- src/main/physicalAdapterDnsScript.test.ts — 4 passed,
  0.973 s, exit 0 (.tmp/wp0-detail-export-dns-repro.log).
  Причина замедления одним прогоном не доказана; полный default run
  повторён на том же production/unit tree, без других native test runs рядом.

- Final полный повтор npm.cmd test на том же production/unit tree —
  **4706 passed /5 skipped /0 failed**, 284 files passed /2 skipped,
  **287.12 s**, exit 0 (.tmp/wp0-detail-export-full-final.log).
  Native recovery/DNS suites и budgets не менялись. Нормативные docs/
  не редактировались; следующий участок требует completed Qodo/CI final SHA.

### 19.10.2026 — WP-0: diagnostics ZIP lifetime (ветка codex/wp0-diagnostics-export-lifetime)

- Предыдущий PR #82 слит: final head 64e089e257511b4f936d60aa8c4e5b6189b66a4a,
  Qodo 1554278 completed без findings, CI 39297189492 success; merge/main
  1549a641ed492eaae5d7c990e24a9a689e46d0f9. REST merged=true и tree equality
  reviewed head→main проверены. Revix full review отсутствует по квоте.
- AT-00-003/004/005/008, F-021/F-074/F-143: export-diagnostics теперь имеет
  requester+UUIDv4 cancellation, main operation UUID/correlation, work deadline
  120000ms и physical drain. Свежий manual snapshot находится внутри admission:
  отменённый queued/collecting snapshot не публикуется; временная запись перед
  синхронным rename. Native picker исключается из work clock, отменяется bounded.
- Архив собирается в отдельном work/bundle, Compress-Archive пишет ZIP вне bundle.
  Готовые binary bytes передаются AsyncIterable в existing identity/ACL-checked
  staging и terminal rename; выбранный файл не изменяется до commit. Ошибки
  возвращаются typed IpcFault без сырых PowerShell/path payloads. Cleanup awaited;
  warning cleanup-failed виден в результате/UI. Состав и финальная redaction
  сохранены по решению владельца ТЗ-06 §10.6. Вложенная forensics queue/summary
  проверяет active owner между async этапами; normal capture callers совместимы.
- Общий useDiagnosticsExport используется DiagnosticsCard и Settings: unmount
  отзывает свой token; late replies не меняют UI/logs/toasts и не сбрасывают новый
  busy owner. Typed cancel тихий; normal success/error и cleanup warning видны.
- До fix: npm.cmd test -- src/main/diagnosticsExportOperations.test.ts — 1 failed,
  493ms, exit1 (.tmp/wp0-diagnostics-export-before.log): operation отсутствовала.
  При расширении harness исправлены mock promisify(execFile) stdout/stderr и
  учёт завершения уже запущенной controlled compression; production guards не
  ослаблялись. Main exporter regressions: 11 passed, 0.984s, exit0
  (.tmp/wp0-diagnostics-main.log). Actual snapshot module: 3 passed, 0.438s,
  exit0 (.tmp/wp0-diagnostics-snapshot.log). Actual React обоих entrypoints —
  8 cases в окончательном full run (первые 6 прошли адресно).
- npm.cmd test -- src/main/diagnosticsExportOperations.test.ts
  src/main/systemSnapshotLifetime.test.ts src/main/systemSnapshot.test.ts
  src/main/trafficForensics.test.ts src/main/diagnosticsPreflight.test.ts
  src/renderer/components/DiagnosticsExport.requestLifetime.test.tsx
  src/renderer/components/DiagnosticsCard.test.tsx
  src/renderer/pages/Settings.render.test.tsx — 103 passed, 11.22s, exit0
  (.tmp/wp0-diagnostics-targeted.log); затем добавлены 2 typed-error UI cases.
- npm.cmd run build — exit0 (.tmp/wp0-diagnostics-build.log), typecheck 165
  channels/0 public any. node scripts/test-electron-runtime.mjs — 6 PASS
  fixtures, exit0 (.tmp/wp0-diagnostics-electron.log). Новый native ZIP fixture
  выполняет production handler/preload/registry и реальные Compress-Archive,
  binary stream, ACL checks, replacement и ZIP read-back. Collection управляемая;
  VPN/network/clipboard не меняются. Первый native run корректно отказал workspace
  namespace с DELETE_CHILD у sandbox accounts; final использует существующий
  privateExportDirectory fixture. Проверки ACL не ослаблялись.
- python docs/04-приёмочные-тесты/traceability/check-coverage.py — AC927/927,
  F210/210, exit0. Полный npm.cmd test и final remote gates выполняются.

- Первый полный npm.cmd test — 4731 passed /5 skipped /0 failed, 287 files
  passed/2 skipped, 374.83s, exit0 (.tmp/wp0-diagnostics-full.log). Во время
  прогона review обнаружил поздний success log вложенного runSystemDiagnostics;
  добавлены optional owner assertion и2 executable collector regressions.
  Этот первый run не называется final-head доказательством новой правки.
- npm.cmd test -- src/main/systemDiagnosticsLifetime.test.ts
  src/main/diagnosticsExportOperations.test.ts src/preload/preloadValidation.test.ts
  —67 passed,1.24s,exit0 (.tmp/wp0-diagnostics-nested.log). Preload legacy zero
  args/token и object refusal проверяются исполняемым bridge. Actual summary:
  npm.cmd test -- src/main/trafficForensicsSummaryLifetime.test.ts —2 passed,
  0.514s,exit0 (.tmp/wp0-diagnostics-summary.log): cancelled read не публикует
  normalized files/summary, normal generation сохранена.
- Final npm.cmd run build —exit0 (.tmp/wp0-diagnostics-build-final.log);
  node scripts/test-electron-runtime.mjs —6 PASS,exit0
  (.tmp/wp0-diagnostics-electron-final.log); node scripts/test-wp1-native.mjs
  --ipc-only —WP1_NATIVE_PASS,exit0 (.tmp/wp0-diagnostics-ipc-final.log).
  Final full run начат после этих изменений на неизменяемом code/test tree.

- Окончательный full attempt: npm.cmd test —4734 passed /5 skipped /1 failed,
  288 files passed/2 skipped,384.42s,exit1
  (.tmp/wp0-diagnostics-full-final.log). Единственный failure — прежний
  serverKeyOperations: retains bounded cause servers:export-key-file / ENOENT,
  default5000ms timeout. Diagnostics suites зелёные. Выполняется отдельный
  recheck всего файла; затем повтор default full без ослабления deadlines.
- Повторный npm.cmd run typecheck —exit0,165 channels/0 public any
  (.tmp/wp0-diagnostics-typecheck-final.log); coverage AC927/927,F210/210
  и git diff --check —exit0.
- npm.cmd test -- src/main/serverKeyOperations.test.ts —57/57 passed,52.29s,
  exit0 (.tmp/wp0-diagnostics-key-recheck.log), исходный code/test/budgets
  сохранены. Повторный полный npm.cmd test начат на том же tree.
- Финальный default npm.cmd test повтор —4735 passed /5 skipped /0 failed,
  289 files passed/2 skipped,323.76s,exit0
  (.tmp/wp0-diagnostics-full-recheck.log). Code/test tree и budgets не менялись.
  Предыдущий timeout сохранён выше. Публикация PR и exact-head Qodo/CI pending.

### PR #83 — Qodo1554946 и третий UI entrypoint

- Исходный head b870f009d0e340af9926ac583790ecf0e04398c8, Qodo1554946
  completed с6 findings. Revix free-quota-reached до20.10 00:00UTC,
  full review отсутствует. CI39304583600 — только исходный head.
- Найден третий ZIP entrypoint Maintenance. До fix4 новых actual-React cases
  failed, прежние8 passed (.tmp/wp0-diagnostics-maintenance-before.log).
  Maintenance теперь использует общий owned hook.20/20 passed; затем
  исправлено поле тестового toast message→description (не production).
- Подтверждён mixed-generation defect: export summary читает live evidence,
  но normalized artifacts/summary/session manifest пишет только в export
  staging с общим redactor. Неполный forensic subtree удаляется до упаковки.
  Три real-filesystem cases удерживают timeline/flows/summary write и отменяют
  owner: retained generation byte-identical. Старый sidecar race test ожидал
  удалённый stage writeManifest hook; теперь удерживает actual summary I/O
  и проверяет тот же queued sidecar-exit persistence.
- Подтверждён cleanup defect: optional callback writer сообщает об остатке
  adjacent temp; после cancellation/failure существующее inapp-notification
  предупреждает без путей. Успех сохраняет warning в result. Main notification
  coalesced per export. Actual cancelled-write+failed-cleanup case добавлен.
- Общий120s budget слишком тесен для последовательных native этапов.
  Export-specific deadline600000ms: test доказывает running после120s и timeout
  после600s. Native process budgets, save picker waitForUser, prompt cancel
  и physical drain сохранены.
- Восстановлен diagnostics zip written audit после terminal success без пути;
  manual picker dismissal снова пишет info. Typed cancellation/stale тихие.
- USB/network finding: intentional ACL/identity/reparse/namespace safety existing
  atomic writer не ослабляется. Неподтверждённые destinations получают typed
  permission; private destination выполняется native fixture.
- Первый review targeted83 passed/4 failed,8.85s,exit1
  (.tmp/wp0-diagnostics-review-targeted.log):3 новых write gates были перекрыты
  test read gate; старый sidecar hook ожидал удалённый writeManifest. Harness
  исправлен без ослабления production guards. Повтор5 suites87/87 passed,
  3.89s,exit0 (.tmp/wp0-diagnostics-review-targeted2.log). Затем усилены
  retained summary/manifest byte-invariance и staged session manifest.
- Review final npm.cmd run build —exit0 (.tmp/wp0-diagnostics-review-build.log);
  node scripts/test-electron-runtime.mjs —6 PASS,exit0
  (.tmp/wp0-diagnostics-review-electron.log); node scripts/test-wp1-native.mjs
  --ipc-only —WP1_NATIVE_PASS,exit0 (.tmp/wp0-diagnostics-review-ipc.log).
  Coverage AC927/927,F210/210 и diff check —exit0. Final full начат на
  неизменяемом code/test tree (.tmp/wp0-diagnostics-review-full.log).
- Финальный review npm.cmd test —4746 passed /5 skipped /0 failed,
  289 files passed/2 skipped,323.00s,exit0
  (.tmp/wp0-diagnostics-review-full.log). Production/test tree с запуска
  не менялся. CI39304583600 на прежнем b870f009 completed/success;
  для нового commit требуются новые Qodo/CI.

- Qodo1555116 completed на c4b967e3164a0fe8d7203335c43c4bde039b34ad:
  пять findings автоматически implemented, новых нет. Namespace finding
  остался pending. Inline comment4317511787 предлагает безопасную альтернативу:
  сохранить strict path, но показать ясную подсказку выбрать local private
  folder и проверить namespace refusal. Эта альтернатива реализована в hook
  всех3 экранов, без ослабления ACL. Новый actual exporter regression
  воспроизводит Assert-ExportNamespace refusal, typed permission, unchanged
  destination, отсутствие staging и success log. UI сохраняет bounded error
  и добавляет конкретную инструкцию про «Документы»/ACL/network.
- При переносе summary в staged copy сохранено pure merging
  preserveObservedSidecarStop: sidecar exit во время summary отражается и в
  staged session manifest. Старый race test теперь проверяет также exported
  sidecar.running=false, не только retained/runtime state.
- npm.cmd test -- src/main/diagnosticsExportOperations.test.ts
  src/main/trafficForensics.test.ts
  src/renderer/components/DiagnosticsExport.requestLifetime.test.tsx
  —75/75 passed,3.18s,exit0 (.tmp/wp0-diagnostics-namespace-targeted.log).
- Namespace follow-up npm.cmd run build —exit0
  (.tmp/wp0-diagnostics-namespace-build.log);6 Electron fixtures —PASS,exit0
  (.tmp/wp0-diagnostics-namespace-electron.log); coverage AC927/927,F210/210
  и git diff --check —exit0. Final full начат на неизменном code/test tree
  (.tmp/wp0-diagnostics-namespace-full.log). IPC/CSP повтор не требуется:
  после прежнего PASS доверенная граница/preload/CSP не менялись.
- Namespace final npm.cmd test —4747 passed /5 skipped /0 failed,
  289 files passed/2 skipped,317.26s,exit0
  (.tmp/wp0-diagnostics-namespace-full.log). Code/test tree не менялся.
  CI39306933512 на прежнем c4b967e completed/success; новому commit нужны
  собственные Qodo/CI.

### 19.10.2026 — WP-0: целостность общего audit/event history

- PR #83 слит после final head28055df133441a881b2e2710b7b20c8c379ab02a,
  Qodo1555252 completed:6/6 implemented,0 open; CI39308634092 success.
  Merge/main4bd9177a52a812be9af3c6727397860b8d6d3aa3. REST merged=true,
  tree reviewed head=main9f8118f674559c24eff7d30c791dec7ea8a519da.
  Revix full review отсутствует по квоте; это не approval.
- Следующий подтверждённый остаток AT-00-005/010,F-143: app.log — общий
  durable JSONL, но startup не проверяет его целостность; broken tail
  может склеиться со следующей записью, history.corrupted отсутствует.
  Connection-history имеет отдельный guard, общий audit/event history — нет.
- Реализация: bounded startup scan существующих двух log generations,
  сохранение их исходных bytes, явный sanitized history.corrupted marker
  и separator перед append к незавершённой строке; новые записи продолжаются.
  Versioned event schema и captured source/owner с честными unknown/
  unconfirmed/indeterminate defaults; monotonic serialization order и
  correlation сохраняются через async append queue. Норматив docs/ не меняется.
  Сначала actual-filesystem regressions, затем production fix и DoD.
- До fix: npm.cmd test -- src/main/appLoggerIntegrity.test.ts —9 failed/9,
  6.31s,exit1 (.tmp/wp0-audit-integrity-before.log).
- Новый shared app-event contract сохраняет legacy JSONL; version1 содержит
  captured source/owner и честные route=unconfirmed/confidence=indeterminate.
  Calendar timestamp/correlation/metadata фиксируются при событии, monotonic
  clock — при сериализации. Bounded scanner:64KiB chunks,256KiB row,32MiB
  per generation; incomplete/unreadable scan —history.unavailable, не PASS.
  Сканируются обе generations до записи маркеров. Bytes не переписываются,
  незавершённый current tail отделяется newline. Ошибка append видна как
  sanitized console history.write-failed; это не гарантия fsync/durability.
- Первый targeted48:44 passed/4 failed,6.58s,exit1
  (.tmp/wp0-audit-integrity-targeted.log). Исправлены: capture calendar ts
  до queue; сохранение validated root route enum при diagnostics redaction;
  regular-file check; test parser пропускает null/array damaged records.
  Повтор7 suites48/48 passed,2.98s,exit0
  (.tmp/wp0-audit-integrity-targeted2.log).
- npm.cmd test -- src/main/appLoggerIntegrity.test.ts
  src/main/auditLogIntegrity.test.ts src/shared/app-event.test.ts
  src/main/appLoggerRotation.test.ts src/main/appLoggerCleanup.test.ts
  src/main/appLoggerError.test.ts src/main/appLoggerRedaction.test.ts
  src/main/actionCorrelation.test.ts —52/52 passed,8 suites,3.22s,exit0
  (.tmp/wp0-audit-integrity-targeted3.log). Включены32MiB scan cap, continued
  oversized row accounting, repeat restart и write-failure recovery.
- npm.cmd run typecheck —exit0,165 channels/0 public any
  (.tmp/wp0-audit-integrity-typecheck.log). Full npm.cmd test и build
  запускаются на неизменном code/test tree; результаты ниже.
- npm.cmd run build —exit0, включает повтор typecheck165 channels/0 public any
  (.tmp/wp0-audit-integrity-build.log). node scripts/test-electron-runtime.mjs
  —6 PASS,exit0 (.tmp/wp0-audit-integrity-electron.log), включая production
  contextBridge/logging и actual diagnostics ZIP. Coverage AC927/927,F210/210
  и git diff --check —exit0. Полный npm.cmd test ещё выполняется.
- Final npm.cmd test —4783 passed/5 skipped/0 failed,292 files passed/2 skipped,
  315.36s,exit0 (.tmp/wp0-audit-integrity-full.log). Code/test tree не менялся
  с начала run. Full/build/typecheck/Electron/coverage/diff прошли; следующий
  участок допускается после собственного completed Qodo и CI на final SHA.
- PR #84: initial head ab2ad5a299ede487761b4d5e3c7b11d8acc4926c,
  automatic Qodo1555507 completed:2 findings. Revix quota до20.10 00:00UTC,
  полноценного review нет. CI39311702631 — только initial head.
- Оба Qodo cases воспроизведены: npm.cmd test --
  src/main/appLoggerIntegrity.test.ts —15 passed/2 failed,2.53s,exit1
  (.tmp/wp0-audit-review-before.log). complete=false ранее был в corruption
  details, но отсутствовал независимый history.unavailable. Теперь оба маркера
  независимы. Near-cap app.log + damaged app.prev.log прежде терял previous
  при записи marker+event, хотя ordinary event помещался. Bounded4096-byte
  allowance служебных startup reports откладывает преждевременную ротацию;
  ordinary rotation продолжается, allowance сбрасывается при roll/clear.
- Повтор того же8-suite targeted command —54/54 passed,3.12s,exit0
  (.tmp/wp0-audit-review-targeted.log), включая последующую ordinary rotation.
  Final full/build и remote review нового SHA необходимы; attribution Qodo
  вручную не меняется.
- Review build/typecheck —exit0 (.tmp/wp0-audit-review-build.log),165 channels/
  0 public any; node scripts/test-electron-runtime.mjs —6 PASS,exit0
  (.tmp/wp0-audit-review-electron.log). Coverage AC927/927,F210/210 и diff
  —exit0. CI39311702631 completed/success на initial ab2ad5a; новый SHA
  всё ещё требует собственного review/CI. Final full ещё выполняется.
- Review full npm.cmd test —4784 passed/1 failed/5 skipped,359.81s,exit1
  (.tmp/wp0-audit-review-full.log). Прежний elevatedPsHelperNative case
  preserves command IDs… занял5516ms при default Vitest5000ms; assertions
  production helper не показали отдельной ошибки. Адресный npm.cmd test --
  src/main/elevatedPsHelperNative.test.ts —2/2 passed,5.71s,exit0
  (.tmp/wp0-audit-review-native-recheck.log). Его код и budgets не менялись.
  Повтор полного npm.cmd test на том же code/test tree —отдельный лог
  .tmp/wp0-audit-review-full2.log; первый full не объявляется зелёным.
- Full2 —4784 passed/1 failed/5 skipped,374.96s,exit1: прежний native
  servers:export-all-proxies-file approval case занял7871ms при Vitest5000ms.
  Ошибка именно outer harness timeout, не failure security assertions.
  Для двух выявленных fixtures outer budgets согласованы с native boundaries:
  helper20s при spawnSync15s, file approval15s как соседние ACL fixtures.
  Production deadlines, <900ms responsiveness и все safety assertions сохранены.
  Новые filesystem suites сами создают parent .tmp, без зависимости от порядка.
  После этих test-only правок запускаются targeted/full/typecheck; прежние два
  failures остаются записанными, не подменяются отдельным успешным прогоном.
- Final targeted command: прежние8 suites + elevatedPsHelperNative.test.ts +
  serverKeyExportSecurity.test.ts —78/78 passed,10 suites,27.98s,exit0
  (.tmp/wp0-audit-review-harness-targeted.log). Final typecheck —exit0,
  165 channels/0 public any (.tmp/wp0-audit-review-final-typecheck.log).
- Full3 npm.cmd test —4785 passed/5 skipped/0 failed,292 files passed/2 skipped,
  360.34s,exit0 (.tmp/wp0-audit-review-full3.log). Code/test tree не менялся
  с начала run. Build и6 Electron fixtures пройдены на этом production tree
  до test-only setup/budget правок. Coverage/diff —exit0. Новый published SHA
  требует собственного completed Qodo и CI; initial-head success не переносится.

### 19.10.2026 — WP-0: requester lifetime групповой проверки ключей

- PR #84 принят: final head 7c716fe9c861346492c4c1c39c6f60a891097fa8,
  Qodo1555833 completed, оба findings implemented; workflow39315249433
  success (Windows/Rust/site). REST merged=true, merge/main5641f2b.
  Tree reviewed/main совпал:0d26be396419f396bf6ab4a72ee2093b5f98f8dc.
  Revix полноценного ревью по квоте не дал; это не approval.
- Подтверждённый следующий остаток AT-00-003/004/008: groups:check-health
  не имел owner/deadline/requester cancellation, поздние workers писали
  profiles и success log; Servers обновлял UI после unmount. Старый catch
  возвращал raw error текстом внутри ok:false.
- До production fix: npm.cmd test -- src/main/groupHealthOperation.test.ts
  —13 failed/13,10.37s,exit1 (.tmp/wp0-group-health-main-before.log).
  Предыдущий совместный run имел3 UI failures/20 passed и ошибку mock setup
  main suite (.tmp/wp0-group-health-before.log); недостающие xray boundary
  mocks исправлены перед отдельным main запуском.
- Реализация использует общий registry с kind health-check, work deadline600s,
  requester token/document lifetime и существующий operations:cancel-request.
  Probe signal проверяется после каждой async границы; raw SOCKS dial,
  закрытие сокетов/процесса и cleanup удерживают lease до settlement.
  Cleanup прежних orphan probes выполняется один раз до probes, чтобы не
  убивать текущие sibling workers. Terminal commit идёт в общей очереди
  import/refresh; изменённые/удалённые credentials дают conflict.
- Первый targeted после fix:35 passed/1 failed,3.45s,exit1
  (.tmp/wp0-group-health-targeted1.log): TLS test ошибочно ожидал retained
  незавершённый handshake после фактического destroy. Добавлены реальные
  close boundaries для sockets; поздний TLS callback ограждён от write.
  Повтор npm.cmd test -- src/main/groupHealthOperation.test.ts
  src/renderer/pages/Servers.requestLifetime.test.tsx src/main/keyHealthChecker.test.ts
  —58/58 passed,3.44s,exit0 (.tmp/wp0-group-health-targeted2.log).
- Typecheck1 выявил два места обновления контракта: shared electron-api
  request token и control HTTP consumer error handling. Оба обновлены,
  typecheck2 —exit0,165 channels/0 public any.
  Проверки дополнительных границ, полный набор и remote gates ниже.
- Расширенный targeted7 suites251/251 passed,5.70s,exit0
  (.tmp/wp0-group-health-targeted4.log). Включены real requester wrapper
  token/document loss, foreign/stale/malformed/duplicate cancellation,
  physical socket-close drain, max5 workers, stale credentials и reentrant commit.
- npm.cmd run typecheck —exit0,165 channels/0 public any
  (.tmp/wp0-group-health-typecheck-final.log); npm.cmd run build —exit0
  (.tmp/wp0-group-health-build.log). node scripts/test-electron-runtime.mjs
  —6 PASS,exit0 (.tmp/wp0-group-health-electron.log); это regression native
  fixtures общей границы/прежних workflows, health worker проверен на
  controlled OS boundaries. Coverage AC927/927,F210/210 и diff —exit0.
- Первый full npm.cmd test —4817 passed/1 failed/5 skipped,305.88s,exit1
  (.tmp/wp0-group-health-full.log). Единственный failure: прежний native
  serverKeyOperations persists nonsecret success counts для export-all-proxies
  занял9333ms при outer Vitest5000ms. Отдельно оба success-count cases:
  npm.cmd test -- src/main/serverKeyOperations.test.ts -t 'persists nonsecret success counts'
  —2 passed/55 skipped,3.15s,exit0 (.tmp/wp0-group-health-export-recheck.log).
  Их outer budget согласован с соседними native file/consent fixtures:15000ms,
  поскольку реальная Windows ACL/file preparation имеет собственный native budget.
  Assertions redaction/counts/correlation и production deadlines не менялись.
  Запускается адресный набор и затем полный default npm.cmd test заново.
- Дополнительный self-review нашёл concrete TLS construction failure:
  tlsConnect мог бросить синхронно, оставляя исходный SOCKS socket открытым;
  добавленный physical-close drain тогда удерживал lease. Full2 намеренно
  остановлен (session35699, verified Vitest PID15872), не засчитывается как PASS.
  Новая regression до fix:1 failed/21 skipped,1.04s,exit1
  (.tmp/wp0-group-health-tls-before.log); её teardown дал также unhandled
  cancelled rejection, harness теперь явно consumes task rejection.
  TLS construction catch уничтожает исходный socket; already-aborted вызов
  отказывает до TLS creation. Запущены повторные адресные/full/build проверки.
- Full3 также намеренно остановлен (session11453, verified Vitest PID31332)
  перед расширением operational-error regressions; PASS не заявляется.
  До fix local I/O denial cases:2 failed/1 passed/22 skipped,0.373s,exit1
  (.tmp/wp0-group-health-permission-before.log). mkdtemp уже отвергал ошибку,
  но write config и pidfile раньше превращали её в offline либо подавляли.
  Теперь failure local setup/spawn/pidfile/TLS construction не меняет verdict
  ключа: сохраняется permission/internal категория, canonical renderer error.
  Remote SOCKS failures остаются sanitized per-key observations.
  Добавлены sync/async spawn EACCES/ENOENT cases и отдельный remote failure case.
  Targeted complete результаты и новый full ниже.
- Final production tree build/typecheck —exit0
  (.tmp/wp0-group-health-build-verified.log),6 native Electron fixtures PASS
  (.tmp/wp0-group-health-electron-verified.log). Targeted7 suites260/260
  passed,4.20s,exit0 (.tmp/wp0-group-health-targeted-complete2.log).
- Full4 default npm.cmd test —4825 passed/2 failed/5 skipped,300.10s,exit1
  (.tmp/wp0-group-health-full4.log). Оба failures — default5000ms outer budgets:
  serverKeyOperations bounded cause export-all-proxies/ENOENT7356ms и прежний
  firewallStatus bulk queries5461ms. Assertions ошибок безопасности не отмечены
  как failed. Чтобы проверить гипотезу конкуренции native Windows fixtures,
  новые бюджеты не расширялись: запущен весь набор последовательно командой
  npm.cmd test -- --maxWorkers=1, лог .tmp/wp0-group-health-full-serial.log.
  Это ещё не PASS; результат будет записан после завершения.
- Полный npm.cmd test -- --maxWorkers=1 —4827 passed/5 skipped/0 failed,
  293 files passed/2 skipped,321.42s,exit0
  (.tmp/wp0-group-health-full-serial.log). Code/test tree не менялся с начала
  этого run. Это полный serial command; прежние default failures сохранены.
  Build/typecheck и6 native Electron fixtures проверили тот же production tree.
  Coverage AC927/927,F210/210 и diff check —exit0. Следующий участок требует
  собственного completed Qodo и CI success на опубликованном final SHA.

### PR #85: замечания Qodo (19.10.2026, поздний вечер)

- Qodo1556439 completed на initial head22e1348 с4 findings. Сохранены
  .tmp/qodo85-initial.json; attribution вручную не менялся. HTTP route
  уже требует POST+control token (обратное утверждение в security finding
  не подтверждается), но raw OS error действительно мог попасть в detail.
- Регрессии до fix: npm.cmd test -- src/main/groupHealthOperation.test.ts
  src/main/externalProxy.test.ts —6 failed/58 passed,0.455s, Vitest exit1
  (.tmp/wp0-group-health-review-before.log). Проверены HTTP409/403 вместо500,
  доступность другой группы и receipt key. Shell tail завершился0; это
  не меняет сохранённый Vitest verdict.
- HTTP consumer теперь переводит категории в соответствующий HTTP status
  и canonical message без OS exception/path, сохраняет404 missing/empty
  и обязательный token. Resource key-health:<groupId> допускает разные
  группы, сохраняя исключение повторов одной группы до physical drain.
  Сериализованные commits проверены на сохранение обоих результатов;
  отмена одной группы не отменяет другую.
- ManagedOperation receipts сохраняют UUIDv4 для cancellation и дополнены
  operationKey. Production credential redactor проверен на2 receipt:
  UUID скрыт, keys/correlation различимы, отмена исходным UUID работает.
- Targeted3 suites121/121 passed,1.75s; расширенный targeted7 suites214/214
  passed,4.57s (.tmp/wp0-group-health-review-targeted2.log). Указанный
  src/main/preloadValidation.test.ts отсутствует и Vitest его не включил;
  поэтому записаны фактические7 suites, а не8.
- Первый npm.cmd run build завершился2: test mock writeFile имел tuple[]
  без аргументов. Исправлена только TS-сигнатура mock; runtime поведения
  не меняет. Повтор build/typecheck —exit0,165 channels/0 public any
  (.tmp/wp0-group-health-review-build2.log). node scripts/test-electron-runtime.mjs
  —6 PASS,exit0 (.tmp/wp0-group-health-review-electron.log).
  Coverage AC927/927,F210/210 —exit0; full serial выполняется.
- Финальный адресный run с верным src/preload/preloadValidation.test.ts:
  npm.cmd test -- src/main/groupHealthOperation.test.ts src/main/externalProxy.test.ts
  src/main/operationRegistry.test.ts src/main/serverGroupsRefresh.test.ts
  src/main/keyHealthChecker.test.ts src/main/externalProxyHostIntegration.test.ts
  src/renderer/pages/Servers.requestLifetime.test.tsx src/preload/preloadValidation.test.ts
  —269/269 passed,8 suites,5.26s,exit0.
- Полный npm.cmd test -- --maxWorkers=1 —4835 passed/5 skipped/0 failed,
  293 files passed/2 skipped,271.89s,exit0 (.tmp/wp0-group-health-review-full.log).
  Во время run исправлена только TS-сигнатура mock writeFile, затем этот
  suite повторно вошёл в final targeted. Production tree не менялся.
  Build/typecheck,6 native fixtures,coverage/diff —exit0. Новый head требует
  automatic completed Qodo и CI success; initial CI39322197254 success
  относится к22e1348 и не заменяет новый gate.

## 20.10.2026 — WP-0: URL availability requester lifetime

- #85 принят: final head97c30599d34f80dd0635042b50c0f6cafbe9ac7b,
  Qodo1556605 completed,4/4 implemented без новых findings; CI39323879365
  success. REST merged=true, main23eca2605d35207db9adebaa2495548ee312a926.
  Reviewed/main tree совпал:e3db73c371992ea068c55616837280e4f2d652f8.
  Revix full review по квоте отсутствует до20.10 03:00 МСК, не approval.
- Следующий подтверждённый остаток AT-00-003/004/005/008: URL availability
  не имел общего owner/deadline/document token; DNS/HTTP/offscreen callbacks
  могли продолжить pipeline и записать history после ухода со страницы.
  Ветка codex/wp0-url-availability-lifetime создана после gate/merge #85.
- До fix npm.cmd test -- src/main/urlAvailabilityOperation.test.ts:
  22 failed/22,15.37s,exit1 (.tmp/wp0-url-ownership-before.log).
  npm.cmd test -- src/renderer/pages/Availability.requestLifetime.test.tsx:
  4 failed/1 passed,1.91s,exit1 (.tmp/wp0-url-ui-before.log).
- checkUrl использует общий registry kind availability-check, work deadline60s,
  UUID/correlation/owner и requester document lifetime. Optional token сохранён
  в main/preload/shared с legacy arity. DNS/ASN/TCP/TLS/HEAD/fallback GET/Clash
  и page setProxy/load/script проверяют отмену; реальные sockets/windows/raw
  commands удерживают ресурс до close/settlement. Запись истории — synchronous
  terminal commit с correlation/provenance; прежние строки сохраняются.
- UI token создаётся до invoke, unmount отменяет запрос. Late success/error
  не обновляют UI/log/history; typed cancellation тихая. Чтения history
  имеют revision fence, чтобы старый read не возвращал очищенную историю.
  Routing self-test остаётся отдельным entrypoint; его main lifetime этим
  участком не объявляется принятым. URL network semantics относятся к WP-7.
- Targeted main2 suites28/28 passed,0.399s; targeted5 suites150/150,2.08s.
  Первый typecheck exit2: generic inference socket result, несуществующий
  preload helper и лишний exact у role query; исправлены, typecheck2 exit0,
  165 channels/0 public any. Расширенный targeted3:162 passed/1 failed,
  2.01s — test ожидал lifecycle вместо ipc для ipc_ correlation. Исправлено
  ожидание; targeted4:163/163 passed,2.11s. Build1 exit0.
- Self-review воспроизвёл утечку offscreen window при синхронном setup throw:
  npm.cmd test -- src/main/urlAvailabilityOperation.test.ts -t 'synchronous setup'
  —1 failed/25 skipped,0.301s,exit1 (.tmp/wp0-url-window-before.log).
  Full1 намеренно остановлен до результата (session77333, проверенный
  Vitest PID33348 и его workers38076/29412); PASS не засчитывается.
  Setup failure теперь уничтожает окно, очищает timers и ждёт close.
- Targeted5: npm.cmd test -- src/main/urlAvailabilityOperation.test.ts
  src/main/urlAvailabilityVerdict.test.ts src/renderer/pages/Availability.requestLifetime.test.tsx
  src/preload/preloadValidation.test.ts src/main/operationRegistry.test.ts
  src/main/requesterOperation.test.ts —164/164 passed,6 suites,2.24s,exit0
  (.tmp/wp0-url-targeted5.log). Build2/typecheck exit0 (.tmp/wp0-url-build2.log).
  Coverage AC927/927,F210/210 и diff check exit0. Final full2/native pending.
- Final npm.cmd test -- --maxWorkers=1 —4871 passed/5 skipped/0 failed,
  295 files passed/2 skipped,291.14s,exit0 (.tmp/wp0-url-full2.log).
  Production/test tree не менялся с начала final run. Build2/typecheck,
  node scripts/test-electron-runtime.mjs (6 PASS, .tmp/wp0-url-electron.log),
  coverage и diff check —exit0. URL-specific probes проверены на controlled
  OS boundaries; шесть native fixtures проверяют общую границу/прежние workflows.
  Собственный completed Qodo/CI на опубликованном SHA обязателен до продолжения.

### PR #86: native window close, DNS и диагностические причины

- Initial head890e83a,CI39326611571 success. Qodo1556823 completed с6 findings
  (.tmp/qodo86-initial.json); вручную attribution не менялся.
- Критический executeJavaScript finding подтверждён настоящим Electron44.4.3:
  после JS redirect основной frame оставался loading, executeJavaScript
  ожидал did-stop-loading даже после actual window close. Native probe:
  URL_EXECUTE_CLOSE_PROBE {loading:true,windowClosed:true,pendingAfterClose:true},
  exit0 (.tmp/wp0-url-execute-native-before-final.log). Первые launcher attempts
  завершались0 без marker: fixture автоматически выходил после последнего окна.
  Они не засчитаны как доказательство; добавлен window-all-closed listener.
- До review fix: npm.cmd test -- src/main/urlAvailabilityOperation.test.ts
  src/renderer/pages/Availability.requestLifetime.test.tsx —11 failed/29 passed,
  2.26s,exit1 (.tmp/wp0-url-review-before.log). Проверены native-close revocation,
  Resolver cancellation/deadline, proxy setup refusal, safe failure causes и
  понятная подсказка validation. После fix адресные2 suites40/40 passed.
- У каждого offscreen окна теперь отдельная in-memory session. После actual
  close native capability отозвана; зависшие Electron JS/load/proxy promises
  не удерживают общий shutdown. Late continuations guarded. Raw Node network
  work по-прежнему owned до settlement/socket close. Private Resolver timeout8s,
  tries1 и cancel() не влияют на чужие DNS. Разные URL checks независимы;
  requester duplicates сохраняют typed conflict, history commits не теряются.
- setProxy failure теперь typed network failure без history commit. Продолжать
  рендер с неизвестным выходом означало бы ложно подписать измеренный маршрут;
  предыдущий fallback не используется. Диагностические причины errno/TLS/HTTP
  и allowlisted Clash reset/refusal/timeout/EOF сохраняются без исходного текста.
  Validation UI показывает ожидаемые HTTP/HTTPS форматы, сохраняя typed error.
- Добавлен scripts/fixtures/url-probe-native.ts в штатный Electron runner:
  настоящие2 окна/redirect/loading/executeJavaScript, разные private sessions,
  default session не используется, actual close обеих probes —9ms.
  node scripts/test-electron-runtime.mjs —7 PASS,exit0
  (.tmp/wp0-url-review-electron.log). Loopback fixture не меняет VPN/OS маршруты.
- Финальный targeted: npm.cmd test -- src/main/urlAvailabilityOperation.test.ts
  src/main/urlAvailabilityVerdict.test.ts src/renderer/pages/Availability.requestLifetime.test.tsx
  src/preload/preloadValidation.test.ts src/main/operationRegistry.test.ts
  src/main/requesterOperation.test.ts —175/175 passed,6 suites,2.85s,exit0
  (.tmp/wp0-url-review-targeted-final.log). Build и final typecheck —exit0,
  165 channels/0 public any; coverage AC927/927,F210/210 и diff check —exit0.
  Final full после review fixes выполняется; initial CI не заменяет новый gate.
- Review final full: npm.cmd test -- --maxWorkers=1 —4882 passed/5 skipped/0 failed,
  295 files passed/2 skipped,329.74s,exit0 (.tmp/wp0-url-review-full.log).
  Production/test tree с начала этого прогона не менялся. Typecheck/build,
  7 native fixtures,coverage и diff check —exit0. Следующий участок только
  после automatic Qodo completed и CI success на опубликованном review SHA.

### WP-0: routing self-test lifetime (20.10.2026)

- #86 принят: final head150670b6d2702a343a9aaab09d10eefa52a0e5a7,
  Qodo1556986 completed,6/6 implemented,новых findings нет;
  CI39328685275 success. Merge/main288a998e11e8532a5f7a0af98bf80831261c25be;
  tree947f1f9fc91dbe3d5653f0f831cdbfe1d1286ad4 совпал с reviewed head.
  Revix до20.10 03:00 МСК по квоте недоступен; отсутствие review не approval.
- Следующий участок AT-00-001/003/004/005/008,F-021/F-074/F-138/F-143:
  runRoutingSelfTest и две реальные страницы Availability/Maintenance.
  Общий registry теперь владеет routing-check,UUID/correlation/manual/deadline60s;
  optional token сохраняет legacy zero-argument preload. Main handler связан
  с документом; чужой sender не может отменить запрос, duplicate token —conflict.
- HTTP получает signal; guards после raw replies/перед fallback/RU echo не дают
  продолжить отменённую проверку. SOCKS negotiation bounded8s остаётся owned;
  поздний socket закрывается без HTTP. Data/abort/error инициируют destroy,
  physical lease удерживается до actual close. Success/completed log terminal.
  Независимые проверки не блокируют друг друга. Измеренные отказы сохраняют
  прежний structured verdict; отмена/deadline —typed errors.
- Availability и protection action Maintenance отменяют routing при unmount,
  ограждают поздние success/error/log/toast и не очищают новую running action.
  Companion leak failure отменяет ещё pending routing. Сам leak self-test,
  прочие maintenance actions и live/server probes этим участком не приняты.
- Beforefix main1:10 failed,15.41s; UI1:3 failed/6 passed,1.85s.
  В первых новых tests обнаружены неточный button selector и invalid correlation
  fixture. После исправления selector повтор before2:13 failed/6 passed,15.50s
  (.tmp/wp0-routing-before2.log); один correlation case ещё имел невалидный UUID
  key и не засчитан как production failure. Maintenance before:4 failed,1.64s
  (.tmp/wp0-routing-maintenance-before.log). Targeted1:85 passed/1 failed,1.92s
  из-за этого correlation fixture; после canonical UUID key targeted2:178/178,
  3.95s. Targeted3 с isolation/remount/companion error:184/184,8 suites,3.68s,
  exit0 (.tmp/wp0-routing-targeted3.log).
- Команда адресных проверок: npm.cmd test -- src/main/routingSelfTestOperation.test.ts
  src/main/routingSelfTest.test.ts src/renderer/pages/Availability.requestLifetime.test.tsx
  src/renderer/pages/Maintenance.requestLifetime.test.tsx src/renderer/MaintenanceSource.test.ts
  src/preload/preloadValidation.test.ts src/main/requesterOperation.test.ts
  src/main/operationRegistry.test.ts. npm.cmd run typecheck —exit0,165 channels/
  0 public any. Coverage AC927/927,F210/210 и git diff --check —exit0.
  Final full/build выполняются; code/test tree после начала full не менялся.
- npm.cmd run build —exit0 (.tmp/wp0-routing-build.log), включает повторный
  typecheck165 channels/0 public any. node scripts/test-electron-runtime.mjs
  —7 PASS,exit0 (.tmp/wp0-routing-electron.log). Это native regression предыдущих
  workflows/общей границы; новые routing boundaries проверены controlled OS.
- Full1:4914 passed/5 skipped/1 failed,325.13s,exit1
  (.tmp/wp0-routing-full.log). Прежний adaptiveNetworkIdentity native fixture
  выполнился за8314ms при outer Vitest5000ms; единственный failure —timeout,
  не несовпадение JSON. Изолированный npm.cmd test -- src/main/adaptiveNetworkIdentity.test.ts
  —25/25 passed,3.26s. У этого native case outer budget35s согласован с30s
  helper process timeout и cold-start overhead; все data assertions сохранены.
  Routing production не менялся. Повторный targeted с этим native suite:
  npm.cmd test -- src/main/adaptiveNetworkIdentity.test.ts плюс8 suites выше
  —209/209 passed,9 suites,5.49s,exit0 (.tmp/wp0-routing-targeted-final.log).
  Full2 запущен после последнего test-only изменения.
- Final full2: npm.cmd test -- --maxWorkers=1 —4915 passed/5 skipped/0 failed,
  297 files passed/2 skipped,312.84s,exit0 (.tmp/wp0-routing-full2.log).
  Production/test tree с начала этого прогона не менялся. Повторный typecheck
  exit0 (.tmp/wp0-routing-typecheck-final.log),build/7 native fixtures,
  coverage/diff check —exit0. Remote Qodo/CI нужны на окончательном SHA.

### PR #87: сохранение per-call IPC trail

- Initial heada9a7cfb, Qodo1557229 completed с1 informational finding:
  потеря handleLogged started/timed finished/failed trail после переноса handler.
  Global ipc-security сохранял ошибки/category, но не заменял прежние timings
  и main exception trail. Замечание подтверждено; attribution вручную не менялся.
  Revix revixappdev[bot] на этом SHA подтвердил quota cooldown до20.10 03:00 МСК;
  полного review нет, отсутствие review не approval.
- Beforefix: npm.cmd test -- src/main/routingSelfTestOperation.test.ts
  -t 'per-call IPC trail' —1 failed/17 skipped,0.343s,exit1
  (.tmp/wp0-routing-review-before.log). Handler теперь снова пишет started,
  finished с ms и failed с исходным Error в main logger. Request token/IP
  payload в trail не добавляются; renderer по-прежнему получает typed envelope.
- Повторные9 targeted suites (та же команда с adaptiveNetworkIdentity выше)
  —210/210 passed,5.40s,exit0 (.tmp/wp0-routing-review-targeted.log).
  Новый full/build запущен после исправления; прежний head не заменяет новые gates.
- npm.cmd run build (включая typecheck165 channels/0 public any) —exit0
  (.tmp/wp0-routing-review-build.log). node scripts/test-electron-runtime.mjs
  —7 PASS,exit0 (.tmp/wp0-routing-review-electron.log). Coverage AC927/927,
  F210/210 и diff check —exit0. Review final full выполняется.

- Review full: npm.cmd test -- --maxWorkers=1 —4916 passed/5 skipped/0 failed,
  297 files passed/2 skipped,312.08s,exit0 (.tmp/wp0-routing-review-full.log).
- Initial remote CI39331654687 на a9a7cfb —failure:4913 passed/4 skipped/3 failed,
  400.93s. bootRecoveryExecution/systemNetwork native fixtures превысили outer5s
  при собственных process bounds15s/10s; configOperations не дождался actual sync
  за polling1s. Изолированный повтор трёх suites —137 passed/1 skipped,58.21s,exit0
  (.tmp/wp0-routing-ci-repro.log). Это не отменяет remote failures.
- В двух конкретных native cases outer budgets20s/15s согласованы с helpers.
  Config actual-I/O fixture ждёт Promise готовности после настоящего I/O вместо
  polling1s; outer15s. Проверки cancellation,файлов,handles и rollback сохранены.
  Production deadlines не изменены; окончательный full выполняется после правок.

- Final после CI fixture fixes: npm.cmd test -- --maxWorkers=1 —4916 passed/
  5 skipped/0 failed,297 files passed/2 skipped,309.54s,exit0
  (.tmp/wp0-routing-review-full-final.log). Code/test tree с начала full не менялся.
  Адресная команда12 suites (9 routing/requester/UI/preload/registry/adaptive
  плюс configOperations,bootRecoveryExecution,systemNetwork) —347 passed/1 skipped,
  56.21s,exit0 (.tmp/wp0-routing-review-targeted-final.log).
  npm.cmd run typecheck —165 channels/0 public any,exit0. Build/7 native fixtures
  выше остаются применимы: после них менялись только test fixtures и журнал.
  Coverage AC927/927,F210/210 и git diff --check —exit0. Новый SHA ожидает Qodo/CI.

### PR #87 принят; следующий участок — server probe

- Final head8a06034f7bbcd0d2495996e333efb9ffe09ac6ca: Qodo1557391 completed,
  finding1/1 implemented,новых нет; attribution вручную не менялась.
  CI39333883253 success (Windows/Rust/site). Revix полного review не дал
  из-за подтверждённого cooldown до20.10 03:00 МСК; это не approval.
  Squash merge/main4ff734f248cecd479c7c7b7814ca53b9488a394e; reviewed/main
  tree совпал:aab47b45416f423c8a1e7107481e502193350180.
- Следующий согласованный WP-0 участок: server:probe/ServerDetailModal.
  Найдено: outer9s timeout завершает только ожидание; global DNS/raw TCP и
  ASN fallback продолжают работу. TCP повторно резолвит host после проверки
  resolved IP. UI не отзывает main работу; geo fallback/group reply не полностью
  ограждены после закрытия. Исправление: общий owner/deadline/request token,
  private bounded DNS,retained actual socket close,guarded HTTP/fallback/UI.
  TCP использует проверенный resolved IP; без IP —typed network refusal.
  TLS/banner остаются отключены; новые WP-7 probes не добавляются.

### Server probe: общий lifetime и отмена модального окна (20.10.2026)

- AT-00-001/003/004/005/008,F-021/F-074/F-138/F-143. Production probe теперь
  server-probe operation,manual owner,UUID/correlation,deadline9s,unique resource.
  Handler принимает optional requester token,документ/reload/crash/cancel и
  shutdown отзывают работу; legacy вызовы остаются доступны.
- Private Resolver(timeout2500ms,tries1) на каждый raw DNS query. Explicit stage
  limit вызывает cancel,поздние addresses не принимаются. Обе DNS families
  удерживаются до actual settlement,включая partial settlement после cancel.
  TCP удерживается до actual close на success/error/timeout/cancel/sync throw.
  Все concurrent boundaries retained отдельно; HTTP получает signal,late ASN
  fallback и следующие latency samples ограждены. Result —terminal commit.
- TCP использует проверенный resolved IP,без скрытой повторной DNS resolution.
  Empty DNS —typed network; private answer —permission. Отдельная регрессия
  воспроизвела обход старого prefix filter через IPv4-mapped IPv6. Native net
  BlockList сохраняет прежние private ranges и корректно покрывает mapped IP,
  IPv6 link-local /10 и разные написания loopback. TLS/banner не включаются.
- Modal cleanup отменяет pending main token и geo fetch; UI deadline10s отзывает
  main/geo work,typed cancellation quiet. Поздние primary/body/fallback/group
  replies не меняют новое окно и не запускают fallback после cleanup.
- Beforefix main: npm.cmd test -- src/main/serverProbeOperation.test.ts —18 failed/
  1 passed,5.40s (.tmp/wp0-server-probe-before.log). UI first:8 failed/2 passed,
  1.91s (.tmp/wp0-server-probe-ui-before.log); quiet-cancel test сначала смотрел
  неверный translation key и не засчитан как production evidence. Key исправлен.
  Первая реализация имела transform error (не применившийся CRLF replacement),
  исправлен до исполнения tests. Main2:19/19 passed,0.469s.
- Partial DNS regression на нашей первой реализации:1 failed/19 skipped,0.449s
  (.tmp/wp0-server-probe-dns-before.log); Promise.allSettled удерживает вторую
  family. Private mapped regression:1 failed/20 skipped,0.399s
  (.tmp/wp0-server-probe-private-before.log); после BlockList passes.
- Targeted3:127 passed/1 failed,3.83s —export-only fixture не дожидался settled
  повторного probe перед проверкой числа cancellations. Добавлено act settlement;
  исходные2 export assertions сохранены. Старый source-string timeout test
  заменён behavioral DNS stage-limit и operation deadline regressions.
- Final targeted: npm.cmd test -- src/main/serverProbeOperation.test.ts
  src/main/serverProbe.test.ts src/renderer/components/ServerDetailModal.probeLifetime.test.tsx
  src/renderer/components/ServerDetailModal.requestLifetime.test.tsx
  src/preload/preloadValidation.test.ts src/main/mainIpcRegression.test.ts
  src/main/requesterOperation.test.ts src/main/operationRegistry.test.ts
  —210/210 passed,8 suites,4.45s,exit0 (.tmp/wp0-server-probe-targeted-final.log).
  Initial typecheck165 channels/0 public any —exit0. Coverage AC927/927,F210/210
  и diff check —exit0. Final full/build выполняются; tree после старта full заморожен.

- npm.cmd run build (включая typecheck165 channels/0 public any) —exit0
  (.tmp/wp0-server-probe-build.log). node scripts/test-electron-runtime.mjs
  —7 native fixtures PASS,exit0 (.tmp/wp0-server-probe-electron.log). Новые
  server probe boundaries проверены controlled OS fixtures,не натурным VPN.

- Full1: npm.cmd test -- --maxWorkers=1 —4951 passed/5 skipped/1 failed,
  314.31s,exit1 (.tmp/wp0-server-probe-full.log). Единственный failure —старый
  ServerDetailModalSource test требовал точную строку const probeTimeout.
  Он заменён уже проходящим behavioral lost-IPC deadline/cancel/late-result
  test в ServerDetailModal.probeLifetime.test.tsx; отдельный z-order test сохранён.
  Production не менялся. Адресный повтор двух UI suites —12/12 passed,exit0
  (.tmp/wp0-server-probe-source-replacement.log). Final full2 запущен после
  последнего test-only изменения; build/7 native fixtures остаются применимы.

- Full2 после замены source assertion:4951 passed/5 skipped/0 failed,
  298 files passed/2 skipped,312.58s,exit0 (.tmp/wp0-server-probe-full-final.log).
- Собственная проверка RTT выявила новую пограничную регрессию: wait-close
  включал drain задержку в latency. Новый held-close250ms test до fix:1 failed/
  21 skipped,0.445s (.tmp/wp0-server-probe-rtt-before.log): samples[250,0,0,0,0].
  Теперь TCP measurement фиксируется на connect,raw promise по-прежнему ждёт
  actual close. Final targeted9 suites:212/212 passed,4.52s,exit0
  (.tmp/wp0-server-probe-targeted-rtt.log); команда выше плюс
  src/renderer/components/ServerDetailModalSource.test.ts. Новые final full3/build
  выполняются после RTT fix; прежний full2 не выдаётся за проверку нового tree.

- Final full3 после RTT fix: npm.cmd test -- --maxWorkers=1 —4952 passed/
  5 skipped/0 failed,298 files passed/2 skipped,303.79s,exit0
  (.tmp/wp0-server-probe-full-rtt.log). Production/test tree с начала прогона
  не менялся. npm.cmd run build/typecheck165 channels/0 public any —exit0
  (.tmp/wp0-server-probe-build-final.log). Повторный node scripts/test-electron-runtime.mjs
  —7 PASS,exit0 (.tmp/wp0-server-probe-electron-final.log). Coverage AC927/927,
  F210/210 и git diff --check —exit0. Новые exact-head Qodo/CI pending.

### PR #88 принят; следующий участок — live-check resource drain

- Final head2c52db0887dfd487ede574acbf3148dfaa18e171: Qodo1557666 completed
  без findings; CI39337723907 success (Windows/Rust/site). Revix подтвердил
  cooldown до20.10 03:00 МСК,полного review нет; это не approval.
  Merge/mainca15040d06f4b33db03ca6c4a50bf4488f8dc7fb; reviewed/main tree
  совпал:3371348304675e3839960115af9e6d738c2180e9.
- Следующий WP-0 участок: physical resource foundations liveServerProbe.
  Найдено: withHandshakeWorkerLock освобождает cancelled/expired queued slot
  раньше previous worker,пропуская следующего worker параллельно предыдущему.
  execPs завершает raw promise на kill/error/timeout до actual child close.
  Исправляем эти две границы с regressions; общий owner/deadline/history/UI
  live-check,raw DNS/TCP/TLS/HTTP остаются следующими частями,не принимаются тут.

### Live-check: queue slot и raw PowerShell close (20.10.2026)

- AT-00-003/007,F-021: cancelled/expired queued handshake request больше не
  освобождает chain раньше previous worker. Дополнительный signal guard перед
  fn ограждает race admission/cancel; admitted worker по-прежнему держит slot
  до собственного settlement.
- execPs на cancel/timeout/error инициирует kill,но raw promise ждёт actual
  child close и pipe drain. Timer/AbortSignal/data/error/close listeners сняты
  на terminal close. После failure новые output chunks не накапливаются; normal
  UTF-8 output и прежняя интерпретация exit code сохранены. Завершённый процесс
  не получает повторный kill. Already-aborted request не spawn-ится; sync spawn
  exception завершается без ожидания несуществующего close.
- Beforefix: npm.cmd test -- src/main/liveServerProbe.resourceDrain.test.ts
  —6 failed/2 passed,1.42s,exit1 (.tmp/wp0-live-drain-before.log).
- После fix5 suites74/74 passed,4.89s. Добавлены2 Windows native cases на
  настоящем PowerShell Start-Sleep (только собственный дочерний процесс): signal
  cancel100ms и timeout400ms возвращают ошибку после native close.
  Final targeted: npm.cmd test -- src/main/liveServerProbe.resourceDrain.test.ts
  src/main/liveServerProbe.test.ts src/main/liveServerProbe.extended.test.ts
  src/main/liveServerProbe.handshake.test.ts src/main/liveServerAuditRegression.test.ts
  —76/76 passed,5 suites,5.16s,exit0 (.tmp/wp0-live-drain-targeted-final.log).
- Coverage AC927/927,F210/210,diff check —exit0. Final full/build выполняются.
  Общий operation registry live-check,progress/history fencing,raw DNS/TCP/TLS/
  HTTP и batch/modal lifetime этим небольшим участком ещё не приняты.

- Final full: npm.cmd test -- --maxWorkers=1 —4962 passed/5 skipped/0 failed,
  299 files passed/2 skipped,308.02s,exit0 (.tmp/wp0-live-drain-full.log).
  Production/test tree с начала full не менялся. npm.cmd run build,включая
  typecheck165 channels/0 public any —exit0 (.tmp/wp0-live-drain-build.log).
  Coverage AC927/927,F210/210,diff check —exit0. Новые native tests —actual
  PowerShell; полный7-fixture Electron runner не повторялся: IPC/preload/bridge
  не менялись. Новые exact-head Qodo/CI pending.

### PR #89 принят; live-check DNS/TCP/TLS/traceroute drain (20.10.2026)

- #89 final head8e32fdf0936cc95309b51478c85aed51392812a5: Qodo1557804 completed
  без findings (.tmp/qodo89-final.json),CI39339629394 success (Windows/Rust/site).
  Revix free-quota-reached до20.10 03:00 МСК; полного review нет,это не approval.
  Merge/main5268e7433fe6b12a472a11d891e520b2a11fec2f; reviewed/main tree
  совпал:05ec0c4627e75836988800be9a8c472df930dd48.
- AT-00-003/007,F-021: private bounded DNS resolver ждёт raw settlement после
  cancel/timeout,поздние адреса отбрасываются. TCP/TLS ждут actual close;
  результат и RTT фиксируются до drain. Поздний TLS ready не заменяет terminal
  failure; spontaneous close и synchronous connect/init errors конечны.
  Traceroute сохраняет partial hops,но kill/error/timeout не выдаёт за command
  completion: promise завершается на actual child close. stdout bounded64KiB.
- Новая networkDrain suite: первый запуск остановлен из-за зависания cleanup
  самого стенда после failed RTT assertion; verdict не получен
  (.tmp/wp0-live-network-before.log). Cleanup дренирует pending fake sockets.
  Повтор до production fix:17 failed/1 passed,1.23s,Vitest exit1
  (.tmp/wp0-live-network-before-final.log). После fix18/18 passed,1.28s.
- Первые6 suites94/94 passed,5.37s; typecheck165 channels/0 public any exit0.
  Добавлены overall TLS timer/sync failure,normal traceroute и4 native loopback
  cases: actual TCP connect/cancel,TLS cancel без handshake,DNS cancellation
  через собственный UDP resolver. Network native suite25/25 passed,1.40s.
- Форматирующий script ошибочно усёк source; IPC checker поймал4 missing
  live-check channels,exit1 (.tmp/wp0-live-network-typecheck-final.log).
  Source восстановлен из проверенного HEAD,целевые fixes повторно применены
  без script-formatting. Test fake TLS lifecycle и pending DNS приведены к
  actual close/settlement,прежние assertions сохранены.
- Final targeted: npm.cmd test -- src/main/liveServerProbe.networkDrain.test.ts
  src/main/liveServerProbe.resourceDrain.test.ts src/main/liveServerProbe.test.ts
  src/main/liveServerProbe.extended.test.ts src/main/liveServerProbe.handshake.test.ts
  src/main/liveServerAuditRegression.test.ts —101/101 passed,6 suites,5.47s,exit0
  (.tmp/wp0-live-network-targeted-final.log). npm.cmd run typecheck —165 channels/
  0 public any,exit0 (.tmp/wp0-live-network-typecheck-recovered.log).
  python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py —AC927/927,
  F210/210,exit0; git diff --check exit0. Final full/build выполняются.
  HTTP/media/SOCKS helpers,общий live operation lifetime/progress/history/UI
  остаются открытыми следующими частями WP-0. Нормативные docs/ не менялись.

- Final full: npm.cmd test -- --maxWorkers=1 —4987 passed/5 skipped/0 failed,
  300 files passed/2 skipped,312.04s,exit0 (.tmp/wp0-live-network-full.log).
  Production/test tree с начала full не менялся. npm.cmd run build,включая
  typecheck165 channels/0 public any —exit0 (.tmp/wp0-live-network-build.log).
  Coverage AC927/927,F210/210,diff check —exit0. IPC/preload/bridge не менялись,
 7-fixture Electron runner не повторялся; native evidence текущего участка —
  четыре loopback resource cases. Exact-head Qodo/CI требуются после публикации.

### PR #90 принят; live-check HTTP resource drain (20.10.2026)

- #90 final head991f0797624199477f83adaf6d89476ae725ac10: Qodo1557968 completed
  без findings (.tmp/qodo90-final.json),CI39341834240 success (Windows/Rust/site).
  Revix free-quota-reached до20.10 03:00 МСК;полного review нет,это не approval.
  Merge/maincf8adf101bc009deed91f757c19d682cbdc3fcaf; reviewed/main tree совпал:
  6a9459e3a04b485517652d1666b674d1492ed223.
- AT-00-003: HTTP live-check теперь удерживает каждый ClientRequest,response
  и отдельный socket до actual close. agent:false исключает shared pooled socket.
  Redirect и HEAD->GET ждут полного drain предыдущей попытки;cancel/deadline
  во время ожидания не запускают следующую. Общий deadline и8KiB cap сохранены.
  Duration фиксируется до final drain;premature close получает error.
- До fix новая httpDrain suite:10 failed/1 passed,6.37s,exit1
  (.tmp/wp0-live-http-before.log),включая timeout прежнего premature-close promise.
  После fix11/11 passed,1.35s. Добавлены duration/already-aborted и2 actual
  loopback HTTP cases: normal HEAD405->GET и cancellation активного GET body.
  Первый native cancel fixture ошибочно отменял HEAD после headers,когда HEAD
  уже нормативно завершён:114 passed/1 failed,5.88s
  (.tmp/wp0-live-http-targeted-final.log). Исправлен стенд HEAD405->pending GET;
  production не изменён:115/115 passed,5.81s (.tmp/wp0-live-http-targeted2.log).
- Дополнительная собственная regression:late response error после cancel был
  unhandled —1 failed/13 skipped,1.44s,exit1 (.tmp/wp0-live-http-late-error-before.log).
  Response/socket error listeners ставятся до cleanup guard и остаются до close;
  поздний reset не заменяет terminal outcome. Final targeted7 suites:115/115
  passed,5.90s,exit0 (.tmp/wp0-live-http-targeted3.log),команда из предыдущего
  участка плюс src/main/liveServerProbe.httpDrain.test.ts.
- npm.cmd run typecheck —165 channels/0 public any,exit0
  (.tmp/wp0-live-http-typecheck.log);после late-error fix запущен новый build
  с typecheck и full. Coverage AC927/927,F210/210,diff check —exit0.
  Media/SOCKS/throughput и isolated handshake child cleanup,общий live owner/
  deadline/progress/history/renderer lifetime ещё в работе. Нормативные docs/
  не менялись; весь WP-0 этим участком не завершается.

- Final HTTP full: npm.cmd test -- --maxWorkers=1 —5001 passed/5 skipped/0 failed,
  301 files passed/2 skipped,325.81s,exit0 (.tmp/wp0-live-http-full.log).
  Production/test tree с начала full не менялся. npm.cmd run build,включая
  typecheck165 channels/0 public any —exit0 (.tmp/wp0-live-http-build.log).
  Coverage AC927/927,F210/210,diff check —exit0. IPC/preload/bridge не менялись;
 7-fixture Electron runner не повторялся. Native evidence текущего участка —
  две actual loopback HTTP checks. Новые exact-head Qodo/CI pending.

### PR #91 принят; handshake/media/throughput drain (20.10.2026)

- #91 final head216342768edeae28e6cc9b69db75f2143f3eac7c: Qodo1558121 completed
  без findings (.tmp/qodo91-final.json), CI39343736114 success.
  Merge/main88bca27e2c12a6f31867da56aa36df90ff196cce; reviewed/main tree совпал:
  b9c19ecc64aa276537da8eaa050b6b69555fdfd7. Revix до03:00 был по квоте,
  полного review нет;это не approval.
- AT-00-003/007: live handshake передаёт signal/retain в SOCKS/HTTPS helpers,
  удерживает late dial и raw/TLS close. Media активно отменяет TLS и не пишет
  поздний HEAD. Каждый throughput sample держит raw+TLS до close до следующего
  sample;duration фиксируется до drain. Header accumulation ограничен64KiB,
  split delimiter не теряет body;sync TLS failure снимает timer/abort.
- Изолированный child удерживает worker slot/workDir до actual close. Ранняя
  ошибка child во время PID persistence не теряется и не вызывает unhandled
  rejection. Проигравший readiness poll отменяется,retained до settlement/close.
- До fix handshakeDrain:5 failed/0 passed,1.27s (.tmp/wp0-live-handshake-before.log).
  Первый fix4 passed/1 failed,6.08s: active-profile fixture ошибочно выбирал
  isolated child и не закрывал его;fixture исправлен без ослабления drain.
  Затем5/5 passed,1.22s (.tmp/wp0-live-handshake-targeted2.log).
- При расширении:24 passed/1 failed (.tmp/wp0-live-handshake-targeted3.log) —
  fixture эмитил error после close;оставлен late error до close. Затем26 passed/
  3 failed (.tmp/wp0-live-handshake-targeted4.log):2 native teardown ошибочно
  advance fake timers при real timers,исправлен teardown;1 реальная regression
  раннего child error исправлена порядком readiness race. После fix138/138
  passed,5.63s (.tmp/wp0-live-handshake-targeted5.log).
- Review выявил также неподконтрольный readiness poll после child error.
  Добавлены retain+локальная отмена и regression;final targeted8 suites139/139
  passed,5.97s (.tmp/wp0-live-handshake-targeted6.log). Команда: npm.cmd test --
  src/main/liveServerProbe.handshakeDrain.test.ts src/main/liveServerProbe.resourceDrain.test.ts
  src/main/liveServerProbe.networkDrain.test.ts src/main/liveServerProbe.httpDrain.test.ts
  src/main/liveServerProbe.test.ts src/main/liveServerProbe.extended.test.ts
  src/main/liveServerProbe.handshake.test.ts src/main/liveServerAuditRegression.test.ts.
  Новая suite24 cases включает2 native:real loopback TLS cancellation и actual
  child close до rm. Старое handshake assertion расширено новым retain аргументом.
- Initial typecheck/build passed (165 channels/0 public any);после readiness fix
  нужны новые full/build. Начатый .tmp/wp0-live-handshake-full.log не final:
  source изменился во время прогона;результат не доказательство final tree.
  Coverage AC927/927,F210/210,diff check exit0. IPC/preload/bridge не менялись;
  7-fixture Electron runner не повторялся. Нормативные docs/ не менялись.
  Общий live operation owner/deadline/history/renderer остаётся следующим
  участком,весь WP-0 не завершён.

- Superseded initial full (.tmp/wp0-live-handshake-full.log):5024 passed/
  5 skipped/1 failed,339.03s,exit1. Единственный failure —5000ms timeout
  существующего native PowerShell case adaptiveNetworkIdentity.test.ts
  keeps the previous profile-only identity behavior (10563ms). Source этого
  теста/модуля не менялся. Причина таймаута пока не установлена;параллельный
  final full начался03:05,первый03:03. Выполняется изолированная проверка.

- Native identity отдельно: npm.cmd test -- src/main/adaptiveNetworkIdentity.test.ts
  —25/25 passed,3.14s,exit0 (.tmp/wp0-live-handshake-network-identity.log).
  Причина разового предыдущего timeout не установлена;несвязанный код не менялся.
- Final production full: npm.cmd test -- --maxWorkers=1 —5025 passed/5 skipped/
  0 failed,302 files passed/2 skipped,329.86s,exit0
  (.tmp/wp0-live-handshake-full-final.log). Production source не менялся с
  начала final full. Во время прогона добавлены2 test assertions:media и
  throughput terminal events обязаны destroy до последующей cancellation,
  чтобы cancel не маскировал ошибку обработчика. Усиленная suite отдельно:
  npm.cmd test -- src/main/liveServerProbe.handshakeDrain.test.ts —24/24
  passed,1.24s (.tmp/wp0-live-handshake-terminal-assertions.log).
- npm.cmd run build final,включая typecheck165 channels/0 public any —exit0
  (.tmp/wp0-live-handshake-build-final.log). Перед commit повторяются
  typecheck/coverage/diff. Exact-head Qodo/CI pending.

### PR #92 — Qodo/Revix remediation (20.10.2026)

- Initial headfef2945dc8f2bcad223c4d8b363aadbe084043b4,Qodo1558277 completed:
  2 remediation findings —stalled SOCKS dial и child close без верхней границы.
  Attribution не менялся. Revix после сброса квоты выполнил review:2 minor
  comments —itest suffix и swallowed expect внутри rm mock.
- SOCKS finding подтверждён:openTcpViaSocks теперь сам создаёт TCP transport,
  держит close и начинает SOCKS negotiation только после connect через
  existing_socket. Abort/общий timeout уничтожают transport до negotiation
  и во время неё. Поздний socket по-прежнему уничтожается/retained.
- New transport tests до fix:3 failed/0 passed и1 unhandled rejection
  (.tmp/wp0-live-handshake-qodo-dial-before.log);fixture старого helper получал
  undefined вместо нового existing_socket. После fix3/3 passed,1.17s.
  Related4 suites81/81 passed,1.56s (.tmp/wp0-live-handshake-qodo-dial-targeted.log).
- Public media/handshake callers теперь идут через существующий registry kind
  server-probe с отдельными resource IDs и deadlines15s/60s. Cancel/deadline
  возвращается promptly,а registry.close и shared handshake worker ждут
  actual close/settlement. Handshake вызывает owned media напрямую,чтобы
  nested caller race не освободил handshake slot до media drain.
- Child exit закрывает собственные stdout/stderr handles:наследованный pipe
  больше не блокирует close после подтверждённого выхода. Таймер НЕ считается
  доказательством смерти child. Если native kill вообще не завершил процесс,
  caller получает terminal timeout/cancel,а слот и workDir сохраняются до
  close;shutdown ждёт тот же ресурс. Это необходимый fail-closed предел,
  освобождать slot/rm живого процесса по одному таймеру небезопасно.
  Managed integration tests проверяют prompt caller,blocked queued successor,
  pending shutdown и late close;raw boundary tests используют controlled
  registry delegate,отдельные managed cases —настоящий registry.
- Revix test concern исправлен:closedAtRemoval записывается внутри rm mock
  и проверяется снаружи после task,так что production catch не проглотит assert.
  Suite переименована в liveServerProbe.handshakeDrain.itest.ts;новые native
  SOCKS tests —keyHealthChecker.transportDrain.itest.ts. CI получил отдельный
  targeted integration step,поэтому rename не убирает проверки из CI.
- Git mv сначала был вызван с неверным cwd-relative path и завершился fatal;
  исправлен путь. Обычный npm test исключает itest:промежуточные63 passed
  не были проверкой новых integration suites. Правильная команда:
  npm.cmd test -- --mode integration src/main/liveServerProbe.handshakeDrain.itest.ts
  src/main/keyHealthChecker.transportDrain.itest.ts —31/31 passed,1.94s,exit0
  (.tmp/wp0-live-handshake-qodo-integration.log),включая3 real SOCKS fixtures.
- Final targeted unit10 suites172/172 passed,6.28s,exit0
  (.tmp/wp0-live-handshake-qodo-targeted-final.log);команда из preceding8 suites
  без переименованного handshakeDrain,плюс keyHealthChecker.test.ts,
  keyHealthChecker.transportDrain.test.ts,groupHealthOperation.test.ts.
  npm.cmd run build,включая typecheck165 channels/0 public any —exit0
  (.tmp/wp0-live-handshake-qodo-build.log). Coverage AC927/927,F210/210 и
  git diff --check exit0. Новый полный прогон в .tmp/wp0-live-handshake-qodo-full.log.

- Follow-up full (.tmp/wp0-live-handshake-qodo-full.log):5003 passed/5 skipped/
  1 failed,317.30s,exit1. Failure residualReview2.test.ts ожидал Cancelled,
  получил connect ECONNREFUSED127.0.0.1:1080:старый fixture мокал только
  SocksClient,теперь требуется контролировать созданную приложением TCP
  границу. В этом case замокан Socket.prototype.connect,остальные assertions
  сохранены. Production source не менялся. npm.cmd test --
  src/main/residualReview2.test.ts src/main/keyHealthChecker.transportDrain.test.ts
  —17/17 passed,1.64s,exit0 (.tmp/wp0-live-handshake-qodo-residual-fixture.log).
  Повтор полного набора: .tmp/wp0-live-handshake-qodo-full-final.log.

- Final follow-up full: npm.cmd test -- --maxWorkers=1 —5004 passed/5 skipped/
  0 failed,302 files passed/2 skipped,318.23s,exit0
  (.tmp/wp0-live-handshake-qodo-full-final.log). Production/test tree не менялся
  во время этого прогона. Integration отдельно31/31 passed (28 handshake/
  media/throughput ownership +3 actual SOCKS fixtures);itest не входят в unit
  count и явно запускаются новым CI step. Build/typecheck165 channels/0 public
  any ранее прошёл на том же production source;после него менялся только
  residual test fixture и journal. Coverage/diff повторяются перед commit.
  Новые Qodo/Revix/CI обязательны на follow-up SHA.

### PR #92 — bounded cleanup escalation (20.10.2026)

- Follow-up head0a42d3240fdcf7592914ef0ce89aa8459a3538fd,Qodo1558452 completed:
  SOCKS finding автоматически implemented,child drain finding остался pending.
  Attribution не менялся. Revix Low risk;повторный itest nit ссылается на уже
  переименованный .itest.ts,поэтому устарел;его suggestion о resource ID учтён
  32hex suffix. Question об escalation потребовал явного shorter cleanup budget.
- Выбран captured ChildProcess handle,а не PID lookup:на Windows это избегает
  риска повторного kill чужого процесса после reuse PID. Вызов SIGTERM,через
  1.5s SIGKILL,через5s без подтверждения close —structured warning state=blocked/
  child-stop-unconfirmed и lease.expire() с terminal error/category=timeout.
  Caller получает конечный результат;worker/resource/PID/workDir остаются
  retained до actual close. Shutdown не выдаёт незавершённый kill за успех.
  После late close release восстанавливается;таймеры снимаются.
- Registry API expire делегирует существующий защищённый deadline transition,
  не обходит commit fence и не освобождает physical lease. Regression до fix:
  70 passed/1 failed,2.12s (.tmp/wp0-live-handshake-cleanup-deadline-before.log).
  После fix registry/resource/handshake3 suites87/87 passed,2.27s
  (.tmp/wp0-live-handshake-escalation-registry.log).
- Первая integration после edit:31 passed/1 failed,1.65s:edit поменял kill в
  abortHandler,но finally ещё посылал SIGKILL. Escalation regression это поймала;
  finally исправлен на SIGTERM. Final integration32/32 passed,1.59s,exit0
  (.tmp/wp0-live-handshake-escalation-integration-final.log). Проверяются
  точные1.5s escalation,5s caller timeout,blocked successor/shutdown,late close.
- Запущены новые build/typecheck и full: .tmp/wp0-live-handshake-escalation-
  build.log/.tmp/wp0-live-handshake-escalation-full.log. Coverage AC927/927,
  F210/210,diff exit0. Новый exact-head Qodo/Revix/CI нужен после push.

- В продолжении выявлен timing gap: escalation создавался только в finally,
  поэтому pending readiness/PID persistence откладывали SIGKILL после abort.
  Новая regression до fix:1 failed/29 skipped,1.45s,exit1
  (.tmp/wp0-live-handshake-readiness-stop-before.log). stopChild теперь
  idempotent,запускает бюджеты непосредственно с первого stop request;
  actual close снимает таймеры независимо от оставшихся retained promises.
  Проверены held readiness,точные1.5s,запрет запуска successor и late drain.
- Два промежуточных integration прогона дали32 passed/1 failed:assert считал
  уже сработавший escalation timer ещё активным и не учитывал queue timer.
  Исправлено только ожидание счётчика;final integration33/33 passed,1.72s,
  exit0 (.tmp/wp0-live-handshake-readiness-stop-checked.log). Команда:
  npm.cmd test -- --mode integration src/main/liveServerProbe.handshakeDrain.itest.ts
  src/main/keyHealthChecker.transportDrain.itest.ts.
- CI39348301027 на head0a42 завершился failure:5004 passed/4 skipped/1 failed,
  native JSON export fixture превысил default5s при двух реальных PowerShell
  ACL exports. Для этого fixture задан15s,как для соседних native file cases;
  assertions и production export не менялись. Последующий targeted3 suites
  99/99 passed,27.19s,exit0 (.tmp/wp0-live-handshake-cleanup-targeted-final.log).
  В той команде лишний nonexistent operationRegistry.resources.test.ts не
  добавил suite;следующий targeted явно содержит liveServerProbe.resourceDrain.
- Build с typecheck165 channels/0 public any прошёл после stopChild fix
  (.tmp/wp0-live-handshake-cleanup-build-final.log). Coverage AC927/927,F210/210,
  diff exit0. Старый full escalation-full начат до stopChild fix и superseded;
  его результат не будет использован для допуска окончательного дерева.

- Targeted окончательного дерева: npm.cmd test -- src/main/operationRegistry.test.ts
  src/main/liveServerProbe.resourceDrain.test.ts src/main/liveServerProbe.handshake.test.ts
  src/main/serverKeyExportSecurity.test.ts —4 suites109/109 passed,23.81s,exit0
  (.tmp/wp0-live-handshake-cleanup-targeted-checked.log). Full окончательного
  дерева запущен без дальнейших source/test edits: npm.cmd test -- --maxWorkers=1
  (.tmp/wp0-live-handshake-cleanup-full-final.log).

- Final full: npm.cmd test -- --maxWorkers=1 —5005 passed/5 skipped/0 failed,
  302 files passed/2 skipped,304.20s,exit0
  (.tmp/wp0-live-handshake-cleanup-full-final.log). Source/test tree не менялся
  во время прогона. Superseded escalation-full тоже завершился5005/5/0,
  321.74s,но не используется как gate последнего fix. Final build/typecheck,
  targeted109/109,integration33/33,coverage AC927/927,F210/210,diff exit0.
  Новый exact-head Qodo/Revix/CI обязателен после push.

### PR #92 — explicit blocked admission and output drain (20.10.2026)

- Head5269ba3,Qodo1558570 completed:SOCKS implemented,child finding всё ещё
  pending;attribution не менялся. Revix118391709473 completed/neutral Low risk:
  retained fail-closed question,новый вопрос о trailing pipe output и suggestion
  заменить exact timer counts observable assertions. Stale itest nit не применим.
- Выявлена разница между terminal caller timeout и зависшей execution queue.
  На5s coordinator теперь отзывает admission,отклоняет queued/new workers
  типизированным conflict и завершает execution lease. Полный physical work
  передан lease.retain:child/socket/readiness/workDir остаются owned;shutdown
  ждёт actual drain. До него новый child не запускается. После physical settlement
  (включая failure) admission автоматически восстанавливается.
  Это bounded/fail-closed альтернатива предложенному Qodo удалению workDir
  после одного лишь таймера. Таймер не доказывает смерть процесса.
- Новая blocked-admission regression до fix:1 failed/30 skipped,1.31s,exit1
  (.tmp/wp0-live-handshake-blocked-admission-before.log). Первый integration
  после fix33 passed/1 failed,1.68s:старый deadline fixture ожидал очередь вместо
  нового immediate conflict. Ожидание обновлено;34/34 passed,1.79s,exit0
  (.tmp/wp0-live-handshake-blocked-admission-checked.log). Timer assertion
  заменён проверкой отсутствия warning/повторного kill и blocked successor.
- Вопрос Revix о final stderr подтверждён:exit закрывал pipes немедленно.
  Regression до fix1 failed/30 skipped,1.26s
  (.tmp/wp0-live-handshake-exit-output-before.log). После confirmed exit даётся
  1.5s на обычный output drain;потом закрываются inherited pipes и пишется
  sanitized child-output-incomplete. Actual close снимает timer. Уже exited
  child не получает новые SIGTERM/SIGKILL. Неподтверждённый live child этим
  timer не освобождается.
- Дополнительный PID-persistence case поймал позднюю установку data listeners:
  1 failed/1 passed/30 skipped,1.52s
  (.tmp/wp0-live-handshake-persist-output-before.log). Data listeners перенесены
  сразу после spawn,до await PID persistence. Final integration2 suites35/35
  passed,1.94s,exit0 (.tmp/wp0-live-handshake-blocked-output-final.log).
  Сохраняется auth_failed от trailing diagnostic в readiness и persistence cases.
- Targeted5 suites127/127 passed,3.30s
  (.tmp/wp0-live-handshake-blocked-targeted.log):npm.cmd test --
  src/main/operationRegistry.test.ts src/main/liveServerProbe.resourceDrain.test.ts
  src/main/liveServerProbe.handshake.test.ts src/main/liveServerProbe.extended.test.ts
  src/main/residualReview2.test.ts. После targeted менялось только время установки
  child data listeners;новый persistence integration проверил это отдельно.
- Запущен final build/typecheck (.tmp/wp0-live-handshake-blocked-build-final.log)
  и full (.tmp/wp0-live-handshake-blocked-full-final.log) на окончательном source.
  Coverage AC927/927,F210/210,diff exit0. Новый exact-head remote gate нужен после push.

- CI39350002218 на5269ba3 завершилсяsuccess:Windows unit/integration,
  IPC/CSP,native IPv6 WFP/Electron,Rust/site —зелёные. Это предыдущий head,
  до новых blocked-admission/output fixes;его success не переносится на них.
  Final blocked-build с typecheck165 channels/0 public any exit0.

- Final blocked-admission full: npm.cmd test -- --maxWorkers=1 —5005 passed/
  5 skipped/0 failed,302 files passed/2 skipped,325.89s,exit0
  (.tmp/wp0-live-handshake-blocked-full-final.log). Source/test tree не менялся
  во время full. Integration35/35,targeted127/127,build/typecheck165/0any,
  coverage AC927/927,F210/210,diff exit0. Physical work сохранён в registry,
  execution queue больше не ждёт unconfirmed child без конечного решения.

### PR #92 — typed worker queue expiry (20.10.2026)

- Headba353ed,Qodo1558657 completed:оба прежних findings автоматически
  implemented;новый aef026e8-23cf-4b97-b92d-909b1de144ca (Observability):
  queued timeout возвращался как diagnostics object,registry писалsuccess.
  Attribution не менялся. Revix118396191573 success/Low risk:новых
  actionable замечаний нет;stale itest nit и прежний fail-closed question
  проверены текущими filename и blocked-admission regressions.
- Новая managed regression сравнивает caller result и operation record для
  queued cancel и15s expiry. До fix1 failed/1 passed/32 skipped,1.52s,exit1
  (.tmp/wp0-live-handshake-queue-taxonomy-before.log):registry status=success.
- Внутренний queue catch больше не превращает expiry в fulfilled diagnostics:
  known cancellation/queue timeout становятся IpcFault(cancelled/timeout),
  уже typed conflict сохраняется,неожиданные exceptions не объявляютсяtimeout.
  Fault проходит через operations.run;публичный wrapper после registry
  переводит cancellation/timeout в прежний диагностический result.
- npm.cmd test -- --mode integration src/main/liveServerProbe.handshakeDrain.itest.ts
  src/main/keyHealthChecker.transportDrain.itest.ts —37/37 passed,1.88s,exit0
  (.tmp/wp0-live-handshake-queue-taxonomy-after.log). Targeted те же5 suites:
  127/127 passed,3.35s,exit0 (.tmp/wp0-live-handshake-queue-taxonomy-targeted.log).
  Запущены build/typecheck (.tmp/wp0-live-handshake-queue-taxonomy-build.log)
  и full (.tmp/wp0-live-handshake-queue-taxonomy-full.log). Coverage927/927,
  210/210,diff exit0. Новый exact-head review/CI будет обязателен после push.

- CI39351400924 наba353ed завершилсяsuccess (Windows/Rust/site,включая
  explicit live itest step и native checks). Это предшествующий source;
  queue-taxonomy fix требует нового exact-head gate. Новый taxonomy build
  с typecheck165 channels/0 public any прошёл,exit0.

- Final taxonomy full: npm.cmd test -- --maxWorkers=1 —5005 passed/5 skipped/
  0 failed,302 files passed/2 skipped,312.16s,exit0
  (.tmp/wp0-live-handshake-queue-taxonomy-full.log). Source/test tree во время
  full не менялся. Integration37/37,targeted127/127,build/typecheck165/0any,
  coverage927/927 и210/210,diff exit0. Новый exact-head Qodo/Revix/CI обязателен.

### PR #92 — Revix typed queue and media failure status (20.10.2026)

- Head3eb8ab2,Qodo1558731 completed:все3 findings автоматически implemented,
  новых нет. Revix118399512303 completed/neutral Low risk дал2 issue:
  timeout классифицировался по message prefix;mediaStream timeout сталskipped.
  Оба подтверждены. Stale itest nit не соответствует уже имеющемуся filename;
  прежний fail-closed вопрос покрыт execution/physical ownership split и5s budget.
- Regression до typed queue fix:resourceDrain3 failed/7 passed,1.96s,exit1
  (.tmp/wp0-live-handshake-typed-queue-before.log). Был также unhandled rejection
  самого ожидаемого failing assertion до timer await;на assertion promise теперь
  сразу установлен rejection observer,его последующий await всё равно проверяет
  результат. Queue cancellation/deadline проверяются по IpcFault/category,
  включая прежние residualReview2 cases,без зависимости от текста сообщения.
- Media status regression до fix1 failed/1 passed/32 skipped,1.47s,exit1
  (.tmp/wp0-live-handshake-media-timeout-before.log):timeout давалskipped.
  Теперь public fallback mediaStream error при timeout,skipped приcancel.
- withHandshakeWorkerLock сам выбрасывает IpcFault(cancelled/timeout/conflict).
  Внутренний catch сохраняет typed fault;message parsing удалён.
  Targeted5 suites127/127 passed,3.33s
  (.tmp/wp0-live-handshake-revix-final-targeted.log);integration2 suites37/37,
  1.84s,exit0 (.tmp/wp0-live-handshake-revix-final-integration.log).
- На вопрос Revix о callers:production search этих symbols находит только
  liveServerProbe.ts (public wrappers,runLiveServerCheck);прямых scheduler callers
  нет. runLiveServerCheck возвращает rejection в общий IPC error envelope;
  batch orchestration имеет catch. Ошибкаconflict не должна превращаться в
  успешный diagnostic result. Общий live caller lifetime/history остаётся
  следующим участком WP-0,не объявлен завершённым этим PR.
- Запущен final build/typecheck (.tmp/wp0-live-handshake-revix-final-build.log)
  и full (.tmp/wp0-live-handshake-revix-final-full.log);coverage AC927/927,
  F210/210,diff exit0. После push нужны новые exact-head Qodo/Revix/CI.

- Final Revix follow-up full:npm.cmd test -- --maxWorkers=1 —5005 passed/
  5 skipped/0 failed,302 files passed/2 skipped,307.72s,exit0
  (.tmp/wp0-live-handshake-revix-final-full.log). Source/test tree во время full
  не менялся. Build/typecheck165 channels/0 public any,integration37/37,
  targeted127/127,coverage AC927/927,F210/210,diff exit0.
  CI39352438985 на предыдущем3eb8ab2 такжеsuccess;новый head требует своих gates.

### PR #92 принят; общий live-check owner (20.10.2026)

- Final reviewed head0ae31eda4b94bbcaa078c15dae18134daecdfeef.
  Qodo1558804 completed на этом SHA:все3 findings автоматически implemented,
  новых/pending нет;attribution не менялся. Revix118402877903 completed/neutral,
  Low risk:2 последних issue исправлены и исчезли. Остались stale itest nit
  (suite уже .itest.ts),вопрос о cleanup (5s terminal/blocked admission + physical
  retention) и вопрос о callers (прямых scheduler callers нет;IPC fault envelope
  и batch catch существуют). Эти вопросы проверены кодом и регрессиями.
- CI39353480596 success на том же exact SHA:Windows full + explicit live itest,
  traceability,real IPC/CSP,native IPv6 WFP/Electron,Rust/site —зелёные.
  Local final:npm.cmd run build/typecheck165/0any;full5005 passed/5 skipped/
  0 failed,307.72s;targeted127/127,integration37/37;coverage927/927,210/210,diff0.
- Squash merge/main4410b6284af082ecd4c06352df1129ef2aae5cfb.
  Reviewed/main tree422af1b004d73ef3a043e093556d65c7f48adecb совпал;
  git diff --exit-code0ae31ed vpn/main exit0. #92 MERGED20.10.2026 01:36:36UTC.
- Следующий участок —codex/wp0-live-operation-owner от этого main. Общий
  runLiveServerCheck ещё допускает late progress/history после отмены;root UUID/
  correlation/deadline/document lifetime и batch/UI fencing ещё не закрыты.
  Детальная рабочая карта —app .tmp/wp0-after92-plan.md (не норматив).
  WP-0 в работе;WP-2 не начат. Нормативные docs/ не менялись.

### WP-0: общий владелец live-проверки (20.10.2026)

- AT-00-003/005/007, F-021/F-143: подтверждены поздние progress/history
  после отмены root runLiveServerCheck, отдельный deadline вместо registry,
  позднее чтение split-routing после import и запись ASN cache после abort.
- Root теперь выполняется в operations с UUIDv4/correlation/owner и прежним
  бюджетом 25s basic/60s extended. lease.wait ограждает каждую фазу, а
  приватный handshake передаёт физический worker прямо root lease. Отмена,
  deadline и shutdown возвращают terminal IpcFault сразу; DNS/socket/child/
  readiness удерживаются до settlement. Поздние progress подавляются,
  последующие фазы не запускаются. History commit синхронный и active-only;
  id результата совпадает с operationId, legacy requestId сохранён.
- Split-routing проверяет сигнал до/после dynamic import; оба ASN provider
  проверяют abort до изменения cache. Новый набор operation.test.ts:
  delayed DNS cancel/deadline/shutdown, parallel close, pre-cancel, Windows
  path child, handshake cleanup+readiness, active history commit, оба ASN
  provider и delayed import. Все 11 регрессий воспроизведены на HEAD4410b62:
  11 failed/0 passed (exit1, .tmp/wp0-live-owner-red-verified.log).
  Setup failures (неполный child_process mock, неверный correlation fixture,
  missing config mock) исправлены в fixtures, до фактического baseline run.
- npm.cmd test -- src/main/liveServerProbe.operation.test.ts
  src/main/liveServerProbe.networkDrain.test.ts src/main/liveServerProbe.test.ts
  —59/59 passed,3 suites,2.64s,exit0 (.tmp/wp0-live-owner-targeted.log).
  npm.cmd test -- --mode integration src/main/liveServerProbe.handshakeDrain.itest.ts
  src/main/keyHealthChecker.transportDrain.itest.ts —37/37 passed,2 suites,
  2.10s,exit0 (.tmp/wp0-live-owner-integration.log).
- npm.cmd run build —exit0;включает typecheck165 channels/0 public any
  (.tmp/wp0-live-owner-build.log). python docs/04-приёмочные-тесты/traceability/
  check-coverage.py —AC927/927,F210/210,exit0;git diff --check exit0.
  Full suite выполняется;PR/exact-head Qodo/Revix/CI ещё не приняты.
- Границы slice: requester map/document reload/crash, batch и renderer guards,
  provenance/corruption live history и остальные producers остаются в плане
  WP-0. WP-2 не начат;нормативные docs/ не менялись.

- Первый full завершился exit1:5013 passed/5 skipped/3 failed,424.16s
  (.tmp/wp0-live-owner-full.log). Все3 failures —прежние audit fixtures,
  ожидавшие cancelled result/history:они вызывали root даже с заранее
  отменённым signal. Обновлены assertions typed cancelled;unique UUID/diff
  проверяются двумя завершёнными реальными loopback HTTP/TCP проверками,
  с2 persisted snapshots вместо отменённых фикстур. Production fix не менялся.
  Повторный targeted4 suites70/70 passed,5.75s,exit0
  (.tmp/wp0-live-owner-targeted2.log);final full/typecheck выполняются.

- Final full:npm.cmd test -- --maxWorkers=1 —5016 passed/5 skipped/0 failed,
  303 files passed/2 skipped,432.03s,exit0
  (.tmp/wp0-live-owner-final-full.log). Код/тесты во время прогона не менялись.
  Повторный npm.cmd run typecheck —165 channels/0 public any,exit0
  (.tmp/wp0-live-owner-final-typecheck.log). Build exit0 до изменения только
  audit fixtures;production source с момента build не менялся.
  Targeted70/70,integration37/37,coverage AC927/927,F210/210,diff check exit0.
  Изменения готовы к PR;exact-head Qodo/Revix/CI остаются обязательными.

### PR #93: Qodo follow-up (20.10.2026)

- Создан #93 https://github.com/newnout6-a11y/vpn/pull/93,head8e57b56.
  Qodo1559039 completed на exact SHA8e57b560653bb5a84c8827d485e21a8ebed90b80:
  c5e8c006 (redacted history correlation) и0fa60b07 (admission released before
  physical drain) подтверждены. Attribution не менялся. Revix118412979733
  completed/success,Ready to merge на старом head;это не заменяет новые gates.
- Receipt id теперь op_32hex,также сохраняются operationKey/correlationId.
  Raw registry UUID остаётся cancellation identity. Generic secret redactor
  по-прежнему маскирует поле id;правило не ослаблено:operationKey и action
  correlation проходят настоящий serializer/redactSensitiveConfig и остаются
  различимыми у двух реальных завершённых loopback checks. Legacy UUID history
  остаётся читаемой,новые metadata fields optional для старых записей.
- OperationLease.drained —readonly promise реального освобождения всех effects.
  Single/batch IPC сохраняют admission и destroyed listener до этих promises,
  возвращая caller cancellation/deadline сразу. Cancel больше не удаляет slot;
  duplicate/limit возвращают typed conflict. Legacy request IDs сохранены.
- Новые sender-limit regressions:single/batch × cancel/deadline,held DNS,
  prompt result,отказ replacement/duplicate,independent sender,listener lifetime
  и повторная admission после drain. До fix6 failed/20 passed
  (.tmp/wp0-live-owner-qodo-red.log,exit1);первый follow-up показал настоящий
  generic id-redaction и новый deferred listener lifetime (2 failed),оба
  учтены без ослабления production redactor.
- Targeted5 suites145/145 passed,5.97s,exit0
  (.tmp/wp0-live-owner-qodo-targeted.log);explicit integration37/37,2.11s,exit0
  (.tmp/wp0-live-owner-qodo-integration.log). Coverage AC927/927,F210/210,diff0.
  Full/build выполняются;новый commit/push/exact-head review ещё не приняты.

- Qodo follow-up final local:npm.cmd run build —exit0 (typecheck165 channels/
  0 public any,.tmp/wp0-live-owner-qodo-build.log);npm.cmd test -- --maxWorkers=1
  —5020 passed/5 skipped/0 failed,303 files passed/2 skipped,440.20s,exit0
  (.tmp/wp0-live-owner-qodo-full.log). Source/test tree не менялся во время full.
  Targeted145/145,integration37/37,coverage AC927/927,F210/210,diff0.
  Старый CI39356680659 на8e57b56 success;новый head требует своих CI/review.

### PR #93 принят; document/batch lifetime (20.10.2026)

- Final reviewed head28540de6d7dde19e4730d30163fa177d114173e8,
  tree8f2d463a95861fe7da73e11e0fd20da7f44fdca4. Qodo1559138 completed на этом
  SHA:оба findings автоматически implemented,новых/pending нет,attribution
  не менялся. Final snapshot .tmp/qodo93-final.json.
- Revix118417529584 completed/neutral,Low risk;единственное замечание —вопрос
  о rejection handling. Production single renderer catch(L168) обрабатывает
  rejected IPC;manual cancel меняет generation до cancel(L183),поздняя ошибка
  игнорируется. Batch renderer catch(L90) и main catch(L3671) также есть.
  Это подтверждено чтением кода;дополнительный существующий UI+IPC набор:
  npm.cmd test -- src/renderer/components/LiveServerCheckSection.test.tsx
  src/renderer/components/LiveServerUiRegression.test.tsx src/shared/ipc-result.test.ts
  —37/37,2.82s,exit0 (.tmp/wp0-live-owner-renderer-review.log). Он не заявлен
  как отдельный новый typed-rejection E2E сценарий. Подтверждённого issue нет.
- CI39358091824 success на exact SHA:Windows full/live integration/traceability/
  real contextBridge+CSP/native IPv6 WFP/Electron,Rust/site прошли.
  Local final:build/typecheck165/0any,full5020 passed/5 skipped/0 failed,
  440.20s,targeted145/145,integration37/37,coverage927/927,210/210,diff0.
- #93 MERGED20.10.2026 02:24:56UTC;main d96af0a20e8d84869d5e067c222b2c41f15b1bd8.
  git diff --exit-code28540de vpn/main exit0;reviewed/main tree совпал.
- Следующий slice —codex/wp0-live-document-lifetime:reload/crash main document,
  batch token до IPC и generation/sequence/unmount guards. OperationLease.drained
  и admission observer уже доступны,повторно вводить их не требуется.
  Live history provenance/corruption и прочие producers остаются в WP-0;
  WP-2 не начат,нормативные docs/ не менялись.

### WP-0 — lifetime документа и batch UI (20.10.2026)

- Single/batch IPC используют requestDocumentLifetime: destroyed, main-frame
  did-navigate и render-process-gone отменяют только запрос владельца. Admission
  и listeners удерживаются до физического drain. Batch cancellation не становится
  ошибкой профиля; поздний result/progress не добавляется после abort.
- Batch UI создаёт UUID до IPC, показывает подготовку и отмену до первого progress,
  проверяет requestId/sequence/generation, инвалидирует старые ответы/errors/finally
  на cancel/hide/unmount. Reopen изолирован от прежней подписки. Single UI также
  использует UUID; canonical IPC_CANCELLED обрабатывается тихо, timeout виден.
- Baseline main: 5 failed/16 passed (.tmp/wp0-live-document-red.log); batch UI:
  7 failed/1 passed (.tmp/wp0-live-batch-ui-red.log). Single UUID:2 failed/8 passed
  (.tmp/wp0-live-single-ui-red.log). Первый объединённый прогон:62 passed/1 failed
  из-за двукратного отображения timeout в существующем UI; исправлен matcher теста.
- npm.cmd test -- src/renderer/components/LiveServerBatchComparison.test.tsx
  src/renderer/components/LiveServerUiRegression.test.tsx
  src/renderer/components/LiveServerCheckSection.test.tsx
  src/main/liveServerProbe.operation.test.ts src/main/liveServerAuditRegression.test.ts
  src/main/requestDocumentLifetime.test.ts —64/64,6 suites,8.60s,exit0
  (.tmp/wp0-live-document-ui-targeted.log). Traceability:AT-00-003/004.
- npm.cmd run build —exit0,typecheck165 channels/0 public any
  (.tmp/wp0-live-document-build.log). npm.cmd test -- --mode integration
  src/main/liveServerProbe.handshakeDrain.itest.ts
  src/main/keyHealthChecker.transportDrain.itest.ts —37/37,2.08s,exit0
  (.tmp/wp0-live-document-integration.log).
- Playwright CLI/Chromium headed,реальный компонент и production CSS,изолированный
  mock IPC стенд .tmp/wp0-live-ui:pending до progress,cancel,progress,result,timeout.
  Light/dark screenshots в output/playwright/wp0-live-*.png просмотрены;отмена
  возвращает старт без alert,timeout виден. Таблица результата сохраняет прежний
  горизонтальный scroll. Это renderer fixture,не live network/Electron/L3.
  Единственный console error —favicon404 стенда. Связанные scripts design-doctrine
  отсутствуют в установленном skill;использованы реальные project gates/visual QA,
  численная WCAG/contrast оценка не заявлена. Стенд и browser остановлены.
- python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py —
  AC927/927,F210/210,exit0 (проверка трассировки,не выполнения всех AT).
  Полный npm.cmd test ещё выполняется;commit/push/exact-head review pending.
  Нормативные docs/ не изменялись;WP-0 в работе,WP-2 не начат.

- Final local: npm.cmd test —5037 passed/5 skipped/0 failed,304 files passed/2 skipped,
  444.15s,exit0 (.tmp/wp0-live-document-full.log). Build/typecheck165/0any,
  targeted64/64,integration37/37,coverage927/927,210/210,diff0.
  Во время full изменены только AT labels в двух tests,без изменения поведения.
  Commit/PR и exact-head Qodo/Revix/CI —следующий gate.

- PR #94 initial813c4a6:Qodo1559260 completed,2 informational findings.
  Attribution не менялся. Snapshot .tmp/qodo94-initial.json.
  (1) Quick cancel/restart может дать typed conflict до physical drain:это
  преднамеренный bounded admission,покрытый sender-limit tests single/batch×
  cancel/deadline. Он не означает успешный новый запуск;ресурсы остаются owned,
  после drain retry допускается. Это информационное UX-ограничение,а не основание
  убирать safety limit. (2) Cancel между child commit и batch continuation терял
  уже сохранённый receipt из batch result —воспроизведено и исправлено:возвращённый
  committed child остаётся в receipt,последующий progress и новый child подавлены.
- Revix118424075836 Needs changes:новый preparing text без i18n (issue) и sync act
  в новых tests (suggestion). Добавлен liveCheck.preparing в ru/en,используется t();
  listener updates ожидают async act. Два locale tests используют настоящий i18n.
  Объединённый red:2 failed/31 passed (.tmp/wp0-live-document-review-red.log),
  английская локаль и committed receipt. После fix targeted6 suites67/67,9.38s,
  exit0 (.tmp/wp0-live-document-review-targeted.log).
- Review follow-up:npm.cmd run build —exit0,typecheck165/0any
  (.tmp/wp0-live-document-review-build.log);explicit integration37/37,2.27s,exit0
  (.tmp/wp0-live-document-review-integration.log);coverage927/927,210/210,diff0.
  Playwright updated preparing ru/light,en/dark проверены на actual i18n+CSS,
  output/playwright/wp0-live-preparing-*.png;stand/browser остановлены.
  Новый full выполняется;исправления ещё не приняты новым exact-head review/CI.

- Initial CI39360106142 на813c4a6 failure:bootRecoveryExecution.test.ts266
  (corrupt trusted firewall) превысил outer Vitest5000ms. Native helper уже имеет
  timeout15000ms;describe budget согласован до20000ms,assertions не менялись.
  Лог .tmp/wp0-live-document-initial-ci-failed.log. Следующий SHA требует нового CI.
- Review full после длительной паузы выполнения завершился exit1:5038 passed/
  5 skipped/2 failed,6451.15s. lifecycleCleanup resolver case и configIpcErrors
  private-export PowerShell boundary каждый получили около6046s. Это observed
  elapsed gap,причина паузы на уровне ОС не установлена;PASS не заявлен.
  Лог .tmp/wp0-live-document-review-full.log. Их test budgets не изменялись.
  Повтор targeted и новый полный прогон запущены после паузы.

- После паузы npm.cmd test -- src/main/bootRecoveryExecution.test.ts
  src/main/lifecycleCleanup.test.ts src/main/configIpcErrors.test.ts —252/252,
  3 suites,54.05s,exit0 (.tmp/wp0-live-document-ci-regressions.log).
  npm.cmd run build повторно exit0,typecheck165/0any,
  .tmp/wp0-live-document-final-build.log. Source/test tree frozen для full.

- Final full (maxWorkers2) без длительной паузы:exit1,5038 passed/5 skipped/
  2 failed,304.42s (.tmp/wp0-live-document-final-full.log). Оба —native CIM
  failure fixtures adaptiveNetworkIdentity.test.ts92:10465/10436ms против outer5s;
  runNative уже имел30s process timeout. Только этой группе дан outer35s,
  assertion fixture failure и production budgets не менялись. Targeted25/25,
  3.23s,exit0 (.tmp/wp0-live-document-cim-regressions.log). Новый full идёт
  с --maxWorkers=1;это обычный прежний режим полного локального прогона.

- Продолжение после interruption:handle23165 отсутствует,Win32_Process не показывает
  живых vitest;final2 log обрывается без итогового отчёта. Прогон не засчитан.
  Новый full запущен с --maxWorkers=1 в .tmp/wp0-live-document-final3-full.log;
  exit отдельно фиксируется в .tmp/wp0-live-document-final3-exit.txt.

- Final3 full завершился exit1:5039 passed/5 skipped/1 failed,322.15s.
  Осталась другая группа того же30s helper:adaptiveNetworkIdentity neither
  identity fixture10563ms против outer5000ms. Ей также дан35s runner budget,
  как уже было у последнего native fixture в этом файле. Assertion unchanged.
  .tmp/wp0-live-document-final3-full.log;новый full final4 выполняется.

- Review final local: npm.cmd test -- --maxWorkers=1 —5040 passed/5 skipped/
  0 failed,304 files passed/2 skipped,334.55s,exit0
  (.tmp/wp0-live-document-final4-full.log,отдельный exit marker0).
  Build/typecheck165/0any,targeted67/67,integration37/37,
  timeout-suite repetition252/252,CIM25/25,coverage927/927,210/210,diff0.
  Source/test tree не менялся во время успешного full. Новый SHA ещё требует
  completed Qodo,разбора Revix и CI success.

## 20.10.2026 — PR #94 принят; целостность live history (WP-0)

PR #94 слит в main: 85edf73ca36a8a5a92c50374db28c581a36e502b. Проверенный head
 d7bdc4fd507fe593fd6626c798d0361c90f631c9 и merge имеют одинаковое дерево (git diff пуст).
CI 39372090694 completed/success (Windows, Rust, site); Qodo 1559916 completed
на этом SHA. Dropped committed receipt автоматически implemented. Осталось
informational/Low: быстрый cancel/restart может получить typed conflict до
physical drain; safety admission и retry после drain покрыты тестами. Attribution
не менялся. Revix 118462005020 completed/success, title Ready to merge на том же
SHA; старый badge в summary не является актуальным verdict. Это minor-ограничение,
допустимое по решению владельца; не объявляется исправленным.

Следующий участок: AT-00-006/010, F-074/F-143, live-server-checks.json.
Подтверждены подавленные read/write ошибки и in-memory успех до disk commit.
Новые 29 real-file cases до fix: 29 failed,395ms,exit1
(.tmp/wp0-live-history-red.log). Теперь staged memory, temp+fsync+rename,
exact prior-file backup, bounded diagnostics history.corrupted/unavailable/
write-failed/recovered, salvage валидных строк и восстановление из backup,
проверка всех diagnostic shapes, detached read view. Явный clear обновляет
backup пустым содержимым, чтобы удалённые строки не воскресли после corruption.
При I/O failure сохраняются предыдущие committed memory/file, наружу идёт
IpcFault с категорией; raw paths/stack не копируются в error или log.

Это существующий plain JSON target-map v0, отдельный от 20 electron-store stores.
Добавлен schemaVersion:0 на записи; legacy без marker читается без переписывания.
Неподдерживаемый/невалидный marker в main или backup отказывается до writes,
также при замене файла после init. Миграции новой версии здесь не заявляются.
Сквозной receipt/correlation сохранён; полная provenance всех producers и
межпроцессная координация ещё остаются задачами WP-0. Нормативные docs/ не менялись.

npm.cmd test -- src/main/liveServerHistory.integrity.test.ts
src/main/liveServerHistory.test.ts src/main/liveServerProbe.operation.test.ts
src/main/liveServerAuditRegression.test.ts —77/77,4 suites,5.17s,exit0
(.tmp/wp0-live-history-targeted4.log). Включены 100 legacy records/5 targets,
malformed nested diagnostics, future SHA-256 invariance, denied read,
copy/write/fsync/rename failures, final commit failure после успешного backup,
retry/restart/clear, реальный loopback receipt и failed operation history commit.
npm.cmd run typecheck —165 channels/0 public any,exit0.
Полный набор и build запускаются; commit/review/CI для этого участка ещё pending.

- Final local live-history integrity: npm.cmd test -- --maxWorkers=1 —5075 passed,
  5 skipped,0 failed;305 files passed/2 skipped,273.24s,exit0
  (.tmp/wp0-live-history-full.log; .tmp/wp0-live-history-full-exit.txt=0).
  npm.cmd run build —exit0,включая typecheck165 channels/0 public any
  (.tmp/wp0-live-history-build.log). Targeted77/77; python -X utf8
  ../docs/04-приёмочные-тесты/traceability/check-coverage.py —AC927/927,F210/210,
  exit0;git diff --check —exit0. Source/test tree не менялся во время full.
  Commit/PR и exact-head Qodo/Revix/CI —следующий gate.

- PR #95 initial885e4ec: Qodo1560044 completed, remediation recommended
  Missing main file hides saved checks. Две регрессии (missing main + valid
  backup; missing main + future backup) до fix:2 failed/34 passed,465ms,exit1
  (.tmp/wp0-live-history-review-red.log). Исправлено admission/recovery при
  отсутствии основного файла; следующий save/restart сохраняет backup rows,
  future backup отказывается без изменения файлов. Targeted4 suites79/79,
  4.98s,exit0 (.tmp/wp0-live-history-review-targeted.log). Attribution не менялся.
- Revix118466883332 completed/neutral,Low risk,title 2 issue(s) found:
  suggestion о сохранении исходных повреждённых bytes и question о init callers.
  Фактические production callers (rg по src,исключая tests): только
  liveServerProbe.ts3543 getPreviousSuccessfulCheck,3606 addCheck внутри owned
  async operation и3791 guarded history IPC. Отдельного startup init нет;
  read failures отклоняют этот запрос typed error,а не прерывают startup.
  Raw rejected rows не сохраняются в отдельный файл после следующей записи:
  AT-00-010 допускает честную маркировку corruption;history.corrupted сообщает
  потерю до следующей записи,валидные rows сохраняются,валидный backup не
  заменяется повреждённым файлом. Восстановление отвергнутых rows и сохранение
  их исходных bytes не заявляются. Это minor suggestion,не скрытое исправление.
  Полный повтор/build и новое exact-head review/CI ещё требуются.

- Initial CI39373659588 success на885e4ec (Windows7m34s,Rust,site),но это не
  проверка follow-up. Review local full:5076 passed/5 skipped/1 failed,
  263.93s,exit1 (.tmp/wp0-live-history-review-full.log). Прежний
  liveServerProbe.test.ts209 ожидал отказ на фиксированном 127.0.0.1:65432,
  но получил ok. После прогона listener отсутствует;владение портом в момент
  теста не установлено. Фикстура могла получить этот ephemeral port сама;
  причинный вердикт о конкретном процессе не делается.
  Заменён только тест: connect принудительно получает ECONNREFUSED,используются
  настоящий Socket error/close и пять попыток;assertions не ослаблены,добавлена
  проверка error code. Production TCP probe не менялся.
  npm.cmd test -- src/main/liveServerProbe.test.ts
  src/main/liveServerHistory.integrity.test.ts src/main/liveServerHistory.test.ts
  src/main/liveServerProbe.operation.test.ts src/main/liveServerAuditRegression.test.ts
  —102/102,5 suites,5.06s,exit0 (.tmp/wp0-live-history-final-targeted.log).
  Build/новый full запускаются;провал не засчитан как PASS.

- Review final local: npm.cmd test -- --maxWorkers=1 —5077 passed/5 skipped/
  0 failed;305 files passed/2 skipped,263.46s,exit0
  (.tmp/wp0-live-history-final-full.log,exit marker0).
  npm.cmd run build —exit0,typecheck165 channels/0 public any
  (.tmp/wp0-live-history-final-build.log);targeted5 suites102/102;
  coverage927/927,210/210,diff0. Source/test tree frozen во время full.
  Новый SHA ещё требует completed Qodo,разбора Revix и CI success.

## 20.10.2026 — PR #95 принят; live provenance/redaction (WP-0)

PR #95 слит:6539b12e6b73cfe248a26a8f9114d45551779318. Проверенный final head
3bdee0d538cac70b7aaa61ffbbde9f0205cabd50 и merge имеют одинаковое дерево.
CI39375050945 success (Windows/Rust/site);Qodo1560112 completed на этом SHA,
единственная прежняя finding автоматически implemented,новых нет. Attribution
не менялся. Revix118471219707 completed/neutral,Low risk,title1 issue(s) found;
это question:при partly valid main сначала используются salvaged main rows,
backup —если их нет. Это явная recovery policy,а не слияние более старой истории
поверх новых валидных записей. Corruption логируется;backup остаётся сохранённым.
Предыдущие suggestion/question и границы source-byte retention описаны выше.
Допустимые minor questions не называются исправленными или approval.

Следующий участок AT-00-005/006,F-074/F-143: новые live receipts получают
provenance из admitted lease (source/owner). Общий route unconfirmed/confidence
indeterminate: DNS,endpoint и isolated proxy могут идти разными путями,их
наблюдения остаются в собственных diagnostic fields. Старым записям provenance
не выдумывается;невалидные metadata отсеиваются с history.corrupted.

Три новые проверки до fix:3 failed/47 passed,5.01s,exit1
(.tmp/wp0-live-provenance-red.log): отсутствующие metadata и секреты в nested
text. sanitizeLiveCheckForStorage использует общий redactSensitiveText для
каждого string leaf,сохраняя типы/booleans,и удаляет credential evidence keys.
Main-generated receipt/profile/correlation identities сохраняются;diagnostic
credential UUID,пароли,Bearer,VPN URI,user paths маскируются. Legacy read view
тоже маскируется;точный старый migration backup не переименовывается в sanitized
copy. Это не заявление об очистке исходных секретов из исторического v0 backup.

Plain JSON schema v0→v1:реестр одного фактического шага live-history-provenance-v1,
marker с from/to/id/SHA-256 входных bytes,exact prior valid file backup перед
записью. Read не переписывает v0;marker и history.migrated появляются только
после успешной записи,повтор v1 сохраняет lineage без повторного шага. Новая
версия ограждает downgrade к strict v0 reader из #95;future version+1 отказана.
Migration red:1 failed/39 skipped (.tmp/wp0-live-provenance-migration-red.log).

Исправлена изоляция прежнего liveServerHistory.test:main-only cleanup оставлял
.bak в OS temp. Теперь каждый case создаёт собственный каталог внутри project
.tmp и удаляет его целиком;начальная история проверяется пустой. Чужие/прежние
артефакты не удалялись.
Адресно4 suites84/84,4.94s,exit0 (.tmp/wp0-live-provenance-targeted3.log),
typecheck165 channels/0 public any exit0. Усилен failure во втором rename
migration commit. Полный набор/build/remote gate ещё pending;WP-0 в работе,
WP-2 не начат. Нормативные docs/ не изменялись.

Первый full после общего redactor: npm.cmd test -- --maxWorkers=1 —5080 passed/5 skipped/2 failed,255.66s,exit1 (.tmp/wp0-live-provenance-full.log). Две прежние regression suites обнаружили UUID-like credentials вне RFC version/variant. Сохранена прежняя широкая UUID-маска [REDACTED_UUID] до общего redactor,на каждом string leaf;internal identities восстанавливаются отдельно. Старые assertions не ослаблялись.
Адресно npm.cmd test -- src/main/extendedReviewFixed.test.ts src/main/liveServerProbe.extended.test.ts src/main/liveServerHistory.integrity.test.ts src/main/liveServerHistory.test.ts src/main/liveServerProbe.operation.test.ts src/main/liveServerAuditRegression.test.ts —122/122,6 suites,5.80s,exit0 (.tmp/wp0-live-provenance-targeted-final.log).
Повторный npm.cmd run build включает typecheck:165 channels,0 public any,exit0 (.tmp/wp0-live-provenance-final-build.log). python docs/04-приёмочные-тесты/traceability/check-coverage.py —AC927/927,F210/210,exit0;git diff --check —exit0. Новый full выполняется;remote gate pending.

Final local: npm.cmd test -- --maxWorkers=1 —5082 passed/5 skipped/0 failed,305 files passed/2 skipped,258.89s,exit0 (.tmp/wp0-live-provenance-final-full.log,exit marker0). Source/test tree frozen во время полного прогона. build/typecheck165 channels/0 public any,coverage AC927/927 F210/210,diff check —exit0. Remote CI/Qodo/Revix pending;WP-0 в работе,WP-2 не начат.

Qodo1560244 completed на a68a750 нашёл4 findings (3 medium,1 low). Все4 воспроизведены до fix:4 failed/41 skipped,403ms,exit1 (.tmp/wp0-live-provenance-qodo-red.log). Сохраняется отдельная exact .v0.bak с проверкой checksum при retry,не перезаписываемая обычными saves;явный clear удаляет её вместе с историей и очищает rolling backup. Это намеренное удаление владельцем,не бессрочное сохранение очищенной истории. При восстановлении из backup migration origin следует фактическому источнику строк;malformed main marker восстанавливается только из валидной lineage (v0/valid marker),иначе запись отказана без изменения bytes. Новые valid main rows не заменяются старыми backup rows. Safe redirect destination пересобирается из protocol/host/path без URL auth/query/fragment;decoded path снова проходит credential/UUID masking.
Адресно6 suites128/128,4.98s,exit0 (.tmp/wp0-live-provenance-qodo-targeted2.log),включая конфликт migration backup и восстановление marker без потери новых строк. Final-main rename failure передвинут на третий rename после отдельных migration/recovery backups. Attribution Qodo не менялся. Revix118477991519 success/Ready to merge на initial SHA;CI39377221905 и новое remote review после fix учитываются отдельно. Новый full/build запущены;WP-0 в работе.

Qodo fixes final local: npm.cmd test -- --maxWorkers=1 —5088 passed/5 skipped/0 failed,305 files passed/2 skipped,280.90s,exit0 (.tmp/wp0-live-provenance-qodo-full.log,exit marker0). npm.cmd run build (typecheck165 channels/0 public any) —exit0 (.tmp/wp0-live-provenance-qodo-build.log);targeted128/128;coverage AC927/927 F210/210,diff check exit0. Code/test tree frozen во время full. Нужны новые автоматические Qodo/Revix и CI на fix SHA.

## 20.10.2026 — PR #96 принят; background correlation (WP-0)

PR #96 слит:31730b90f49e275e4ba2f07bb95c92c3b62daf0c. Final head831efc1e7f8128bc9bba606915b31ac1adc03695 и merge имеют одинаковое дерево35a41eaea2a98f1ba8c994f6d00fc3efcea0ed44. CI39378399442 success (Windows/Rust/site,включая unit/live drain/native Electron/WFP ABI fixtures). Qodo1560323 completed на final SHA:все4 initial findings автоматически implemented,новых нет;attribution не менялся. Revix118481636610 completed/success,Ready to merge. Local final5088 passed/5 skipped,build/typecheck/coverage/diff exit0.
Следующий участок AT-00-005,F-143:pre-admission schedule events и startup crash recovery получают один scope на всё async действие с source lifecycle и соответствующим owner. Конечные результаты ещё проверяются;WP-0 в работе,WP-2 не начат.

Production callbacks index.ts: schedule connect/disconnect целиком в withCorrelation(op_UUID,{source:lifecycle,owner:schedule}),включая initial trigger log,preflight,admitted lane,terminal log и notification. Disconnect возвращает Promise вместо fire-and-forget;notification awaited без продления native lane. Startup recovery получает отдельный lifecycle/recovery scope до runtime/baseline checks;сетевые эффекты и recovery policy не менялись.
Runtime tests компилируют actual index.ts callbacks/declarations с controlled effects,используя настоящий withCorrelation,ConnectionLifecycle/runScheduledConnection. До fix5/5 failed (553ms,exit1,.tmp/wp0-background-correlation-red.log). Дополнительная delayed notification regression1 failed/5 skipped (482ms,.tmp/wp0-background-notification-red.log). Первый targeted после fix имел1 failure/34 passed:ошибка test fixture lane.stop options переданы строкой;исправлена фикстура на {owner:schedule},production stopProtection уже передаёт этот owner.
Final targeted npm.cmd test -- src/main/backgroundActionCorrelation.test.ts src/main/actionCorrelation.test.ts src/main/scheduledConnection.test.ts src/main/mainIpcRegression.test.ts src/main/connectionLifecycle.test.ts —45/45,5 suites,965ms,exit0 (.tmp/wp0-background-correlation-targeted3.log). Проверены overlapping IDs,error recovery/schedule,async stop и delayed notification. Full/build запущены;coverage927/927,210/210 и diff exit0. Native network recovery этими controlled effects не объявлена PASS;WP-0 в работе.

Build initial exit2:новая schedule fixture не содержала обязательный profileId (TS2741),исправлена на пустой legacy-compatible profileId. Начатый full прерван (exit1),не засчитан как проверка;последующий build2 exit0. При сверке recovery обнаружен аналогичный preflight gap в adoptRetainedSoftProtection:2 failing runtime cases (492ms,.tmp/wp0-background-soft-red.log),обёрнут в отдельный lifecycle/recovery scope до trust inspection и reconciliation,включая failure log. Policy reconciliation не менялась. Final targeted5 suites47/47,966ms,exit0 (.tmp/wp0-background-correlation-final-targeted.log). Новый final full/build запущены после замораживания кода/тестов;coverage/diff exit0.

При сверке поздних effects обнаружено:warning dialog failure после завершения startup recovery теряет active async scope. Regression1 failed/8 skipped (556ms,.tmp/wp0-background-dialog-red.log). Зафиксирован recovery correlationId и explicit scope только для позднего error-log;dialog остаётся nonblocking,исходное действие не удерживается до ответа пользователя. Оба dialog catch используют общий reporter. Для исправления предыдущий ещё незавершённый full остановлен (exit1,не PASS). Final targeted48/48,5 suites,1.01s,exit0 (.tmp/wp0-background-correlation-final-targeted2.log). Новый final-full2/build2 запущены;до их результата дальнейших code/test edits не планируется.

Full2 завершён с20 failed/5077 passed/5 skipped,278.36s,exit1 (.tmp/wp0-background-correlation-final-full2.log). Причины:старые source-extraction fixtures lifecycleCleanup/connectionHistoryStorage не подключали новые private Effects declarations и реальные correlation bindings. Обновлены только harness dependencies/declaration sets;старые safety/history assertions сохранены. Адресно npm.cmd test -- src/main/backgroundActionCorrelation.test.ts src/main/actionCorrelation.test.ts src/main/scheduledConnection.test.ts src/main/mainIpcRegression.test.ts src/main/connectionLifecycle.test.ts src/main/connectionHistoryStorage.test.ts src/main/lifecycleCleanup.test.ts —334/334,7 suites,18.09s,exit0 (.tmp/wp0-background-correlation-regressions.log). Запущены final-full3/build3;новый код заморожен.

Final local: npm.cmd test -- --maxWorkers=1 —5097 passed/5 skipped/0 failed,306 files passed/2 skipped,272.27s,exit0 (.tmp/wp0-background-correlation-final-full3.log,exit marker0). Source/test tree frozen на время full. npm.cmd run build (включая typecheck165 channels/0 public any) —exit0 (.tmp/wp0-background-correlation-final-build3.log);targeted334/334,7 suites;python docs/04-приёмочные-тесты/traceability/check-coverage.py AC927/927 F210/210 и git diff --check exit0. Новый PR требует exact-head Qodo/Revix/CI. WP-0 в работе,WP-2 не начат;normative docs/ не менялись.

## 20.10.2026 — PR #97 принят; leak self-test lifetime (WP-0)

PR #97 слит:e3e4d4b74ac678a12b8a615fafd928fa0153c739. Final reviewed head b72aa0c192cfb322506e35fb4c1677bc2c986103 и merge имеют одинаковое дерево43a185dca2e467caa03bdca3a92862af4d0b0e8a. CI39381109296 success,все3 jobs. Qodo1560573 completed exact SHA,0 findings. Revix118490208184 completed/neutral,Low risk:один nitpick на currentCorrelationId()! в private effect,доступном только через withCorrelation wrapper;этот invariant покрыт runtime tests. Принят как minor по решению владельца,не назван approval/исправленным. Attribution не менялся.
Следующий AT-00-003/005/008 участок:раздельные subscriber leases общей leak self-test,physical curl/PS cancellation/drain и delayed forensic import fencing. WP-0 в работе,WP-2 не начат.

### Leak self-test: владение общей проверкой и физический drain

AT-00-003/005/008: каждый подписчик общей проверки получил собственную managed operation leak-check (deadline 60 s), отмену и отдельную копию результата. Отмена одного не останавливает остальных; последняя отмена или global stop завершают принадлежащий проверке curl/PowerShell. execFile без shell удерживает callback и close; новая проверка отклоняется conflict до физического drain. Неотменяемый native read и delayed forensic import удерживаются до завершения, после отмены не запускаются fallback/probes и не публикуется forensic event. Global stop сохраняет совместимый sanitized cancelled result, индивидуальные cancel/deadline типизированы. Periodic/event owners — adaptive-retry; shutdown registry удерживает все эффекты.

Добавлены 12 lifetime scenarios, включая настоящий принадлежащий тесту Node child без сетевых запросов; сохранены 10 прежних behavioral tests. Начальный red:3 failed,10.20s,exit1 (.tmp/wp0-leak-lifetime-red.log); expanded boundaries:1 failed/8 passed,1.47s,exit1 (.tmp/wp0-leak-boundaries.log). Старые mocks без ChildProcess.close дали7 failed/12 passed и8 unhandled errors,31.74s,exit1 (.tmp/wp0-leak-legacy-red.log); адаптирован harness, прежние assertions сохранены. Correlation regression изначально зелёная (1 passed/2 skipped,462ms), несмотря на имя wp0-leak-shared-correlation-red.log. Последний адресный npm.cmd test -- src/main/leakSelfTest.lifetime.test.ts src/main/leakSelfTest.test.ts src/main/operationRegistry.test.ts —97/97,3 suites,2.36s,exit0 (.tmp/wp0-leak-targeted3.log). Предварительный typecheck165 channels/0 public any exit0;traceability AC927/927,F210/210 exit0 не означает выполнение приёмки.

Requester IPC cancellation и unmount UI намеренно остаются следующим отдельным участком; текущий main handler ещё вызывает API без requester token. Full/build и remote gate текущего участка pending. WP-0 в работе,WP-2 не начат; нормативные docs/ не менялись.

Final local: npm.cmd test -- --maxWorkers=1 —5113 passed/5 skipped/0 failed,307 files passed/2 skipped,281.92s,exit0 (.tmp/wp0-leak-final-full.log,EXIT_CODE=0). npm.cmd run build (typecheck165 channels/0 public any) —exit0 (.tmp/wp0-leak-final-build.log). Адресно npm.cmd test -- src/main/leakSelfTest.lifetime.test.ts src/main/leakSelfTest.test.ts src/main/operationRegistry.test.ts —97/97,3 suites,2.45s,exit0 (.tmp/wp0-leak-final-targeted.log). python docs/04-приёмочные-тесты/traceability/check-coverage.py —AC927/927,F210/210,exit0;git diff --check —exit0. Source/test tree frozen во время полного прогона;remote CI и автоматические Qodo/Revix pending. WP-0 в работе,WP-2 не начат.

Qodo1560809 completed на2695b33:2 findings —action_required Reliability (forensic promise не awaited) и informational Observability (verdict log до delayed import). Оба воспроизведены:2 failed/11 skipped,752ms,exit1 (.tmp/wp0-leak-qodo-red.log). Реальная recordTrafficForensicsAppEvent также начинала append после cancellation во время manifest read:1 failed/8 skipped,291ms,exit1 (.tmp/wp0-leak-forensic-red.log). Теперь await удерживает всю forensic promise и её rejection;optional assertActive проверяется до/после manifest read и после уже начатого append,поздний append/late warning запрещены. Уже начатая запись не объявлена физически отменяемой:её завершение удерживается. Verdict log перенесён за awaited forensic boundary и final session/signal fence.
Первый targeted fix:1 failed/153 passed,6.89s —новый held forensic mock сохранял implementation между тестами;beforeEach явно сбрасывает его к resolved true. Final targeted npm.cmd test -- src/main/leakSelfTest.lifetime.test.ts src/main/leakSelfTest.test.ts src/main/trafficForensicsSessionSecurity.test.ts src/main/trafficForensics.test.ts src/main/operationRegistry.test.ts —156/156,5 suites,3.57s,exit0 (.tmp/wp0-leak-qodo-targeted2.log). Добавлены реальные writer tests:cancel на manifest read и удержание successful/failed append без позднего warning. Attribution Qodo не менялся. Revix5581750763 на initial SHA сообщил free-quota-reached до21.10 00:00UTC;полного ревью нет,это не approval. Новый full/build/automatic review pending.

Qodo fixes final local: npm.cmd test -- --maxWorkers=1 —5117 passed/5 skipped/0 failed,307 files passed/2 skipped,281.60s,exit0 (.tmp/wp0-leak-qodo-full.log,EXIT_CODE=0). npm.cmd run build (typecheck165 channels/0 public any) —exit0 (.tmp/wp0-leak-qodo-build.log). Targeted156/156,coverage AC927/927 F210/210 и git diff --check exit0. Код/тесты не менялись во время full. Нужны exact-head CI и автоматический completed Qodo после push.

## 20.10.2026 — PR #98 принят; requester lifetime leak self-test (WP-0)

PR #98 слит:f903715da4a0f7565242a600f93ba42fe5d1c7a3. Reviewed head38c58745abce387e945312ef3505e46b39dd1781;CI39385160293 success,все3 jobs (Windows unit/live drain/contextBridge/native Electron/WFP ABI fixtures,Rust,site). Qodo1560893 completed exact SHA:оба initial findings автоматически implemented,новых нет;attribution не менялся. Revix по квоте полного ревью не выполнил (initial review5581750763 free-quota-reached до21.10 00:00UTC);это не approval. Local final5117 passed/5 skipped,281.60s;targeted156/156;build/typecheck/coverage/diff exit0.
Следующий AT-00-001/003/005/008 участок:optional requester UUID в IPC/preload,document cancellation,отдельные токены leak/routing в Maintenance,DiagnosticsCard unmount fencing. Диагностический snapshot при обнаружении утечки должен удерживаться тем же subscriber lease до физического завершения. WP-0 в работе,WP-2 не начат.

Requester integration:run-leak-self-test принимает optional UUIDv4 через shared contract/electron API/preload;legacy zero-token сохранён,main handler использует настоящий runRequesterOperation. Subscriber lease дополнительно удерживает afterResult diagnostic snapshot с тем же signal/deadline;global stop охватывает подписчиков после завершения shared probes. Физический snapshot collector остаётся неотменяемым на уже начатой native boundary,но его promise удерживается,дальнейшая публикация fenced существующим captureSnapshot API.
DiagnosticsCard создаёт UUID,при unmount отзывает запрос;late success/error не мутируют store/log/local busy state,typed cancellation quiet. Maintenance использует разные UUID leak/routing;unmount отменяет оба,ошибка одного отменяет оставшийся pending companion. Завершённые tokens очищаются;старое mounted action не очищает новое.
Red UI:7 failed/6 passed,1.43s,exit1 (.tmp/wp0-leak-request-ui-red.log);red actual-source main handler:4 failed/13 skipped,1.01s,exit1 (.tmp/wp0-leak-request-main-red.log). Первый targeted55/55,4.20s. Расширенный targeted1 failed/147 passed,5.93s —старый MaintenanceSource ожидал literal runLeakSelfTest() без token;обновлён точный assertion нового вызова. Final targeted npm.cmd test -- src/main/leakSelfTest.lifetime.test.ts src/main/leakSelfTest.test.ts src/main/requesterOperation.test.ts src/main/operationRegistry.test.ts src/main/systemSnapshotLifetime.test.ts src/renderer/components/DiagnosticsCard.requestLifetime.test.tsx src/renderer/components/DiagnosticsCard.test.tsx src/renderer/pages/Maintenance.requestLifetime.test.tsx src/renderer/MaintenanceSource.test.ts src/main/ipcChannelContract.test.ts —152/152,10 suites,6.38s,exit0 (.tmp/wp0-leak-request-targeted3.log). Проверены malformed/duplicate/foreign/same-token-different-sender,document loss,peer survival,snapshot drain/timeout/global stop и best-effort failure.
Initial build exit1:IPC result mismatch any —в index.ts пропущен import runRequesterOperation;добавлен импорт,повторный build выполняется (.tmp/wp0-leak-request-build2.log). Coverage AC927/927,F210/210 exit0 не считается выполненной приёмкой. UI layout/copy/styles не менялись;functional jsdom states проверены,visual/browser и отсутствующие scripts design-doctrine не объявлены PASS. Full/remote gates pending;WP-0 в работе,WP-2 не начат.

Повторный npm.cmd run build —exit0 (.tmp/wp0-leak-request-build2.log),typecheck165 channels/0 public any. Код/тесты заморожены перед полным набором. При сверке AT-00-008 обнаружен ещё существующий gap:Maintenance считает inconclusive только routing verdict/cancelled summary,а LeakResultPanel красит любой non-leak ответ зелёным,даже при physicalAdapterInspectionComplete=false или неизвестном IP. Это не изменено текущим lifetime patch;предлагается отдельная fail-closed UI проверка по принятому общему scope WP-0. Полная приёмка WP-0 поэтому не объявлена.

Final local: npm.cmd test -- --maxWorkers=1 —5132 passed/5 skipped/0 failed,308 files passed/2 skipped,275.82s,exit0 (.tmp/wp0-leak-request-full.log,EXIT_CODE=0). Final code/test tree frozen во время full. npm.cmd run build (включая typecheck165 channels/0 public any) —exit0 (.tmp/wp0-leak-request-build2.log). Targeted152/152,10 suites;python docs/04-приёмочные-тесты/traceability/check-coverage.py AC927/927 F210/210 и git diff --check exit0. Automatic Qodo и exact-head CI следующего PR ещё pending;WP-0 в работе,WP-2 не начат.

Qodo1561100 completed на4ada55f нашёл remediation_recommended Correctness:ожидание snapshot под тем же leak-check deadline могло заменить известную утечку timeout/cancelled. Исправление принято в scope PR99. Начальный regression run имел transform error из-за CRLF-sensitive temporary edit (no tests,136ms,exit1,.tmp/wp0-leak-request-qodo-transform-red.log);исходные lifetime tests/cleanup восстановлены из HEAD,не удалены. Настоящий red:3 failed/18 skipped,4.23s,exit1 (.tmp/wp0-leak-request-qodo-red.log).
Итоговая архитектура обновлена:afterResult и продление subscriber lease убраны. Main немедленно возвращает готовый verdict;diagnostic snapshot запускается отдельной managed operation snapshot с60s deadline,owner manual,исходной correlation и exclusive resource. Одновременные leak verdicts используют один активный snapshot. Snapshot не отменяется поздней потерей requester/global leak stop после выданного verdict;его отменяет/удерживает общий shutdown registry. Уже начатый native collector не объявлен физически прерываемым. Его retained promise ждёт drain,а существующий signal fence не допускает позднюю запись. Snapshot failure/timeout не меняют leak verdict.
Адресно npm.cmd test -- src/main/leakSelfTest.lifetime.test.ts src/main/leakSelfTest.test.ts src/main/requesterOperation.test.ts src/main/operationRegistry.test.ts src/main/systemSnapshotLifetime.test.ts src/renderer/components/DiagnosticsCard.requestLifetime.test.tsx src/renderer/components/DiagnosticsCard.test.tsx src/renderer/pages/Maintenance.requestLifetime.test.tsx src/renderer/MaintenanceSource.test.ts src/main/ipcChannelContract.test.ts —158/158,10 suites,6.41s,exit0 (.tmp/wp0-leak-request-qodo-targeted2.log). Дополнительно проверены сохранение verdict при queued snapshot/deadline/global stop,shutdown drain,один capture при peers и correlation обеих операций. Attribution Qodo не менялся. Revix5582044411 на initial SHA:free-quota-reached,полного ревью нет. Новый full/build/remote gate pending.

Initial CI39387530878 на4ada55f failed:1 failed/5132 passed/4 skipped,356.48s. Единственная ошибка прежней native quarantine fixture recoveryManifestStorage.test.ts:spawnSync powershell.exe ETIMEDOUT на15s (variant same);дальнейшие native jobs этого run были skipped. Лог .tmp/wp0-leak-request-ci-failed.log сохранён. Отдельная локальная проверка с явным VPNTE_PWSH, npm.cmd test -- src/main/recoveryManifestStorage.test.ts -t 'native quarantine' —5 passed/55 filtered skipped,4.93s,exit0 (.tmp/wp0-leak-request-native-quarantine.log),все пять вариантов реально исполнены в собственном project .tmp folder. Production/recovery safety assertions и deadlines не менялись;один remote timeout не объявлен опровергнутым локальным PASS. Новый exact-head CI после Qodo fix обязателен.

Qodo fix final local: npm.cmd test -- --maxWorkers=1 —5138 passed/5 skipped/0 failed,308 files passed/2 skipped,268.94s,exit0 (.tmp/wp0-leak-request-qodo-full.log,EXIT_CODE=0). Source/test tree frozen. npm.cmd run build (typecheck165 channels/0 public any) —exit0 (.tmp/wp0-leak-request-qodo-build.log). Targeted158/158,10 suites;native quarantine5/5 с55 filtered skips;traceability AC927/927 F210/210 и git diff --check exit0. Нужны автоматический completed Qodo и успешный CI на новом fix SHA.


## 20.10.2026 — PR #99 принят; достоверность leak verdict (WP-0)

PR #99 слит: ef6390f4960eceed73f33acd256154482bd8578a; reviewed head f09cff8cef7adf6c119aecc1e3f9631cc753938e. Деревья head/merge совпадают: ab51df94144dca4d8ab224348c801ae69f35e44a. CI 39389031477 success, все 3 jobs; Qodo 1561232 completed exact SHA, initial Correctness finding автоматически implemented, новых нет; attribution не менялся. Revix 5582044411 на initial SHA: free-quota-reached до 21.10 00:00 UTC, полного ревью нет, это не approval. Final local: 5138 passed/5 skipped, 268.94s; targeted 158/158; npm.cmd run build (typecheck 165 channels/0 public any), traceability AC927/927 F210/210 и diff check exit0.

Следующий подтверждённый gap AT-00-008: Maintenance выдаёт success при incomplete/empty physical inspection или отсутствующем IP; DiagnosticsCard красит любой non-leak зелёным. Принятый общий scope WP-0 охватывает исправление; норматив docs/ не меняется. Новый regression red: 10 failed/15 passed и 1 failed suite из-за ещё отсутствующего shared helper, 1.65s, exit1 (.tmp/wp0-leak-verdict-red.log). Общий evidence verdict требует explicit complete=true, корректный default IPv4 и измеренные adapter probes; zero samples/unknown launch/DNS/TLS response не подтверждают защиту. Полученный physical egress IP сохраняет leak при позднем curl failure. Применяется также к periodic/event clean callbacks и VPN IP baseline adoption. Типы результата объединены, публичная форма сохранена.

Первый адресный run: 2 failed/63 passed (старые clean fixtures не имели ни одной physical пробы). Второй: 1 failed/83 passed (source literal assertion обновлён на вызов общего verdict). Final targeted перед UI осмотром: npm.cmd test -- src/shared/leak-self-test.test.ts src/renderer/components/DiagnosticsCard.requestLifetime.test.tsx src/renderer/pages/Maintenance.requestLifetime.test.tsx src/main/leakSelfTest.test.ts src/main/leakSelfTest.lifetime.test.ts src/main/indeterminateIpAutoVerify.test.ts src/renderer/components/DiagnosticsCard.test.tsx src/renderer/MaintenanceSource.test.ts src/main/ipcChannelContract.test.ts — 115/115,9 suites,6.30s,exit0 (.tmp/wp0-leak-verdict-targeted4.log). build/typecheck165/0,coverage927/927 F210/210,diff exit0. Full идёт на frozen code/test tree.

Playwright UI fixture с настоящими DiagnosticsCard/Maintenance: пять состояний × две темы проверены; 280/320/414px без document overflow (scrollWidth272/312/406). Светлая/тёмная warning screenshots просмотрены: output/playwright/wp0-leak-verdict-{light,dark}-unknown.png. Визуально обнаружен ещё legacy summary OK при новом warning/leak: планируется вычислять пользовательский текст по evidence, а не доверять старой summary. Эти результаты не означают реальную сетевую L3-приёмку. design-doctrine accuracy_report/verify_states scripts и referenced rule files отсутствуют; формальный design gate PASS не заявлен. WP-0 в работе, WP-2 не начат.


Initial full на неизменном первом code/test tree: npm.cmd test -- --maxWorkers=1 —5166 passed/5 skipped/0 failed,309 files passed/2 skipped,281.42s,exit0 (.tmp/wp0-leak-verdict-full.log). После его завершения пользовательский текст вынесен в общий leakSelfTestMessage: UI/log/toast не доверяют legacy summary; причины incomplete/missing-IP/empty/unknown показываются явно. Backend details/forensic summary сохранены. Добавлен message regression, invalid-IP auto-baseline test изолирован от неизвестного curl; прежние redaction tests теперь явно подтверждают проход каждой из четырёх веток с корректным verified IP.
Final targeted —116/116,9 suites,6.35s,exit0 (.tmp/wp0-leak-verdict-targeted-final.log). npm.cmd run build (включая typecheck165/0) —exit0 (.tmp/wp0-leak-verdict-final-build.log). Final UI:10 сценариев5×2 темы,противоречивый OK отсутствует в panel и Maintenance;30 responsive сценариев5×2×3 ширины280/320/414px без document overflow (.tmp/wp0-leak-verdict-final-ui.log,final-responsive.log). Final light/dark screenshots визуально просмотрены:output/playwright/wp0-leak-verdict-final-{light,dark}.png. Оба временных browser/Vite процесса остановлены. Новый full на frozen final code/test tree выполняется.


Final local frozen tree: npm.cmd test -- --maxWorkers=1 —5167 passed/5 skipped/0 failed,309 files passed/2 skipped,276.13s,exit0 (.tmp/wp0-leak-verdict-final-full.log,EXIT_CODE=0). npm.cmd run build (включая typecheck165 channels/0 public any) —exit0 (.tmp/wp0-leak-verdict-final-build.log). Targeted116/116,9 suites;traceability AC927/927 F210/210 и git diff --check exit0. UI fixture10 состояний и30 responsive случаев описаны выше. Remote exact-head CI/automatic Qodo ещё pending; WP-0 не завершён, WP-2 не начат.


PR #100 открыт на 69693b654d4018cacfb17aafbe21d9abbe31b042. Qodo1561598 completed exact SHA: два remediation_recommended — Correctness (потеря IP/adapter evidence и DNS-разницы в Maintenance/log) и Observability (global cancellation выглядела как неполная инспекция). Оба воспроизведены: npm.cmd test -- src/shared/leak-self-test.test.ts src/renderer/components/DiagnosticsCard.requestLifetime.test.tsx src/renderer/pages/Maintenance.requestLifetime.test.tsx src/main/leakSelfTest.test.ts —10 failed/48 passed,3.02s,exit1 (.tmp/wp0-leak-verdict-qodo-red.log). Attribution не менялся; review saved .tmp/qodo100-final.json (это initial review,не final fix review).

Fix: общий evidence message снова включает названия достигнутых физических адаптеров,их IP и TUN IP,а также dnsLeakDetail при расхождении сервисов. Старой summary статус по-прежнему не доверяет. Legacy global-stop result дополнен совместимым optional cancelled:true; cancelled всегда inconclusive,видно «Тест отменён»,без ложной причины об adapter coverage. Положительное leak evidence имеет приоритет. Адресно те же9 suites:125/125,6.73s,exit0 (.tmp/wp0-leak-verdict-qodo-targeted.log); npm.cmd run build (typecheck165/0) —exit0 (.tmp/wp0-leak-verdict-qodo-build.log). Final code/test tree frozen для нового full. Playwright:7 состояний×2 темы×3 ширины=42 случая,overflow0,сохранённые leak/cancel screenshots визуально просмотрены (.tmp/wp0-leak-verdict-qodo-ui.log,output/playwright/wp0-leak-verdict-qodo-*.png). Временные browser/Vite процессы остановлены.

Revix5582479023 на initial SHA сообщил free-quota-reached до21.10 00:00UTC:полного ревью нет,это не approval. CI39392273503 initial SHA ещё выполняется. Новый exact-head Qodo/CI после fix обязателен. Пока ждём gates,только read-only inventory: предыдущие104 literal success:false включали log payloads. Уточнённый AST inventory success/ok:false нашёл123 literals,из них81 непосредственно возвращаемый;это не число дефектов:есть уже typed results,guard envelopes и HTTP control responses. .tmp/wp0-domain-return-inventory.{cjs,json}. Semantic matrix настоящих feature handlers ещё не завершена.


Qodo fixes final local: npm.cmd test -- --maxWorkers=1 —5176 passed/5 skipped/0 failed,309 files passed/2 skipped,270.84s,exit0 (.tmp/wp0-leak-verdict-qodo-full.log,EXIT_CODE=0). npm.cmd run build (typecheck165 channels/0 public any) —exit0 (.tmp/wp0-leak-verdict-qodo-build.log). Targeted125/125,9 suites;traceability AC927/927 F210/210 и diff check exit0. Full выполнялся на frozen final code/test tree. CI39392273503 на initial69693b6 завершён success,все3 jobs;это не CI нового fix SHA. Требуются новый exact-head CI и автоматический completed Qodo.


## 20.10.2026 — WP-0: типизированные ошибки обновления подписок

PR #100 принят: final head b28317f67c208a4a14ea3eed0b924fdf031ec3f8, Qodo1561768 completed, оба замечания initial review1561598 автоматически implemented; новых нет. CI39393579304 success (Windows/Rust/site). Merge/main b444af53d8b320c2f179aa8835039a9125f141dd; reviewed и merge trees идентичны:0578af70bee580b98b6d8e7e975c0213ad59ba20. Revix5582479023 сообщил free-quota-reached до21.10 00:00UTC, полного review нет; это не approval. Attribution findings вручную не менялся.

AT-00-004/005, F-074/F-143, cross-regression AT-04-007/F-064: production groups:refresh возвращал обычный {ok:false,error:exception.message}; guard оборачивал его в outer ok:true. Raw error также попадал в lastFetchError и затем groups:list. Уточнение инвентаризации: текущий OperationRegistry уже распознавал returned ok:false как terminal error; предположение о ложном success в истории не подтвердилось. Недоставало категории ошибки и единого отказа на IPC boundary.

Refresh теперь бросает canonical IpcFault внутри operation owner, сохраняя исходную известную category; неизвестные исключения консервативно internal. Missing group=conflict, manual/no-subscription=validation, empty provider list=validation с безопасной статической причиной в group metadata. Последние профили/active ID/lastFetchedAt сохраняются, partial device fetch не коммитится; network/timeout даёт unreachable, local/internal error не доказывает expiry. Успешный retry очищает lastFetchError. Scheduler продолжает sweep после отказов; re-paste получает исходный typed fault. Ошибки refresh-policy также validation/conflict. Новые сообщения в metadata и локальные feature logs не копируют exception text. Servers перечитывает group metadata после typed failure; requester cancellation остаётся quiet. Success shape прежний, plain false union удалён.

Проверки: новый real-handler/guard/registry matrix сначала имел17 setup failures из-за mock defaults и UI regression (18 failed/24 passed,4.53s); после исправления только mock setup, до production fix —11 failed/31 passed,4.39s. Это meaningful red (.tmp/wp0-refresh-domain-red.log). После fix первые2 suites42/42; final targeted command: npm.cmd test -- src/main/serverGroupsRefresh.test.ts src/main/serverGroupsIpcErrors.test.ts src/renderer/pages/Servers.requestLifetime.test.tsx src/main/ipcChannelContract.test.ts —102 passed,4 files,3.51s,exit0 (.tmp/wp0-refresh-domain-targeted.log). Matrix7 resolver categories +7 store categories +7 secondary-device categories; canonical response, safe metadata/list, correlated terminal history, lock/listener cleanup; missing/manual/empty/policy/scheduler cases и UI metadata/cancel.

Первый npm.cmd run build обнаружил устаревшую false-result ветку re-paste (TS2339); удалена. Повтор npm.cmd run build, включая typecheck165 channels/0 public any —exit0 (.tmp/wp0-refresh-domain-build.log). node scripts/test-electron-runtime.mjs —первый запуск: новая7-category native matrix прошла, следующий старый assertion требовал новый импортированный профиль, уже созданный новым successful refresh; фикстура использует отдельный fresh-native.example.test. Повтор —все7 *_PASS,exit0 (.tmp/wp0-refresh-domain-native-final.log): настоящий Electron44.4.3, production handlers/guard/preload/registry/DPAPI stores, typed categories/codes/correlation через настоящий sandbox contextBridge, safe group metadata, unchanged saved profiles, no stale cancellation token/listeners, successful retry. Resolver контролируемый; это не натурная сетевая L3-приёмка. python ../docs/04-приёмочные-тесты/traceability/check-coverage.py (из приложения; эквивалентный запуск из корня выполнен) —AC927/927,F210/210,exit0; git diff --check —exit0.

Полный npm.cmd test -- --maxWorkers=1 и final typecheck выполняются. Remote Qodo/CI следующего PR ещё не запущены. WP-0 не завершён: semantic inventory остальных domain results и финальная актуальная AT-матрица остаются; HTTP/TLS/parser exceptions, потерявшие structured code ранее в resolver, пока честно internal — этот участок не доказывает их полную taxonomy. WP-2 ещё не начат. Нормативные docs/ не изменялись.

Первый full завершён: npm.cmd test -- --maxWorkers=1 —5203 passed/5 skipped/0 failed,310 files passed/2 skipped,279.27s,exit0 (.tmp/wp0-refresh-domain-full.log). Final повторный typecheck —exit0 (.tmp/wp0-refresh-domain-typecheck.log). Собственное review затем нашло stale-status edge: local refresh failure перезаписывал новый expired старым active. Регрессия сначала1 failed/25 passed,0.38s (.tmp/wp0-refresh-domain-status-red.log); обработчик теперь изменяет status только для network/timeout, остальные сохраняют актуальное значение. Final targeted те же4 suites —103 passed,4.00s,exit0 (.tmp/wp0-refresh-domain-targeted-final.log). Final full/build повторяются после этой конкретной правки; предыдущий зелёный full не подменяет их.

Final local verification после stale-status fix: npm.cmd test -- --maxWorkers=1 —5204 passed/5 skipped/0 failed,310 files passed/2 skipped,291.86s,exit0 (.tmp/wp0-refresh-domain-full-final.log,EXIT_CODE=0). npm.cmd run build —exit0,165 channels/0 public any (.tmp/wp0-refresh-domain-build-final.log). Повтор node scripts/test-electron-runtime.mjs —все7 *_PASS,exit0 (.tmp/wp0-refresh-domain-native-current.log). Code/test tree во время final full не менялся. Следующий шаг —commit/push/PR, completed Qodo и CI на его точном head; до этого следующий кодовый участок не начинается.


Qodo1562107 completed exact initial baeab38bee0dca9336c2e96b86599f771bc2022c выявил2 remediation_recommended (утрата диагностической причины и сохранение active после реального resolver failure) и1 informational (empty subscription показывалась как invalid parameters). Замечания подтверждены8 failing regressions/51 passed,5.29s,exit1 (.tmp/wp0-refresh-domain-qodo-red.log); attribution вручную не менялся. Initial CI39396385972 не заменяет проверки следующего SHA.

Исправление включает настоящий producer: execSubscriptionCurl сохраняет категории DNS/TCP/TLS/HTTP/timeout; malformed request/redirect и полученный неподдерживаемый provider payload имеют validation. Fetch retry aggregation больше не стирает категорию; all-timeout остаётся timeout, полученный невалидный ответ приоритетнее более позднего fallback timeout. Resolver diagnostic message редактируется существующим redactor и сохраняется локально. Feature logs снова передают оригинальный Error в production appLogger, который редактирует message/stack; IPC и group metadata содержат только canonical текст. Network/timeout →unreachable, provider validation →expired, local/internal не перезаписывает новый status. При empty/неподдерживаемом provider response Servers показывает отдельный ru/en текст с сохранением ключей после чтения group metadata; cancellation quiet.

Actual resolver→feature catch→guard→history regression теперь проходит с controlled child_process.spawn: curl6 DNS,7 TCP,60 TLS,22 HTTP,28 timeout,3 invalid URL,0 invalid provider body. Category/code/status и сохранение профилей проверяются через production resolver, не через заранее созданный IpcFault. Actual appLogger + actual redactors сохраняют HTTP/TLS/DNS причину и file:line, удаляя credential URL/token/user path. Финальные targeted6 suites: npm.cmd test -- src/main/serverGroupsIpcErrors.test.ts src/main/serverGroupsRefresh.test.ts src/main/vpnProfilesRegression.test.ts src/main/appLoggerRedaction.test.ts src/renderer/pages/Servers.requestLifetime.test.tsx src/main/ipcChannelContract.test.ts —125 passed,3.83s,exit0 (.tmp/wp0-refresh-domain-qodo-targeted.log). Предыдущий targeted124/124 был до второго UI provider-validation case. Final full/build/native выполняются заново после исправлений Qodo. Прежняя граница этого slice про утраченную resolver category устранена; остальные domain handlers и полная WP-0 matrix остаются.

Initial CI39396385972 на baeab38 завершился failure в SERVER_REQUEST_NATIVE: assertion ожидал русское canonical message, Windows runner выбрал English navigator.language (actual Network operation failed / expected Сетевая операция не выполнена). Исправлена только locale-зависимая fixture: production preload явно получает en/ru через i18nSetLocale, native matrix теперь7 categories×2 locales, persisted metadata остаётся canonical ru. Повтор node scripts/test-electron-runtime.mjs —все7 *_PASS,exit0 (.tmp/wp0-refresh-domain-qodo-native-final.log); первоначальный local native тоже прошёл (.tmp/wp0-refresh-domain-qodo-native.log), но не выявлял English default. История failure сохранена (.tmp/wp0-refresh-domain-ci-initial-failed.log). Build после source/Qodo fixes —exit0,165 channels/0 public any (.tmp/wp0-refresh-domain-qodo-build.log). Traceability AC927/927 F210/210 и diff check exit0.

Final local после Qodo fixes: npm.cmd test -- --maxWorkers=1 —5214 passed/5 skipped/0 failed,310 files passed/2 skipped,274.74s,exit0 (.tmp/wp0-refresh-domain-qodo-full.log,EXIT_CODE=0). Production src и unit-test tree во время full не менялись; отдельная native fixture locale fix проверена своим повторным native прогоном. Build/typecheck165 channels/0 public any —exit0; targeted125/125; native7 *_PASS, включая14 category×locale cases; traceability/diff check exit0. Исправления готовы к commit/push; требуются новый exact-head CI и completed автоматический Qodo.


## 20.10.2026 — принят PR #101; следующий участок WP-0: ошибки уведомлений

PR #101 слит после исправления всех3 замечаний Qodo. Final head b026c9bd4428aac6bc5180ef248c8ab18d73a82c: Qodo1562325 completed, все3 findings автоматически implemented, новых нет; CI39398190723 success, все3 jobs (Windows/Rust/site). Merge/main22c4052f16fdf5d7064221e3a4a037156c3d9272; reviewed и merge trees идентичны:ef7c5169aa227105f97ef2f35f38987c335416b2. Initial CI39396385972 failure (locale-dependent native assertion) и Qodo1562107 сохранены как история, не заменены новым PASS. Revix на initial head сообщил free-quota-reached до21.10 00:00UTC, полного review нет, это не approval. Attribution вручную не менялся.

Read-only инвентаризация уточнена: исходный AST scan пропускал false as const; новый .tmp/wp0-domain-return-inventory-current.cjs учитывает wrapper expressions. 146 false literals/104 непосредственно возвращаемых объектов —кандидаты для семантической проверки, не104 дефекта; туда входят guard envelopes, HTTP control responses, штатные measurement outcomes и уже типизированные отказы. TypeScript inventory всё ещё165 handlers. Новые .tmp/wp0-domain-*-current.json сохраняют данные. В уведомлениях подтверждены returned raw string errors, catch fallback enabled:true и UI callbacks, проглатывающие reset failure/open-settings rejection. Следующий участок ограничен WP-0 error boundary; частичный reset report нельзя потерять при типизации.


## 20.10.2026 — WP-0: ошибки уведомлений и частичный сброс Windows-блокировки

Подтверждены нарушения AT-00-001/004/005/008 (F-074/F-138/F-143): check-os-state скрывал сбой чтения реестра за enabled:true; reset/open-settings возвращали сырые строки внутри успешного guard envelope; UI игнорировал partial report и отклонение открытия настроек. Новые production-handler/guard/source regressions сначала36 failed/5 passed,0.33s,exit1 (.tmp/wp0-notification-domain-red.log); UI regressions5 failed/6 passed,4.44s,exit1 (.tmp/wp0-notification-domain-ui-red.log). Первый main-only red до добавления source tests:27 failed/4 passed; неудачная Python-правка пути не изменила source test и затем была повторена с правильным cwd.

Теперь unexpected faults проходят через общий canonical envelope; NotificationResetReport сохраняет cleared AUMIDs и типизированные per-AUMID errors без command output. Ошибки patch имеют validation. Истинное отсутствие значения —default allowed; permission/timeout/unknown/malformed REG_DWORD больше не маскируются. Только Enabled=0 удаляется через reg.exe execFile с отдельными аргументами; explicit Enabled=1 и другие значения не удаляются. Отказы сохраняют локальный Error diagnostic через production redactor. Инвалидация cache не позволяет старому in-flight read снова заполнить cache. На реальной русской Windows read-only query заведомо отсутствующего HKCU fixture key подтвердил OEM866 stderr, который UTF8 повреждал; чтение buffer и распознавание UTF8/OEM866/1251 добавлены с реальной byte regression. Реестр пользователя не менялся.

NotificationSettings показывает reset/open failures и количество cleared/failed с canonical ru/en причиной; cancellation quiet. Повторный reset блокируется, устаревший OS ответ не заменяет новый, unmount запрещает поздние rechecks/state updates и очищает таймер. Регрессии покрывают оба unmount сценария (pending reset и уже назначенный poll). UI проверен настоящим Chromium через playwright-cli на изолированном harness production component+styles+i18n с controlled IPC: ru/en partial text, отказ Open Settings, screenshots dark/ru,dark/en,light/ru визуально просмотрены (.tmp/notification-visual/). Первая навигация до запуска loopback-сервера дала ERR_CONNECTION_REFUSED; повтор после старта успешен. Передача URL с & через Windows npx.cmd отрезала lang; locale затем проверена отдельным URL. Формальный design gate отсутствует в проекте и не заявляется.

Адресно npm.cmd test -- src/main/notificationResultContract.test.ts src/main/notificationsReset.test.ts src/main/notificationsGating.test.ts src/main/notificationPrefs.test.ts src/renderer/components/NotificationSettings.test.tsx src/main/ipcChannelContract.test.ts —72 passed,6 files,2.17s,exit0 (.tmp/wp0-notification-domain-targeted-final.log). Во время разработки typecheck выявил имя ipcError, затенённое UI state (исправлено alias), затем Buffer|string в test Error constructor (исправлено String); эти запуски не были PASS. npm.cmd run build после исправлений —exit0,165 channels/0 public any (.tmp/wp0-notification-domain-build.log). node scripts/test-electron-runtime.mjs —8 *_PASS,exit0 (.tmp/wp0-notification-domain-native.log), в том числе новый NOTIFICATIONS_NATIVE_PASS: настоящий Electron44.4.3, production source/handlers/guard/preload/DPAPI store,7 categories×2 locales, partial clear, retry/default, unchanged preferences и rejection Open Settings. Только reg execution/Settings launch управляемые; это не натурная доставка Windows toast и не полная L3-приёмка. Traceability AC927/927,F210/210 и git diff --check —exit0.

Полный npm.cmd test -- --maxWorkers=1 выполняется; его результат ещё не объявлен. Source дерево во время полного прогона не менялось; тип test Error(message) был исправлен на Error(String(message)) после запуска, поэтому после этого full нужен финальный прогон с неизменным деревом. Qodo/CI нового PR ещё не запускались. WP-0 остаётся активным; WP-2 не начат, остальные domain partial results и финальная AT-матрица впереди. Нормативные docs/ не изменены.


Финальный полный прогон на неизменном source/test tree: npm.cmd test -- --maxWorkers=1 —5258 passed/5 skipped/0 failed,310 files passed/2 skipped,274.28s,exit0 (.tmp/wp0-notification-domain-full-final.log,EXIT_CODE=0). Первый full также5258/5 skipped/0 failed,273.68s (.tmp/wp0-notification-domain-full.log); повтор после type-only fixture correction подтвердил окончательное дерево. Финальный targeted72/72, build/typecheck165 channels/0 public any,8 Electron *_PASS,traceability AC927/927 F210/210,diff check —exit0. Browser и loopback harness server завершены. Готово к commit/push/PR; для перехода дальше нужны completed automatic Qodo и зелёный CI на exact head.


PR #102 создан и attached: initial head58360032fb02629c32ca89fcce29ca84019c1268, CI39401779024. Для освобождения лимита100 attachments убрана только карточка давно merged PR #2; GitHub PR не менялся. Qodo1562727 completed exact initial head дал2 remediation_recommended: locale-dependent missing-registry detection и задержка/утрата OS delivery при persistent read failure. Revix сообщил free-quota-reached до21.10 00:00UTC, полного review нет, отсутствие не approval. Один read-only Qodo status запрос вернул transient fetch failed, следующий успешно прочитал completed review; attribution вручную не менялся.

Оба замечания подтверждены2 failed/14 passed,0.21s,exit1 (.tmp/wp0-notification-domain-qodo-red.log). Решение по первому заменяет прежний reg.exe текстовый парсер целиком: notificationRegistry использует Microsoft.Win32.Registry через bounded PowerShell, типизированные JSON receipts missing/value/error и числовой HRESULT/тип .NET исключения в локальной диагностике. Base64 AUMID не интерполируется как PowerShell source. Язык Windows и OEM decoding больше не участвуют. Reset за одно открытие конкретного key проверяет DWORD и удаляет только Enabled=0, сохраняя partial report и остальные настройки. Прежние OEM tests/green относятся к initial реализации и не являются доказательством нового helper.

По второму: strict Settings API сохраняет typed error, не выдаёт enabled. Notify не ждёт read-only probe: при unknown пробует системный toast и in-app fallback; доказанный blocked использует только fallback. Одновременные probes coalesced; negative cache хранит ошибку30s без ложного enabled и без повторного spawn/warnings на каждом notification. Явный check из Settings делает force read; reset инвалидирует cache с revision fence. Tests подтверждают pending query, OS show сразу, fallback, один spawn/diagnostic при persistent failure, strict rejection, fresh retry, сохранение block, parsed malformed receipts и encoded AUMID. Gating tests теперь детерминированно mock Windows registry и не запускают реальный процесс фоном.

Final targeted npm.cmd test -- src/main/notificationsReset.test.ts src/main/notificationResultContract.test.ts src/main/notificationsGating.test.ts src/main/notificationPrefs.test.ts src/renderer/components/NotificationSettings.test.tsx src/main/ipcChannelContract.test.ts —75 passed,6 files,2.11s,exit0 (.tmp/wp0-notification-domain-qodo-targeted-final.log). Новый mock сначала вызвал TS7053 при Symbol index, исправлен Object.defineProperty; финальный npm.cmd run build —exit0,165 channels/0 public any (.tmp/wp0-notification-domain-qodo-build.log). node scripts/test-electron-runtime.mjs —8 *_PASS,exit0 (.tmp/wp0-notification-domain-qodo-native.log): production .NET helper дополнительно реально прочитал заведомо отсутствующий изолированный AUMID на этой Windows (actualMissingRegistryRead:true), не меняя registry; error/partial matrix остаётся controlled boundary. Traceability927/927,210/210,diff check exit0. Полный набор после Qodo fixes выполняется заново; новые exact-head remote gates ещё нужны.


Final local после Qodo fixes: npm.cmd test -- --maxWorkers=1 —5261 passed/5 skipped/0 failed,310 files passed/2 skipped,276.35s,exit0 (.tmp/wp0-notification-domain-qodo-full.log,EXIT_CODE=0). Source и unit-test tree во время этого full не менялись. Build/typecheck165 IPC channels/0 public any, targeted75/75,8 native *_PASS,traceability/diff check —exit0. Initial CI39401779024 также success на5836003, но не заменяет новый CI после исправлений. Исправления готовы к commit/push; нужен повторный automatic Qodo на окончательном SHA. WP-0 в работе, WP-2 не начат.


## 20.10.2026 — принят PR #102; WP-0: честная очистка диагностики

PR #102 слит: exact final head b9394b29207f9fef179744e20c03c13084c29e89, Qodo1562926 completed, оба initial findings автоматически implemented, новых нет. CI39403368777 success: Windows/Rust/site. Merge/main c14cd759633e53a4bf7c30a33c71341b83dd487c; reviewed и merge trees совпадают:35771beb4bf62d6c43d578edf5e8c5b7ca86380b. Revix по квоте не выполнил полного review до21.10 00:00UTC, отсутствие не approval. Attribution вручную не менялся. Первые git rev-parse без кавычек вокруг ^{tree} PowerShell разобрал как scriptblock, проверки завершились ошибкой; повтор с кавычками дал одинаковые trees.

Следующий bounded slice AT-00-001/004/005/008, cross-regression AT-08-005; F-074/F-138/F-143: clear-diagnostic-artifacts подавлял rm failures; clearAppLog отдельно подавлял отказы engine/previous files; open-snapshots-folder сериализовал raw shell exception, open-tun-log-folder/open-log-folder игнорировали nonempty shell receipt. Четыре production handlers перенесены без изменения поведения в diagnosticMaintenance; новые guard regressions дали22 failed/8 passed,344ms (.tmp/wp0-maintenance-red.log). Logger regression на async EACCES дала1 failed/3 passed,293ms (.tmp/wp0-maintenance-logger-red.log); первый вариант mock ошибочно бросал синхронно, затем исправлена только async граница. UI первый запуск5 setup failures из-за неверного имени кнопки; после использования существующей locale string meaningful red4 failed/1 passed,1.56s (.tmp/wp0-maintenance-ui-red.log).

DiagnosticClearReport теперь сохраняет подтверждённые clears и canonical per-artifact IpcError, без absolute paths/raw error strings. ENOENT у optional previous logs означает отсутствие файла, остальные ошибки не скрываются. Capture running/cleanupPending даёт conflict до удаления; untrusted namespace permission до эффектов. Если log preflight падает после directory clears, эти clears сохраняются. Original errors пишутся через production redactor локально после очистки app.log, чтобы вызов не стёр собственную диагностику. Open folder failures проходят общий outer envelope; success contracts сохранены. Logs вызывает единственный artifact cleanup, ждёт все3 independent requests через allSettled, сохраняет failed history, показывает ru/en partial counts и canonical причины, блокирует duplicate click и поздние effects после unmount/старого read. Нормативные docs/ не менялись. Остальные maintenance/runtime/partial network results ещё не исправлялись; WP-0 в работе, WP-2 не начат.

Адресно npm.cmd test -- src/main/diagnosticMaintenance.test.ts src/main/appLoggerCleanup.test.ts src/main/mainIpcRegression.test.ts src/main/ipcChannelContract.test.ts src/renderer/pages/Logs.cleanup.test.tsx src/renderer/pages/Logs.render.test.tsx src/renderer/LogsSource.test.ts src/renderer/components/DiagnosticsCard.test.tsx —89 passed,8 files,3.20s,exit0 (.tmp/wp0-maintenance-targeted-final.log). npm.cmd run build —exit0,165 channels/0 public any (.tmp/wp0-maintenance-build-final.log). node scripts/test-electron-runtime.mjs —9 *_PASS,exit0 (.tmp/wp0-maintenance-native-final.log): новый MAINTENANCE_NATIVE_PASS использует настоящие production handlers/logger/guard/preload/sandbox,7 categories×2 locales и реальные файлы только в выделенной .tmp run directory. Controlled capture/ACL/path/shell и syscall faults; это не натурная ACL или сетевая L3-приёмка. Проверены оставшиеся после частичного отказа файлы, подтверждённые clears, сохранение failure evidence в app.log после clear, retry. Первый native assertion ожидал исходный xray.log, уже очищенный ранее успешным log step в category matrix; fixture пересоздаёт отдельное evidence перед partial сценарием. Повтор прошёл.

UI partial toast визуально проверен Chromium/playwright-cli: ru/dark,en/dark,ru/light, screenshots просмотрены в .tmp/maintenance-visual. Production Logs/MacToast/styles/i18n с controlled IPC. Первое открытие до CLI bundling дало404 bundle.js; после сборки reload успешен. Node REPL import esbuild CJS дал module is not defined, CLI сборка успешна. Существующий MacToast выдаёт React warning о ref/PopChild; он не менялся в этом slice. Design accuracy/state/responsive scripts отсутствуют в проекте, формальный gate PASS не заявляется. Browser и loopback server закрыты. Traceability AC927/927,F210/210 и git diff --check exit0. Полный npm.cmd test -- --maxWorkers=1 ещё выполняется на неизменном source/test tree; результат не объявлен.


Final local verification: npm.cmd test -- --maxWorkers=1 —5305 passed/5 skipped/0 failed,312 files passed/2 skipped,263.66s,exit0 (.tmp/wp0-maintenance-full.log,EXIT_CODE=0). Source и unit-test tree во время full не менялись. Final build/typecheck165 channels/0 public any,89 targeted tests,9 native *_PASS,traceability/diff check —exit0. Для следующего PR освобождена одна из100 карточек: убрана только attachment давно merged PR #3 (merged19.06.2026), GitHub PR не менялся. Следующий кодовый участок начнётся только после completed automatic Qodo и exact-head CI.


## 20.10.2026 — PR #103: исправления по automatic Qodo

Qodo1563327 completed на initial5e3a53f89d259a619ce434fbf42b5166829519dd подтвердил4 remediation_recommended: rejected cleanup оставлял logger queue сломанной; failed history clear отзывал pending read без повторного чтения; ENOENT завышал число удалений; вложенный Error терял non-enumerable message/stack. Все4 проверены и исправлены; attribution вручную не менялся. Revix сообщил free-quota-reached до21.10 00:00UTC; полного review нет, отсутствие не approval. Initial CI39406660402 не заменяет будущий exact-head CI.

Caller по-прежнему получает reject cleanup, но shared log lane восстанавливается и сохраняет следующий diagnostic event. Watcher stop включён в try/finally. Current files очищаются truncate, previous unlink; ENOENT не создаёт новые файлы и попадает в отдельный absent, успешные syscall в cleared. Directory rm без force также различает absence. Partial report сохраняет cleared/absent/per-artifact errors. Ошибки передаются appLogger как top-level Error после очистки, production redactor сохраняет санитизированные message/stack. Logs после failed history clear повторно читает историю и статистику с текущими фильтрами, отвергая старые ответы. RU/EN partial toast отдельно показывает cleared/absent/failed.

Meaningful red: npm.cmd test -- src/main/appLoggerCleanup.test.ts src/renderer/pages/Logs.cleanup.test.tsx —4 failed/10 passed,2.65s,exit1 (.tmp/wp0-maintenance-qodo-red.log). После исправления первоначальный targeted имел1 failed/51 passed из-за устаревшего expected absent для отсутствующего forensic namespace; expectation исправлен. Final targeted: npm.cmd test -- src/main/diagnosticMaintenance.test.ts src/main/appLoggerCleanup.test.ts src/main/mainIpcRegression.test.ts src/main/ipcChannelContract.test.ts src/renderer/pages/Logs.cleanup.test.tsx src/renderer/pages/Logs.render.test.tsx src/renderer/LogsSource.test.ts src/renderer/components/DiagnosticsCard.test.tsx —95 passed,8 files,3.63s,exit0 (.tmp/wp0-maintenance-qodo-targeted-final.log).

Final npm.cmd test -- --maxWorkers=1 —5311 passed/5 skipped/0 failed,312 files passed/2 skipped,269.36s,exit0 (.tmp/wp0-maintenance-qodo-full.log,EXIT_CODE=0). Source/unit-test tree не менялся во время full. npm.cmd run build —exit0,165 IPC channels/0 public any (.tmp/wp0-maintenance-qodo-build.log). node scripts/test-electron-runtime.mjs —все9 *_PASS,exit0 (.tmp/wp0-maintenance-qodo-native-final.log). Native дополнительно проверил запись после rejected preflight, absence totals, сохранённые файлы и настоящий redactor message/stack без user path. Первый correction assertion требовал путь maintenance.cjs в stack, который production redactor правильно удаляет; заменён на наличие stack frames и отсутствие user path, redaction не ослаблена. Capture/ACL/shell/fault boundaries управляемые, настоящая сетевая/ACL L3-приёмка не заявляется.

Final partial toast визуально просмотрен в Chromium en/dark и ru/light (.tmp/maintenance-visual/*-partial-final.png); initial ru/dark также проверен. Существующий React warning MacToast ref/PopChild остаётся; формальные accuracy/state/responsive gates отсутствуют, PASS не заявляется. Browser закрыт, loopback server остановлен. python docs/04-приёмочные-тесты/traceability/check-coverage.py —AC927/927,F210/210,exit0; git diff --check —exit0. Оба журнала актуализированы. Исправления готовы к commit/push; до следующего кодового участка нужны completed automatic Qodo и CI на окончательном SHA. WP-0 остаётся активным, WP-2 не начат; нормативные docs/ не изменялись.


Дополнительное собственное review PR #103 подтвердило гонку: filter read, начатый во время успешной очистки, имел уже новый epoch и мог вернуть удалённые строки после success. Regression npm.cmd test -- src/renderer/pages/Logs.cleanup.test.tsx —1 failed/7 passed,1.80s,exit1 (.tmp/wp0-maintenance-during-clear-red.log). Завершение clear теперь отзывает также reads, начатые во время удаления; failed clear по-прежнему запускает fresh reload с текущим filter. Final targeted те же8 suites —96 passed,3.31s,exit0 (.tmp/wp0-maintenance-during-clear-targeted.log). Final npm.cmd test -- --maxWorkers=1 —5312 passed/5 skipped/0 failed,312 files passed/2 skipped,269.09s,exit0 (.tmp/wp0-maintenance-during-clear-full.log,EXIT_CODE=0), неизменный source/test tree. npm.cmd run build —exit0 (.tmp/wp0-maintenance-during-clear-build.log); node scripts/test-electron-runtime.mjs —9 *_PASS,exit0 (.tmp/wp0-maintenance-during-clear-native.log). git diff --check exit0. Визуальный вид не менялся. Qodo1563526 completed на17c2efe47eefb7a5e0ac0c162a8ec2588ab315fd автоматически implemented все4 initial findings, новых нет; это не заменяет новое review после дополнительной правки. Следующий кодовый участок всё ещё ожидает final exact-head Qodo/CI.


CI39409150654 на2fdc7b5a04907fe9e0aae953527775f86395211c завершился failure: единственный splitTunnelDiscovery.test.ts / finds sibling products under the same vendor dir превысил outer5000ms;5312 passed/4 skipped/1 failed,400.31s (.tmp/wp0-maintenance-final-ci-failed.log). Обнаружена ошибка изоляции fixture: виртуальный fs не ограничивал PowerShell registry queries, и suite запускал три реальных host registry scan перед проверкой Programs tree. Child-process boundary этого unit теперь mock empty registry response; проверяется3 calls к powershell.exe, реальные directory/junction/helper assertions сохранены, timeout не повышен. Production-код не менялся. npm.cmd test -- src/main/splitTunnelDiscovery.test.ts src/main/splitTunnelProcess.test.ts src/main/splitTunnelPath.test.ts —36 passed,3 files,509ms,exit0 (.tmp/wp0-maintenance-ci-fixture-targeted.log). npm.cmd run typecheck —exit0,165 channels/0 public any (.tmp/wp0-maintenance-ci-fixture-typecheck.log); traceability AC927/927,F210/210 и diff check exit0. Full после fixture correction выполняется, результат ещё не объявлен. Qodo1563638 completed на2fdc7b5 без открытых findings; CI39408233088 предыдущего17c2efe автоматически cancelled после нового push. Оба предыдущих remote результата не заменяют проверки следующего commit.


Final full после изоляции registry boundary: npm.cmd test -- --maxWorkers=1 —5312 passed/5 skipped/0 failed,312 files passed/2 skipped,269.50s,exit0 (.tmp/wp0-maintenance-ci-fixture-full.log,EXIT_CODE=0). Source/unit-test tree не менялся во время прогона. Последнее изменение затрагивает только unit fixture; build/native9 PASS для production tree сохраняют силу, новый CI повторит их на окончательном SHA. Для перехода дальше по-прежнему нужны новый automatic Qodo и успешный exact-head CI.


Qodo1563861 completed на851144cfc05920277bba0ab175c382b14c344f0e сохранил4 initial findings implemented и дал1 maintainability remediation_recommended: новый assertion числа registry calls не доказывал состав hives. Усиление проверяет decoded UTF16LE EncodedCommand и точное множество/порядок трёх Uninstall roots: HKLM native, HKLM WOW6432Node, HKCU. Изменение только в unit fixture; timeout и production discovery прежние. npm.cmd test -- src/main/splitTunnelDiscovery.test.ts src/main/splitTunnelProcess.test.ts src/main/splitTunnelPath.test.ts —36 passed,3 files,478ms,exit0 (.tmp/wp0-maintenance-hive-targeted.log). npm.cmd run typecheck —exit0,165 channels/0 public any (.tmp/wp0-maintenance-hive-typecheck.log). Attribution вручную не менялся. Full выполняется на неизменном source/unit-test tree; после push потребуется новый automatic Qodo и CI точного head.


Окончательный full после hive assertion: npm.cmd test -- --maxWorkers=1 —5312 passed/5 skipped/0 failed,312 files passed/2 skipped,272.80s,exit0 (.tmp/wp0-maintenance-hive-full.log,EXIT_CODE=0). Unit/source tree во время full не менялся. Targeted36/36, typecheck165 channels/0 public any, traceability927/927 и210/210, diff check —exit0. Новые remote gates требуются после commit/push. WP-0 не завершён, WP-2 не начат.


## 20.10.2026 — PR #103 принят; типизированные отказы runtime/maintenance (WP-0)

PR #103 слит: 3554beb2819bec6b96e2fc15f2e3dfc6c235af17; reviewed head 6923f7b30c25a983868ade4b96c313b2173d2c77. Деревья reviewed/merge совпадают: 6144e1314e51146cec6cb6699c1fec2b988fb259. Exact-head CI39411986600 success во всех трёх jobs; automatic Qodo1563978 completed, все5 findings автоматически implemented, новых нет. Revix на initial5e3a53f —free-quota-reached до21.10 00:00UTC, полного review нет; это не approval. Attribution вручную не менялся.

AT-00-001/004/005/008; F-074/F-138/F-143: active-TUN guards baseline/firewall/adapter/runtime возвращали success либо нетипизированный отказ. Теперь success:false + canonical conflict, без мутаций; firewall health сохранён. Runtime failures больше не содержат raw exception text или выдуманные нулевые counts. Подтверждённый partial receipt сохранён с success:false; внутренний lifecycle owner всё ещё отклоняет partial и отдельно доказывает exit. Stop dispatch не повторяется после timeout/exited/protocol/rejected/busy/closed; fallback только при настоящем pre-dispatch RecoveryWorkerError unavailable. Worker timeout классифицирован как timeout, busy/closed —conflict; fallback EACCES/EPERM —permission, ETIMEDOUT и настоящий execFile killed/SIGTERM/null-code —timeout; maxBuffer не считается deadline. Неизменны ownership, строгая валидация keys/counters/names, native deadlines и fresh exit proof. Принятый scope общего WP-0 охватывает эти исправления; норматив docs/ не меняется.

Red: npm.cmd test -- src/main/ownedRuntimeStop.test.ts src/main/runtimeMaintenance.test.ts —38 failed/12 passed,730ms,exit1 (.tmp/wp0-runtime-maintenance-red.log). First targeted7 suites —290/290,18.50s. Typecheck сначала выявил widening literal success в новой union; исправлено false as const. Final targeted: npm.cmd test -- src/main/ownedRuntimeStop.test.ts src/main/runtimeMaintenance.test.ts src/main/ownedRuntimeStatus.test.ts src/main/tunRuntimeExitProof.test.ts src/main/lifecycleCleanup.test.ts src/main/mainIpcRegression.test.ts src/main/ipcChannelContract.test.ts —316 passed,7 files,20.35s,exit0 (.tmp/wp0-runtime-maintenance-targeted.log). Реальные AST-extracted main handlers + handleLogged исполняются через production trusted boundary:4 guards без эффектов,7 категорий на каждом канале, canonical payload без raw path/stack, общий correlation id, health failure, confirmed empty и partial receipts. Native/network boundaries в этих регрессиях управляемые; L3 не заявляется.

Final npm.cmd test -- --maxWorkers=1 —5360 passed/5 skipped/0 failed,313 files passed/2 skipped,272.70s,exit0 (.tmp/wp0-runtime-maintenance-full.log,EXIT_CODE=0), source/unit-test tree frozen. npm.cmd run typecheck —165 channels/0 public any,exit0 (.tmp/wp0-runtime-maintenance-typecheck.log). npm.cmd run build —exit0 (.tmp/wp0-runtime-maintenance-build.log); node scripts/test-electron-runtime.mjs —9 *_PASS,exit0 (.tmp/wp0-runtime-maintenance-native.log). python docs/04-приёмочные-тесты/traceability/check-coverage.py —AC927/927,F210/210,exit0; git diff --check —exit0. Traceability не заменяет исполнение AT. До следующего кодового участка обязательны automatic completed Qodo и successful CI на окончательном SHA после push. WP-0 остаётся активным: остаток —network/firewall/browser domain reports и final AT matrix; WP-2 не начат.


Automatic Qodo1564222 completed на09bcab4154ed3021f3dbbefb80da4883243ea1fd:1 Correctness remediation_recommended и1 Observability informational. Оба подтверждены; attribution не менялся. Active-TUN typed refusal попадал в fail раньше blocked; partial runtime receipt скрывал counters за generic message. Red: npm.cmd test -- src/main/runtimeMaintenance.test.ts src/renderer/pages/Maintenance.requestLifetime.test.tsx —5 failed/62 passed,1.55s,exit1 (.tmp/wp0-runtime-maintenance-qodo-red.log). Теперь blocked проверяется прежде success:false, даёт warn и итоговый warning toast с честным summary; настоящий failure остаётся fail. Частичная остановка показывает killed/candidates и просьбу повторить, сохраняя canonical error и полный receipt.

Targeted8 suites —340 passed,21.33s,exit0 (.tmp/wp0-runtime-maintenance-qodo-targeted.log). Первый typecheck выявил неподдерживаемый exact в новом ByRoleOptions; selector заменён на anchored regex. Final npm.cmd run build включает typecheck165 channels/0 public any —exit0 (.tmp/wp0-runtime-maintenance-qodo-build.log); node scripts/test-electron-runtime.mjs —9 *_PASS,exit0 (.tmp/wp0-runtime-maintenance-qodo-native.log). Final npm.cmd test -- --maxWorkers=1 —5366 passed/5 skipped/0 failed,313 files passed/2 skipped,282.42s,exit0 (.tmp/wp0-runtime-maintenance-qodo-full.log,EXIT_CODE=0); source/unit-test tree frozen. Coverage AC927/927,F210/210 и diff check —exit0. Initial CI39413914747 success во всех3 jobs на09bcab4; это не заменяет новый exact-head CI после fix. Revix для09bcab4 подтвердил free-quota-reached до21.10 00:00UTC; полного review нет.

Playwright Chromium: изменённый control Починить пройден с confirm, dark warning и light partial screenshot визуально просмотрены (output/playwright/runtime104-dark-warning-final.png, runtime104-light-partial-final.png). Partial text1 из2 виден красным, blocked detail жёлтый. Реальная ширина/scrollWidth:280/280,320/320,414/414 —без horizontal overflow для light partial. Первоначальный temporary harness выбирал chunk CSS вместо main index CSS; исправлен до финального осмотра. Прежний React MacToast/PopChild ref warning остаётся. node scripts/accuracy_report.mjs, node scripts/verify_states.mjs src/renderer/pages/Maintenance.tsx, node scripts/verify_responsive.mjs src/renderer/pages/Maintenance.tsx —MODULE_NOT_FOUND,exit1:формальных UI gates в проекте нет, их PASS/N/N не заявляется. Browser закрыт, loopback server остановлен. WP-0 остаётся активным; до следующего участка нужны final automatic Qodo и successful CI.


Final-head CI39415070767 на64517b85aeeaecea7ce168f6d8015fabcbd419cd failed:1 failed/5366 passed/4 skipped,339.60s. Единственный systemSnapshot.test.ts native oversized readonly collection завершился generic Native diagnostic process failed на30.261s (deadline30000); лог .tmp/wp0-runtime-maintenance-qodo-ci-failed.log. Последующие native CI steps skipped. Automatic Qodo1564358 completed на64517b8, оба findings автоматически implemented, новых нет; attribution не менялся.

Локальный неизменённый snapshot suite: npm.cmd test -- src/main/systemSnapshot.test.ts —12/12,7.21s,exit0 (.tmp/wp0-runtime-maintenance-snapshot-before.log),не опровергает remote failure. Подтверждена зависимость native transport fixture от настоящих host CIM/network cmdlets: проверка длинного direct argv/encoding не требует инвентаризации CI-сети. Только в fixture реальные PowerShell-функции задают controlled readonly cmdlet responses; исполняется исходный production script в настоящем powershell.exe с прежним30000ms. Проверяются encoded argv>8191, порядок всех14секций и payload markers, оба empty proxy markers, реальный elevated bool, Unicode round-trip. Отдельный100ms native process timeout остаётся настоящим; production collector/deadline, scripts и cancellation не меняются. Это проверка native transport/script, а не L3 host-state acceptance.

Final targeted: npm.cmd test -- src/main/systemSnapshot.test.ts src/main/systemSnapshotLifetime.test.ts —15 passed,2 files,1.28s,exit0 (.tmp/wp0-runtime-maintenance-snapshot-targeted-final.log). Первый targeted command также содержал несуществующий systemSnapshotCancellation.test.ts filter; реально были12 tests/1suite,1.26s; исправленный command выше покрывает настоящий Lifetime suite. npm.cmd run typecheck —165 channels/0 public any,exit0 (.tmp/wp0-runtime-maintenance-snapshot-typecheck.log). Final npm.cmd test -- --maxWorkers=1 —5366 passed/5 skipped/0 failed,313 files passed/2 skipped,274.99s,exit0 (.tmp/wp0-runtime-maintenance-snapshot-full.log,EXIT_CODE=0), source/unit-test tree frozen. Coverage AC927/927,F210/210 и diff check exit0. Build/native9 PASS текущего production tree записаны выше; после commit/push требуются новые automatic Qodo/CI exact SHA. WP-0 остаётся активным, WP-2 не начат.


## WP-0: типизированный сетевой rollback (20.10.2026)

Предыдущий PR #104 слит 20.10 в 11:52:33 UTC: reviewed head aadfcd678ef56302fdaa036d8ccd12ec41b4eb05, merge 29f83079729a2284e62a7ca76a1099f1d962f000, tree44bf2b1fc508e52f240a2098a6029562d06b5ba1. Повторно проверены successful CI39417029156 на exact head и completed automatic Qodo1564594 на том же SHA: оба findings automatically implemented, новых нет. Attribution не менялся. Revix quota exhausted до21.10 00:00 UTC /03:00 МСК; отсутствие review не approval.

Текущий участок: baseline возвращает canonical error вместо raw native/storage exception, сохраняет независимо восстановленные записи и compensation receipt при apply failure; path снимка исключён из публичного apply result. Native PowerShell step permission определяется CategoryInfo, без парсинга локализованной строки. Adapter rollback и DNS retry передают success:false/error и подтверждённых соседей при partial failure; trusted absence остаётся skipped:true, success:true. Неизвестный native исход не получает придуманных restored counts. Подтверждённые partial counts видны в сообщении Maintenance; ошибка удаления manifest сохраняет receipt. Ownership, валидаторы, независимое восстановление и запрет replay потерянного helper reply сохранены.

Адресно: npm.cmd test -- src/main/systemNetwork.test.ts src/main/physicalAdapterLifecycle.test.ts src/main/physicalAdapterLockdownSource.test.ts src/main/runtimeMaintenance.test.ts src/renderer/pages/Maintenance.requestLifetime.test.tsx --maxWorkers=1 —220 passed/1 skipped/0 failed,5 suites,9.37s (.tmp/wp0-network-rollback-targeted-final.log). Включены настоящий PowerShell permission-category producer, retry wrapper, partial neighbors, trusted absence, cleanup denial и реальные renderer failure/skip summaries. Это L1/L2 и изолированный native script proof; полный L3 этим не заявляется. После небольшого уточнения текста partial counts запущен полный набор; окончательные результаты будут дописаны. Нормативные docs/ не изменены. WP-0 активен, WP-2 не начат.


Полный первый прогон npm.cmd test -- --maxWorkers=1 —1 failed/5400 passed/5 skipped,312 files passed/1 failed/2 skipped,280.70s,exit1 (.tmp/wp0-network-rollback-full.log). Единственная ошибка —старое exact-equality expectation trusted absence в lifecycleCleanup.test.ts не учитывало новое success:true. Обновлена только ожидаемая no-op форма; untrusted read по-прежнему обязан reject.

В той же цепочке подтверждён пропущенный active-TUN guard на network:repair-orphaned-dns: handler напрямую вызывал тот же adapter rollback. Теперь возвращается canonical conflict/success:false/blocked/skipped без чтения и мутаций; актуальная main-boundary matrix проверяет5 handlers ×7категорий и5 active refusals, renderer показывает безопасный отказ как warn. Guard проверяет running; атомарная сериализация с connecting/drain этим участком не заявляется. После исправлений npm.cmd test -- src/main/systemNetwork.test.ts src/main/physicalAdapterLifecycle.test.ts src/main/physicalAdapterLockdownSource.test.ts src/main/runtimeMaintenance.test.ts src/main/lifecycleCleanup.test.ts src/renderer/pages/Maintenance.requestLifetime.test.tsx --maxWorkers=1 —414 passed/1 skipped/0 failed,6 suites,22.16s,exit0 (.tmp/wp0-network-rollback-targeted-guards.log). Запущен окончательный full на неизменном source/test tree.


Окончательные проверки: npm.cmd test -- --maxWorkers=1 —5402 passed/5 skipped/0 failed,313 files passed/2 skipped,264.75s,exit0 (.tmp/wp0-network-rollback-full-final.log,EXIT_CODE=0). npm.cmd run build (включая npm run typecheck:165 channels,0 public any) —exit0 (.tmp/wp0-network-rollback-build-final.log). node scripts/test-electron-runtime.mjs —9 *_PASS,exit0 (.tmp/wp0-network-rollback-native.log). python docs/04-приёмочные-тесты/traceability/check-coverage.py —AC927/927,F210/210,exit0; git diff --check —exit0. Изолированные native fixtures не заменяют L3; нормативные docs/ не изменены. Следующий кодовый участок —только после completed automatic Qodo и successful CI окончательного SHA.


PR #105 создан и attached, initial head102f3c6f4ca6b4f0b297804109f37efd823b68a0. CI39420550723 success на initial SHA. Для лимита100 карточек удалена только attachment давно merged PR #5; GitHub PR не менялся. Automatic Qodo1565033 completed на initial SHA дал5 remediation_recommended, все подтверждены и исправляются кодом; attribution не менялся. Revix сообщил quota exhausted до21.10 00:00UTC/03:00МСК, полного review нет.

Qodo regressions до fixes: npm.cmd test -- src/main/systemNetwork.test.ts src/main/physicalAdapterLifecycle.test.ts src/main/admin.test.ts --maxWorkers=1 —9 failed/146 passed/1 skipped,9.17s,exit1 (.tmp/wp0-network-rollback-qodo-before.log). Подтверждены misleading denominator после фильтрации adapter records; precedence validation над реальным permission; потеря sudo-prompt denial; diagnostic unlink после удаления trusted journal; wrapped .NET registry authorization exception с CategoryInfo NotSpecified.

Fixes: при отклонённых записях показывается только число подтверждённых адаптеров и явный пропуск записей, без ложного полного знаменателя; native permission имеет приоритет; PS обходит InnerException и проверяет тип/HRESULT E_ACCESSDENIED; admin producer сохраняет code и преобразует fixed sudo-prompt sentinel User did not grant permission. в EACCES; diagnostic copy удаляется перед trusted manifest, поэтому неудача сохраняет исполнимую retry metadata. Реальная readonly HKCU GUID-subtree fixture воспроизвела метод .NET, затем выполнила очистку только своего ключа.

Собственная проверка дополнительно воспроизвела4 ложных подтверждения native markers (suffix, marker внутри diagnostic, success+error, duplicate):4 failed/62 passed,3.74s,exit1 (.tmp/wp0-network-rollback-markers-before.log). Теперь каждый DNS/IPv6/policy/transition phase требует единственный точный marker; противоречия и дубликаты блокируют retirement manifest. Дополнительные3 DNS/policy/transition regressions включены. Первичный markers-targeted имел1 устаревшее source-text expectation (417 passed/1 failed/1 skipped), заменено проверкой нового parsing call; functional regressions сохранены.

Промежуточный qodo-targeted дал31 failed/401 passed/1 skipped,22.16s,а qodo-build остановлен TS2304:restoredDetail по ошибке вставлен в apply вместо rollback, плюс native fixture не восстанавливала manifest перед повторным вызовом. Обе ошибки исправлены, production safety assertions не ослаблены. Окончательный адресный npm.cmd test -- src/main/systemNetwork.test.ts src/main/physicalAdapterLifecycle.test.ts src/main/physicalAdapterLockdownSource.test.ts src/main/runtimeMaintenance.test.ts src/main/lifecycleCleanup.test.ts src/main/admin.test.ts src/main/adminPowerShellTransport.test.ts src/renderer/pages/Maintenance.requestLifetime.test.tsx --maxWorkers=1 —435 passed/1 skipped/0 failed,8 suites,26.83s,exit0 (.tmp/wp0-network-rollback-qodo-targeted-final.log). npm.cmd run build incl typecheck165/0any exit0; node scripts/test-electron-runtime.mjs —9 *_PASS,exit0; AC927/927,F210/210,diff check exit0. Окончательный full запущен на неизменном source/test tree; после push нужны новые automatic Qodo/CI exact SHA.


После Qodo/self-review fixes финальный npm.cmd test -- --maxWorkers=1 —5414 passed/5 skipped/0 failed,313 files passed/2 skipped,265.06s,exit0 (.tmp/wp0-network-rollback-qodo-full.log,EXIT_CODE=0). Source/test tree неизменен во время полного прогона. Финальные targeted435/1skip, build/typecheck165/0any, native9 PASS, traceability и diff exit0 записаны выше. Готово к follow-up commit/push в #105; старые successful CI и completed Qodo относятся только к102f3c6, требуются новые exact-head gates. WP-0 активен, WP-2 не начат.


## WP-0: типизированные ошибки firewall (20.10.2026)

PR #105 слит 20.10 в12:34:39 UTC: reviewed head8e153e50ffc3c4ff6a087dc5a64872ac20ebb22d, merge85f5636ba9c200531cc89037c5eeeaff11b70ff7, tree905c93566463b68092bc86abe450b94dc67db82f совпадает с reviewed head. CI39422494675 success на окончательном SHA; automatic Qodo1565258 completed, все5 прежних findings автоматически implemented, новых нет. Attribution не менялся. Revix квота исчерпана до21.10 00:00UTC/03:00МСК; полного review нет, отсутствие не approval.

Текущий участок AT-00-004/001/005,F-074/F-138/F-143: firewall возвращает canonical error вместо raw native/storage exception, сохраняет категории независимых rollback failures, native permission через CategoryInfo/InnerException/HRESULT/Win32Error5. Компенсация с ошибкой сохраняет unknown и retry journal, не обещает выполненный откат. Manual disable и confirmed reset сохраняют typed error в shared/TunController API; confirmation guard остаётся обязательным. Ownership, strict recovery, независимость valid records/WFP и правила destructive reset не меняются. Нормативные docs/ не изменены.

Red: npm.cmd test -- src/main/firewallTransactions.test.ts --maxWorkers=1 —15 failed/97 passed/1 skipped,5.12s,exit1 (.tmp/wp0-firewall-red.log). Промежуточные failures сохранены: .tmp/wp0-firewall-first.log (11 failed/101 passed/1 skipped), .tmp/wp0-firewall-second.log (1 failed/111 passed/1 skipped). Изменены ожидания старого raw текста на canonical, native fixtures читают новый failure protocol; helper policy по-прежнему запрещает call operator, поэтому обёртка использует обычный try. Первые5 suites —185 passed/1 skipped,9.10s. Расширенный targeted сначала66 failed/406 passed/1 skipped: новая обвязка ошибочно передавала reset token всем каналам; исправлена arity только в harness. Затем9 suites —475 passed/1 skipped,19.18s,exit0 (.tmp/wp0-firewall-targeted-final2.log), до дополнительного Win32 native case.

Первый build остановлен TS2304:IpcFault import; исправлено. npm.cmd run build включает typecheck165 channels/0 public any,exit0 (.tmp/wp0-firewall-build-final.log); node scripts/test-electron-runtime.mjs —9 *_PASS,exit0 (.tmp/wp0-firewall-native.log). Traceability AC927/927,F210/210 и diff check exit0. Full запущен на неизменном source/test tree. Во время read-only review выявлено требование exact WFP loader prefix; после full будет отдельная регрессия для сохранения verified prelude перед failure wrapper. Окончательная проверка ещё не заявляется. WP-0 активен, WP-2 не начат.


Первый full: npm.cmd test -- --maxWorkers=1 —5465 passed/5 skipped/0 failed,313 files passed/2 skipped,269.15s,exit0 (.tmp/wp0-firewall-full.log,EXIT_CODE=0). После этого отдельная регрессия exact pinned WFP loader воспроизвела ошибку обёртки:1 failed/127 skipped,453ms,exit1 (.tmp/wp0-firewall-wfp-prefix-red.log). Теперь SHA-256-verified loader остаётся в начале WFP script; failure wrapper охватывает только body, политика helper не ослаблена. Production helper validator исполняется с startIfUnavailable:false, без старта native helper, подтверждая отсутствие policy rejection/fallback.

Расширенный targeted3 сначала1 failed/526 passed/1 skipped: избыточная новая проверка prefix отвергала прежний body-only mock, проверяющий явный выбор policy; это требование оставлено реальному helper. Final targeted4: npm.cmd test -- src/main/firewallTransactions.test.ts src/main/firewallKillSwitchValidation.test.ts src/main/firewallManifestSecurity.test.ts src/main/firewallExceptionReadback.test.ts src/main/firewallPolicySelection.test.ts src/main/runtimeMaintenance.test.ts src/main/mainIpcRegression.test.ts src/main/ipcChannelContract.test.ts src/main/lifecycleCleanup.test.ts src/main/elevatedPsHelper.test.ts src/main/wfpIpv6.test.ts --maxWorkers=1 —527 passed/1 skipped,11 suites,19.50s,exit0 (.tmp/wp0-firewall-targeted-final4.log). Реальные PowerShell fixtures проверяют CategoryInfo, wrapped UnauthorizedAccess, Win32Error5, фиксированный WFP conflict sentinel, независимые соседние profile restores и consumption protocol в production runner. Mocked file fallback проверяет permission/timeout и failure marker без replay; post-repair health и startup warning sanitization покрыты. Native fixtures не меняют firewall хоста, полный L3 не заявляется.

Final npm.cmd run build включает typecheck165/0any,exit0 (.tmp/wp0-firewall-build-final3.log). node scripts/test-electron-runtime.mjs —9 *_PASS,exit0 (.tmp/wp0-firewall-native-final.log). Из app первый coverage command ошибочно указывал docs/ вместо ../docs/ (exit2); исправленный python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py —AC927/927,F210/210,exit0. git diff --check exit0. Окончательный full на неизменном source/test tree выполняется; WP-0 активен, WP-2 не начат.


Окончательный full: npm.cmd test -- --maxWorkers=1 —5469 passed/5 skipped/0 failed,313 files passed/2 skipped,264.55s,exit0 (.tmp/wp0-firewall-full-final.log,EXIT_CODE=0). Source/test tree неизменен в полном прогоне. Targeted527/1skip, build/typecheck165/0any, native9 PASS, traceability и diff exit0 записаны выше. Перед следующим кодовым участком требуются automatic completed Qodo и successful CI окончательного SHA после push. Для лимита100 attachments проверено состояние GitHub PR #6:MERGED; при attach нового PR будет удалена только его старая карточка, GitHub PR не меняется. WP-0 активен, WP-2 не начат.


PR #106 создан/attached наf0feefc3100a409dfa9fe8364bb35fa3167d5f73; для лимита100 удалена только карточка merged PR #6. Initial CI39426263707 success. Automatic Qodo1565801 completed наinitial SHA:2 remediation_recommended и1 informational. Все3 подтверждены; attribution не менялся (.tmp/qodo106-initial.json). Revix free-quota-reached до21.10 00:00UTC, полного review нет.

Qodo red: npm.cmd test -- src/main/firewallTransactions.test.ts --maxWorkers=1 —7 failed/125 passed/1 skipped,7.00s,exit1 (.tmp/wp0-firewall-qodo-red.log). В reservation IpcFault сохранены category conflict и статическая actionable подсказка остановить конкурирующий TUN/VPN; наружу не передаётся динамический native текст. Native errors получают bounded structured diagnostics: step/profile/cmdlet/exception type/HRESULT/Win32 code, без exception message/path/stack; parser whitelist и лимит8 records/1024 bytes. Helper transport/exit failures и file failures сохраняют диагностический контекст в redacted appLogger. Rejected manifest records имеют отдельный внутренний fault: corruption больше не обвиняет ввод пользователя, explicit skipped detail и retry сохранены.

Intermediate targeted1 —2 failed/130 passed/1 skipped,7.20s: ожидание WFP output не учитывало новую diagnostic line, а per-step conflict category отличается от aggregate internal; исправлены только expectations. Final npm.cmd test -- src/main/firewallTransactions.test.ts src/main/firewallKillSwitchValidation.test.ts src/main/firewallManifestSecurity.test.ts src/main/firewallExceptionReadback.test.ts src/main/firewallPolicySelection.test.ts src/main/runtimeMaintenance.test.ts src/main/mainIpcRegression.test.ts src/main/ipcChannelContract.test.ts src/main/lifecycleCleanup.test.ts src/main/elevatedPsHelper.test.ts src/main/wfpIpv6.test.ts --maxWorkers=1 —529 passed/1 skipped,11 suites,19.64s,exit0 (.tmp/wp0-firewall-qodo-targeted-final.log). Build/typecheck165/0any exit0 (.tmp/wp0-firewall-qodo-build.log); Electron native9 PASS exit0 (.tmp/wp0-firewall-qodo-native.log); coverage AC927/927,F210/210 и diff check exit0. Full выполняется на неизменном source/test tree. После push нужны новые automatic Qodo/CI final SHA; initial success не заменяет этот gate. WP-0 активен, WP-2 не начат.


Окончательный Qodo-fix full: npm.cmd test -- --maxWorkers=1 —5471 passed/5 skipped/0 failed,313 files passed/2 skipped,263.80s,exit0 (.tmp/wp0-firewall-qodo-full.log,EXIT_CODE=0). Source/test tree неизменен во время прогона. Final targeted529/1skip, build/typecheck165/0any, native9 PASS, traceability и diff exit0 записаны выше. Follow-up готов к commit/push; новые automatic Qodo и CI обязательны на его SHA. WP-0 активен, WP-2 не начат.


## WP-0: типизированные ошибки защиты браузеров (20.10.2026)

PR #106 слит20.10 в13:20:55UTC: reviewed head a96f64c63c93b28886194a4e30c3d60c2cf673f3, merge d2332b4f2c75184e80de02d3b90b9b4abe6498e5; tree3f3c38d2820a99585168eb0fb0e53f40e6c13fb4 совпадает с reviewed head. CI39428320995 success exact SHA. Automatic Qodo1566039 completed: все3 прежних findings автоматически implemented, новых нет, attribution не менялся. Revix подтвердил quota exhausted до21.10 00:00UTC/03:00МСК; полного review нет, отсутствие не approval.

AT-00-001/004/005,F-074/F-138/F-143: returned failures apply/rollback browser hardening получают canonical IpcError; публичные details больше не содержат native exception и абсолютные пути профилей/backup. Redacted appLogger сохраняет exception и контекст шага/key/path в correlation scope. Категории берутся из структурированных error codes/IpcFault; reg.exe exit1 и локализованный текст не считаются доказательством permission. Ошибки необязательных registry paths не превращают verified preference fallback в failure. Partial changed/restartRequired, независимый restore соседних файлов/registry и retained manifest при сбое сохранены. Нет профилей — прежний successful no-op; missing rollback state/non-Windows — typed conflict без эффектов. Нормативные docs/ не изменены.

Red: npm.cmd test -- src/main/browserHardening.test.ts --maxWorkers=1 —29 failed/8 passed,1.12s,exit1 (.tmp/wp0-browser-red.log). После первого fix37/37 passed,1.05s. Расширенный npm.cmd test -- src/main/browserHardening.test.ts src/main/runtimeMaintenance.test.ts src/main/mainIpcRegression.test.ts src/main/ipcChannelContract.test.ts --maxWorkers=1 —147 passed,4 suites,1.47s,exit0 (.tmp/wp0-browser-targeted.log). Actual main registrations/handleLogged/trusted boundary вызывают production browser functions;7 категорий в apply/rollback, registry write/readback/backup faults, partial writes, independent restore и correlation/private diagnostics проверены без изменения browser/registry хоста. npm.cmd run build incl typecheck165 channels/0public any —exit0 (.tmp/wp0-browser-build.log). Coverage AC927/927,F210/210 и git diff --check exit0. Full и Electron smoke выполняются; final SHA требует automatic Qodo/CI до следующего кодового участка. WP-0 активен, WP-2 не начат.


Окончательный full на неизменном source/test tree: npm.cmd test -- --maxWorkers=1 —5509 passed/5 skipped/0 failed,313 files passed/2 skipped,264.91s,exit0 (.tmp/wp0-browser-full.log,EXIT_CODE=0). npm.cmd run build (включая typecheck165/0any) exit0; node scripts/test-electron-runtime.mjs —9 *_PASS,exit0 (.tmp/wp0-browser-native.log); адресные147/147, coverage AC927/927,F210/210 и diff check exit0. Source/tests после этих проверок не менялись. Готово к commit/push и новым automatic Qodo/CI exact SHA. Для лимита100 attachments GitHub PR #7 проверен:CLOSED без merge и его карточка сохранена; PR #8 проверен:MERGED, при attach нового PR удаляется только его старая карточка. WP-0 активен, WP-2 не начат.


PR #107 создан/attached на1652e11a987fc69f7869c797cf748af5fbdf1f2a. Automatic Qodo1566381 completed:3 remediation_recommended —warning noise для штатно отсутствующих registry keys, execFile killed/SIGTERM/null-code timeout receipt и потеря message/stack вложенного Error. Все3 подтверждены; attribution не менялся (.tmp/qodo107-initial.json). Revix снова подтвердил free-quota-reached до21.10 00:00UTC/03:00МСК, полного review нет.

Red: npm.cmd test -- src/main/browserHardening.test.ts --maxWorkers=1 —4 failed/47 passed,1.46s,exit1 (.tmp/wp0-browser-qodo-red.log). Обычные export/initial-query/backup probes теперь debug; обязательный write/readback/restore failure сохраняет warn. Классификация локального reg.exe deadline использует фактический killed:true/signal:SIGTERM/code:null receipt; maxBuffer kill и unconfirmed kill остаются internal. Реальный ограниченный Node child воспроизводит receipt в двух IPC paths, не запускает reg.exe. Nested diagnostic Error явно копирует enumerable name/message/stack перед production logger redaction/bounds.

Первый targeted после fix имел14 failed/142 passed,1.93s: прежние assertions ожидали identity Error вместо диагностического plain object; expectations уточнены на сохранённые name/message/stack. Команда ошибочно включала отсутствующий appLoggerHistory.test.ts filter и реально запустила5 suites; финальный command использует существующий Integrity suite. Final npm.cmd test -- src/main/browserHardening.test.ts src/main/appLoggerRedaction.test.ts src/main/appLoggerIntegrity.test.ts src/main/runtimeMaintenance.test.ts src/main/mainIpcRegression.test.ts src/main/ipcChannelContract.test.ts --maxWorkers=1 —174 passed,6 suites,2.66s,exit0 (.tmp/wp0-browser-qodo-targeted.log). Production diagnostic producer вместе с настоящим appLogger подтверждает traceback location и удаление token/private username из сохранённого JSONL. Coverage AC927/927,F210/210 и diff check exit0. Full/build на неизменном source/test tree выполняются; после push нужны новые automatic Qodo/CI final SHA. WP-0 активен, WP-2 не начат.


Окончательный Qodo-fix full: npm.cmd test -- --maxWorkers=1 —5515 passed/5 skipped/0 failed,313 files passed/2 skipped,272.42s,exit0 (.tmp/wp0-browser-qodo-full.log,EXIT_CODE=0). Source/test tree во время full неизменен. npm.cmd run build incl typecheck165/0any exit0 (.tmp/wp0-browser-qodo-build.log); node scripts/test-electron-runtime.mjs —9 *_PASS,exit0 (.tmp/wp0-browser-qodo-native.log); targeted174/174,coverage и diff exit0 записаны выше. Initial CI39430910322 success относится только к1652e11; для follow-up после push нужны новый CI и completed automatic Qodo exact SHA. WP-0 активен,WP-2 не начат.


Remote CI39432562990 на260edd9 завершился failure: Unit5515 passed/4 skipped/1 failed,474.61s. Единственный failure —serverKeyExportSecurity.test.ts:191 malformed write exception/servers:export-all-proxies-file, testTimeout5000ms (.tmp/pr107-ci-final-failed.log). Native ACL preparation precedes injected file.writeFile failure; соседние реальные file-export cases уже имеют15000ms. Для этого существующего fixture case установлен тот же budget15000ms; production ACL/operation deadlines и assertions не менялись. Это не отсутствие review: automatic Qodo1566585 completed на260edd9, все3 findings автоматически implemented, новых нет.

Локальный focused run начат до budget edit и завершён22/22,17.70s (.tmp/wp0-browser-ci-export-before.log); tests file изменён во время этого запуска, поэтому он не считается final frozen-tree proof и не опровергает remote failure. После budget edit запускаются новый focused и полный набор на неизменном дереве. WP-0 активен, WP-2 не начат.


Первый frozen targeted после budget edit:22/22,19.43s,exit0 (.tmp/wp0-browser-ci-export-final.log). Начатый вслед full остановлен exit1 до завершения; PASS ему не приписывается. Self-review добавил к malformed-write fixture явное подтверждение вызова file.writeFile: generic internal от ACL preflight больше не может незаметно удовлетворить assertion инъекции. Это только test harness/expectation, production не менялся. Новый final targeted/full запущен после этой правки на неизменном source/test tree (.tmp/wp0-browser-ci-export-final2.log,.tmp/wp0-browser-ci-full-final2.log). npm.cmd run typecheck165/0any и coverage AC927/F210 exit0 до дополнительного assertion; финальный typecheck повторится.


Final после CI fixture fix: npm.cmd test -- src/main/serverKeyExportSecurity.test.ts --maxWorkers=1 —22/22,18.27s,exit0 (.tmp/wp0-browser-ci-export-final2.log), затем npm.cmd test -- --maxWorkers=1 —5515 passed/5 skipped/0 failed,313 files passed/2 skipped,270.44s,exit0 (.tmp/wp0-browser-ci-full-final2.log,EXIT_CODE=0). Source/test tree неизменен во время final targeted/full. npm.cmd run typecheck —165 channels/0public any,exit0 (.tmp/wp0-browser-ci-typecheck-final2.log); coverage AC927/927,F210/210 и diff check exit0. Последний production tree уже прошёл build и Electron9 PASS, после него менялся только test fixture. После follow-up push требуются новые automatic Qodo/CI exact SHA; remote failure не скрыт. WP-0 активен, WP-2 не начат.


## WP-0: категории отказов экспорта ключей и истории операций (20.10.2026)

PR #107 слит20.10 в14:08:50UTC: reviewed head516358dd85f8b7c005ff5b1e1d78cf58b66a9c41, merge b27b4a516394be303a6d70344704361e9704c83a; tree3e0243bf900772346dbf5f1fe5a9bc168c29e40d совпал после fetch с reviewed head. CI39435205526 success exact SHA; automatic Qodo1566986 completed, все3 findings implemented, новых нет, attribution не менялся. Revix сообщил quota exhausted до21.10 00:00UTC/03:00МСК; полного review нет, отсутствие не approval.

AT-00-001/004/005,F-074/F-138/F-143: пять actual key-export handlers сохраняют reason/protocol/partial counters и добавляют canonical conflict error при отсутствующем профиле/конфигурации или несовместимом сохранённом outbound. Это состояние сохранённых данных, не ошибка пользовательского аргумента. Native I/O failures уже типизированы через IpcFault и не объявляются новой реализацией. Native consent, quiet dismissal, clipboard ownership, protected write и terminal commit сохраняются. Удалена дублирующая устаревшая декларация proxy-list результата в Servers; используется shared ElectronAPI.

OperationRegistry сохраняет canonical code/category returned failure в истории как error/cancelled, включая synchronous final commit. До исправления commit с returned false ошибочно публиковал success. Категория читается только при совпадении allowlisted code/category; malformed/строковые legacy ошибки получают internal, текст не интерпретируется. Уже committed result не переписывается поздней отменой. Guarded actual handler/structured clone/unwrap проверяет совпадение correlation с историей; отказ не открывает save picker и не пишет файл/clipboard.

Red: npm.cmd test -- src/main/operationRegistry.test.ts src/main/serverKeyExportSecurity.test.ts --maxWorkers=1 —30 failed/102 passed,21.58s,exit1 (.tmp/wp0-key-errors-red.log). После fix та же команда —132/132 passed,19.52s,exit0 (.tmp/wp0-key-errors-targeted.log). npm.cmd run typecheck —165 channels/0 public any,exit0. Последние правки удаляют старую renderer type duplication и добавляют history assertion существующей consent-cancel regression; final full/build запущены после них. Coverage AC927/927,F210/210 и diff check exit0; traceability не означает исполнение AT. WP-0 активен,WP-2 не начат.


Final local: npm.cmd test -- --maxWorkers=1 —5546 passed/5 skipped/0 failed,313 files passed/2 skipped,279.59s,exit0 (.tmp/wp0-key-errors-full.log,EXIT_CODE=0). Source/test tree неизменен во время полного набора. npm.cmd run build incl typecheck165/0public any —exit0 (.tmp/wp0-key-errors-build.log); node scripts/test-electron-runtime.mjs —9 *_PASS,exit0 (.tmp/wp0-key-errors-native.log). Targeted132/132,coverage AC927/927,F210/210 и diff exit0 записаны выше. Final commit/push требует automatic completed Qodo и exact-head CI success перед следующим кодовым участком. WP-0 активен,WP-2 не начат.


## WP-0: категории ошибок подключения и остановки (20.10.2026)

PR #108 слит20.10 в14:28:03UTC: reviewed head88599a2f69fe5950adb3797eaa57133de32d1311, merge08b71737752d064c5fa68926f38f25a595229c0d; tree34982036ff3681ab249bb4e254a646f5242ba007 совпал после fetch с reviewed head. CI39437884080 success exact SHA; automatic Qodo1567354 completed, findings[]. Revix quota exhausted до21.10 00:00UTC/03:00МСК; полного review нет, отсутствие не approval.

AT-00-001/004/005/008, F-019/F-074/F-138/F-143: returned failures запуска/остановки/защищённого перезапуска требуют стабильные code/category. Сохранены опубликованные OPERATION_* и SCHEDULE_PROFILE_UNAVAILABLE: fallback расписания не меняется. Main lane и общий registry сохраняют подтверждённую категорию в terminal history, malformed code/category остаются internal. Recovery worker и фактический killed/SIGTERM/null-code timeout классифицируются структурно. Native exception/path/stack остаются в private diagnostic; публичные cleanup warnings называют шаг и сохраняют retry guidance, networkCleanup/runtimeStopped receipts и независимость восстановления после exit proof. Подсказка WFP conflict остаётся actionable.

Откат доверенного манифеста по-прежнему восстанавливает исправные записи и явно сообщает о пропущенных: production validator→rollback→Stop test проверяет static reason/index без пути/секрета из испорченной записи. Типизированная ошибка обновления Soft не сбрасывает подтверждённую прежнюю защиту; позднее исключение/отмена/timeout и потеря evidence отменяют retention. Состояние результата операции отделено от состояния действующей защиты. Внешняя feature policy WP-10 и нормативные docs/ не меняются.

Red: npm.cmd test -- src/main/connectionOperations.test.ts src/main/tunControllerStartup.test.ts src/main/lifecycleCleanup.test.ts --maxWorkers=1 —31 failed/233 passed,17.99s,exit1 (.tmp/wp0-connection-errors-red.log). Первый typecheck failed из-за строгого union/legacy arms; второй прошёл165channels/0public any. Targeted1:18 failed/450 passed,27.49s; выявлены regression с потерей skipped report, fixture binding и прежние raw-string assertions. Targeted2:3 failed/535 passed,24.36s (Vitest failure; shell ошибочно вернул0 после Get-Content). Targeted3:1 failed/659 passed,25.82s,exit1 —Soft retention regression; исправлена кодом и новыми category/late-throw тестами. Targeted4:4 failed/1273 passed,36.56s,exit1 —source-extracted history harness без новых dependencies. Typecheck3 failed только на required parameter в callback mock; исправлен adapter wrapper.

Final targeted: npm.cmd test -- src/shared/ipc-result.test.ts src/main/connection src/main/tunControllerStartup.test.ts src/main/lifecycleCleanup.test.ts src/main/operationRegistry.test.ts src/main/scheduledConnection.test.ts src/main/scheduler.test.ts src/main/physicalAdapterLifecycle.test.ts src/main/runtimeMaintenance.test.ts src/main/tunnelStateMachine.test.ts src/renderer/pages/Dashboard.cancel.test.tsx src/main/ipcResultContract.test.ts src/main/ipcContractAcceptance.test.ts --maxWorkers=1 —1277 passed,21 suites,35.23s,exit0 (.tmp/wp0-connection-errors-targeted5.log). npm.cmd run build incl typecheck165/0public any —exit0 (.tmp/wp0-connection-errors-build.log); node scripts/test-electron-runtime.mjs —9 *_PASS,exit0 (.tmp/wp0-connection-errors-native.log). Coverage AC927/927,F210/210 и git diff --check exit0; coverage не означает исполнение AT. Полный набор идёт на неизменном source/test tree. После push нужны automatic completed Qodo и exact-head CI success до следующего кодового участка. WP-0 активен, WP-2 не начат.


Первый full: npm.cmd test -- --maxWorkers=1 —33 failed/5582 passed/5 skipped,4 failed/309 passed/2 skipped suites,277.97s,exit1;1 unhandled ReferenceError (.tmp/wp0-connection-errors-full.log). Причины: два source-extracted harness не подключили production connectionFailure/classifyTunError; три старых source assertions искали прежнюю запись false вместо factory. Harness теперь исполняет настоящий extracted classifier, не повторяет классификацию. Первые focused4suites:2 failed/87 passed,1.32s —ещё два ожидания raw Xray diagnostic. Обновлены на canonical result и проверку сохранённого Error.message в private logger; cleanup/drain оракулы сохранены. Final focused: npm.cmd test -- src/main/tunControllerPreparation.test.ts src/main/ownedRuntimeStop.test.ts src/main/auditFixesRegression.test.ts src/main/tunControllerRecoverySource.test.ts --maxWorkers=1 —89/89 passed,4suites,1.31s,exit0 (.tmp/wp0-connection-errors-full-fix-targeted2.log). Production после первого full не менялся; новый full и typecheck запущены на окончательных tests. Ошибочному первому full PASS не приписывается.


Окончательный full на неизменном source/test tree: npm.cmd test -- --maxWorkers=1 —5615 passed/5 skipped/0 failed,313 suites passed/2 skipped,276.02s,exit0 (.tmp/wp0-connection-errors-full-final.log,EXIT_CODE=0). Final typecheck165 channels/0public any —exit0 (.tmp/wp0-connection-errors-typecheck-final2.log). Production build/Electron9 PASS относятся к тому же production tree; после них менялись только test harness/expectations. Targeted1277/1277 и последующие89/89,coverage AC927/927,F210/210 и diff exit0 записаны выше. Готово к commit/push; automatic Qodo и CI должны пройти окончательный SHA перед следующим кодовым участком. WP-0 активен,WP-2 не начат.


PR #109 создан/attached на65bc632828f6b2fd8bc64a88298e1da004d65418; для лимита100 удалена только карточка PR #10 после GitHub MERGED проверки. Initial CI39443871958 success exact SHA (Windows/Rust/site); automatic Qodo1568143 completed:4 pending findings —утрата guidance неподдерживаемого VPN input, recovery-report hint baseline, различий split/direct/offline proxy и названия неуспешного этапа startup. Все4 подтверждены; attribution не менялся (.tmp/qodo109-initial.json). Revix free-quota-reached до21.10 00:00UTC/03:00МСК, полного review нет.

Qodo red: npm.cmd test -- src/main/lifecycleCleanup.test.ts src/main/tunControllerPreparation.test.ts --maxWorkers=1 —10 failed/200 passed,23.48s,exit1 (.tmp/wp0-connection-errors-qodo-red.log). Исправлены static actionable messages, без возврата arbitrary exception text: no-supported-profiles имеет отдельный typed validation fault и авторскую guidance; baseline success-warning/failure catch направляет к отчёту восстановления; proxy producer возвращает structured split/direct/offline reason, consumer выбирает статическую инструкцию; Xray/runtime/sing-box/protected restart/invalid address называют этап и действие. Raw diagnostics остаются в private logger. Порядок компенсации/native drain и policy автоматизаций не менялись.

Первый targeted после fix:219/219,3suites,24.29s. Дополнены actual validator→startup cases для трёх proxy reasons и actual runtime preparation catch/protected restart. Final npm.cmd test -- src/main/lifecycleCleanup.test.ts src/main/tunControllerPreparation.test.ts src/main/tunControllerStartup.test.ts src/main/tunControllerRecoverySource.test.ts src/main/connection src/main/vpnProfilesRegression.test.ts src/main/runtimeMaintenance.test.ts src/main/tunnelStateMachine.test.ts --maxWorkers=1 —622/622,16suites,31.77s,exit0 (.tmp/wp0-connection-errors-qodo-targeted2.log). npm.cmd run build incl typecheck165channels/0public any —exit0 (.tmp/wp0-connection-errors-qodo-build.log); node scripts/test-electron-runtime.mjs —9 *_PASS,exit0 (.tmp/wp0-connection-errors-qodo-native.log). Full запущен на неизменном source/test tree; initial CI/Qodo не заменяют обязательные новые gates после follow-up push. WP-0 активен,WP-2 не начат.


Qodo-fix final full: npm.cmd test -- --maxWorkers=1 —5624 passed/5 skipped/0 failed,313 suites passed/2 skipped,274.89s,exit0 (.tmp/wp0-connection-errors-qodo-full.log,EXIT_CODE=0). Source/test tree неизменен во время полного прогона. Build/typecheck165/0public any,Electron9 PASS,targeted622/622,coverage AC927/F210 и diff exit0 записаны выше. Follow-up готов к commit/push; после него обязательны новые automatic Qodo/CI final SHA. WP-0 активен,WP-2 не начат.


## WP-0: типизированные отказы ротации и adaptive restart (20.10.2026)

PR #109 слит20.10 в15:22:06UTC: reviewed head f152cddff410f7ac818e12fcc9cf9bda17490df9, merge90b1c36a4c2cc28219e1a1057477421932afdce8; tree a69914e14b540964b33e929cd67e0b11182a94d8 совпал с reviewed head после fetch. CI39446719499 success (Windows/Rust/site), automatic Qodo1568487 completed на том же head: все4 findings implemented, новых нет; attribution не менялся. Revix quota exhausted до21.10 00:00UTC/03:00МСК; полного review нет, отсутствие не approval.

AT-00-001/003/004/005,F-019/F-074/F-138/F-143: shared ConnectionRotationResult требует canonical code/category при false. Empty config получает conflict, нет доступных серверов network; failed restart сохраняет подтверждённую category и authored guidance. Malformed legacy metadata не даёт перенести raw native text в IPC/notification. Missing outbound и остановленный во время подготовки runtime имеют conflict. Lane/FSM/registry согласуют terminal category/status returned и thrown отказов, включая cancelled. Исправлена существующая registry regression: выброшенный IpcFault(cancelled) раньше давал status:error/category:cancelled. Adaptive helper использует ConnectionStartResult: утрата owner/generation возвращает typed cancelled, неуспешная sibling health проверка network. Поздний successful restart после supersede больше не выглядит успехом; newer owner не останавливается и не публикуется. Выбор профиля, retry timer, retained protection, 2-of-3 health window и WP-10 feature policy сохранены; нормативные docs/ не менялись.

Red: npm.cmd test -- src/main/rotationLifecycle.test.ts src/main/rotationOperations.test.ts src/main/adaptiveFallbackTransition.test.ts --maxWorkers=1 —28 failed/51 passed,4.59s,exit1 (.tmp/wp0-rotation-errors-red.log). Targeted1 после fix —1 failed/135 passed,4.68s (registry thrown cancelled status). Отдельный npm.cmd test -- src/main/operationRegistry.test.ts --maxWorkers=1 —1 failed/113 passed,2.39s,exit1; adaptive late-success red —2 failed/16 passed,689ms,exit1. После fix targeted2 —258/258,6.54s,exit0. Расширенный targeted имел6 failed/259 passed,5.50s: vi.resetModules создал другую class identity статически импортированного IpcFault в fixture; тест теперь получает настоящий fault из текущего module graph.

Final targeted: npm.cmd test -- src/main/rotationLifecycle.test.ts src/main/rotationOperations.test.ts src/main/profileRotation.test.ts src/main/rotationProbeDrain.test.ts src/main/adaptiveFallbackTransition.test.ts src/main/connectionStopDeadline.test.ts src/main/profileTransitionWiring.test.ts src/main/operationRegistry.test.ts src/renderer/components/RotationSettings.test.tsx --maxWorkers=1 —265/265,9suites,5.43s,exit0 (.tmp/wp0-rotation-errors-targeted-final2.log). Actual rotation handler/guard/structuredClone/unwrap и Conf-backed config проверяют7 категорий; отдельно7 thrown категорий сохраняют прежний live evidence. npm.cmd run typecheck —165channels/0public any,exit0 до последних test assertions; финальный build повторяет typecheck. Coverage AC927/927,F210/210 и diff exit0, это traceability, не исполнение всех AT. Full/build запущены на неизменном source/test tree. После push обязательны completed automatic Qodo и success CI final SHA до следующего кодового участка. WP-0 активен,WP-2 не начат.


Первый полный набор: npm.cmd test -- --maxWorkers=1 —3 failed/5669 passed/5 skipped,312 passed/1 failed/2 skipped suites,283.51s,exit1 (.tmp/wp0-rotation-errors-full.log). Все3 — прежний shared assertion serverGroupsIpcErrors.test.ts требовал error и для cancelled. Первый Electron run тоже exit1: server-request-native.ts ожидал тот же прежний status. Исправлены только expectations на cancelled при category:cancelled; production после первого полного набора неизменен. Focused npm.cmd test -- src/main/serverGroupsIpcErrors.test.ts src/main/operationRegistry.test.ts src/main/rotationLifecycle.test.ts src/main/rotationOperations.test.ts --maxWorkers=1 —223/223,4suites,5.02s,exit0 (.tmp/wp0-rotation-errors-history-targeted.log).

node scripts/test-electron-runtime.mjs после fixture fix —9 *_PASS,exit0 (.tmp/wp0-rotation-errors-native-final.log). Actual subscription handler/production preload/contextBridge сохраняют7 categories и согласованный terminal status в ru/en. Final npm.cmd run typecheck —165channels/0public any,exit0 (.tmp/wp0-rotation-errors-typecheck-final.log). Build production tree уже прошёл exit0 (.tmp/wp0-rotation-errors-build.log); после него менялись только test expectations. Новый полный набор запущен на окончательных source/test/fixture files. Первому ошибочному full/native PASS не приписывается.


Final full: npm.cmd test -- --maxWorkers=1 —5672 passed/5 skipped/0 failed,313 suites passed/2 skipped,286.15s,exit0 (.tmp/wp0-rotation-errors-full-final.log,EXIT_CODE=0). Source/test/fixture tree неизменен во время этого полного прогона. Final typecheck165channels/0public any,build,Electron9 *_PASS,focused265/265 и223/223 записаны выше. Coverage AC927/927,F210/210 и diff check проверяются перед commit. После push обязательны completed automatic Qodo и exact-head CI success; WP-0 активен,WP-2 не начат.


PR #110 создан/attached на5493f68cf67b1696da9dbaad49e4a20f3bb377d1. Для лимита100 удалена только карточка #11 после live GitHub MERGED проверки (20.06.2026); сам PR не изменялся. Automatic Qodo1568876 completed на5493f68:1 finding pending —duplicate punctuation в failure notification. Подтверждено actual handler regression, attribution не менялся (.tmp/qodo110-initial.json).

Qodo red: npm.cmd test -- src/main/rotationOperations.test.ts --maxWorkers=1 —4 failed/44 passed,5.53s,exit1 (.tmp/wp0-rotation-errors-qodo-red.log). Guidance с точкой/восклицанием/вопросом/многоточием теперь не получает дополнительную точку; guidance без terminal punctuation по-прежнему получает разделительную точку. Сам error payload и текст protection warning сохраняются. Final targeted npm.cmd test -- src/main/rotationOperations.test.ts src/main/profileRotation.test.ts --maxWorkers=1 —66/66,2suites,5.59s,exit0 (.tmp/wp0-rotation-errors-qodo-targeted.log). Full/build/native запущены на неизменном final source/test tree; после push обязательны новые exact-head CI и completed automatic Qodo. WP-0 активен,WP-2 не начат.


Initial CI39450143681 success на5493f68 (Windows/Rust/site); Revix review COMMENTED содержит free-quota-reached, reset21.10 00:00UTC/03:00МСК. Это summary, не full review/approval. Final после punctuation fix: npm.cmd test -- --maxWorkers=1 —5677 passed/5 skipped/0 failed,313 suites passed/2 skipped,280.29s,exit0 (.tmp/wp0-rotation-errors-qodo-full.log,EXIT_CODE=0). Source/test tree во время полного прогона неизменен. npm.cmd run build incl typecheck165channels/0public any exit0 (.tmp/wp0-rotation-errors-qodo-build.log),node scripts/test-electron-runtime.mjs —9 *_PASS,exit0 (.tmp/wp0-rotation-errors-qodo-native.log). Targeted66/66; coverage AC927/F210 и diff проверяются перед follow-up commit. После push нужны новые exact-head CI и completed automatic Qodo. WP-0 активен,WP-2 не начат.


## WP-0: реестр startup-миграций (20.10.2026)

PR #110 слит20.10 в16:00:49UTC: reviewed head6c6d2d5b84a6d26f651ea6a5145cd649ea867def,merge fad1b598ba33309a52436852358bd35523e053b8; tree e8785f139c63dd75f73104e62bd512a94f967811 совпал с reviewed head/main. CI39451761837 success (Windows/Rust/site),automatic Qodo1569209 completed на том же SHA: прежнее замечание automatically implemented, новых нет; attribution не менялся. Revix free-quota-reached до21.10 00:00UTC/03:00МСК; полного review нет,summary не approval. Gates повторно проверены live.

AT-00-006/005,F-074/F-143: семь существующих startup repairs теперь перечислены в typed ordered registry storeMigrations.ts; production index вызывает один runner. Порядок/метод receivers/идемпотентные проверки на каждом старте сохранены. Один action correlation,source lifecycle,owner recovery; started/success/error каждого шага, safe category и stop/rethrow при ошибке. Completion означает выполненную проверку,не вымышленную applied migration; schema versions не повышались.

Initial red npm.cmd test -- src/main/startupStoreMigrations.test.ts --maxWorkers=1 —3 failed/0 passed,785ms,exit1 (.tmp/wp0-startup-migrations-red.log): отсутствующий runner. После реализации focused6 suites99/99,1.81s. Logger fixture получает actionCorrelation из текущего module graph после vi.resetModules. Добавлены семь typed failure cases на каждом шаге,receiver binding и закрытие scope. Final npm.cmd test -- src/main/startupStoreMigrations.test.ts src/main/storeMigrations.test.ts src/main/storeSchemaStorage.test.ts src/main/storeSchemaElectron.test.ts src/main/serverPickerMigration.test.ts src/main/serverPickerConsolidate.test.ts src/main/serverPickerPingPoisoning.test.ts --maxWorkers=1 —108/108,7suites,2.38s,exit0 (.tmp/wp0-startup-migrations-targeted-final.log). Actual Conf legacy settings→picker→groups,сохранённый outbound,encrypted secret и byte-identical restart проверены.

npm.cmd run build incl typecheck165channels/0public any —exit0 (.tmp/wp0-startup-migrations-build.log); node scripts/test-electron-runtime.mjs —9 *_PASS,exit0 (.tmp/wp0-startup-migrations-native.log). Coverage AC927/927,F210/210,diff check exit0. Full запущен на неизменном source/test tree; его результат и automatic Qodo/CI final SHA ещё требуются. Матрица в начале этого файла историческая и подлежит итоговой сверке всех10 AT; WP-0 пока активен,WP-2 не начат.


Final полный npm.cmd test -- --maxWorkers=1 —5687 passed/5 skipped/0 failed,314 suites passed/2 skipped,312.93s,exit0 (.tmp/wp0-startup-migrations-full.log,EXIT_CODE=0). Source/test tree неизменен во время полного прогона. Build/typecheck165channels/0public any,Electron9 *_PASS,targeted108/108 и coverage AC927/F210 прошли. Перед следующим кодовым участком требуются completed automatic Qodo и success CI окончательного SHA этого PR.


PR #111 создан/attached на199b80cecd0d505d4215aa297e9865bdc892dc76. Для лимита100 удалена только карточка #12 после live GitHub MERGED проверки; сам PR не изменялся. Automatic Qodo1569415 completed на этом SHA:1 pending finding Redacted logs lack correlation coverage —подтверждён пробел тестового доказательства; production failure не заявляется. Attribution не менялся (.tmp/qodo111-initial.json). Revix free-quota-reached до21.10 00:00UTC,summary не full review.

Добавлен отдельный startupStoreMigrations.logging.test.ts без mock appLogger: два реальных runner actions (success и permission failure),production JSONL и getFullLogs diagnostic redactor. Проверены distinct prefixed IDs всех шагов, lifecycle/recovery metadata, монотонный порядок, strict step order, stop после failure и masking password/UUID/private exception. npm.cmd test -- src/main/startupStoreMigrations.logging.test.ts src/main/startupStoreMigrations.test.ts src/main/actionCorrelation.test.ts src/main/appLoggerRedaction.test.ts --maxWorkers=1 —18/18,4suites,2.07s,exit0 (.tmp/wp0-startup-migrations-qodo-targeted.log). Production source не менялся после initial full/build/native; новый full и typecheck запущены на окончательном test tree. После push нужны новые automatic Qodo и CI final SHA.


Первый полный после добавления real-logger fixture: npm.cmd test -- --maxWorkers=1 —1 failed/5687 passed/5 skipped,314 passed/1 failed/2 skipped suites,415.50s,exit1 (.tmp/wp0-startup-migrations-qodo-full.log). Единственный failure: прежний native tunRouteProbe.test.ts competing routes завершался5344ms при outer5000ms; execFileSync fixture допускает10000ms. Только outer budget этой native matrix согласован до15000ms; production dispatch3000ms,child10000ms,assertions/route policy неизменны. Targeted npm.cmd test -- src/main/tunRouteProbe.test.ts src/main/startupStoreMigrations.logging.test.ts src/main/startupStoreMigrations.test.ts --maxWorkers=1 —27/27,3suites,2.87s,exit0 (.tmp/wp0-startup-migrations-qodo-targeted-final.log). Повторный full запущен на final source/test tree; предыдущий failed не называется PASS. npm.cmd run typecheck —165channels/0public any,exit0 (.tmp/wp0-startup-migrations-qodo-typecheck.log). Initial CI39455320485 success на199b80c,но после follow-up нужны новые final-SHA CI/Qodo.


После прерывания turn handle full-final46309 отсутствует; live Win32_Process подтвердил отсутствие vitest/npm test,а .tmp/wp0-startup-migrations-qodo-full-final.log не содержит summary/EXIT_CODE. Этот прогон interrupted,не PASS и не test failure. Новый полный набор запущен в .tmp/wp0-startup-migrations-qodo-full-resumed.log после проверки,что прежний процесс завершён. Source/test tree не менялся.


Resumed full npm.cmd test -- --maxWorkers=1 —1 failed/5687 passed/5 skipped,314 passed/1 failed/2 skipped suites,422.15s,exit1 (.tmp/wp0-startup-migrations-qodo-full-resumed.log). Root failure —configOperations.test.ts beforeEach hook10000ms: privateExportDirectory native ACL process допускает15000ms. Test body cancellation не выполнялось; вторичный teardown SyntaxError возник при разборе пустого logger output. Focused npm.cmd test -- src/main/configOperations.test.ts -t "cancels config" --maxWorkers=1 —4 passed/39 filtered skipped,6.75s,exit0 (.tmp/wp0-startup-config-cancel-focused.log).

Fixture beforeEach получил30000ms с учётом15s ACL+imports; production и test-body cancellation budgets не менялись. logRows теперь await production flushAppLog перед чтением JSONL,корректно обрабатывает пустой файл/ENOENT,сохраняет strict count/schema parsing. Failed full не объявляется PASS. Расширенный focused запущен перед новым полным прогоном.


После fixture fixes: npm.cmd test -- src/main/configOperations.test.ts src/main/tunRouteProbe.test.ts src/main/startupStoreMigrations.logging.test.ts src/main/startupStoreMigrations.test.ts --maxWorkers=1 —70/70,4 suites,56.74s,exit0 (.tmp/wp0-startup-migrations-qodo-targeted-resumed.log). Final npm.cmd run typecheck —165 channels/0 public any,exit0 (.tmp/wp0-startup-migrations-qodo-typecheck-fixture-final.log). Coverage AC927/927,F210/210 и git diff --check exit0. Новый full запущен в .tmp/wp0-startup-migrations-qodo-full-fixture-final.log; результат ещё ожидается. Production source после199b80c неизменен.


Final после fixture fixes: npm.cmd test -- --maxWorkers=1 —5688 passed/5 skipped/0 failed,315 passed/2 skipped suites,380.34s,exit0 (.tmp/wp0-startup-migrations-qodo-full-fixture-final.log,EXIT_CODE=0). Source/test tree неизменен во время полного прогона. Final typecheck165 channels/0 public any,focused70/70,coverage AC927/F210 и diff exit0. Production build/native9 *_PASS уже проходили на199b80c; после него менялись только tests/docs. После follow-up push обязательны новые automatic completed Qodo и success CI exact head до следующего кода.


## WP-0: допуск версий JSON-документов (20.10.2026)

PR #111 слит20.10 в17:24:59UTC: reviewed head9d9ee3e5f53fc26361c8fcb78d90b706be9a19e0,merge fcae9eda77ae4b7f095734867237718b56ac3a4a; tree39f30b7d1d640a4097d28c6c209da6234d4b561a совпал с reviewed head/main. CI39464861303 success (Windows/Rust/site); automatic Qodo1570429 completed на exact head,прежнее замечание automatically implemented,новых нет. Attribution не менялся (.tmp/qodo111-followup.json). Revix quota exhausted до21.10 00:00UTC/03:00МСК;summary не full review/approval. Сетевой обрыв gh run watch не был CI failure: success повторно подтверждён run view/pr checks до merge.

AT-00-006/F-074: дополнительная инвентаризация выявила version admission gap у application-owned JSON backups browser/location/Git/env и persistent forensics manifest. Следующий участок сохраняет поддержанные исторические форматы; future-version должен давать typed refusal до системных изменений и не изменять bytes файла. Политики WP-8/WP-9 не расширяются. WP-0 активен,WP-2 не начат.


Реализован отдельный DOCUMENT_SCHEMA_VERSIONS в существующем storeSchema (4 backup formats0,forensics2) с общей проверкой и StoreSchemaError. Reads/apply/rollback/status и prewrite checks отказывают future/invalid version,включая cached forensic session и per-session manifest; schema failures не теряются в autoconfig boolean results. Bulk rollback продолжает независимые targets перед typed отказом. Новые backup documents явно пишут schemaVersion0,старые0/unversioned сохраняют чтение/rollback; вымышленных migrations/schema bumps нет. Это проверка перед записью,не межпроцессный OS CAS. Старое incomplete-JSON recovery форензики во время background truncate/write сохранено; ошибки доступа при schema inspection не подавляются.

Первый red fixture ошибался отсутствующим exec mock у постороннего Android target (42 failed/8 passed); после изоляции targets40 failed/10 passed,затем после корректного native registry readback38 failed/12 passed (861ms,exit1,.tmp/wp0-document-schema-red-confirmed.log). Они подтверждают отсутствие admission,не production regression. После реализации focused1 failed/289 passed: старое exact env backup expectation не учитывало новый schemaVersion0; expectation обновлено. Focused293/293,7suites,3.20s. При усилении strict forensic reads2 failed/109 passed: existing recovery должен выдерживать truncate-before-write окно; сохранена прежняя SyntaxError policy,version и I/O failures explicit. Повтор111/111,3suites,2.06s.

Окончательный focused npm.cmd test -- src/main/documentSchemaStorage.test.ts src/main/autoconfig/env.test.ts src/main/autoconfig/index.test.ts src/main/browserHardening.test.ts src/main/locationPrivacy.test.ts src/main/trafficForensicsSessionSecurity.test.ts src/main/trafficForensics.test.ts src/main/storeSchemaStorage.test.ts src/main/storeSchemaInventory.test.ts --maxWorkers=1 —348/348,9suites,3.72s,exit0 (.tmp/wp0-document-schema-targeted-final3.log). Real files/SHA256,malformed versions,new backups,legacy rollback0/unversioned,forensics0/1/2,cached latest/session replacement,prewrite replacement и независимый rollback проверены. Native effects mocked,это не L3. Full/build/typecheck/native ещё требуются.


Первый полный npm.cmd test -- --maxWorkers=1 —2 failed/5749 passed/5 skipped,315 passed/1 failed/2 skipped suites,328.47s,exit1 (.tmp/wp0-document-schema-full.log,EXIT_CODE=1). Обе ошибки —native read-only runtimeDirSecurity.test.ts outer5000ms при child timeout15000ms: owner11043ms/write-access5522ms. Диагностический неизменный focused -t "emits a native failure receipt" —4 passed/99 filtered skipped,3.10s,exit0. Только outer budget native subset согласован до35000ms (parser case использует2 children по15s); production/security policy/assertions не менялись. Повторный targeted с native subset —451/451,10suites,6.99s,exit0 (.tmp/wp0-document-schema-targeted-final4.log).

Production npm.cmd run build включая typecheck165 channels/0 public any —exit0 (.tmp/wp0-document-schema-build.log); node scripts/test-electron-runtime.mjs —9 *_PASS,exit0 (.tmp/wp0-document-schema-native.log). После этих checks менялся только тестовый outer budget. Новый full и final typecheck запущены на неизменном source/test tree. Предыдущий failed не называется PASS.


Final full npm.cmd test -- --maxWorkers=1 —5751 passed/5 skipped/0 failed,316 passed/2 skipped suites,342.23s,exit0 (.tmp/wp0-document-schema-full-final.log,EXIT_CODE=0). Source/test tree неизменен во время полного прогона. Final npm.cmd run typecheck —165 channels/0 public any,exit0 (.tmp/wp0-document-schema-typecheck-final.log). Build и Electron9 *_PASS прошли на final production tree; после них менялся только native test budget. Focused451/451; coverage AC927/927,F210/210 и diff exit0. После push обязательны completed automatic Qodo и success exact-head CI. Затем остаются удаление устаревшего diag/ по решению владельца §10.7 и итоговая сверка/фиксация10 AT; WP-0 пока активен.


PR #112 создан/attached на47a5a3b470bf057107ed0858b3b03d11bbf068ba. Лимит100: удалена только карточка #13 после live GitHub MERGED проверки (30.09); сам PR не изменялся. Initial CI39468683960 требуется сверить отдельно; automatic Qodo1570761 completed на47a5a3b нашёл3 pending: independent Soft env cleanup после Git refusal; actual Git status при corrupt/unreadable backup; owned forensic provider cleanup при refused disk manifest (.tmp/qodo112-initial.json). Attribution не менялся. Revix free-quota-reached,не full approval.

Red npm.cmd test -- src/main/documentSchemaStorage.test.ts src/main/lifecycleCleanup.test.ts --maxWorkers=1 —4 failed/250 passed,58.49s,exit1 (.tmp/wp0-document-schema-qodo-red.log). Исправлены actual index rollback ordering (env stop выполняется перед повторным отказом другого target), независимая Git live status query, path-free stop только для подтверждённого ownedCapture/runtimeState при future/invalid/unreadable document. Native ack обязателен; чужой disk manifest не даёт authority; refused files не переписываются. Restart сначала безопасно останавливает своё,затем отказывает новому start. Status остановки строится по собственному подтверждённому runtime result с явным CaptureStoppedArtifactsUnavailable.

Corrupt/unreadable Git backup по-прежнему блокирует apply и сохраняется: baseline нельзя использовать для безопасного rollback. Исправлена ложная отметка unapplied,не введена перезапись повреждённого snapshot. Этот safe refusal регрессией проверен на actual files/API. Первое expectation main fixture ошибочно требовало rollback вместо production rollbackApplied; поправлено. Targeted69 passed/191 filtered skipped,1.80s,exit0. Расширенный focused6 failed/347 passed из-за assertion "pktmon stop": production закрепляет SystemDirectory/pktmon.exe,исправлено на этот фактический безопасный вызов. Final focused353/353,6suites,6.95s,exit0 (.tmp/wp0-document-schema-qodo-focused-final.log). Build incl165 channels/0 public any exit0 (.tmp/wp0-document-schema-qodo-build.log); после build изменены только test assertion и explanatory comment. Новый full/native запущены на final source/test tree.


Полный прогон после Qodo fixes: npm.cmd test -- --maxWorkers=1 —5760 passed/5 skipped/0 failed,316 passed/2 skipped suites,330.00s,exit0 (.tmp/wp0-document-schema-qodo-full.log,EXIT_CODE=0). Native Electron9 *_PASS,exit0 (.tmp/wp0-document-schema-qodo-native.log). Initial remote CI39468683960 на47a5a3b завершился failure: serverKeyOperations held write ожидал5s до native creation/ACL (два child calls с production timeout15s каждый). Test wait согласован35s,outer45s; production deadlines и cancellation/resource assertions неизменны. Focused npm.cmd test -- src/main/serverKeyOperations.test.ts --maxWorkers=1 —57/57,43.42s,exit0 (.tmp/wp0-document-schema-qodo-key-focused.log). После test-only изменения запущен новый final full; предыдущий failed CI не называется PASS.


Final после CI fixture budget: npm.cmd test -- --maxWorkers=1 —5760 passed/5 skipped/0 failed,316 passed/2 skipped suites,382.20s,exit0 (.tmp/wp0-document-schema-qodo-full-final.log,EXIT_CODE=0). Source/test tree неизменен во время прогона. npm.cmd run typecheck —165 channels/0 public any,exit0 (.tmp/wp0-document-schema-qodo-typecheck-final.log). python docs/04-приёмочные-тесты/traceability/check-coverage.py —AC927/927,F210/210,exit0; git diff --check —exit0. Build/native9 PASS выполнены на окончательном production source,после них менялись только test expectations/budgets и поясняющий comment. После push требуются новый automatic completed Qodo и success CI exact head.


## WP-0: завершающая приёмка и удаление diag (20.10.2026)

PR #112 слит20.10.2026 в18:19:32UTC: reviewed head243ef56f8568f419f9ae9395d09373ac19320885,merge898db00499ee456d1ce623c750107e2d6aba53fc. Tree c31131d7877be2c359abe5bbac137efb3562a2a8 совпал у reviewed head/main. CI39472416208 success (Windows/Rust/site). Automatic Qodo1571090 completed на243ef56f8568f419f9ae9395d09373ac19320885: новых findings нет; env cleanup и owned capture stop автоматически implemented. Старое finding ed09166b-e008-4b59-971a-73f2527ac6d8 остаётся pending. Проверка кода/регрессий: git.isApplied уже читает фактический proxy после corrupt/unreadable backup. Второй пункт карточки — запрет apply с нечитаемым baseline — намеренная fail-closed политика, явно объяснённая в source/PR и проверенная actual file fixtures: файл сохранён, native changes отсутствуют. Подмена baseline уничтожила бы возможность безопасного отката; поэтому этот оставшийся пункт не принят как дефект. Attribution вручную не менялся; completed review не называется автоматическим одобрением этой карточки. Revix free-quota-reached до21.10 00:00UTC/03:00МСК, summary не full review/approval.

Остаток по §10.7: удалены8 tracked файлов автономного diag/; production ссылок нет. Скрипты не запускались, очистка старых OS Scheduled Tasks/diag-runtime не заявляется. Итоговая матрица AT-00-001…010 заменяет устаревший промежуточный остаток в acceptance report; history FAIL сохранена. WP-2 не начат. Завершение WP-0 вступает в силу после CI/review и слияния этого завершающего PR.


Первый full завершающей ветки npm.cmd test -- --maxWorkers=1 —1 failed/5759 passed/5 skipped,315 passed/1 failed/2 skipped suites,386.94s,exit1 (.tmp/wp0-final-acceptance-full.log). Единственный failure serverKeyOperations: EBUSY file export diagnostic case outer5000ms,фактически12180ms. До fault injection выполняются реальные createPrivateConfigExport/prepareConfigExport (два child calls по15s),поэтому5s не соответствует native fixture. Suite-only outer45s согласован для всех key operation fixtures; прежние локальные15s overrides убраны. Production budgets и отдельные <900ms cancellation assertions неизменны. Новых behavior tests не требуется: это согласование test runner budget существующих native fixtures. После patch обязательны focused/full/typecheck.


После suite budget fix npm.cmd test -- src/main/serverKeyOperations.test.ts --maxWorkers=1 —57/57,53.25s,exit0 (.tmp/wp0-final-acceptance-key-focused.log). npm.cmd run typecheck —165 channels/0 public any,exit0 (.tmp/wp0-final-acceptance-typecheck-final.log). Coverage AC927/927,F210/210 и diff exit0. Final full запущен в .tmp/wp0-final-acceptance-full-final.log; source/test tree после старта неизменен.


Завершающая ветка: `npm.cmd test -- --maxWorkers=1` —5760 passed,5 skipped,0 failed;316 passed/2 skipped suites,367.64s,exit0 (`.tmp/wp0-final-acceptance-full-final.log`,EXIT_CODE=0). `npm.cmd test -- src/main/serverKeyOperations.test.ts --maxWorkers=1` —57/57,53.25s,exit0. `npm.cmd run typecheck` —165 channels/0 public any,exit0 (`.tmp/wp0-final-acceptance-typecheck-final.log`). `python docs/04-приёмочные-тесты/traceability/check-coverage.py` —AC927/927,F210/210,exit0; `git diff --check` —exit0. Source/test tree во время final full не менялся. Runtime source/scripts/resources/package/workflows совпадают с reviewed #112; build и9 native Electron PASS от него остаются применимыми. 37 относительных ссылок итоговой матрицы проверены —missing0. Root normative docs/ неизменны. Удалена только карточка старого merged PR #14 для освобождения лимита100 (GitHub state MERGED,mergedAt02.10.2026); сам PR не менялся. После push обязательны completed automatic Qodo и success CI окончательного коммита; эта запись не утверждает их заранее.


## WP-0: канонические доменные контракты — завершающая сверка (20.10.2026)

После слияния #113 (head bd3a96560c5c01248525de03d7b4ddfa74eacc72, merge 918e20dfe1a1e357275aacae26d2845177cd9a3a; CI39476483272 success; Qodo1571517 completed с minor замечанием о нормативной ссылке WP-8/WP-0) сверка полного списка работ выявила два невыделенных канонических имени и собственный LCG вместо fast-check в AT-00-007. Это небольшой остаток WP-0; пакет окончательно закрывается после follow-up PR. WP-2 не начат. Нормативные docs/ не редактируются.

CheckResult<TItem> объединяет существующие диагностические payloads через прежние публичные aliases: wire shape и IPC envelope v1 сохранены. ProfileCompatibility v1 описывает статический выбор sing-box/Xray и причины отказа; production resolveProxyEngine потребляет решение, сохраняя прежние cores, validation и сообщения исключений. Этот контракт не доказывает handshake/lab admission и не включает новые ядра. Golden tests проверяют выбор/отказ, invalid future native profile, JSON roundtrip, неизменность input и отсутствие credentials.

AT-00-007 использует fast-check sample (seed0x5eed003,200 команд,10 async workers). Disconnect/cancel используют существующий lane.stop, который отменяет pending start; отдельный runtime API не добавлен. Сохранены fake PID/TUN ledger, typed losers, terminal event pairing и финальный disconnect.

Red npm.cmd test -- src/main/profileCompatibility.test.ts --maxWorkers=1:13 failed/1 passed,347ms,exit1 (.tmp/wp0-canonical-contracts-red.log). Type-only expectTypeOf не удостоверял существование отсутствующих типов. После реализации focused npm.cmd test -- src/main/profileCompatibility.test.ts src/main/nativeXrayCompatibility.test.ts src/main/transportCompatibility.test.ts src/main/xrayEngine.test.ts src/main/tunAdapter.test.ts src/main/tunnelStateMachine.test.ts src/main/connectionCancellation.test.ts src/main/systemDiagnostics.test.ts --maxWorkers=1:130/130,8suites,2.22s,exit0 (.tmp/wp0-canonical-focused.log). npm.cmd run typecheck:165 channels/0 public any,exit0. Полный прогон и production build/native ещё требуют результата; remote review/CI пока не заявляются.


Production npm.cmd run build (включает165-channel typecheck) —exit0 (.tmp/wp0-canonical-build.log). node scripts/test-electron-runtime.mjs —9 *_PASS,exit0 (.tmp/wp0-canonical-native.log). python docs/04-приёмочные-тесты/traceability/check-coverage.py —AC927/927,F210/210,exit0; это трассировка, не исполнение AT. git diff --check —exit0. Удалена только карточка старого #15 для лимита100 после live MERGED проверки (02.10.2026); сам PR не менялся.


Final npm.cmd test -- --maxWorkers=1 —5774 passed,5 skipped,0 failed;317 passed/2 skipped suites,332.22s,exit0 (.tmp/wp0-canonical-full.log,EXIT_CODE=0). Source/test tree не менялся во время прогона. Typecheck165 channels/0 public any,build и9 native PASS относятся к этому production tree. Coverage AC927/F210 exit0;40 относительных ссылок итоговой матрицы существуют. После push обязательны completed automatic Qodo и success CI окончательного SHA; статус завершения вступает в силу при слиянии follow-up.


## Health-check: причины warn/fail в отдельных событиях (20.10.2026)

В установленной сессии 22:17–22:26 МСК у 22 зарегистрированных lifecycle operations есть пары running/terminal с совпадающей correlation: 19 success, 2 cancelled, 1 отказ экспорта proxy-list категории conflict. Это подтверждает наблюдаемость этих операций, а не запись каждого клика. Навигация и ввод без предусмотренного event не видны; часть renderer-сообщений идёт отдельным IPC с другим ID, owner может быть unknown. Агент читает файлы по запросу; постоянное наблюдение не включено.

Обнаружено: общий IPC result усекался до 2000 символов до поздних пунктов health-check warn/fail. Каждый такой пункт теперь создаёт отдельный system diagnostic finding с check/category/label/status/value/details. Сохраняются общий bounded logger, redaction, action correlation и assertActive до записи. Уровень события info сохраняет status warn/fail как данные отчёта; следующая проверка не должна находить собственные findings как новые app-log faults. Полный response и короткая summary не меняются. Нормативные docs/ не редактируются.

Регрессии исполняют production runSystemDiagnostics/combineStatus/getLogSummary с подставленными OS readers, реальным JSONL logger и redactor: причины после длинных 35 info; credential/topology redaction и correlation; bounded длинная запись; отсутствие самоподдерживающего warn при сохранении внешнего fault; healthy и cancellation без поздних findings/terminal. Первый прогон (4 failed) выявил ошибку harness export syntax. Следующий (2 failed/2 passed) содержал missing finding и ошибку synthetic correlation ID; fixture заменена валидным opaque UUID-v4 ID. После реализации focused — 23/23, 4 suites, 1.27s, exit0: npm.cmd test -- src/main/systemDiagnostics.logging.test.ts src/main/systemDiagnostics.test.ts src/main/appLoggerRedaction.test.ts src/main/actionCorrelation.test.ts --maxWorkers=1.

Typecheck — 165 channels, 0 public any, exit0; npm.cmd run build — exit0. Coverage AC927/927,F210/210 и git diff --check — exit0. Полный прогон и внешние review/CI ещё требуют результата.


Final npm.cmd test -- --maxWorkers=1: 5778 passed, 5 skipped, 0 failed; 318 passed/2 skipped suites, 281.02s, exit0 (.tmp/health-findings-full.log, EXIT_CODE=0). Source/test tree во время прогона не менялся. Typecheck165/0 any и build выполнены на этом source; coverage AC927/F210 и diff exit0. Требуются completed automatic Qodo и success CI окончательного SHA перед merge.


Qodo automatic review1572513 (head4e1d05f8e31364ea4f2662cffbe4e95ba86437a4) обнаружил Proxy passwords persist in app logs: proxy-current сохранял env:ALL_PROXY с SOCKS userinfo. Замечание подтверждено синтетическими реальными JSONL regression fixtures: npm.cmd test -- src/main/systemDiagnostics.logging.test.ts --maxWorkers=1 —5 failed/4 passed,exit1 (.tmp/health-findings-qodo-red.log). Общий redactSensitiveText теперь скрывает целые socks/socks4/socks4a/socks5/socks5h URLs,включая credentials/topology,сохраняя соседнюю причину. Добавлены5 actual logger fixtures и property1000 runs seed1019 с encoded credentials/IPv6/mixed case.

После исправления npm.cmd test -- src/main/systemDiagnostics.logging.test.ts src/main/systemDiagnostics.test.ts src/main/appLoggerRedaction.test.ts src/main/actionCorrelation.test.ts src/main/redactor.property.test.ts --maxWorkers=1 —32/32,5 suites,1.80s,exit0 (.tmp/health-findings-qodo-focused.log). npm.cmd run typecheck —165 channels/0 public any,exit0 (.tmp/health-findings-qodo-typecheck.log); npm.cmd run build —exit0 (.tmp/health-findings-qodo-build.log). Coverage AC927/927,F210/210 и diff exit0. Full ещё выполняется; после push обязательны новый completed automatic Qodo и success CI окончательного SHA. Revix для первого head сообщил quota exhausted до21.10 00:00UTC; это не approval. Ранее собранный EXE без SOCKS fix устарел и не выдаётся как окончательный.


Final после SOCKS redaction: npm.cmd test -- --maxWorkers=1 —5784 passed,5 skipped,0 failed;318 passed/2 skipped suites,293.97s,exit0 (.tmp/health-findings-qodo-full.log,EXIT_CODE=0). Source/test tree во время прогона неизменен. Typecheck165/0 any,production build,focused32/32 выполнены на окончательном source. Coverage AC927/F210 подтверждает трассировку,не исполнение AT;exit0. Требуются новый automatic completed Qodo и success CI окончательного SHA перед merge.


## Отмена смены сервера: подтверждение очистки и фоновые проверки (20.10.2026)

Эпизод установленной сборки в app.log: отмена 23:22:59 МСК; kill-switch снят 23:23:03.776; stop 23:23:04.014 подтвердил baseline/firewall/adapters=true; поздние фоновые проверки 23:23:08.672 и 23:23:12.897 назвали обычный прямой доступ утечкой. Каноническая панель осталась unknown: stopped удостоверял выход процесса, но не передавал квитанцию полного rollback в FSM. Это не доказательство пробоя активного kill-switch. DNS/direct-out timeouts предыдущего health-check не объяснены этим исправлением.

Native stop теперь передаёт generation и фактическую квитанцию очистки. FSM подтверждает disconnected только при текущем поколении, отсутствии активного connection owner, остановленном runtime/Soft и baseline/firewall/adapters=true. Preserved stop, неполная очистка, устаревший receipt или живой процесс не подтверждают отключение. Main привязывает фоновые periodic/event leak checks к работающему подтверждённому TUN; stopping/adapting/terminal статусы немедленно отменяют выполняемые пробы. Проверки до запуска и перед callback предотвращают поздние баннеры, ручная диагностика остаётся доступна. Pending network-change grace timer удаляется при остановке watcher. Health-check пропускает только свой точный renderer warn summary; независимые warnings и error summary остаются видимыми. Нормативные docs/ не редактируются.

Регрессии исполняют production FSM, native stop body с OS fixtures, main status wiring, leak probes с контролируемыми child close, реальный JSONL logger, Dashboard + store + ConnectionLifecycle. Проверены cancel-cleanup → off → connect без лишнего disconnect, три неполных rollback, старое поколение, preserved stop/active owner, watcher restart, manual probe и сохранение реальной active leak alarm. Red: npm.cmd test -- src/main/tunnelStateMachine.test.ts src/renderer/pages/Dashboard.cancel.test.tsx src/main/leakSelfTest.test.ts src/main/systemDiagnostics.logging.test.ts --maxWorkers=1 —9 failed/82 passed,exit1 (.tmp/cancel-switch-red.log); два из отказов касались fake-timer isolation после missing API, остальные воспроизводили отсутствующее поведение. Focused 7 suites —345/345,34.09s,exit0 (.tmp/cancel-switch-focused-2.log); дополнительный main wiring/leak lifetime —24/24,4.73s,exit0 (.tmp/cancel-switch-wiring.log).

npm.cmd run typecheck —165 channels,0 public any,exit0 (.tmp/cancel-switch-typecheck-final.log). npm.cmd run build —exit0 (.tmp/cancel-switch-build.log). node scripts/test-electron-runtime.mjs —9 *_PASS,exit0 (.tmp/cancel-switch-native.log). python ../docs/04-приёмочные-тесты/traceability/check-coverage.py —AC927/927,F210/210,exit0; это трассировка, не исполнение L3 AT. Full suite ещё выполняется; remote review/CI и новый EXE пока не заявляются.

Final npm.cmd test -- --maxWorkers=1 —5797 passed,5 skipped,0 failed;318 passed/2 skipped suites,360.16s,exit0 (.tmp/cancel-switch-full.log,EXIT_CODE=0). Source/test tree во время полного прогона не менялся. Typecheck165/0 any,production build и9 native PASS относятся к этому source; coverage AC927/F210 и git diff --check exit0. Перед merge требуются completed automatic Qodo и success CI окончательного SHA.


## Qodo: сохранять проверки при удерживаемой блокировке (21.10.2026)

Automatic Qodo1573513 завершён на 00b68ab21ac94e5efc6f586b09bb3593bd524c8b. Finding e40a7221-f215-4c4b-ab6f-5296a01a41b0 подтверждён: прежний gate требовал connected + running и выключал проверки при killswitch-active/adapting/restarting/error. Это могло скрыть реальную утечку при отказе TUN с удерживаемой защитой. Уточнён gate по ожидаемой защите: running/proxy-down/killswitch-active включают фоновые проверки; stopping/stopped выключают до намеренного rollback; адаптация, crash/restart и error сохраняют предыдущую обязанность блокировать. Initial retry до подтверждения защиты сам по себе gate не включает. UI disconnected по-прежнему требует полной native cleanup receipt.

Добавлены actual main wiring + child probe регрессии четырёх retained states с positive leak callback и periodic blocked probe; unprotected initial retry не запускает проверку. Red npm.cmd test -- src/main/leakSelfTest.lifetime.test.ts --maxWorkers=1 —5 failed/24 passed,exit1 (.tmp/cancel-switch-qodo-red.log). После исправления npm.cmd test -- src/main/leakSelfTest.test.ts src/main/leakSelfTest.lifetime.test.ts src/main/tunnelStateMachine.test.ts src/main/lifecycleCleanup.test.ts src/renderer/pages/Dashboard.cancel.test.tsx src/main/systemDiagnostics.logging.test.ts --maxWorkers=1 —317/317,6 suites,35.94s,exit0 (.tmp/cancel-switch-qodo-focused.log). Новый full выполняется; ранее собранный EXE с первоначальным gate устарел и не выдаётся как итоговый. Attribution Qodo не изменялся, после push требуется новое automatic review окончательного SHA. Revix подтвердил quota exhausted до21.10 00:00UTC (03:00МСК); summary не является approval.

Final после retained-protection fix: npm.cmd test -- --maxWorkers=1 —5802 passed,5 skipped,0 failed;318 passed/2 skipped suites,367.69s,exit0 (.tmp/cancel-switch-qodo-full.log,EXIT_CODE=0). Source/test tree во время прогона неизменен. npm.cmd run build (включая typecheck165 channels/0 public any) —exit0 (.tmp/cancel-switch-qodo-build.log). node scripts/test-electron-runtime.mjs —9 *_PASS,exit0 (.tmp/cancel-switch-qodo-native.log). Coverage AC927/F210 и diff exit0. Первый CI39495818241 на старом00b68ab завершился failure: native quarantine same-content spawnSync powershell.exe ETIMEDOUT,15034ms при лимите15000; остальные4 quarantine variants прошли,5797 passed/1 failed/4 skipped. Новый head должен пройти весь CI, старый не считается зелёным.


## Отмена смены сервера: возврат к прежнему подключению (21.10.2026)

Владелец уточнил поведение: «Отмена» должна прервать новую попытку и вернуть сервер, на котором было подключение до переключения. Ранее сделанные исправления полной cleanup receipt, ложных leak alarms после снятия защиты и самоподдерживающегося health-check warning сохраняются. Это явное разрешение владельца на возврат прежнего подключения, не изменение нормативных docs/.

Перед переключением сохраняются прежний selected id и отдельный снимок последних успешных StartOptions. Один owner-scoped servers:cancel-switch отменяет только новую попытку через AbortSignal; второй глобальный cancel-transition из Dashboard удалён, чтобы он не мог оборвать уже начавшийся возврат. До native restart старый runtime остаётся нетронутым. После dispatch отменённая попытка дожидается завершения, выполняется подтверждённый полный rollback baseline/firewall/adapters и прежние StartOptions передаются новому владельцу ConnectionLifecycle. Canonical connected подтверждает основной координатор по фактическим runtime evidence; running event сам по себе недостаточен. Прежний selected id и свежая IP baseline восстанавливаются; guard держится до окончания возврата. Disconnect/shutdown отменяют возврат и не дают воскресить туннель. Timeout восстановления остаётся ошибкой, а не обычной отменой; ConnectionLifecycle.drain удерживает внешний owner до физического завершения startup и cleanup после bounded caller result. Неуспешный возврат или cleanup показываются как ошибка.

Qodo API доступен с ключом владельца. Completed run1573714 на89e4eccba66dc85f37d180faba04d4fd34ce820e подтвердил implemented для e40a7221-f215-4c4b-ab6f-5296a01a41b0 и новое action_required 36cb6aca-b069-4a58-8c67-afe907299252: stopping → error при неподтверждённом runtime exit оставлял leak gate выключенным, хотя protection удерживалась. Замечание воспроизведено и исправлено: current-generation failed stop receipt без runtimeStopped=true восстанавливает только прежнюю обязанность мониторинга. Initial unprotected failure, partial rollback и старая receipt сами по себе gate не включают. Attribution вручную не менялся.

Red npm.cmd test -- src/main/serverPickerSwitch.test.ts --maxWorkers=1:6 failed/14 passed (.tmp/cancel-switch-restore-red.log). Red npm.cmd test -- src/main/leakSelfTest.lifetime.test.ts --maxWorkers=1:2 failed/30 passed,exit1 (.tmp/cancel-switch-stop-qodo-red.log). Первые focused 7 suites:346/346,69.02s,exit0; затем native ownership/drain focused 3 suites:238/238,66.14s,exit0. Окончательный source после дополнительной timeout-регрессии требует отдельного полного прогона. Первый полный прогон был запущен до завершающей drain-правки и не используется как окончательное доказательство. Финальные проверки, automatic Qodo и CI будут записаны ниже. Установленный VPN и сеть пользователя не переключались.

Промежуточный full .tmp/cancel-switch-restore-full.log завершился 5824 passed/1 failed/5 skipped,exit1: lane.drain is not a function. Во время этого прогона был добавлен drain; Vitest использовал уже загруженный прежний модуль с обновлённым тестом. Отдельный focused 238/238 на свежем процессе подтвердил actual drain. Промежуточный full не засчитывается; запущен свежий полный процесс на неизменяемом окончательном source.

Свежий full на неизменном production source (.tmp/cancel-switch-restore-final-full.log):5824 passed/2 failed/5 skipped,376.46s,exit1. Оба отказа — существующие QUIC unit-тесты twitchHlsProbe.test.ts, каждый превысил5000ms при обращении к двум живым Twitch endpoints. Изолированный повтор до исправления:14/14,2.59s,exit0 (.tmp/cancel-switch-twitch-repro.log), что не заменяет failed full. Для unit-политики добавлена детерминированная TLS socket fixture с HTTP200 и close/drain; реальные QUIC predicate, media diagnostics и assertions сохранены, дополнительно проверены оба endpoint и reachable. Runtime probe не менялся; реальная socket/handshake lifetime проверяется отдельным itest. Focused после fixture:14/14,1.85s (tests9ms),exit0 (.tmp/cancel-switch-twitch-deterministic.log). Запущен полный npm.cmd test с обычным конфигом CI.

Окончательный npm.cmd test (обычный конфиг CI) на неизменном source/test tree:5826 passed/5 skipped/0 failed;318 passed/2 skipped suites,410.25s,exit0 (.tmp/cancel-switch-restore-final-resumed-full.log,EXIT_CODE=0). Прерванный .tmp/cancel-switch-restore-stable-full.log итоговой сводки не получил и не засчитывается. npm.cmd run typecheck:165 channels/0 public any,exit0 (.tmp/cancel-switch-restore-stable-typecheck.log). npm.cmd run build:exit0 (.tmp/cancel-switch-restore-final-build.log). node scripts/test-electron-runtime.mjs:9 *_PASS,exit0 (.tmp/cancel-switch-restore-final-native.log). npm.cmd test -- --mode integration src/main/liveServerProbe.handshakeDrain.itest.ts src/main/keyHealthChecker.transportDrain.itest.ts:37/37,1.74s,exit0 (.tmp/cancel-switch-restore-transport-itest.log). python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py:AC927/F210,exit0; это трассировка, не packet/L3 oracle. git diff --check:exit0. Нового EXE и completed exact-head remote review ещё нет.


## PR #116: замечания Qodo и Revix к возврату сервера (21.10.2026)

Qodo API с ключом владельца работает. Completed run1582220 на9c3b8fa7b8b57e1597ef69e1ddedc998b8f3caa5 подтвердил implemented для двух прежних findings и обнаружил action_required 04876317-ec2c-4a03-8d0b-5c8b8fa0fe5a: bare native start при возврате пропускал повторное применение baseline и другие direct-VPN effects. Возврат переведён на общий startDirectVpnProtectionEffects под прежним ConnectionLifecycle owner, с точными сохранёнными StartOptions. Снова применяются baseline, adaptive verification, IP/leak monitoring, snapshots и сессия истории; неуспех сохраняет обычный cleanup и типизированный результат. Нормативные docs/ не менялись.

Revix на9c3b8fa завершил review с needs-changes: новый Dashboard log вынесен в t() и обе локали; suggestion об устойчивой идентификации health summary принят — optional allowlisted health-check-summary проходит Maintenance -> store -> preload/schema -> main JSONL details.eventCode. Диагностика не зависит от языка/формулировки новых summary. Exact legacy text сохранён для уже записанных старых журналов; независимые предупреждения и error summary остаются видимыми. Вопрос о preserved stop проверен: actual native stop отправляет adapting, а не stopping; production-body assertion и retained-protection probe tests подтверждают сохранение обязанности мониторинга. CI9c3b8fa был полностью зелёный, но это не заменяет review/CI нового head.

Baseline red: npm.cmd test -- src/main/lifecycleCleanup.test.ts -t 're-applies the rolled-back baseline' --maxWorkers=1 —1 failed/206 skipped,exit1 (.tmp/cancel-switch-baseline-red.log). Stable-event red: npm.cmd test -- src/main/systemDiagnostics.logging.test.ts src/renderer/pages/Maintenance.requestLifetime.test.tsx src/preload/preloadValidation.test.ts -t 'renderer health event|health summary with its event|stable renderer event code' --maxWorkers=1 —4 failed/97 skipped,exit1 (.tmp/cancel-switch-review-marker-red.log). После исправлений focused6 suites: npm.cmd test -- src/main/lifecycleCleanup.test.ts src/main/serverPickerSwitch.test.ts src/main/systemDiagnostics.logging.test.ts src/renderer/pages/Dashboard.cancel.test.tsx src/renderer/pages/Maintenance.requestLifetime.test.tsx src/preload/preloadValidation.test.ts --maxWorkers=1 —352/352,56.13s,exit0 (.tmp/cancel-switch-review-focused.log). npm.cmd run typecheck —165 channels/0 public any,exit0 (.tmp/cancel-switch-review-typecheck.log). Coverage AC927/F210 exit0; это трассировка, не выполнение L3. Новый full выполняется на неизменном source; после push требуются свежие Qodo/Revix и CI. Attribution Qodo вручную не менялся.


Окончательный npm.cmd test на неизменном source/test tree:5831 passed/5 skipped/0 failed;318 passed/2 skipped suites,394.21s,exit0 (.tmp/cancel-switch-review-full.log,EXIT_CODE=0). npm.cmd run build, включая165-channel typecheck/0 public any:exit0 (.tmp/cancel-switch-review-build.log). node scripts/test-electron-runtime.mjs:9 *_PASS,exit0 (.tmp/cancel-switch-review-native.log). Ранее выполненный отдельный typecheck —exit0; focused352/352 и coverageAC927/F210 —exit0. git diff --check —exit0. Реальная сеть и установленный VPN не переключались. После commit/push обязательны новые automatic Qodo/Revix и CI окончательного head; прежний9c3b8fa и прежний EXE не считаются окончательным состоянием этого исправления.


## PR #116: завершать проверку возвращённого сервера после manual guard (21.10.2026)

Qodo automatic run1582721 завершился на0fe81ed24e22d093218073543b22d82f903b878f: три прежних findings implemented, новое action_required 0b07a06e-c9b4-46d5-b08f-432e8b168477 (Restored tunnels never finish verification). Подтверждено: direct startup создаёт adaptive context и вызывает verifier, пока manualProfileSwitchActive=true; verifier выходит по owner guard, а прежний end hook не перезапускает его при уже существующем context. End hook теперь после снятия manual guard повторно запускает verification существующего context, если runtime работает; для обычной смены без context сохраняется прежний ensure path. Во время restore защита owner/generation не ослабляется.

Расширен actual-body harness: исполняются реальные setProfileSwitchHooks, restore, direct effects, scheduleAdaptiveVerification и verifyAdaptiveConnection; динамический импорт заменяется только fixture server-probe boundary. Новые регрессии проверяют success при adaptive off/on, фактический вызов probe при on, error verification и отсутствие позднего success после stop. Red npm.cmd test -- src/main/lifecycleCleanup.test.ts -t 'finishes real restored verification|reports a verification error after restoration' --maxWorkers=1 —3 failed/207 skipped,exit1 (.tmp/cancel-switch-verification-red.log). После исправления npm.cmd test -- src/main/lifecycleCleanup.test.ts src/main/serverPickerSwitch.test.ts --maxWorkers=1 —233/233,52.76s,exit0 (.tmp/cancel-switch-verification-focused.log). npm.cmd run typecheck —165 channels/0 public any,exit0 (.tmp/cancel-switch-verification-typecheck.log). Coverage AC927/F210 —exit0. Новый full/build/native выполняется на неизменном source.

CI39599465585 на0fe81ed был полностью success. Revix оставил question о lifecycle lane; проверка показала, что отменяемый picker switch держит внешний switchOwner, напрямую ждёт native restart и полную stop receipt, а не ConnectionLifecycle.start. Restore первым входит в эту lane после cleanup. Независимый stop/shutdown конфликт не обходится и не объявляется успехом; ответ с evidence: https://github.com/newnout6-a11y/vpn/pull/116#discussion_r4336794239. Это не закрывает новое замечание Qodo. Установщик0fe81ed (sha256460effbe172420b762de4bd141c4030f144014c1e7d941e0ca398270d6d51da2,187 ASAR matches,7z exit0) предшествует настоящему verification fix и не выдаётся как окончательный.


Final npm.cmd test на неизменном source/test tree:5834 passed/5 skipped/0 failed;318 passed/2 skipped suites,394.36s,exit0 (.tmp/cancel-switch-verification-full.log,EXIT_CODE=0). npm.cmd run build, включая165-channel typecheck/0 public any, завершил все стадии и запустил следующий native step (.tmp/cancel-switch-verification-build.log). После прерывания транспорта session24154 не восстанавливалась; сохранённые9 native PASS дополнительно подтверждены отдельным node scripts/test-electron-runtime.mjs —9 PASS,exit0 (.tmp/cancel-switch-verification-native-confirmed.log,EXIT_CODE=0). Отдельный typecheck,focused233/233,coverageAC927/F210 и git diff --check —exit0. Production source между проверками не менялся. Перед merge требуются новые automatic Qodo/Revix и success CI окончательного SHA.


## Повторные проверки firewall и очистка при отмене смены сервера (21.10.2026)

Адресное исправление WP-0/WP-3 по журналам установленной 1.1.24: подключение 5.76–8.58 с, обычная смена 5.21–6.06 с, восстановление после отмены 13.26–14.01 с от нажатия. Пассивное чтение firewall занимало 1.19–5.15 с; несколько запросов на одно событие накапливались в очереди вместе с WFP reservation. После отмены restartProtected и picker выполняли два полных stop подряд.

Параллельные getFirewallKillSwitchStatus теперь разделяют только выполняющееся чтение на текущем хвосте firewallQueue. Любая поставленная между ними операция изменяет барьер: следующий читатель ждёт её и получает новое доказательство. Завершённый результат не кэшируется. Во время canonical transition App инвалидирует прежнюю проверку и запрашивает полное чтение после завершения; проигнорированный старый snapshot не запускает побочные проверки. restartProtected передаёт owner-scoped квитанцию завершённого полного stop. Picker пропускает второй stop только при success и baseline/firewall/adapters=true; при отсутствующей, неуспешной или частичной квитанции сохраняется обычная очистка. Отмена после успешного старта/во время IP baseline и приоритет disconnect/shutdown сохраняются. Трассировка: AT-00-003/008, AT-03-001/007/008; F-019/F-021/F-030.

Добавлено 15 регрессионных сценариев. До исправления адресный red-прогон: 9 failed, 6 passed. После исправления адресные 7 suites: 260 passed, 1 существующий skipped, exit 0. Сценарии исполняют production firewall queue, App callback, restartProtected и picker handlers с управляемыми OS/IPC границами: 11 одновременных читателей дают одно полное чтение; мутация между чтениями требует нового результата; неполная cleanup receipt не разрешает пропустить stop.

Проверки на неизменных production source/tests:
- `npm.cmd run typecheck` — exit 0; 165 IPC channels, 0 public any.
- `npm.cmd test -- --reporter=dot` — 5849 passed, 5 существующих skipped, 0 failed; 318 passed/2 skipped suites, 393.08 s, exit 0. Журнал: `vpn-tunnel-enforcer/.tmp/firewall-lifecycle-20261021-full-vitest.log`.
- `python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py` из корня — AC 927/927, F 210/210, exit 0; это полнота трассировки.
- `npx.cmd electron-vite build` — exit 0.
- `node scripts/test-electron-runtime.mjs` — 9 *_PASS, exit 0, изолированные фикстуры. Журнал: `vpn-tunnel-enforcer/.tmp/firewall-lifecycle-20261021-electron-smoke.log`.
- `npm.cmd run dist:win -- --config.directories.output=dist/firewall-lifecycle-20261021` — exit 0; включает повторный typecheck/build и штатную подготовку installer shutdown.
- `git diff --check` — exit 0.

Установщик: `vpn-tunnel-enforcer/dist/firewall-lifecycle-20261021/VPN-Tunnel-Enforcer-Setup-1.1.24.exe`, 139777269 байт, SHA-256 `271e928fa610ee2f9aeaed025202f515dcbf95e1d41d5522f3bd973ec7e4e855`. Все 187 текущих файлов out/ побайтово совпадают с app.asar в win-unpacked. Установщик не запускался; фактическое время подключения/отмены после этих изменений ещё не измерено. Работающее установленное приложение и его VPN не переключались.
