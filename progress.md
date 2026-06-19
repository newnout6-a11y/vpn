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
