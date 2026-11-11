# Work package `delivery` — installer, packaging, CI (final state)

Lane: `installer/**`, `xtask/**`, `resources/engines.toml`, `.github/workflows/*.yml`. Nothing else was edited.

## Status
- [x] xtask: pin manifest module (schema 2, `[[archive]]`, `[[local]]`, `[[tool]]` NSIS), `engines`, `verify`, `nsis`
- [x] xtask: `dist [--skip-build] [--bin-dir DIR]` (release build, notices, stage, exact file-set check,
      makensis `/WX`, checksums) and `version`
- [x] xtask: `smoke-install` (CI only; written and compiled, never run here)
- [x] installer: `vpnte.nsi` + `lang.nsh` (en/ru), licence texts, CLI shims
- [x] CI: `ci.yml` (rust, docs, elevated, package, website unchanged), `release.yml`; `real-vpn.yml` removed
- [x] this file: verified here / only CI / `--setup` contract / decisions / open points

## What exists
| Path | What |
|---|---|
| `xtask/src/manifest.rs` | pin-manifest types (`Sha256Hex`, `RelPath`, `Expect`), validation, `expected_stage`, `verify_stage` (exact file set, every offender named), text normalisation |
| `xtask/src/fetch.rs` | `target/download-cache/<sha256>.zip`, hash checked before caching and on every use; zip member by exact name, hashed before anything is written |
| `xtask/src/engines.rs` | `engines [--offline]` (dev drop `resources/`), `verify` |
| `xtask/src/tools.rs` | `nsis`: pinned NSIS unpacked to `target/tools/nsis` (zip-slip safe, marker written last) |
| `xtask/src/dist.rs` | `dist`: `cargo build --release --locked -p vpnte-app -p vpnte-proxies --bin vpn-tunnel-enforcer --bin vpnte_proxy`, stage `target/stage`, check, `makensis /V2 /WX /INPUTCHARSET UTF8 /DVERSION /DSTAGE /DOUTDIR`, `target/dist/{VPN-Tunnel-Enforcer-Setup-<v>.exe,checksums.txt}` |
| `xtask/src/notices.rs` | `licenses/THIRD-PARTY-NOTICES.txt` from `cargo metadata --locked --filter-platform x86_64-pc-windows-msvc` (linked crates.io deps of the two binaries, identical licence texts printed once) |
| `xtask/src/smoke.rs` | `smoke-install` (refuses unless `CI=true`, and refuses if any installation exists) |
| `resources/engines.toml` | schema 2: 3 archives (7 members incl. 3 licence files), 7 repo files, NSIS 3.13 tool |
| `installer/vpnte.nsi`, `installer/lang.nsh` | the installer / uninstaller (UTF-8 with BOM) |
| `installer/licenses/GPL-3.0.txt` | full GPL-3.0 text (sing-box ships only a notice) |
| `installer/third-party-assets.txt` | hand-kept notices of UI assets compiled into the exe (fonts, flag-icons MIT) |
| `installer/shims/vpnte-proxy.{cmd,ps1}` | old CLI names forwarding to `vpnte-proxy.exe` |
| `.github/workflows/ci.yml`, `release.yml` | CI and tag release |

Installed layout (= `target/stage`, checked to be exactly this set; the uninstaller is added by the installer):
```
$INSTDIR\VPN Tunnel Enforcer.exe   vpnte-proxy.exe   vpnte-proxy.cmd   vpnte-proxy.ps1   Uninstall VPN Tunnel Enforcer.exe
$INSTDIR\resources\sing-box.exe libcronet.dll xray.exe wintun.dll geoip-ru.srs geosite-category-gov-ru.srs
$INSTDIR\licenses\sing-box.txt GPL-3.0.txt xray.txt wintun.txt OFL-InterTight.txt OFL-JetBrainsMono.txt THIRD-PARTY-NOTICES.txt
```

## Verified on this machine
- `cargo test --manifest-path xtask/Cargo.toml --target-dir target/xtask --locked`: 12 tests green (manifest
  validation, `Sha256Hex` / `RelPath` vectors of spec §7.2, stage check: missing / unexpected / changed / empty dir /
  text pins, built files may not shadow pins, notices closure and grouping, the .nsi installs and removes every
  staged root entry and never `RMDir /r $INSTDIR`, checksums format, version, CI guard).
- `cargo clippy … --all-targets --locked -- -D warnings` clean; `cargo fmt --manifest-path xtask/Cargo.toml --check` clean.
- `cargo xtask verify` and `cargo xtask engines --offline`: the dev drop matches the pins (nothing rewritten).
- `cargo xtask nsis`: downloaded `nsis-3.13.zip` from the pinned SourceForge URL, hash matched, 441 files
  unpacked; second run reports `ok` from the marker. `makensis -VERSION` = v3.13.
- Stand-in packaging: `cargo xtask dist --skip-build --bin-dir target/xtask/stand-in` (two copies of the xtask exe
  as the binaries, a one-line notices file): 17 files staged from the cached archives and repo files, exact set
  verified, makensis `/WX` compiled `VPN-Tunnel-Enforcer-Setup-2.0.0.exe` (33.3 MB) + `checksums.txt`. A `/V4`
  compile listed zero warnings. The produced installer was never executed.
- Workflows: parsed with PyYAML; every `uses:` is pinned to a 40-hex commit SHA (checkout v7.0.1, cache v6.1.0,
  upload-artifact v7.0.2, setup-node v7.1.0 — SHAs resolved through the GitHub API); every `cargo xtask`
  command they call exists; `check-coverage.py` exits 0 locally.

## Only CI can verify (not run here, by rule or because the code does not exist yet)
- Full `cargo xtask dist`: the release build of `vpnte-app` / `vpnte-proxies` (the app crate does not exist yet,
  so the `package` and `release` jobs fail until it does) and the notices from real `cargo metadata`.
- Everything the installer does at runtime: silent install, registry identity, shortcuts + AUMID, upgrade over
  itself (chains the installed uninstaller with `--updated`), silent uninstall, nothing left behind, the
  installed engines' `version`, the app's `--smoke` (all in `smoke-install`, job `package`).
- The `--setup` helper (app team) end to end: gate, cleanup, stamping, launch.
- Workspace-wide `cargo fmt --all --check`, clippy, `cargo test --workspace`, and the elevated
  `cargo test --workspace --locked -- --ignored --test-threads=1` (job `elevated`, fresh runner, guarded by an
  "is elevated" check).
- Not covered anywhere yet: the Electron 1.1.24 → Rust in-place upgrade (needs the old installer, which is not
  published anywhere CI could fetch it by pin). See open points.

## Contract for the app team: what the installer and CI call (implement exactly this)

### General rules for `--setup`
- Form: `"<exe>" --setup <command> --install-dir "<dir>" [options]`; `--setup` is argv[1]. `<dir>` is the absolute
  installation directory without a trailing backslash; compare paths case-insensitively after `GetFullPathNameW`.
- The installer runs a COPY of the app exe named `vpnte-setup.exe` from its temp `$PLUGINSDIR` (never the file in
  `<dir>`). Nothing may be derived from the helper's own name or location; everything comes from `--install-dir`.
- Dispatched first in `main()`: before the `runas` relaunch, the single-instance mutex / pipe, file logging, data
  dir creation, legacy import, WebView2 and any window. Never shows UI, a message box or a UAC prompt; writes
  nothing under `<dir>` or the user's data dir (except what a command below says).
- Runs with the installer's token: elevated administrator (the machine-wide elevated user, not necessarily the
  logged-on user).
- Output: nsExec captures stdout + stderr together and decodes them as ANSI, so print ASCII only. On failure print
  exactly one line of plain English to stderr (it is shown under the localized message box text and logged).
  Informational lines on stdout are allowed (logged in the install details). Never print secrets or paths of
  user data.
- Exit codes: `0` success, `1` failed / refused (with the stderr line), `2` usage error (unknown command, missing or
  invalid option). An unknown `--setup` command must exit `2` immediately: never fall through to the UI. The
  installer treats every non-zero code, and nsExec's `error` / `timeout`, as failure.
- Time limits enforced by the installer (nsExec kills the helper and treats it as failure): `await-shutdown`
  150 s, `uninstall` 150 s, `stamp-shortcuts` 60 s, `launch-as-user` 30 s.

### Commands
| Command (exact argv after the exe) | Called when | Must do | Installer on non-zero |
|---|---|---|---|
| `--setup await-shutdown --install-dir <dir>` (optional `--timeout <1..=300 s>`, default 120) | every install (start of the install section, before the previous version is chained and before any file changes) and every uninstall (before cleanup and removal, standalone and chained) | spec delivery §6.6 `await_shutdown`, with this layout (below). Nothing running → exit 0 within ~1 s. | localized `GateFailed` box + the stderr line, exit code 1, setup stops; nothing was changed |
| `--setup uninstall --install-dir <dir>` | standalone uninstall only (never with `--updated`), after `await-shutdown` returned 0, before any file is removed | (1) protection cleanup = the same function as `--cleanup`: every WFP object of our provider incl. persistent `strict` filters, the applied proxy baseline of the current user, legacy firewall rules / WFP objects / tasks (`\VPNTE\BootRecoveryTask`, root `VPNTE Boot Recovery`) — failure → exit 1; (2) roll back the journaled tweaks of the uninstalling user — failure → stdout warning, continue; (3) delete the autostart task `\VPN Tunnel Enforcer` (absent = done) — failure → warning, continue; (4) `RemoveAllDestinations` for AUMID `com.vpntunnelenforcer.app` — best effort. Never touches user data (the uninstaller deletes data itself, only with `--delete-app-data`). | localized `CleanupFailed` box + line, exit code 1, uninstall aborted with the app still installed |
| `--setup stamp-shortcuts --install-dir <dir>` | install, right after NSIS created `%ProgramData%\Microsoft\Windows\Start Menu\Programs\VPN Tunnel Enforcer.lnk` and `%PUBLIC%\Desktop\VPN Tunnel Enforcer.lnk` (the desktop one may be absent) | for each of the two links that exists and targets `<dir>\VPN Tunnel Enforcer.exe`: `IPropertyStore::SetValue(PKEY_AppUserModel_ID, "com.vpntunnelenforcer.app")`, `Commit`, `IPersistFile::Save`. Create nothing else; the installer refreshes the shell itself. | logged only (install continues); CI fails if a link lacks the AUMID |
| `--setup launch-as-user --install-dir <dir>` | finish-page "Run" checkbox; silent install with `--force-run` | start `<dir>\VPN Tunnel Enforcer.exe` without arguments as the interactive desktop user, un-elevated (shell `IShellDispatch2::ShellExecute` via the desktop folder view), and return at once (do not wait). The app then elevates itself as usual. | ignored |

`await-shutdown` details (layout of this brief, not the spec's `engines\vpnte-*` names):
- Owned process = image path (`QueryFullProcessImageNameW`) under `<dir>` — `VPN Tunnel Enforcer.exe`,
  `vpnte-proxy.exe`, `resources\sing-box.exe`, `resources\xray.exe` — or a legacy Electron image
  (`vpnte-sing-box.exe`, `vpnte-xray.exe`, `vpnte-etw-sidecar.exe`, `vpnte-external-proxy.exe`) under `<dir>` or
  `%ProgramData%\VPNTE\runtime\`. NEVER select by image name alone: the user's own `xray.exe` / `sing-box.exe`
  elsewhere is not ours. Exclude the helper's own PID.
- Primary = owned `VPN Tunnel Enforcer.exe` at `<dir>` whose parent is not another owned main-exe process (a parent
  counts only if created before the child). More than one primary, or an owned main-exe process whose path
  cannot be read → refuse `Cannot identify the installed primary client. Close VPNTE normally and retry; no
  processes were killed.` A main exe running from another directory is ignored.
- Bind a handle to the primary (`SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION`) BEFORE signalling; its image
  path must still be `<dir>\VPN Tunnel Enforcer.exe` (else `Primary process identity changed; update refused.`).
- Signal by starting `"<dir>\VPN Tunnel Enforcer.exe" --shutdown-for-update` (the INSTALLED exe: this reaches an
  Electron 1.1.24 primary through Electron's second-instance path and a Rust primary through the pipe).
- Wait up to `--timeout` (else `Client cleanup timed out; update refused.`); the bound handle's exit code must be
  `73` (else `Client exited without cleanup acknowledgement; update refused.`).
- Drain ≤ 5 s (poll 200 ms). Leftover owned processes other than a primary (engines, `vpnte-proxy.exe`, Electron
  helper children of the acknowledged primary) and orphan engines without any primary may be terminated (≤ 3 s
  each); the client primary itself is never terminated. Anything left → `VPNTE background processes remain;
  update refused.` Empty `--install-dir` → `Installation path is missing; update refused.`

### Other app behaviour the installer and CI rely on (not `--setup`)
- `--shutdown-for-update` (lifecycle-app): a secondary forwards it to the primary and exits `0` silently within
  milliseconds; with no primary it exits `0` and starts nothing; the primary exits with `73` after its bounded
  cleanup, always for an installer request, and `73` is produced by no other path.
- Unknown arguments (for example `--updated` from an old launcher) are ignored, never fatal.
- `--no-elevate --smoke` (CI `smoke-install`; env `VPNTE_NO_ELEVATE=1` and `VPNTE_DATA_DIR=<temp>` are also set):
  initialise without UI and without elevation (resources dir `<exe dir>\resources`, engine files present, data
  dir usable), print exactly ONE line to stdout (e.g. `VPN Tunnel Enforcer 2.0.0 smoke ok`), exit `0` within 60 s;
  any failure → non-zero + one stderr line. Until it exists CI accepts `--version` (exit 0 within 30 s, stdout
  containing the workspace version) after killing the `--smoke` run it started (by PID).
- Identity the installer writes and the app must use: AUMID `com.vpntunnelenforcer.app` (release builds), exe
  name `VPN Tunnel Enforcer.exe`, resources dir `<exe dir>\resources`.

## Decisions (made here, owner asleep)
- D1 Layout = brief, not spec §6.3: engines keep their original names under `resources\`, the two rule-sets too;
  root also holds the old CLI names `vpnte-proxy.cmd` / `vpnte-proxy.ps1` as one-line shims forwarding to
  `vpnte-proxy.exe` (external-proxy spec D9: user scripts call these names).
- D2 Pin manifest schema 2: each file has one `install` path (single source of truth). `engines` fills the dev drop
  with the archive members installed under `resources/`; `dist` stages every entry. Licence files of the engine
  archives are pinned members too.
- D3 Repo text files (`[[local]] text = true`: licence texts, shims) are pinned over their LF-normalised content
  and staged with CRLF: git `core.autocrlf=true` here and on GitHub Windows runners, not everywhere, so a raw-byte
  pin would depend on checkout settings. Binary repo files (`.srs`) are pinned raw.
- D4 Licences: engine licence files, the full GPL-3.0 text (sha256 `3972dc97…6986` = gnu.org gpl-3.0.txt; sing-box
  ships only an 808-byte notice), both OFL texts, and `THIRD-PARTY-NOTICES.txt` generated by xtask (engines with
  versions, licences and source links from the manifest; the hand-kept `installer/third-party-assets.txt`; licence
  texts of every linked crates.io crate read from the crate sources). No `cargo about` (one more tool to pin).
  UI packages that vendor more assets (for example Lucide, ISC) must add them to `third-party-assets.txt`.
- D5 One gate run per install, at the start of the install section (no pre-install pages, so `.onInit` would be
  the same moment). Uninstaller gate in the section after the confirm page, not in `un.onInit`: cancelling an
  uninstall must not stop the VPN.
- D6 The helper always runs as `$PLUGINSDIR\vpnte-setup.exe` (installer: extracted from the stage, stored once by the
  datablock optimiser; uninstaller: copied from `$INSTDIR`): the installed exe is never locked by the helper, and
  the helper never has the primary's name or path (the Electron uninstaller's name-based PowerShell gate would
  otherwise count it). So the brief's literal `"$INSTDIR\VPN Tunnel Enforcer.exe" --setup uninstall` runs as
  `"$PLUGINSDIR\vpnte-setup.exe" --setup uninstall --install-dir "$INSTDIR"`: same bytes, explicit directory.
- D7 NSIS creates both links itself (they exist even if the helper fails) and refreshes the shell
  (`SHChangeNotify`, 64-bit `%SystemRoot%\System32\ie4uinit.exe -show` with FS redirection disabled, B-01/B-19);
  the helper only stamps the AUMID (NSIS has no built-in for it; the WinShell plugin is not part of NSIS).
  Fresh install: both links re-created; `--updated`: desktop link only if present; `--no-desktop-shortcut` honoured.
- D8 Upgrade = chain the uninstaller found under the same GUID key (Electron or Rust) from a copy with
  `/S /KEEP_APP_DATA /allusers --keep-shortcuts --updated _?=<dir>`, 5 tries 1 s apart, then Retry/Cancel box,
  then `PreviousFailed` + exit 2. Not launchable at all → log and install over the old files (old behaviour).
  `AllowSkipFiles off`: a file that cannot be written stops setup instead of a silent mixed installation.
- D9 Uninstall with `--updated` opens every installed file for writing before deleting anything; a busy file
  aborts (exit 2) and the old installation stays complete. This replaces electron-builder's rename-aside-and-
  restore, which cannot see the real lock case (a running exe can be renamed) and needs a same-volume temp dir.
- D10 Standalone uninstall without `VPN Tunnel Enforcer.exe` refuses (`AppMissing`): its network rules cannot be
  removed without it; reinstall, then uninstall. The chained (`--updated`) path skips the gate in that case.
- D11 Files are removed by name at the root and folder-wise for `resources\` and `licenses\`; `RMDir "$INSTDIR"`
  only if empty (a unit test forbids `RMDir /r "$INSTDIR"`). `--delete-app-data` (standalone only, after the
  helper's cleanup) removes `%APPDATA%\VPN Tunnel Enforcer`, `%APPDATA%\vpn-tunnel-enforcer`,
  `%LOCALAPPDATA%\VPN Tunnel Enforcer` of the uninstalling user and `%ProgramData%\VPNTE`,
  `%ProgramData%\VPN-Tunnel-Enforcer`. Without it user data always stays. Every install deletes the Electron
  installer's self-copy `%LOCALAPPDATA%\vpn-tunnel-enforcer-updater` (B-23).
- D12 Registry = exactly the Electron value set (no Publisher). Install dir: `/D=` if given, else the existing
  `HKLM\Software\{GUID}\InstallLocation` (64-bit view), else `$PROGRAMFILES64\VPN Tunnel Enforcer`; no directory page.
- D13 WebView2 runtime check: a hint box with the download URL (`/SD IDOK`), never an abort, and no browser opened
  from the elevated installer.
- D14 CI: `rust` (fmt, engines + verify, clippy, tests, also for xtask) → `elevated` and `package` in parallel on
  fresh `windows-2025` runners (privileged tests and the installer never share a machine with each other);
  traceability as a 1-minute Ubuntu job (pure Python over `docs/`). Toolchain pinned by `RUST_TOOLCHAIN: 1.99.1`
  in the workflows (`rust-toolchain.toml` is outside this lane). Caches: cargo registry by lock files; downloads
  by the manifest hash (re-verified after restore, so a cache cannot inject bytes).
- D15 `release.yml`: tag must equal `v<workspace version>` (`cargo xtask version`), no caches, `dist` +
  `smoke-install`, then a DRAFT GitHub release with the installer and `checksums.txt`; the owner publishes it
  (code signing is undecided). `contents: write` only on that job.
- D16 `real-vpn.yml` and its caller job removed (they drove the Electron app through npm; the Rust stand is spec
  §6.10, phase 2), together with the `real_vpn` / `cancel_after_ms` dispatch inputs. The `website` job is kept
  verbatim; its `if: ${{ !inputs.real_vpn }}` is now always true.
- D17 `smoke-install` refuses unless `CI=true` and also when any installation (either generation) exists; it
  installs, checks files byte-for-byte against the stage, registry, links + AUMID, runs the installed engines'
  `version`, starts the app, upgrades over itself, uninstalls through a copy with `_?=`, and checks that the dir,
  both keys and both links are gone. Children it starts are stopped by PID (`taskkill /T`), never by name.

## Open points
- Code signing (ТЗ-06 §10.8): open owner question, not decided here; no `--sign` step exists.
- The `vpnte-app` crate does not exist yet: the `package` / `release` jobs fail until it exists and implements the
  contract above (and `vpnte_proxy` is a real CLI).
- Electron 1.1.24 → Rust upgrade is not exercised automatically: CI would need the old installer (not published).
  If the owner uploads it somewhere stable, add a pinned `[[archive]]`-like entry and a smoke step (install old,
  install new, check).
- Spec items dropped as out of brief: `cargo deny` job, engine canary job, `--sign`, `real-vpn` stand.
- The app should re-stamp the AUMID of its links at start if `stamp-shortcuts` ever failed (lifecycle-app choice).
- After the Electron → Rust upgrade the Electron SYSTEM task `\VPNTE\BootRecoveryTask` (the chained Electron
  uninstaller skips it with `--updated`) stays until the Rust app's first elevated start runs the
  firewall-recovery legacy cleanup (spec §6.6/B-14); no installer step removes it.

## Log
- 05:50 read brief, CONTRACT.md, spec §2.1-2.5, §2.7-2.9, §3.1-3.6, §4, §5, §6.2-6.9, §7.1-7.3.
- 06:00 manifest schema 2 + GPL text + shims + asset notices; xtask restructured into modules.
- 06:05 `cargo xtask nsis` (download from SourceForge, hash OK, unpacked); unit tests, clippy, fmt green.
- 06:10 stand-in `dist --skip-build`: 17 staged files verified, `/WX` compile green, installer not run.
- 06:25 CI written and validated (YAML, SHA pins); traceability exit 0 locally.
- 06:40 contract written; CI guard unit-tested; final checks: 12 tests, clippy, fmt, stand-in compile green.
- 06:50 final stand-in run green again; the stand-in installer in `target/dist` was deleted afterwards so that
  nobody runs it by mistake (it would install the xtask exe as the app). Reproduce the check with:
  `cargo xtask dist --skip-build --bin-dir target/xtask/stand-in` (stand-ins: `vpn-tunnel-enforcer.exe` and
  `vpnte_proxy.exe` = copies of `target/xtask/debug/xtask.exe`, plus any `THIRD-PARTY-NOTICES.txt`).
