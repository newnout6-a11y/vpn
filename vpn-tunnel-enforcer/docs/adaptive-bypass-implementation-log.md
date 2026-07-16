# Adaptive Bypass Implementation Log

## 2026-07-10

### Start

- Began implementation of `adaptive-bypass-plan.md`.
- Confirmed the current controller represents compatibility only through `stealthMode`.
- Confirmed `restartWithLastOptions()` performs a full stop/start, so it cannot be used for an adaptive transition that must preserve the protected network state.
- UI launch is explicitly excluded from this work. Verification will use unit tests, TypeScript build, and packaging only.

### Next

- Add focused regression coverage and package the installer after final audit.

### Implemented

- Added `src/main/adaptiveBypass.ts` with explicit baseline, TLS-compatibility,
  MTU-compatibility, and external-managed modes.
- Added a bounded local learning cache: 24 records, 30-day expiry, and HMAC
  keys derived from a per-install secret plus local network/profile signals.
  Raw network identifiers and profile endpoint fields are never persisted.
- Added `adaptiveBypassEnabled`, enabled by default, to the main and renderer
  settings schemas. The existing manual stealth switch remains available and
  keeps its legacy behavior.
- Split generated sing-box compatibility behavior: TLS record fragmentation
  belongs to TLS-compatibility only; MTU 1280 belongs to MTU-compatibility
  only. Reality and external local proxies do not receive TLS fragmentation.
- Added one post-start tunnel-health verification through the existing
  multi-anchor HTTP probe. On a failed probe the controller performs at most
  one compatibility transition for the same connection.
- Added one Direct VPN fallback after that compatibility attempt: it selects
  only a non-offline sibling with the same `groupId`, never changes the saved
  active profile, and reuses the protected lifecycle transition.
- Routed manual Direct VPN profile changes through the same initial adaptive
  mode selection and monitoring path.
- Added `restartForAdaptiveChange()`. It stops only the owned runtime while
  preserving the kill switch, network baseline, and adapter lockdown. A
  failed replacement start falls back to the normal full cleanup path.
- Added renderer-visible status, a single adaptive toggle, and a reset action
  for learned decisions. Added IPC for status, retry, and reset.

### Verification

- `npm run build` passed without launching the UI.
- `npm test` passed: 65 files and 572 tests.
- `npm run dist:win` passed and produced the NSIS installer.

### Final Pass

- Added the advanced toggle for the one-time sibling-server fallback.
- Rebuilt and retested after routing manual server changes and profile rotation
  through the adaptive mode selection.
- Final verification: `npm test` passed with 65 files / 573 tests and the
  Windows NSIS installer was rebuilt successfully.
