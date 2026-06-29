// src/main/snapshotBootstrap.ts
//
// V8 snapshot loader for the Electron main process — OPTIONAL & SAFE.
//
// When a custom V8 startup snapshot has been generated (via
// scripts/generate-v8-snapshot.mjs) and loaded by Electron, the
// deserialized module exports are exposed on the `snapshotResult`
// global. This module patches Node's Module._load to return those
// pre-deserialized exports for the snapshot'd packages, skipping the
// parse -> compile -> execute cycle entirely (~200-500 ms saved at
// startup).
//
// If no snapshot is active (the normal case), this module is a COMPLETE
// NO-OP: every require falls through to the real filesystem loader and
// the app behaves identically to a non-snapshot build.
//
// This module is imported as the FIRST statement in src/main/index.ts
// so the require patch is installed before any externalized dependency
// is loaded.
//
// ── Which modules are intercepted ───────────────────────────────────
//   Only the heaviest externalized deps: axios, electron-store, socks,
//   sudo-prompt. Built-in Node modules are already in Electron's
//   default snapshot.
//
// ── Safety ──────────────────────────────────────────────────────────
//   Everything is wrapped in try/catch. If the snapshot is corrupt, the
//   wrong V8 version, or the global is missing, the app falls back to
//   normal require with zero impact.

const SNAPSHOT_MODULES = ['axios', 'electron-store', 'socks', 'sudo-prompt'] as const

function installSnapshotLoader(): void {
  try {
    const snapshotResult = (globalThis as any).snapshotResult
    if (!snapshotResult || typeof snapshotResult !== 'object') return

    const cache: Record<string, unknown> =
      snapshotResult.modules ?? snapshotResult.requireCache ?? {}
    const available = new Set(
      SNAPSHOT_MODULES.filter((mod) => cache[mod] !== undefined)
    )
    if (available.size === 0) return

    // Node's internal module loader. `require('module')` gives us the
    // Module class whose _load is the single chokepoint every require()
    // flows through. We use globalThis.require (not an ES import) so
    // this file has zero non-builtin dependencies and never triggers a
    // disk load for the snapshot'd packages it intends to intercept.
    const Module = (globalThis as any).require('module')
    if (!Module || typeof Module._load !== 'function') return

    const originalLoad = Module._load
    Module._load = function (request: string, parent: unknown, isMain: boolean) {
      if (available.has(request)) {
        const cached = cache[request]
        if (cached !== undefined) return cached
      }
      return originalLoad.call(this, request, parent, isMain)
    }
  } catch {
    // Never let snapshot loading break the app — silently fall back
    // to the normal filesystem require path.
  }
}

installSnapshotLoader()
