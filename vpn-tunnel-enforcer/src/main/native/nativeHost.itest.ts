// AT-07-002 / AT-12-007 / AT-08-007: the native-read host under the real Electron runtime.
// Integration only (npm run test:electron-probe, also run by CI). Regression class: koffi.view over foreign memory
// killed the elevated main process at startup while the same code passed under plain Node (#26).
import { spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { buildSync } from 'esbuild'
import { describe, expect, it } from 'vitest'

const enabled = process.platform === 'win32' && process.env.VPNTE_SKIP_ELECTRON_PROBE !== '1'
const packagedAsar = resolve('dist/win-unpacked/resources/app.asar')
// Plain Node cannot see inside an .asar, so only the archive itself is checked here; Electron loads the file in it.
const packagedWorker = join(packagedAsar, 'out/main/nativeHostWorker.js')

function bundle(dir: string, entry: string, name: string): string {
  const outfile = join(dir, name)
  buildSync({ entryPoints: [resolve(entry)], bundle: true, platform: 'node', format: 'cjs', outfile, external: ['electron', 'koffi'], logLevel: 'silent' })
  return outfile
}

function runE2E(workerPath: string, dir: string, skipAbort = false): string[] {
  const outPath = join(dir, 'e2e.out')
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const electronExe: string = require('electron')
  const main = bundle(dir, 'src/main/native/nativeHostE2E.ts', 'e2e-main.cjs')
  // Even an empty ELECTRON_RUN_AS_NODE switches Electron into plain Node mode: it must be absent.
  const env: NodeJS.ProcessEnv = { ...process.env, VPNTE_E2E_WORKER: workerPath, VPNTE_E2E_OUT: outPath, VPNTE_DISABLE_NATIVE_NET: '0', VPNTE_E2E_SKIP_ABORT: skipAbort ? '1' : '0' }
  delete env.ELECTRON_RUN_AS_NODE
  const result = spawnSync(electronExe, [main, '--disable-gpu'], {
    env,
    encoding: 'utf8', timeout: 180_000, windowsHide: true
  })
  expect(result.error, String(result.error)).toBeUndefined()
  expect(result.status, `electron exit status; stderr: ${result.stderr}`).toBe(0)
  return existsSync(outPath) ? readFileSync(outPath, 'utf8').split(/\r?\n/).filter(Boolean) : []
}

function assertSurvivesHostDeath(lines: string[], expectAbort = true): void {
  const text = lines.join('\n')
  expect(text, text).toContain('E2E_DONE')
  expect(text).not.toContain('E2E_FAILED')
  // Both rounds: koffi really loads and enumerates in the utility process, and nothing reported `unavailable`.
  for (const round of ['r1', 'r2']) {
    expect(lines.some(l => l.startsWith(`${round}.adapters=ok`)), `${round}.adapters: ${text}`).toBe(true)
    expect(lines.some(l => l.startsWith(`${round}.selected-routes=ok(3)`) || l.startsWith(`${round}.selected-routes=refused`)), `${round}.selected-routes: ${text}`).toBe(true)
    expect(lines.filter(l => l.startsWith(`${round}.`) && l.includes('UNAVAILABLE')), text).toEqual([])
  }
  if (expectAbort) {
    // The test worker dies on purpose: the request is reported as unavailable and the main process carries on.
    expect(lines.some(l => l.startsWith('abort=UNAVAILABLE')), text).toBe(true)
    // `unavailable` also covers a timeout, so require the observed fatal exit of the worker (not a timeout kill).
    expect(lines.some(l => l.includes('native host died') && l.includes('native host exited')), text).toBe(true)
    expect(lines.some(l => l.includes('timed out')), text).toBe(false)
    expect(lines.some(l => l.startsWith('main-alive-after-abort')), text).toBe(true)
  }
  // A new host serves the next call.
  expect(lines.some(l => l.startsWith('respawn.adapters=ok')), text).toBe(true)
}

describe.skipIf(!enabled)('native-read host under the Electron runtime', () => {
  it('serves every read twice, survives a fatal host crash and respawns', () => {
    const cache = resolve('node_modules/.cache')
    mkdirSync(cache, { recursive: true })
    const dir = mkdtempSync(join(cache, 'vpnte-host-e2e-'))
    try {
      // The TEST worker (production host + a crash op); the shipped worker has no crash op.
      const worker = bundle(dir, 'src/main/native/nativeHostTestWorker.ts', 'nativeHostTestWorker.cjs')
      assertSurvivesHostDeath(runE2E(worker, dir))
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  }, 240_000)

  // Needs `npm run dist:win` first. Proves asar + unpacked koffi.node resolution inside a utility process.
  it.skipIf(!existsSync(packagedAsar))('serves every read from the packaged app.asar (unpacked koffi.node)', () => {
    const cache = resolve('node_modules/.cache')
    mkdirSync(cache, { recursive: true })
    const dir = mkdtempSync(join(cache, 'vpnte-host-e2e-packaged-'))
    try {
      // The shipped worker has no crash op, so this run proves loading/serving from the asar, not crash isolation.
      assertSurvivesHostDeath(runE2E(packagedWorker, dir, true), false)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  }, 240_000)
})
