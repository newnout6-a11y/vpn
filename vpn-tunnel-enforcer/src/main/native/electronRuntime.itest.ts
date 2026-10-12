// AT-07-002 / AT-08-007: every native reader must run inside the real Electron runtime without aborting it.
// Integration only (npm run test:native-itest). Regression: koffi.view over foreign memory killed the
// elevated main process at startup under Electron while the same code passed under plain Node.
import { spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { buildSync } from 'esbuild'
import { describe, expect, it } from 'vitest'

const enabled = process.platform === 'win32' && process.env.VPNTE_SKIP_ELECTRON_PROBE !== '1'

describe.skipIf(!enabled)('native readers under the Electron runtime', () => {
  it('complete two rounds without a fatal error', () => {
    // Inside the project so the bundle resolves the external 'koffi' (also for its dynamic import()).
    const cache = resolve('node_modules/.cache')
    mkdirSync(cache, { recursive: true })
    const dir = mkdtempSync(join(cache, 'vpnte-electron-probe-'))
    try {
      const outfile = join(dir, 'probe.cjs')
      buildSync({
        entryPoints: [resolve('src/main/native/electronRuntimeProbe.ts')], bundle: true, platform: 'node', format: 'cjs',
        outfile, external: ['electron', 'koffi'], logLevel: 'silent'
      })
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const electronExe: string = require('electron')
      const result = spawnSync(electronExe, [outfile], {
        env: { ...process.env, ELECTRON_RUN_AS_NODE: '1', VPNTE_DISABLE_NATIVE_NET: '0', NODE_PATH: resolve('node_modules') },
        encoding: 'utf8', timeout: 90000, windowsHide: true
      })
      const output = `${result.stdout}\n${result.stderr}`
      expect(output).not.toContain('FATAL ERROR')
      expect(output).toContain('round2')
      // koffi must really load and enumerate under Electron (a silent throw everywhere would also "not crash").
      expect(output).toMatch(/round2 adapters=\d+/)
      expect(output).toContain('PROBE_DONE')
      expect(result.status).toBe(0)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  }, 120000)
})
