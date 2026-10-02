// WP-11 Electron migration; AT-01-001/003/004/007/010, F-166/F-167.
// Runs real Electron with the production preload and security modules, using
// isolated userData. Does not start VPN runtimes or change network/clipboard state.
import { spawnSync } from 'node:child_process'
import { createRequire } from 'node:module'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { build } from 'esbuild'

const require = createRequire(import.meta.url)
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const tempRoot = join(root, '.tmp')
mkdirSync(tempRoot, { recursive: true })
const work = mkdtempSync(join(tempRoot, 'electron-smoke-'))
try {
  writeFileSync(join(work, 'renderer.html'), '<!doctype html><meta http-equiv="Content-Security-Policy" content="default-src \'none\'"><title>Electron migration smoke</title>')
  writeFileSync(join(work, 'other.html'), '<!doctype html><title>Untrusted entry</title>')
  await build({
    entryPoints: [join(root, 'scripts/fixtures/electron-runtime-smoke.ts')],
    outfile: join(work, 'main.cjs'), bundle: true, platform: 'node',
    format: 'cjs', external: ['electron']
  })
  const env = { ...process.env }
  delete env.ELECTRON_RUN_AS_NODE
  delete env.NODE_ENV // No unit-test escape or test cipher in this native smoke.
  env.VPNTE_SMOKE_DIR = work
  env.VPNTE_SMOKE_PRELOAD = join(root, 'out/preload/index.js')
  env.VPNTE_SMOKE_VERSION = require('../package.json').devDependencies.electron
  const result = spawnSync(require('electron'), [join(work, 'main.cjs')], {
    cwd: root, env, encoding: 'utf8', windowsHide: true, timeout: 60_000
  })
  if (result.stdout) process.stdout.write(result.stdout)
  if (result.status !== 0 || !result.stdout?.includes('ELECTRON_SMOKE_PASS')) {
    if (result.stderr) process.stderr.write(result.stderr)
    throw result.error ?? new Error(`Electron smoke failed (exit ${result.status})`)
  }
} finally {
  // Only this run's newly created directory is removed.
  if (dirname(work) !== tempRoot) throw new Error('Unexpected smoke cleanup path')
  rmSync(work, { recursive: true, force: true })
}
