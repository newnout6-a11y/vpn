import { spawnSync } from 'node:child_process'
import { createRequire } from 'node:module'
import { mkdirSync, mkdtempSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { build } from 'esbuild'
import { runWithCleanup, removeWp1WorkDirectory } from './wp1-test-cleanup.mjs'
const require = createRequire(import.meta.url)
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const sameVersion = process.argv.includes('--same-version')
const legacy = process.env.VPNTE_ELECTRON42_EXE
if (!sameVersion && !legacy) {
  console.error('WP1_MIGRATION_NOT_CHECKED: set VPNTE_ELECTRON42_EXE to an actual Electron 42 executable. --same-version runs a distinct local subset, not cross-version acceptance.')
  process.exit(77)
}
const tempRoot = join(root, '.tmp'); mkdirSync(tempRoot, { recursive: true })
const work = mkdtempSync(join(tempRoot, 'wp1-migration-'))
const stdout = await runWithCleanup(async () => {
  const outputs = []
  await build({ entryPoints: [join(root, 'scripts/fixtures/wp1-migration.ts')], outfile: join(work, 'main.cjs'),
    bundle: true, platform: 'node', format: 'cjs', external: ['electron'] })
  for (const phase of [sameVersion ? 'seed44' : 'seed42', 'fail44', 'migrate44', 'unavailable44', 'restart44']) {
    const env = { ...process.env, VPNTE_WP1_WORK: work, VPNTE_WP1_PHASE: phase }
    delete env.NODE_ENV; delete env.ELECTRON_RUN_AS_NODE
    const result = spawnSync(phase === 'seed42' ? legacy : require('electron'), [join(work, 'main.cjs')], {
      cwd: root, env, encoding: 'utf8', windowsHide: true, timeout: 60_000
    })
    if (result.stdout) outputs.push(result.stdout)
    if (result.status !== 0 || !result.stdout?.includes('WP1_MIGRATION_PASS')) {
      if (result.stderr) process.stderr.write(result.stderr)
      throw result.error ?? new Error(`${phase} failed (exit ${result.status})`)
    }
  }
  return outputs.join('')
}, () => removeWp1WorkDirectory(work, tempRoot))
if (stdout) process.stdout.write(stdout)
console.log('WP1_MIGRATION_RESULT', JSON.stringify({ localStoreChecks: 'PASS',
  electron42To44: sameVersion ? 'NOT-CHECKED (same-version seed)' : 'PASS', vmMatrix: 'NOT-CHECKED' }))
