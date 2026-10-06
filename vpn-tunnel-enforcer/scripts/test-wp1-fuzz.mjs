// AT-01-004/011: opt-in full mutation/property budget, without a shell-specific env command.
import { spawnSync } from 'node:child_process'
import { createRequire } from 'node:module'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
const require = createRequire(import.meta.url)
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const vitestPackage = require.resolve('vitest/package.json')
const vitestBin = resolve(dirname(vitestPackage), require(vitestPackage).bin.vitest)
const result = spawnSync(process.execPath, [vitestBin, 'run',
  'src/main/ipcBoundaryAcceptance.test.ts', 'src/main/redactor.property.test.ts', '--maxWorkers=2'], {
  cwd: root, env: { ...process.env, VPNTE_WP1_FUZZ: '1' }, stdio: 'inherit', timeout: 1_500_000
})
if (result.error) throw result.error
process.exitCode = result.status ?? 1
