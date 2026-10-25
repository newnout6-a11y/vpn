// AT-03-006/007/010/011: standalone opt-in OS mutations on a newly created NIC.
// No Electron, VPN profiles, app startup, or selection of an existing adapter.
import { spawnSync } from 'node:child_process'
import { mkdirSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const args = process.argv.slice(2)
if (args.some(arg => arg !== '--isolated') || args.length > 1) throw new Error('Usage: npm run bench:adapter-lockdown -- [--isolated]')
if (process.platform !== 'win32' || process.arch !== 'x64') throw new Error('Windows x64 is required')
function run(exe, parameters) {
  const result = spawnSync(exe, parameters, { cwd: root, windowsHide: true, stdio: 'inherit' })
  if (result.error) throw result.error
  if (result.status !== 0) process.exit(result.status ?? 1)
}
const build = join(root, 'scripts/build-adapter-lockdown.mjs')
run(process.execPath, [build])
run(process.execPath, [build, '--benchmark'])
const worker = join(root, 'resources/vpnte-adapter-lockdown.exe')
const benchmark = join(root, '.tmp/adapter-lockdown-benchmark/benchmark.exe')
run(worker, ['--self-test'])
run(benchmark, ['--self-test'])
if (args.includes('--isolated')) {
  const work = join(root, '.tmp/adapter-lockdown-benchmark')
  mkdirSync(work, { recursive: true })
  console.log('[adapter-native] real isolated NIC: apply, verify, restore, verify, remove (requires administrator)')
  run(benchmark, [worker, join(root, 'resources/wintun.dll'), work])
} else {
  console.log('[adapter-native] self-tests complete; elevated real test: npm run bench:adapter-lockdown -- --isolated')
}
