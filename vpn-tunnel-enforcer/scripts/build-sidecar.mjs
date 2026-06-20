// Builds the native real-time ETW sidecar (Rust/ferrisetw) and copies the
// resulting executable into `resources/` so electron-builder bundles it.
//
// The Electron integration (`src/main/trafficForensics.ts`) probes for
// `vpnte-etw-sidecar.exe` first and falls back to the bundled PowerShell poller
// when it is absent, so this step is non-fatal when the Rust toolchain is not
// installed (e.g. CI on non-Windows or a fresh dev box): it warns and skips,
// and packaging continues with the PowerShell fallback.
import { spawnSync } from 'child_process'
import { copyFileSync, existsSync, mkdirSync } from 'fs'
import { homedir } from 'os'
import { dirname, join, resolve } from 'path'
import { fileURLToPath } from 'url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const crateDir = join(root, 'native', 'vpnte-etw-sidecar')
const builtExe = join(crateDir, 'target', 'release', 'vpnte-etw-sidecar.exe')
const destDir = join(root, 'resources')
const destExe = join(destDir, 'vpnte-etw-sidecar.exe')
const cargoCandidates = [
  'cargo',
  join(homedir(), '.cargo', 'bin', process.platform === 'win32' ? 'cargo.exe' : 'cargo')
]

function warn(message) {
  console.warn(`[build-sidecar] ${message}`)
}

if (process.platform !== 'win32') {
  warn(`host platform is ${process.platform}, not win32; skipping native ETW sidecar build (PowerShell fallback will be used).`)
  process.exit(0)
}

const cargoPath = cargoCandidates.find((candidate) => {
  const probe = spawnSync(candidate, ['--version'], { stdio: 'ignore', shell: true })
  return probe.status === 0
})
const cargoProbe = cargoPath ? { status: 0 } : { status: 1 }
if (cargoProbe.status !== 0) {
  warn('cargo (Rust toolchain) not found on PATH; skipping native ETW sidecar build (PowerShell fallback will be used).')
  warn('Install it via https://rustup.rs (target x86_64-pc-windows-msvc) to ship the native sidecar.')
  process.exit(0)
}

console.log('[build-sidecar] building native ETW sidecar (cargo build --release)...')
const build = spawnSync(cargoPath, ['build', '--release'], {
  cwd: crateDir,
  stdio: 'inherit',
  shell: true
})
if (build.status !== 0) {
  console.error('[build-sidecar] cargo build failed.')
  process.exit(build.status ?? 1)
}

if (!existsSync(builtExe)) {
  console.error(`[build-sidecar] expected build output not found: ${builtExe}`)
  process.exit(1)
}

mkdirSync(destDir, { recursive: true })
copyFileSync(builtExe, destExe)
console.log(`[build-sidecar] copied ${builtExe} -> ${destExe}`)
