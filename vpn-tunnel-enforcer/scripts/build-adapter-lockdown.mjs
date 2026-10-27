// The same standalone Windows binary is shipped and used by the component benchmark.
import { spawnSync } from 'node:child_process'
import { existsSync, mkdirSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const benchmark = process.argv.includes('--benchmark')
if (process.platform !== 'win32') {
  console.log('[adapter-native] Windows-only build skipped; explicit legacy path remains available.')
  process.exit(0)
}
if (process.arch !== 'x64') throw new Error('Adapter native build currently supports x64 only')
const source = join(root, benchmark ? 'native/adapter-lockdown/benchmark.cpp' : 'native/adapter-lockdown/worker.cpp')
const output = join(root, benchmark ? '.tmp/adapter-lockdown-benchmark/benchmark.exe' : 'resources/vpnte-adapter-lockdown.exe')
mkdirSync(dirname(output), { recursive: true })
const candidates = ['g++.exe', 'C:\\ProgramData\\mingw64\\mingw64\\bin\\g++.exe', 'C:\\msys64\\mingw64\\bin\\g++.exe']
const compiler = candidates.find(path => spawnSync(path, ['--version'], { windowsHide: true, stdio: 'ignore' }).status === 0)
if (compiler) {
  const result = spawnSync(compiler, ['-std=c++17', '-O2', '-Wall', '-Wextra', '-Werror', '-DUNICODE', '-D_UNICODE',
    '-static', ...(benchmark ? ['-municode'] : []), source, '-o', output, '-lole32', '-luuid', '-liphlpapi', '-lws2_32', '-ladvapi32'], { cwd: root, windowsHide: true, stdio: 'inherit' })
  if (result.status !== 0) process.exit(result.status ?? 1)
} else {
  // Windows hosted/developer machines with MSVC use the installed SDK and compiler.
  const vswhere = join(process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)', 'Microsoft Visual Studio/Installer/vswhere.exe')
  if (!existsSync(vswhere)) throw new Error('Native build requires MinGW-w64 g++ or Visual Studio C++ Build Tools')
  const found = spawnSync(vswhere, ['-latest', '-products', '*', '-requires', 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64', '-property', 'installationPath'], { encoding: 'utf8', windowsHide: true })
  const installation = found.stdout?.trim()
  if (!installation || /[\r\n"&|<>^%]/.test(installation + source + output)) throw new Error('MSVC build path unavailable or unsupported')
  const temporary = join(root, '.tmp/adapter-native-build')
  mkdirSync(temporary, { recursive: true })
  const command = `"${join(installation, 'VC/Auxiliary/Build/vcvars64.bat')}" >nul && cl.exe /nologo /std:c++17 /O2 /EHsc /W4 /MT /DUNICODE /D_UNICODE "${source}" /Fe:"${output}" /link ole32.lib uuid.lib iphlpapi.lib ws2_32.lib advapi32.lib`
  const result = spawnSync(process.env.ComSpec || 'cmd.exe', ['/d', '/s', '/c', `"${command}"`], { cwd: temporary, windowsHide: true, stdio: 'inherit' })
  if (result.status !== 0) process.exit(result.status ?? 1)
}
console.log(`[adapter-native] compiled ${benchmark ? '.tmp/adapter-lockdown-benchmark/benchmark.exe' : 'resources/vpnte-adapter-lockdown.exe'}`)
