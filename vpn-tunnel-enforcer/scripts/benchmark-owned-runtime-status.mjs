// Read-only comparison of the actual lifecycle fallback and typed worker.
// Run from vpn-tunnel-enforcer; no VPN process, registry or network mutations.
import { readFileSync, writeFileSync, existsSync } from 'node:fs'
import { createRequire } from 'node:module'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import assert from 'node:assert/strict'
import ts from 'typescript'

if (process.platform !== 'win32') throw new Error('Windows benchmark required')
const require = createRequire(import.meta.url)
function compile(path, dependencies = {}) {
  const js = ts.transpileModule(readFileSync(path, 'utf8'), {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS }
  }).outputText
  const exports = {}
  new Function('require', 'exports', js)(name => name in dependencies ? dependencies[name] : require(name), exports)
  return exports
}
const protocol = compile('src/main/recoveryPsProtocol.ts')
const transport = compile('src/main/recoveryPsWorker.ts', {
  './admin': { isProcessElevated: async () => false }, './appLogger': { logEvent: () => {} }, './recoveryPsProtocol': protocol
})
const runtimeDir = 'C:\\VPNTE-native-readonly-benchmark'
assert.equal(existsSync(runtimeDir), false, 'Benchmark directory must be absent')
const source = readFileSync('src/main/tunController.ts', 'utf8')
const ast = ts.createSourceFile('tunController.ts', source, ts.ScriptTarget.Latest, true)
const reader = ast.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'isOwnedTunRuntimeRunning')
assert.ok(reader, 'Production runtime status reader required')
let legacyScript
const deps = {
  getTunRuntimeDir: () => runtimeDir,
  executeRecoveryOperation: async () => { throw new transport.RecoveryWorkerError('unavailable', 'benchmark fallback extraction') },
  RecoveryWorkerError: transport.RecoveryWorkerError,
  RUNTIME_EXE_NAME: 'vpnte-sing-box.exe', psSingleQuote: text => "'" + text.replace(/'/g, "''") + "'",
  runPowerShell: async script => { legacyScript = script; return 'false' }, logEvent: () => {}
}
const compiled = ts.transpileModule(reader.getText(ast).replace(/^export /, '') + '\nreturn isOwnedTunRuntimeRunning;', {
  compilerOptions: { target: ts.ScriptTarget.ES2022 }
}).outputText
await new Function(...Object.keys(deps), compiled)(...Object.values(deps))(true)
assert.ok(legacyScript && !/\b(?:Set-|Remove-|Stop-|Start-|New-)\w+/.test(legacyScript))
const env = { ...process.env }
for (const key of Object.keys(env)) if (key.toLowerCase() === 'psmodulepath') delete env[key]
const exec = promisify(execFile)
const encoded = Buffer.from("$ErrorActionPreference='Stop';" + legacyScript, 'utf16le').toString('base64')
const workerStarted = performance.now()
const worker = new transport.RecoveryPsWorker(process.env.ProgramData || 'C:\\ProgramData')
const request = { op: 'inspect-runtime', runtimeDir }
const rounds = []
let startupAndFirstReadMs
try {
  assert.equal(await worker.execute(request, 5000), 'false')
  startupAndFirstReadMs = performance.now() - workerStarted
  for (let round = 1; round <= 5; round++) {
    const cold = async () => {
      const started = performance.now()
      const { stdout } = await exec('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', encoded], {
        env, windowsHide: true, timeout: 5000, encoding: 'utf8', maxBuffer: 4096
      })
      assert.equal(stdout.trim(), 'false')
      return performance.now() - started
    }
    const warm = async () => {
      const started = performance.now()
      assert.equal(await worker.execute(request, 5000), 'false')
      return performance.now() - started
    }
    // Alternate order; each operation executes a new CIM query.
    let freshProcessMs, productionWorkerMs
    if (round % 2) { freshProcessMs = await cold(); productionWorkerMs = await warm() }
    else { productionWorkerMs = await warm(); freshProcessMs = await cold() }
    rounds.push({ round, freshProcessMs: +freshProcessMs.toFixed(1), productionWorkerMs: +productionWorkerMs.toFixed(1), freshAbsentOutcomeEqual: true })
  }
} finally { await worker.stop() }
assert.equal(worker.hasExited, true)
const report = {
  at: new Date().toISOString(), startupAndFirstReadMs: +startupAndFirstReadMs.toFixed(1), rounds,
  workerExitConfirmed: worker.hasExited,
  limits: ['Real production fixed query and worker; only an absent runtime directory.',
    'First worker observation includes startup; warm samples include request roundtrip and new CIM execution.',
    'No actual VPN process exit, protected connect/stop or leak acceptance measured.']
}
writeFileSync('.tmp/owned-runtime-status-native-benchmark.json', JSON.stringify(report, null, 2) + '\n')
console.log(JSON.stringify(report, null, 2))
