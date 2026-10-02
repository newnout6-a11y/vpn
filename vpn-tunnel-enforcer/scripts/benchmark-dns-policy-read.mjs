// Read-only Windows benchmark. Run: node scripts/benchmark-dns-policy-read.mjs
// Reports transport timings and output equivalence, never registry values.
import { spawn, execFileSync } from 'node:child_process'
import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { createInterface } from 'node:readline'
import { once } from 'node:events'
import assert from 'node:assert/strict'
import ts from 'typescript'

if (process.platform !== 'win32') throw new Error('Native Windows PowerShell required')
const iterations = 5
const source = await readFile(fileURLToPath(new URL('../src/main/recoveryPsProtocol.ts', import.meta.url)), 'utf8')
const compiled = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } }).outputText
const { DNS_POLICY_SNAPSHOT_SCRIPT, recoveryWorkerScript } = await import('data:text/javascript;base64,' + Buffer.from(compiled).toString('base64'))
const executable = 'powershell.exe'
const env = { ...process.env }
for (const key of Object.keys(env)) if (key.toLowerCase() === 'psmodulepath') delete env[key]
const encode = script => Buffer.from(script, 'utf16le').toString('base64')
const prefix = "$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
const coldMs = []
let reference
for (let index = 0; index < iterations; index++) {
  const started = performance.now()
  const stdout = execFileSync(executable, ['-NoProfile', '-NoLogo', '-NonInteractive', '-EncodedCommand', encode(prefix + DNS_POLICY_SNAPSHOT_SCRIPT)], {
    env, windowsHide: true, timeout: 15000, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe']
  })
  coldMs.push(performance.now() - started)
  const rows = JSON.parse(stdout.replace(/^\uFEFF/, '').trim())
  assert.equal(rows.length, 2)
  reference ??= rows
  assert.deepEqual(rows, reference, 'Registry values changed between measurements')
}
const started = performance.now()
const worker = spawn(executable, ['-NoProfile', '-NoLogo', '-NonInteractive', '-EncodedCommand', encode(recoveryWorkerScript(process.env.ProgramData || 'C:\\ProgramData'))], {
  env, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe']
})
const closed = once(worker, 'close')
// Attach rejection handling immediately; a spawn error must not be unhandled.
closed.catch(() => undefined)
worker.stderr.on('data', () => {})
worker.stdin.on('error', () => {})
const lines = createInterface({ input: worker.stdout })[Symbol.asyncIterator]()
async function nextFrame() {
  let timer
  try {
    const line = await Promise.race([
      lines.next(),
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('Worker response timed out')), 15000) })
    ])
    if (line.done) throw new Error('Worker output closed before response')
    return JSON.parse(line.value.replace(/^\uFEFF/, '').trim())
  } finally { clearTimeout(timer) }
}
let startupMs
const workerMs = []
try {
  assert.deepEqual(await nextFrame(), { id: 0, ok: true, value: 'RECOVERY_WORKER_READY' })
  startupMs = performance.now() - started
  for (let id = 1; id <= iterations; id++) {
    const submitted = performance.now()
    worker.stdin.write(JSON.stringify({ id, request: { op: 'inspect-dns-policy' } }) + '\n')
    const frame = await nextFrame()
    workerMs.push(performance.now() - submitted)
    assert.equal(frame.id, id)
    assert.equal(frame.ok, true)
    assert.equal(typeof frame.value, 'string')
    assert.deepEqual(JSON.parse(frame.value), reference, 'Fixed worker and standalone readers differ')
  }
} finally {
  worker.stdin.end('__EXIT__\n')
  const killTimer = setTimeout(() => worker.kill(), 1000)
  try {
    const [code, signal] = await closed
    assert.equal(code, 0, 'Worker did not exit normally')
    assert.equal(signal, null, 'Worker required forced termination')
  } finally { clearTimeout(killTimer) }
}
const summary = samples => {
  const sorted = [...samples].sort((a, b) => a - b)
  return { samplesMs: samples.map(ms => Math.round(ms * 100) / 100), medianMs: Math.round(sorted[Math.floor(sorted.length / 2)] * 100) / 100 }
}
console.log(JSON.stringify({
  schemaVersion: 1, operation: 'inspect-dns-policy', iterations,
  startupMs: Math.round(startupMs * 100) / 100,
  coldStandalone: summary(coldMs), persistentWorker: summary(workerMs),
  outputsEquivalent: true, workerClosed: true,
  limits: ['Read-only registry operation, not full VPN latency.', 'Worker startup reported separately; steady-state excludes it.', 'No contention or module warm-up in this isolated worker.', 'Benchmark aborts if registry values change during measurement.']
}, null, 2))
