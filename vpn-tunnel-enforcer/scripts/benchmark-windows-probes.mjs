// Read-only benchmark. No VPN, adapter, firewall, registry or ACL mutations.
import { spawn, execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { performance } from 'node:perf_hooks'
import { mkdir, writeFile } from 'node:fs/promises'
import { resolve } from 'node:path'

if (process.platform !== 'win32') throw new Error('Windows PowerShell benchmark requires Windows')
const execute = promisify(execFile)
const samples = 5
const probes = {
  noop: '1',
  firewallProfiles: '@(Get-NetFirewallProfile -Profile Domain,Private,Public -ErrorAction Stop).Count',
  ownedFirewallRules: '(Get-NetFirewallRule -DisplayName "VPNTE-killswitch*" -ErrorAction SilentlyContinue | Measure-Object).Count',
  adapters: '@(Get-NetAdapter -ErrorAction Stop).Count',
  tunRoutes: '@(Get-NetRoute -DestinationPrefix "0.0.0.0/0", "0.0.0.0/1" -ErrorAction SilentlyContinue).Count'
}
const results = { createdAt: new Date().toISOString(), powershell: 'powershell.exe', samples, readOnly: true, cold: {}, warm: {} }
for (const [name, script] of Object.entries(probes)) {
  results.cold[name] = []
  for (let i = 0; i < samples; i++) {
    const start = performance.now()
    try {
      const encoded = Buffer.from("$ErrorActionPreference='Stop';" + script, 'utf16le').toString('base64')
      await execute('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', encoded], { windowsHide: true, timeout: 15000 })
      results.cold[name].push({ ms: Math.round(performance.now() - start), success: true })
    } catch { results.cold[name].push({ ms: Math.round(performance.now() - start), success: false }) }
  }
}
const runner = `
[Console]::OutputEncoding=[Text.Encoding]::UTF8
[Console]::WriteLine('READY');[Console]::Out.Flush()
while($line=[Console]::In.ReadLine()) {
  $ErrorActionPreference='Stop'
  try {
    $request=$line|ConvertFrom-Json
    $timer=[Diagnostics.Stopwatch]::StartNew()
    & ([ScriptBlock]::Create($request.script)) | Out-Null
    $timer.Stop()
    @{success=$true;executionMs=$timer.ElapsedMilliseconds}|ConvertTo-Json -Compress
  } catch { @{success=$false}|ConvertTo-Json -Compress }
  [Console]::Out.Flush()
}`
const workerStart = performance.now()
const worker = spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(runner, 'utf16le').toString('base64')], { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] })
let waiting
let buffer = ''
const lines = []
worker.stdout.setEncoding('utf8')
worker.stdout.on('data', chunk => {
  buffer += chunk
  let newline
  while ((newline = buffer.indexOf('\n')) !== -1) {
    const line = buffer.slice(0, newline).trim()
    buffer = buffer.slice(newline + 1)
    if (waiting) { const settle = waiting; waiting = undefined; settle(line) }
    else lines.push(line)
  }
})
worker.stderr.resume()
function nextLine() {
  if (lines.length) return Promise.resolve(lines.shift())
  return new Promise((accept, reject) => {
    const timeout = setTimeout(() => { waiting = undefined; reject(new Error('Read-only worker deadline')) }, 15000)
    waiting = line => { clearTimeout(timeout); accept(line) }
  })
}
try {
  if (await nextLine() !== 'READY') throw new Error('Read-only worker did not start')
  results.warmStartupMs = Math.round(performance.now() - workerStart)
  for (const [name, script] of Object.entries(probes)) {
    results.warm[name] = []
    for (let i = 0; i < samples; i++) {
      const reply = nextLine()
      const start = performance.now()
      worker.stdin.write(JSON.stringify({ script }) + '\n')
      const response = JSON.parse(await reply)
      results.warm[name].push({ ms: Math.round(performance.now() - start), ...response })
    }
  }
} finally { worker.stdin.end(); worker.kill() }
const outputDir = resolve('.tmp')
await mkdir(outputDir, { recursive: true })
const output = resolve(outputDir, 'windows-probe-benchmark.json')
await writeFile(output, JSON.stringify(results, null, 2) + '\n')
const median = values => [...values].sort((a, b) => a - b)[Math.floor(values.length / 2)]
for (const name of Object.keys(probes)) {
  console.log(JSON.stringify({ probe: name, coldMedianMs: median(results.cold[name].map(x => x.ms)), warmFirstMs: results.warm[name][0].ms, warmMedianMs: median(results.warm[name].map(x => x.ms)), allSucceeded: [...results.cold[name], ...results.warm[name]].every(x => x.success) }))
}
console.log('Detailed samples: ' + output)
