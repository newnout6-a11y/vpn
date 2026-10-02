// Read-only native comparison. Run: node scripts/benchmark-helper-warmup.mjs
// Imports, queries and fresh snapshots only; prints no topology or policy values.
import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'
import assert from 'node:assert/strict'
import ts from 'typescript'
if (process.platform !== 'win32') throw new Error('Native Windows PowerShell required')
const main = name => fileURLToPath(new URL('../src/main/' + name + '.ts', import.meta.url))
const compile = source => ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } }).outputText
const helperSource = await readFile(main('elevatedPsHelper'), 'utf8')
const helperAst = ts.createSourceFile('helper.ts', helperSource, ts.ScriptTarget.Latest, true)
function declaration(ast, name) {
  const statement = ast.statements.find(node => ts.isVariableStatement(node) && node.declarationList.declarations.some(item => item.name.getText(ast) === name))
  if (!statement) throw new Error('Production declaration missing: ' + name)
  return statement.getText(ast)
}
const runner = new Function(compile(declaration(helperAst, 'PS_RUNNER_SCRIPT')) + '\nreturn PS_RUNNER_SCRIPT;')()
const warmup = new Function(compile(declaration(helperAst, 'HELPER_WARMUP_COMMANDS')) + '\nreturn HELPER_WARMUP_COMMANDS;')()
const tunSource = await readFile(main('tunAdapter'), 'utf8')
const { ALL_KNOWN_ALIASES } = await import('data:text/javascript;base64,' + Buffer.from(compile(tunSource)).toString('base64'))
const physicalSource = await readFile(main('physicalAdapterLockdown'), 'utf8')
const physicalAst = ts.createSourceFile('physical.ts', physicalSource, ts.ScriptTarget.Latest, true)
const snapshot = physicalAst.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'snapshotPhysicalAdapters')
if (!snapshot) throw new Error('Production snapshot missing')
let physicalScript
const deps = { cachedAdaptersSnapshot: null, cachedAdaptersSnapshotTime: 0, snapshotPromise: null,
  ALL_KNOWN_ALIASES, psSingleQuote: value => "'" + value.replace(/'/g, "''") + "'",
  runPS: async script => { physicalScript = script; return '[]' }, logEvent: () => {}, isCellularOrTetheringAdapter: () => false }
await new Function(...Object.keys(deps), compile(snapshot.getText(physicalAst)) + '\nreturn snapshotPhysicalAdapters;')(...Object.values(deps))()
if (!physicalScript || /\b(?:Set-|Disable-|Enable-|Remove-|New-)\w+|reg\s+add|netsh/i.test(physicalScript)) throw new Error('Read-only snapshot guard failed')
const reads = [
  "Get-NetFirewallProfile -Profile Domain,Private,Public -ErrorAction Stop | Select-Object Name,DefaultOutboundAction | ConvertTo-Json -Compress",
  physicalScript
]
function measure(warmed) {
  const scripts = [...(warmed ? warmup.map(command => command.script) : []), ...reads]
  const started = performance.now()
  const result = spawnSync('powershell.exe', ['-NoProfile', '-NoLogo', '-NonInteractive', '-Command', runner], {
    input: scripts.map((script, index) => JSON.stringify({ id: index + 1, script })).join('\n') + '\n__EXIT__\n',
    encoding: 'utf8', windowsHide: true, timeout: 30000
  })
  assert.equal(result.error, undefined, 'Native process failed or timed out')
  assert.equal(result.status, 0, 'Native process did not exit normally')
  const responses = result.stdout.trim().split(/\r?\n/).map(line => JSON.parse(line))
  assert.equal(responses.length, scripts.length)
  for (let index = 0; index < responses.length; index++) {
    assert.equal(responses[index].id, index + 1)
    assert.equal(responses[index].exitCode, 0, 'Readonly command failed')
    assert.equal(responses[index].success, true)
    assert.ok(Number.isFinite(responses[index].executionMs) && responses[index].executionMs >= 0)
  }
  const readResponses = responses.slice(-2)
  const readValues = readResponses.map(response => response.stdout.trim() ? JSON.parse(response.stdout.trim()) : [])
  if (warmed) for (const response of responses.slice(0, -2)) assert.equal(response.stdout.trim(), '')
  return { values: readValues, timing: {
    processWallMs: Math.round(performance.now() - started),
    warmupExecutionMs: responses.slice(0, -2).reduce((sum, response) => sum + response.executionMs, 0),
    profileReadMs: readResponses[0].executionMs, physicalSnapshotMs: readResponses[1].executionMs,
    remainingReadExecutionMs: readResponses.reduce((sum, response) => sum + response.executionMs, 0)
  } }
}
const samples = []
for (let iteration = 1; iteration <= 3; iteration++) {
  const cold = measure(false)
  const warmed = measure(true)
  assert.deepEqual(warmed.values, cold.values, 'Fresh native outputs changed; latency comparison is not equivalent')
  samples.push({ iteration, cold: cold.timing, warmed: warmed.timing })
}
console.log(JSON.stringify({ schemaVersion: 1, samples, freshOutputsEquivalent: true, processesExitedNormally: true,
  limits: ['Only helper readonly preparation and fresh reads, not full protected VPN cycles.', 'Remaining read timings exclude prior startup warm-up; process wall time includes it.', 'Immediate connect may still wait for unfinished warm-up.', 'No application queue contention or firewall mutations are modeled.', 'Benchmark aborts if native state changes between each comparison pair.']
}, null, 2))
