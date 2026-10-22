// AT-00-005: read-only diagnostic AFTER the measured scenario; never warm its cold start.
import { readFileSync, mkdirSync, writeFileSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import ts from 'typescript'

export function parsePreparationProbe(child) {
  const fail = () => { throw new Error('PowerShell preparation probe unavailable') }
  if (child.error || child.status !== 0) fail()
  let value
  try { value = JSON.parse(child.stdout.trim()) } catch { fail() }
  if (!value || typeof value.fallbackUsed !== 'boolean' || !['importsMs', 'queryMs'].every(k => Number.isFinite(value[k]) && value[k] >= 0 && value[k] < 30000)
      || !Array.isArray(value.profiles) || value.profiles.length !== 3) fail()
  const profiles = value.profiles.map(p => {
    if (!p || !['Domain', 'Private', 'Public'].includes(p.name) || !['True', 'False', 'NotConfigured'].includes(p.enabled)
        || !['Allow', 'Block', 'NotConfigured'].includes(p.outbound)) fail()
    return { name: p.name, enabled: p.enabled, outbound: p.outbound }
  }).sort((a, b) => a.name.localeCompare(b.name))
  if (new Set(profiles.map(p => p.name)).size !== 3) fail()
  return { importsMs: value.importsMs, queryMs: value.queryMs, fallbackUsed: value.fallbackUsed, profiles }
}

export function buildPreparationProbe(imports) {
  return `$ErrorActionPreference='Stop'
$fallbackUsed=$false
$watch=[Diagnostics.Stopwatch]::StartNew()
${imports}
$importsMs=$watch.ElapsedMilliseconds; $watch.Restart()
$profiles=@(Get-NetFirewallProfile -Profile Domain,Private,Public -ErrorAction Stop | ForEach-Object {
  [pscustomobject]@{name=[string]$_.Name;enabled=[string]$_.Enabled;outbound=[string]$_.DefaultOutboundAction}
})
[pscustomobject]@{importsMs=$importsMs;queryMs=$watch.ElapsedMilliseconds;fallbackUsed=$fallbackUsed;profiles=$profiles}|ConvertTo-Json -Depth 4 -Compress`
}

function measurePreparation() {
  const source = readFileSync('src/main/elevatedPsHelper.ts', 'utf8')
  const ast = ts.createSourceFile('helper.ts', source, ts.ScriptTarget.Latest, true)
  const node = ast.statements.find(n => ts.isVariableStatement(n) && n.declarationList.declarations.some(d => d.name.getText(ast) === 'HELPER_WARMUP_COMMANDS'))
  if (!node) throw new Error('Production warm-up unavailable')
  const commands = new Function(ts.transpileModule(node.getText(ast), { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText + ';return HELPER_WARMUP_COMMANDS;')()
  const query = 'Get-NetFirewallProfile -Profile Domain,Private,Public -ErrorAction Stop | Out-Null'
  if (!commands[0].script.endsWith(query)) throw new Error('Production warm-up query unavailable')
  const fallback = 'catch { Import-Module NetSecurity -ErrorAction Stop }'
  if (!commands[0].script.includes(fallback)) throw new Error('Production warm-up fallback unavailable')
  const imports = { full: 'Import-Module NetSecurity -ErrorAction Stop',
    selective: commands[0].script.slice(0, -query.length).replace(fallback, 'catch { $fallbackUsed=$true; Import-Module NetSecurity -ErrorAction Stop }') }
  const measurements = []
  let baseline
  for (let round = 0; round < 3; round++) for (const variant of round % 2 ? ['selective', 'full'] : ['full', 'selective']) {
    const script = buildPreparationProbe(imports[variant])
    const value = parsePreparationProbe(spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')],
      { encoding: 'utf8', windowsHide: true, timeout: 30000, maxBuffer: 1024 * 1024 }))
    const profiles = JSON.stringify(value.profiles)
    baseline ??= profiles
    if (profiles !== baseline) throw new Error('Preparation probe profiles differ')
    measurements.push({ round, variant, importsMs: value.importsMs, queryMs: value.queryMs, fallbackUsed: value.fallbackUsed })
  }
  return { status: 'PASS', profilesEqual: true, measurements }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  let report
  try { report = measurePreparation() }
  catch { report = { status: 'FAIL', reason: 'preparation-probe-unavailable' }; process.exitCode = 1 }
  mkdirSync('.tmp/real-vpn', { recursive: true })
  writeFileSync('.tmp/real-vpn/ps-preparation.json', JSON.stringify(report, null, 2))
  console.log(JSON.stringify(report))
}
