import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, rmdirSync, unlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import ts from 'typescript'
import { describe, expect, it, vi } from 'vitest'

vi.mock('./admin', () => ({ isProcessElevated: async () => false }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))

// Execute the actual production generator, without loading Electron or invoking
// a real elevated boundary. Native cmdlets below are in-memory fixtures only.
const source = readFileSync(join(process.cwd(), 'src/main/firewallKillSwitch.ts'), 'utf8')
const ast = ts.createSourceFile('firewallKillSwitch.ts', source, ts.ScriptTarget.Latest, true)
const functions = ast.statements.filter(node => ts.isFunctionDeclaration(node)
  && ['exceptionRuleNames', 'exceptionPolicyScript'].includes(node.name?.text ?? ''))
if (functions.length !== 2) throw new Error('Production exception generator not found')
const compiled = ts.transpileModule(functions.map(node => node.getText(ast)).join('\n'), {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS }
}).outputText
const generate = new Function('createHash', 'RULE_PREFIX', `${compiled}; return exceptionPolicyScript`)(createHash, 'VPNTE-killswitch') as
  (policy: { apps: string[]; cidrs: string[] }) => string

function run(count: number, mode = 'valid', empty = false): { success: boolean; error: string; bulk: number; association: number; address: number; queries: string[][]; remaining: string[] } {
  const policy = { apps: Array.from({ length: count }, (_, i) => `C:\\Apps\\app-${i}.exe`), cidrs: empty ? [] : ['192.0.2.1'] }
  const script = `
$script:rules=@{};$script:bulk=0;$script:association=0;$script:address=0;$script:mode='${mode}';$script:expectImmediate=${count < 8 ? '$true' : '$false'}
$script:queries=New-Object 'Collections.Generic.List[object]'
if($script:mode -like 'cleanup-*'){
  foreach($name in @('VPNTE-killswitch-user-old','VPNTE-killswitch-allow-extra-ip','VPNTE-killswitch-allow-app','VPNTE-killswitch-userish-foreign','other-user-foreign')){
    $script:rules[$name]=[pscustomobject]@{Name=('id-'+$name);DisplayName=$name;Program=$null}
  }
}
function Get-NetFirewallProfile { 'Domain','Private','Public' | ForEach-Object { [pscustomobject]@{DefaultOutboundAction='Block'} } }
function Get-NetFirewallRule { param([string[]]$DisplayName)
  $script:queries.Add(@($DisplayName))
  $result=@($script:rules.Values | Where-Object { $name=$_.DisplayName; @($DisplayName | Where-Object { $name -like $_ }).Count -gt 0 })
  if($script:bulk -and $DisplayName -notlike '*user-*'){throw 'Unexpected query'}
  if($script:bulk -and $DisplayName -notmatch '\\*$' -and $result.Count -and $result[0].Program){
    if($script:mode -eq 'disabled'){$result[0].Enabled='False'}
    if($script:mode -eq 'replaced'){$result[0].Name='new-identity'}
    if($script:mode -eq 'duplicate-rule'){return @($result[0],$result[0])}
  }
  $result
}
function Remove-NetFirewallRule { param([Parameter(ValueFromPipeline=$true)]$Rule) process {
  if($Rule){
    if($script:mode -eq 'cleanup-remove-error'){throw 'Fixture removal failed'}
    if($script:mode -ne 'cleanup-user-leftover' -or $Rule.DisplayName -notlike 'VPNTE-killswitch-user-*'){$script:rules.Remove($Rule.DisplayName)}
  }
} }
function New-NetFirewallRule { param($DisplayName,$Direction,$Action,$Profile,$Enabled,$Program,$RemoteAddress)
  if($script:expectImmediate -and $Program -and @($script:rules.Values | Where-Object {$_.Program}).Count -ne $script:association){throw 'Small policy lost immediate verification'}
  $script:rules[$DisplayName]=[pscustomobject]@{Name=('id-'+$DisplayName);DisplayName=$DisplayName;Direction=$Direction;Action=$Action;Enabled=$Enabled;Program=$Program;RemoteAddress=$RemoteAddress}
}
function Get-NetFirewallApplicationFilter { param([switch]$All,[Parameter(ValueFromPipeline=$true)]$Rule) process {
  if($All){
    $script:bulk++
    if($script:mode -eq 'query-error'){throw 'Fixture query failed'}
    $filters=@($script:rules.Values | Where-Object {$_.Program} | ForEach-Object { [pscustomobject]@{InstanceID=$_.Name;Program=$_.Program.ToUpperInvariant()} })
    if($script:mode -eq 'missing' -or $script:mode -eq 'foreign-only'){$filters=@($filters | Select-Object -Skip 1)}
    if($script:mode -eq 'duplicate'){$filters+=@($filters[0])}
    if($script:mode -eq 'changed-program'){$filters[0].Program='C:\\wrong.exe'}
    # A foreign rule with the correct Program must never establish ownership.
    $filters+=@([pscustomobject]@{InstanceID='foreign-rule';Program=$script:rules.Values.Where({$_.Program})[0].Program})
    $filters
  }else{
    $script:association++
    if($script:mode -eq 'single-missing'){return}
    $filter=[pscustomobject]@{InstanceID=$Rule.Name;Program=$Rule.Program}
    $filter
    if($script:mode -eq 'single-duplicate'){$filter}
  }
} }
function Get-NetFirewallAddressFilter { param([Parameter(ValueFromPipeline=$true)]$Rule) process {
  $script:address++
  if($script:mode -eq 'changed-address'){[pscustomobject]@{RemoteAddress='198.51.100.2'}}else{[pscustomobject]@{RemoteAddress=$Rule.RemoteAddress}}
} }
$success=$false;$failure=''
try {
${generate(policy)}
  $success=$true
}catch{$failure=$_.Exception.Message}
Write-Output ('RESULT:'+(@{success=$success;error=$failure;bulk=$script:bulk;association=$script:association;address=$script:address;queries=$script:queries.ToArray();remaining=@($script:rules.Keys|Sort-Object)}|ConvertTo-Json -Compress -Depth 4))
`
  const root = join(process.cwd(), '.tmp')
  mkdirSync(root, { recursive: true })
  const directory = mkdtempSync(join(root, 'firewall-readback-'))
  const path = join(directory, 'fixture.ps1')
  try {
    writeFileSync(path, '\ufeff' + script)
    const output = execFileSync(process.env.VPNTE_PWSH || 'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', path],
      { encoding: 'utf8', timeout: 15000, stdio: ['ignore', 'pipe', 'pipe'] })
    const result = output.split(/\r?\n/).find(line => line.startsWith('RESULT:'))
    if (!result) throw new Error('Native fixture result missing')
    return JSON.parse(result.slice(7))
  } finally { unlinkSync(path); rmdirSync(directory) }
}

describe.skipIf(process.platform !== 'win32' && !process.env.VPNTE_PWSH)('native application read-back (AT-03-004/007/008)', () => {
  it('removes only both stale exception groups in one query, then freshly verifies the empty set (AT-03-004/008)', () => {
    const result = run(0, 'cleanup-valid', true)
    expect(result).toMatchObject({ success: true, bulk: 0, association: 0, address: 0 })
    expect(result.queries).toEqual([
      ['VPNTE-killswitch-user-*', 'VPNTE-killswitch-allow-extra-ip'], ['VPNTE-killswitch-user-*']
    ])
    expect(new Set(result.remaining)).toEqual(new Set(['VPNTE-killswitch-allow-app', 'VPNTE-killswitch-userish-foreign', 'other-user-foreign']))
  }, 20000)
  it.each(['cleanup-remove-error', 'cleanup-user-leftover'])('does not report verified exceptions after %s (AT-03-007/008)', mode => {
    const result = run(0, mode, true)
    expect(result.success).toBe(false)
    expect(result.error).toBeTruthy()
    expect(result.remaining).toContain('VPNTE-killswitch-user-old')
    expect(result.remaining).toContain('other-user-foreign')
  }, 20000)
  it('admits the bulk production script to the firewall helper policy before elevation (AT-03-004)', async () => {
    const platform = process.platform
    Object.defineProperty(process, 'platform', { value: 'win32', configurable: true })
    try {
      const helper = await vi.importActual<typeof import('./elevatedPsHelper')>('./elevatedPsHelper')
      const script = generate({ apps: Array.from({ length: 8 }, (_, i) => `C:\\Apps\\${i}.exe`), cidrs: [] })
      await expect(helper.execElevatedPs(script, 1000, 'firewall-killswitch')).rejects.toMatchObject({ code: 'elevated-helper-unavailable' })
    } finally { Object.defineProperty(process, 'platform', { value: platform, configurable: true }) }
  })
  it.each([0, 1, 7, 8, 20])('verifies %i apps with the correct query count and unchanged address proof', count => {
    expect(run(count)).toMatchObject({ success: true, bulk: count >= 8 ? 1 : 0, association: count >= 8 ? 0 : count, address: 1 })
  }, 20000)
  it.each(['missing', 'foreign-only', 'duplicate', 'changed-program', 'replaced', 'disabled', 'duplicate-rule', 'query-error', 'changed-address'])(
    'rejects %s without claiming verified policy', mode => {
      const result = run(8, mode)
      expect(result.success).toBe(false)
      expect(result.error).toBeTruthy()
      expect(result.bulk).toBe(1)
      expect(result.association).toBe(0) // No silent replay or weakened fallback.
    }, 20000)
  it.each(['single-missing', 'single-duplicate'])('rejects invalid small-policy association: %s', mode => {
    expect(run(1, mode)).toMatchObject({ success: false, error: 'Program filter read-back mismatch', bulk: 0, association: 1 })
  }, 20000)
})
