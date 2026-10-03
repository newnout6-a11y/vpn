// AT-06-003 / AT-02-002 / AT-00-003: selected routes and exact current ownership.
// Supporting native route evidence only; this does not run the L3 egress oracle.
import { readFileSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import ts from 'typescript'
import { describe, expect, it, vi } from 'vitest'

const source = ts.createSourceFile('tunController.ts', readFileSync('src/main/tunController.ts', 'utf8'), ts.ScriptTarget.Latest, true)
const declaration = source.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'areTunRoutesActive')!
const js = ts.transpileModule(declaration.getText(source).replace(/^export\s+/, ''), { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText
const guid = '11111111-2222-3333-4444-555555555555'
function harness() {
  const state = { running: true, pid: 1234, startedAt: 1 }
  let alias = 'Ethernet 5'
  const owner: any = { schemaVersion: 1, owner: 'VPNTE', alias, interfaceGuid: guid }
  const runPowerShell = vi.fn(async (_script: string, _timeout: number) => 'true')
  const readRecoveryManifest = vi.fn(async (_name: string, validate: (v: any) => any) => owner && validate(owner))
  const logEvent = vi.fn()
  const run = new Function('currentStatus', 'getTunAdapterAlias', 'readRecoveryManifest', 'runPowerShell', 'psSingleQuote', 'logEvent', js + '\nreturn areTunRoutesActive;')(
    state, () => alias, readRecoveryManifest, runPowerShell, (s: string) => "'" + s.replace(/'/g, "''") + "'", logEvent)
  return { run, state, owner, runPowerShell, readRecoveryManifest, setAlias: (value: string) => { alias = value } }
}

describe.runIf(process.platform === 'win32')('selected TUN route probe', () => {
  it.each(['owner', 'guid', 'alias'])('rejects invalid %s ownership before native dispatch', async field => {
    const h = harness()
    if (field === 'owner') h.owner.owner = 'foreign'
    if (field === 'guid') h.owner.interfaceGuid = 'invalid'
    if (field === 'alias') h.owner.alias = 'Ethernet 6'
    expect(await h.run()).toBe(false)
    expect(h.runPowerShell).not.toHaveBeenCalled()
  })
  it.each(['missing', 'stopped', 'failure', 'malformed', 'late-session'])('fails closed for %s evidence', async scenario => {
    const h = harness()
    if (scenario === 'missing') h.readRecoveryManifest.mockResolvedValue(null)
    if (scenario === 'stopped') h.state.running = false
    if (scenario === 'failure') h.runPowerShell.mockRejectedValue(new Error('deadline'))
    if (scenario === 'malformed') h.runPowerShell.mockResolvedValue('not true')
    if (scenario === 'late-session') h.runPowerShell.mockImplementation(async () => { h.state.pid++; return 'true' })
    expect(await h.run()).toBe(false)
  })
  it.each(['fragmented', 'competing', 'missing-route', 'wrong-guid', 'down', 'foreign-driver', 'wrong-address', 'query-failure'])('executes the production script for %s routes', async scenario => {
    const h = harness()
    h.runPowerShell.mockImplementation(async (script, timeout) => {
      expect(timeout).toBe(3000)
      expect(script).not.toMatch(/Get-NetRoute|Set-Net|New-Net/)
      const fake = `
function Get-CimInstance {
 param($Namespace,$ClassName,$Filter)
 if ($Namespace -ne 'root/StandardCimv2') { throw 'Unexpected namespace' }
 switch ($ClassName) {
 MSFT_NetAdapter { [pscustomobject]@{Name='Ethernet 5';InterfaceIndex=7;InterfaceGuid='${scenario === 'wrong-guid' ? 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' : guid}';InterfaceOperationalStatus=${scenario === 'down' ? 2 : 1};DriverDescription='${scenario === 'foreign-driver' ? 'Foreign' : 'Wintun'}';PnPDeviceID='SWD\\Wintun\\fixture'} }
 MSFT_NetIPAddress { if ($Filter -ne 'InterfaceIndex = 7') { throw 'Unexpected index' }; [pscustomobject]@{IPAddress='${scenario === 'wrong-address' ? '192.168.1.1' : '192.168.250.253'}';PrefixLength=30} }
 default { throw 'Unexpected class' }
 }
}
function Invoke-CimMethod {
 param($Namespace,$ClassName,$MethodName,$Arguments)
 if ($MethodName -ne 'Find' -or $ClassName -ne 'MSFT_NetRoute' -or $Arguments.ContainsKey('InterfaceIndex')) { throw 'Route lookup must select without forcing an interface' }
 ${scenario === 'query-failure' ? "throw 'query failed'" : ''}
 [pscustomobject]@{ReturnValue=0;CmdletOutput=@([pscustomobject]@{IPAddress='192.168.250.253';InterfaceIndex=7}; ${scenario === 'missing-route' ? '$null' : `[pscustomobject]@{DestinationPrefix='32.0.0.0/3';InterfaceIndex=${scenario === 'competing' ? 8 : 7}}`})}
}
${script}`
      return execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(fake, 'utf16le').toString('base64')], { windowsHide: true, timeout: 10000, encoding: 'utf8', stdio: 'pipe' })
    })
    expect(await h.run()).toBe(scenario === 'fragmented')
  })
})
