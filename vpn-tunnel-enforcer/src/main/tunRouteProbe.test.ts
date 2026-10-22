// AT-06-003 / AT-02-002 / AT-00-003: selected routes and exact current ownership.
// Supporting native route evidence only; this does not run the L3 egress oracle.
import { readFileSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import ts from 'typescript'
import { afterEach, describe, expect, it, vi } from 'vitest'

const source = ts.createSourceFile('tunController.ts', readFileSync('src/main/tunController.ts', 'utf8'), ts.ScriptTarget.Latest, true)
const declaration = source.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'areTunRoutesActive')
if (!declaration) throw new Error('Production areTunRoutesActive declaration is missing')
const js = ts.transpileModule(declaration.getText(source).replace(/^export\s+/, ''), { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText
const guid = '11111111-2222-3333-4444-555555555555'
function harness() {
  const state = { running: true, pid: 1234, startedAt: 1 }
  let alias = 'Ethernet 5'
  const owner: any = { schemaVersion: 1, owner: 'VPNTE', alias, interfaceGuid: guid }
  const runPowerShell = vi.fn(async (_script: string, _timeout: number) => 'true')
  const readRecoveryManifest = vi.fn(async (_name: string, validate: (v: any) => any) => owner && validate(owner))
  const logEvent = vi.fn()
  const nativeRoutes = vi.fn(async () => [7, 7, 7])
  const run = new Function('currentStatus', 'getTunAdapterAlias', 'readRecoveryManifest', 'runPowerShell', 'psSingleQuote', 'logEvent', 'nativeSelectedIpv4Interfaces', js + '\nreturn areTunRoutesActive;')(
    state, () => alias, readRecoveryManifest, runPowerShell, (s: string) => "'" + s.replace(/'/g, "''") + "'", logEvent, nativeRoutes)
  return { run, state, owner, runPowerShell, readRecoveryManifest, nativeRoutes, logEvent, setAlias: (value: string) => { alias = value } }
}

afterEach(() => { vi.unstubAllEnvs() })

describe.runIf(process.platform === 'win32')('selected TUN route probe', () => {
  it('uses fresh adapter ownership before the unrestricted native route selection', async () => {
    vi.stubEnv('VPNTE_DISABLE_NATIVE_NET', '0')
    const h = harness()
    h.runPowerShell.mockImplementation(async script => {
      expect(h.nativeRoutes).not.toHaveBeenCalled()
      expect(script).toMatch(/MSFT_NetAdapter|MSFT_NetIPAddress/)
      expect(script).not.toMatch(/Invoke-CimMethod/)
      return '7'
    })
    expect(await h.run()).toBe(true)
    expect(h.runPowerShell).toHaveBeenCalledOnce()
    expect(h.nativeRoutes).toHaveBeenCalledOnce()
  })
  it('rejects a competing selected interface without retrying the authoritative read', async () => {
    vi.stubEnv('VPNTE_DISABLE_NATIVE_NET', '0')
    const h = harness(); h.runPowerShell.mockResolvedValue('7'); h.nativeRoutes.mockResolvedValue([7, 8, 7])
    expect(await h.run()).toBe(false)
    expect(h.nativeRoutes).toHaveBeenCalledOnce()
    expect(h.runPowerShell).toHaveBeenCalledOnce()
  })
  it('repeats the complete original CIM proof if native route selection refuses', async () => {
    vi.stubEnv('VPNTE_DISABLE_NATIVE_NET', '0')
    const h = harness(), error = new Error('native unavailable')
    h.runPowerShell.mockResolvedValueOnce('7').mockResolvedValueOnce('true')
    h.nativeRoutes.mockRejectedValue(error)
    expect(await h.run()).toBe(true)
    expect(h.runPowerShell).toHaveBeenCalledTimes(2)
    expect(h.runPowerShell.mock.calls[1][0]).toMatch(/MSFT_NetAdapter[\s\S]+MSFT_NetIPAddress[\s\S]+Invoke-CimMethod/)
    expect(h.logEvent).toHaveBeenCalledWith('debug', 'tun', 'native route selection unavailable, using PowerShell', error)
  })
  it.each(['', 'false', '0', '-1', '4294967296', 'invalid'])('rejects an invalid owned interface index %j before native selection', async value => {
    vi.stubEnv('VPNTE_DISABLE_NATIVE_NET', '0')
    const h = harness(); h.runPowerShell.mockResolvedValue(value)
    expect(await h.run()).toBe(false)
    expect(h.nativeRoutes).not.toHaveBeenCalled()
  })
  it.each(['pid', 'startedAt', 'alias'])('rejects a late native route answer after %s changes', async field => {
    vi.stubEnv('VPNTE_DISABLE_NATIVE_NET', '0')
    const h = harness(); h.runPowerShell.mockResolvedValue('7')
    h.nativeRoutes.mockImplementation(async () => {
      if (field === 'pid') h.state.pid++
      if (field === 'startedAt') h.state.startedAt++
      if (field === 'alias') h.setAlias('Ethernet 6')
      return [7, 7, 7]
    })
    expect(await h.run()).toBe(false)
    expect(h.nativeRoutes).toHaveBeenCalledOnce()
  })
  it('rejects an ownership response from a previous session before dispatching native selection', async () => {
    vi.stubEnv('VPNTE_DISABLE_NATIVE_NET', '0')
    const h = harness()
    h.runPowerShell.mockImplementation(async () => { h.state.startedAt++; return '7' })
    expect(await h.run()).toBe(false)
    expect(h.nativeRoutes).not.toHaveBeenCalled()
  })
  it('requires fresh ownership again after native refusal', async () => {
    vi.stubEnv('VPNTE_DISABLE_NATIVE_NET', '0')
    const h = harness()
    h.runPowerShell.mockResolvedValueOnce('7').mockResolvedValueOnce('false')
    h.nativeRoutes.mockRejectedValue(new Error('refused'))
    expect(await h.run()).toBe(false)
    expect(h.runPowerShell).toHaveBeenCalledTimes(2)
  })
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
  it.each(['fragmented', 'competing', 'missing-route', 'wrong-guid', 'down', 'foreign-driver', 'wrong-address', 'query-failure']
    .flatMap(scenario => [false, true].map(native => ({ scenario, native }))))('executes the production script for $scenario routes (native=$native)', async ({ scenario, native }) => {
    vi.stubEnv('VPNTE_DISABLE_NATIVE_NET', native ? '0' : '1')
    const h = harness()
    if (scenario === 'competing') h.nativeRoutes.mockResolvedValue([7, 8, 7])
    if (scenario === 'missing-route' || scenario === 'query-failure') h.nativeRoutes.mockRejectedValue(new Error('No complete route selection'))
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
  }, 15_000) // Native fixture permits 10s for PowerShell; production dispatch remains 3s.
})
