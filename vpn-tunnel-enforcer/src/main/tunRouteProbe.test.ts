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
  const nativeOwnership = vi.fn(async (): Promise<number | null> => 7)
  const run = new Function('currentStatus', 'getTunAdapterAlias', 'readRecoveryManifest', 'runPowerShell', 'psSingleQuote', 'logEvent', 'nativeSelectedIpv4Interfaces', 'nativeOwnedTunIndex', js + '\nreturn areTunRoutesActive;')(
    state, () => alias, readRecoveryManifest, runPowerShell, (s: string) => "'" + s.replace(/'/g, "''") + "'", logEvent, nativeRoutes, nativeOwnership)
  return { run, state, owner, runPowerShell, readRecoveryManifest, nativeRoutes, nativeOwnership, logEvent, setAlias: (value: string) => { alias = value } }
}

afterEach(() => { vi.unstubAllEnvs(); vi.useRealTimers() })

describe.runIf(process.platform === 'win32')('selected TUN route probe', () => {
  it('uses fresh native ownership before unrestricted route selection without PowerShell', async () => {
    vi.stubEnv('VPNTE_DISABLE_NATIVE_NET', '0')
    const h = harness()
    h.nativeOwnership.mockImplementation(async () => { expect(h.nativeRoutes).not.toHaveBeenCalled(); return 7 })
    expect(await h.run()).toBe(true)
    expect(h.nativeOwnership).toHaveBeenCalledExactlyOnceWith('Ethernet 5', guid)
    expect(h.nativeRoutes).toHaveBeenCalledOnce()
    expect(h.runPowerShell).not.toHaveBeenCalled()
  })
  it('does not retry authoritative competing routes or absent ownership', async () => {
    vi.stubEnv('VPNTE_DISABLE_NATIVE_NET', '0')
    const h = harness(); h.nativeRoutes.mockResolvedValue([7, 8, 7])
    expect(await h.run()).toBe(false)
    h.nativeOwnership.mockResolvedValue(null)
    expect(await h.run()).toBe(false)
    expect(h.nativeRoutes).toHaveBeenCalledOnce()
    expect(h.runPowerShell).not.toHaveBeenCalled()
  })
  it.each(['ownership', 'routes'])('repeats the complete CIM proof after native %s refusal', async stage => {
    vi.stubEnv('VPNTE_DISABLE_NATIVE_NET', '0')
    const h = harness()
    if (stage === 'ownership') h.nativeOwnership.mockRejectedValue(new Error('refused'))
    else h.nativeRoutes.mockRejectedValue(new Error('refused'))
    expect(await h.run()).toBe(true)
    expect(h.runPowerShell).toHaveBeenCalledOnce()
    expect(h.runPowerShell.mock.calls[0][0]).toMatch(/MSFT_NetAdapter[\s\S]+MSFT_NetIPAddress[\s\S]+Invoke-CimMethod/)
    h.runPowerShell.mockResolvedValue('false')
    expect(await h.run()).toBe(false)
  })
  it('reserves the remaining caller deadline after stalled native ownership and ignores its late success', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'performance'] })
    vi.stubEnv('VPNTE_DISABLE_NATIVE_NET', '0')
    const h = harness(), complete = vi.fn()
    let finish!: (index: number) => void
    h.nativeOwnership.mockImplementation(() => new Promise(resolve => { finish = resolve }))
    h.runPowerShell.mockImplementation(() => new Promise(() => {}))
    const pending = h.run().then(complete)
    await vi.advanceTimersByTimeAsync(250)
    expect(h.runPowerShell).toHaveBeenCalledOnce()
    expect(h.runPowerShell.mock.calls[0][1]).toBe(2750)
    finish(7); await vi.advanceTimersByTimeAsync(2750)
    await pending
    expect(complete).toHaveBeenCalledExactlyOnceWith(false)
    expect(h.nativeRoutes).not.toHaveBeenCalled()
    expect(vi.getTimerCount()).toBe(0)
  })
  it.each(['manifest', 'routes', 'fallback'])('bounds stalled %s within the complete 3000ms budget', async stage => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'performance'] })
    vi.stubEnv('VPNTE_DISABLE_NATIVE_NET', '0')
    const h = harness(), complete = vi.fn()
    if (stage === 'manifest') h.readRecoveryManifest.mockImplementation(() => new Promise(() => {}))
    if (stage === 'routes') h.nativeRoutes.mockImplementation(() => new Promise(() => {}))
    if (stage === 'fallback') {
      h.nativeOwnership.mockRejectedValue(new Error('refused'))
      h.runPowerShell.mockImplementation(() => new Promise(() => {}))
    }
    const pending = h.run().then(complete)
    await vi.advanceTimersByTimeAsync(2999)
    expect(complete).not.toHaveBeenCalled()
    await vi.advanceTimersByTimeAsync(1); await pending
    expect(complete).toHaveBeenCalledExactlyOnceWith(false)
    expect(vi.getTimerCount()).toBe(0)
  })
  it.each(['pid', 'startedAt', 'alias'])('rejects native ownership from an obsolete %s session before route lookup', async field => {
    vi.stubEnv('VPNTE_DISABLE_NATIVE_NET', '0')
    const h = harness()
    h.nativeOwnership.mockImplementation(async () => {
      if (field === 'pid') h.state.pid++
      if (field === 'startedAt') h.state.startedAt++
      if (field === 'alias') h.setAlias('Ethernet 6')
      return 7
    })
    expect(await h.run()).toBe(false)
    expect(h.nativeRoutes).not.toHaveBeenCalled()
    expect(h.runPowerShell).not.toHaveBeenCalled()
  })
  it.each(['pid', 'startedAt', 'alias'])('rejects late native route evidence after %s changes', async field => {
    vi.stubEnv('VPNTE_DISABLE_NATIVE_NET', '0')
    const h = harness()
    h.nativeRoutes.mockImplementation(async () => {
      if (field === 'pid') h.state.pid++
      if (field === 'startedAt') h.state.startedAt++
      if (field === 'alias') h.setAlias('Ethernet 6')
      return [7, 7, 7]
    })
    expect(await h.run()).toBe(false)
  })
  it.each(['missing', 'stopped', 'owner', 'guid', 'alias'])('refuses invalid %s manifest/session before any native read', async scenario => {
    const h = harness()
    if (scenario === 'missing') h.readRecoveryManifest.mockResolvedValue(null)
    if (scenario === 'stopped') h.state.running = false
    if (scenario === 'owner') h.owner.owner = 'foreign'
    if (scenario === 'guid') h.owner.interfaceGuid = 'invalid'
    if (scenario === 'alias') h.owner.alias = 'Ethernet 6'
    expect(await h.run()).toBe(false)
    expect(h.nativeOwnership).not.toHaveBeenCalled()
    expect(h.runPowerShell).not.toHaveBeenCalled()
  })
  it.each(['fragmented', 'competing', 'missing-route', 'wrong-guid', 'down', 'foreign-driver', 'wrong-address', 'query-failure']
    .flatMap(scenario => [false, true].map(native => ({ scenario, native }))))('executes the production script for $scenario routes (native=$native)', async ({ scenario, native }) => {
    vi.stubEnv('VPNTE_DISABLE_NATIVE_NET', native ? '0' : '1')
    const h = harness()
    h.nativeOwnership.mockRejectedValue(new Error('exercise complete CIM fallback'))
    if (scenario === 'missing-route' || scenario === 'query-failure') h.nativeRoutes.mockRejectedValue(new Error('No complete route selection'))
    h.runPowerShell.mockImplementation(async (script, timeout) => {
      expect(timeout).toBeGreaterThan(0)
      expect(timeout).toBeLessThanOrEqual(3000)
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
