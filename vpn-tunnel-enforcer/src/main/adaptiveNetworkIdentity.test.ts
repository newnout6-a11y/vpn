import { beforeEach, describe, expect, it, vi } from 'vitest'
import { execFileSync } from 'child_process'
import { gzipSync } from 'zlib'
const state = vi.hoisted(() => ({ exec: vi.fn(), worker: vi.fn() }))
vi.mock('./recoveryPsWorker', () => ({ executeRecoveryOperation: state.worker }))
vi.mock('child_process', async original => {
  const actual = await original<typeof import('child_process')>()
  return { ...actual, default: { ...actual, execFile: state.exec }, execFile: state.exec }
})
import { readAdaptiveNetworkIdentity, ADAPTIVE_NETWORK_IDENTITY_SCRIPT } from './adaptiveNetworkIdentity'
import { recoveryWorkerFunctions } from './recoveryPsProtocol'

const dispatch = `${recoveryWorkerFunctions(process.env.ProgramData || 'C:\\ProgramData')}
Invoke-RecoveryOperation ([pscustomobject]@{op='inspect-network-identity'})`

function runNative(script: string): string {
  // The full production dispatcher exceeds CreateProcess's encoded argv limit.
  const source = gzipSync(Buffer.from(script, 'utf8')).toString('base64')
  const launcher = `$stream=New-Object IO.MemoryStream(,[Convert]::FromBase64String('${source}'));
$gzip=New-Object IO.Compression.GZipStream($stream,[IO.Compression.CompressionMode]::Decompress);
$reader=New-Object IO.StreamReader($gzip,[Text.Encoding]::UTF8);
try{$script=$reader.ReadToEnd()}finally{$reader.Dispose();$gzip.Dispose();$stream.Dispose()};
& ([scriptblock]::Create($script))`
  const env = { ...process.env }
  for (const key of Object.keys(env)) if (key.toLowerCase() === 'psmodulepath') delete env[key]
  return execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand',
    Buffer.from(launcher, 'utf16le').toString('base64')], { env, windowsHide: true, timeout: 30000, encoding: 'utf8', stdio: 'pipe' })
}

function result(value: any) {
  state.worker.mockResolvedValue(JSON.stringify(value))
  state.exec.mockImplementation((_exe, _args, _options, cb) => { cb(null, JSON.stringify(value)); return {} })
}
const row = { alias: 'Wi-Fi', guid: 'fixture-guid', profiles: ['Домашняя сеть'], gateways: ['192.168.1.1', 'fe80::1'] }
beforeEach(() => { state.exec.mockReset(); state.worker.mockReset(); result([row]) })
describe('private network identity read (AT-10-007)', () => {
  it('uses fresh fixed worker reads without spawning and keeps a stable IPv4 identity across IPv6 lockdown', async () => {
    expect(await readAdaptiveNetworkIdentity()).toEqual([{ ...row, gateways: ['192.168.1.1'] }])
    result({ ...row, gateways: ['192.168.1.1'] })
    expect(await readAdaptiveNetworkIdentity()).toEqual([{ ...row, gateways: ['192.168.1.1'] }])
    expect(state.worker.mock.calls).toEqual([[{ op: 'inspect-network-identity' }, 4000], [{ op: 'inspect-network-identity' }, 4000]])
    expect(state.exec).not.toHaveBeenCalled()
  })
  it('keeps the bounded hidden standalone read only when the worker is unavailable before dispatch', async () => {
    state.worker.mockRejectedValue(Object.assign(new Error('not elevated'), { code: 'unavailable' }))
    expect(await readAdaptiveNetworkIdentity()).toEqual([{ ...row, gateways: ['192.168.1.1'] }])
    const [_exe, args, options] = state.exec.mock.calls[0]
    expect(options).toMatchObject({ windowsHide: true, timeout: 4000, maxBuffer: 256 * 1024 })
    const script = Buffer.from(args[args.length - 1], 'base64').toString('utf16le')
    expect(script).toContain('-ClassName MSFT_NetConnectionProfile')
    expect(script).toContain("Store = 1 AND (DestinationPrefix = '0.0.0.0/0' OR DestinationPrefix = '::/0')")
    expect(script).not.toMatch(/\b(?:Get|Set|Remove|Disable)-Net\w+\s*(?:\||-)/)
  })
  it('observes a changed network on the next read instead of reusing a cached identity', async () => {
    expect(await readAdaptiveNetworkIdentity()).toEqual([{ ...row, gateways: ['192.168.1.1'] }])
    const changed = { ...row, profiles: ['Другая сеть'], gateways: ['10.0.0.1'] }
    result([changed])
    expect(await readAdaptiveNetworkIdentity()).toEqual([changed])
    expect(state.worker).toHaveBeenCalledTimes(2)
    expect(state.exec).not.toHaveBeenCalled()
  })
  it.each(['busy', 'closed', 'timeout', 'exited', 'protocol', 'rejected', undefined])('keeps identity unknown without a retry after worker error %s (AT-03-012)', async code => {
    state.worker.mockRejectedValue(Object.assign(new Error('worker failure'), { code }))
    expect((await readAdaptiveNetworkIdentity()) === null).toBe(true)
    expect(state.exec).not.toHaveBeenCalled()
  })
  it.each([{ value: [] }, { value: null }, { value: {} }, { value: [{ alias: 'Wi-Fi', guid: 'guid', profiles: [], gateways: [] }] }, { value: [{ ...row, profiles: [42] }] }])('fails closed for missing / malformed identity: %j', async ({ value }) => {
    result(value)
    expect(await readAdaptiveNetworkIdentity()).toBeNull()
  })
  it('returns unknown when the command fails or emits truncated JSON', async () => {
    state.worker.mockRejectedValue(new Error('query failed'))
    expect(await readAdaptiveNetworkIdentity()).toBeNull()
    state.worker.mockResolvedValue('{broken')
    expect(await readAdaptiveNetworkIdentity()).toBeNull()
    expect(state.exec).not.toHaveBeenCalled()
    state.worker.mockRejectedValue(Object.assign(new Error('not available'), { code: 'unavailable' }))
    state.exec.mockImplementation((_exe, _args, _options, cb) => cb(new Error('timeout')))
    expect(await readAdaptiveNetworkIdentity()).toBeNull()
    state.exec.mockImplementation((_exe, _args, _options, cb) => cb(null, '{broken'))
    expect(await readAdaptiveNetworkIdentity()).toBeNull()
  })
  it('retains the 256 KiB output bound for worker responses', async () => {
    result([{ ...row, profiles: ['я'.repeat(128 * 1024)] }])
    expect((await readAdaptiveNetworkIdentity()) === null).toBe(true)
    expect(state.exec).not.toHaveBeenCalled()
  })
  it('deduplicates and sorts Unicode profiles and retains IPv6 on IPv6-only uplinks', async () => {
    result([{ ...row, profiles: ['Я', 'А', 'Я'], gateways: ['fe80::2', 'fe80::1', 'fe80::2'] }])
    expect(await readAdaptiveNetworkIdentity()).toEqual([{ ...row, profiles: ['А', 'Я'], gateways: ['fe80::1', 'fe80::2'] }])
  })
  it.runIf(process.platform === 'win32').each(['MSFT_NetAdapter', 'MSFT_NetConnectionProfile', 'MSFT_NetRoute'])('fails closed if the CIM query for %s fails', failedClass => {
    const harness = `
function Get-CimInstance {
  param($Namespace,$ClassName,$Filter,$ErrorAction)
  if ($ClassName -eq '${failedClass}') { throw 'fixture failure' }
}
${dispatch}`
    expect(() => runNative(harness)).toThrow('fixture failure')
  })
  it.runIf(process.platform === 'win32').each(['profile-only', 'gateway-only', 'neither'])('keeps the previous %s identity behavior', fixture => {
    const harness = `
function Get-CimInstance {
  param($Namespace,$ClassName,$Filter,$ErrorAction)
  switch ($ClassName) {
    MSFT_NetAdapter { [pscustomobject]@{Hidden=$false;InterfaceOperationalStatus=1;NetworkAddresses=@('001122334455');InterfaceDescription='Physical Wi-Fi';Name='Wi-Fi';InterfaceGuid='fixture-guid';InterfaceIndex=7} }
    MSFT_NetConnectionProfile { ${fixture === 'profile-only' ? "[pscustomobject]@{InterfaceIndex=7;Name='Домашняя сеть'}" : ''} }
    MSFT_NetRoute { ${fixture === 'gateway-only' ? "[pscustomobject]@{InterfaceIndex=7;NextHop='fe80::1'}" : ''} }
  }
}
${dispatch}`
    const stdout = runNative(harness)
    expect(JSON.parse(stdout.trim())).toEqual(fixture === 'neither' ? [] : [{ alias: 'Wi-Fi', guid: 'fixture-guid',
      profiles: fixture === 'profile-only' ? ['Домашняя сеть'] : [], gateways: fixture === 'gateway-only' ? ['fe80::1'] : [] }])
  })
  it.runIf(process.platform === 'win32')('executes the production script with fake native cmdlets, retaining arrays and Unicode', () => {
    const harness = `
function Get-CimInstance {
  param($Namespace,$ClassName,$Filter,$ErrorAction)
  if ($Namespace -ne 'root/StandardCimv2' -or $ErrorAction -ne 'Stop') { throw 'Unexpected query' }
  switch ($ClassName) {
    MSFT_NetAdapter {
      [pscustomobject]@{Hidden=$false;InterfaceOperationalStatus=1;NetworkAddresses=@('001122334455');InterfaceDescription='Physical Wi-Fi';Name='Wi-Fi';InterfaceGuid='fixture-guid';InterfaceIndex=7}
      foreach ($fixture in @(
        @{Hidden=$true;InterfaceOperationalStatus=1;NetworkAddresses=@('001122334466');InterfaceDescription='Physical Wi-Fi'},
        @{Hidden=$false;InterfaceOperationalStatus=2;NetworkAddresses=@('001122334466');InterfaceDescription='Physical Wi-Fi'},
        @{Hidden=$false;InterfaceOperationalStatus=1;NetworkAddresses=@('');InterfaceDescription='Physical Wi-Fi'},
        @{Hidden=$false;InterfaceOperationalStatus=1;NetworkAddresses=@('001122334466');InterfaceDescription='Wintun Userspace Tunnel'},
        @{Hidden=$false;InterfaceOperationalStatus=1;NetworkAddresses=@('001122334466');InterfaceDescription='WireGuard Tunnel'}
      )) { $fixture.Name='excluded'; $fixture.InterfaceIndex=8; [pscustomobject]$fixture }
    }
    MSFT_NetConnectionProfile {
      [pscustomobject]@{InterfaceIndex=7;Name='Домашняя сеть';InstanceID='nla-fixture'}
      [pscustomobject]@{InterfaceIndex=8;Name='Foreign network'}
    }
    MSFT_NetRoute {
      if ($Filter -ne "Store = 1 AND (DestinationPrefix = '0.0.0.0/0' OR DestinationPrefix = '::/0')") { throw 'Inactive or non-default routes queried' }
      [pscustomobject]@{InterfaceIndex=7;NextHop='192.168.1.1'}
      [pscustomobject]@{InterfaceIndex=7;NextHop='fe80::1'}
      [pscustomobject]@{InterfaceIndex=7;NextHop='0.0.0.0'}
      [pscustomobject]@{InterfaceIndex=7;NextHop='::'}
      [pscustomobject]@{InterfaceIndex=8;NextHop='192.168.2.1'}
    }
    default { throw 'Unexpected class' }
  }
}
${dispatch}`
    const stdout = runNative(harness)
    expect(JSON.parse(stdout.trim())).toEqual([{ alias: 'Wi-Fi', guid: 'fixture-guid', profiles: ['Домашняя сеть|nla-fixture'], gateways: ['192.168.1.1', 'fe80::1'] }])
  })
})
