// AT-03-006/007/010/011/012: actual client lifetime/protocol with fake OS boundaries.
import { EventEmitter } from 'node:events'
import { PassThrough } from 'node:stream'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({ spawn: vi.fn(), stage: vi.fn(), harden: vi.fn(), verify: vi.fn(), elevated: vi.fn(), exists: vi.fn(), log: vi.fn() }))
vi.mock('child_process', () => ({ spawn: mocks.spawn }))
vi.mock('fs', () => ({ existsSync: mocks.exists }))
vi.mock('os', () => ({ release: () => '10.0.26100' }))
vi.mock('electron', () => ({ app: { isPackaged: false } }))
vi.mock('../admin', () => ({ isProcessElevated: mocks.elevated }))
vi.mock('../runtimePaths', () => ({ getPrivilegedRuntimeDir: () => 'C:\\ProgramData\\VPNTE\\runtime\\fixture\\tun-runtime' }))
vi.mock('../runtimeArtifact', () => ({ stageVerifiedRuntimeArtifact: mocks.stage }))
vi.mock('../runtimeDirSecurity', () => ({ ensureElevatedRuntimeDirHardened: mocks.harden, verifyDirectoryHardened: mocks.verify }))
vi.mock('../appLogger', () => ({ logEvent: mocks.log }))

import { encodeAdapterCommands, checkAdapterReceipt, runAdapterCommands, applyNativeAdapterLockdown, restoreNativeAdapterLockdown, type AdapterCommand } from './adapterLockdownNative'
const guid = '11111111-1111-1111-1111-111111111111'
const command = (): AdapterCommand => ({ guid, ipv6: 'off', dns: 'set', servers: ['192.0.2.53'] })
function fixture() {
  const child = Object.assign(new EventEmitter(), { stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough() })
  mocks.spawn.mockReturnValue(child)
  return child
}
async function admitted() { await vi.waitFor(() => expect(mocks.spawn).toHaveBeenCalledOnce()) }

beforeEach(() => {
  vi.clearAllMocks()
  mocks.stage.mockResolvedValue(false)
  mocks.harden.mockResolvedValue({ hardened: true })
  mocks.verify.mockResolvedValue({ hardened: true })
  mocks.elevated.mockResolvedValue(true)
  mocks.exists.mockReturnValue(true)
  delete process.env.VPNTE_DISABLE_NATIVE_LOCKDOWN
})

describe('native adapter batch protocol', () => {
  it('encodes only exact GUID/action/IP tuples without shell syntax', () => {
    expect(encodeAdapterCommands([command()])).toBe(`VPNTE_LOCKDOWN_V1\n0|{${guid}}|off|set|192.0.2.53\n`)
  })
  it.each([
    [], [command(), command()], [{ ...command(), guid: 'injected|command' }],
    [{ ...command(), servers: ['192.0.2.53\ncommand'] }], [{ ...command(), ipv6: 'disable-device' }],
    [{ ...command(), dns: 'reset', servers: ['192.0.2.53'] }], [{ ...command(), servers: [] }]
  ].map(input => [input]))('rejects malformed/duplicate or inconsistent input before dispatch: %j', (input) => {
    expect(() => encodeAdapterCommands(input as AdapterCommand[])).toThrow()
  })
  it.each(['', 'A0_ipv6:off\nA0_dns:set\nA0_dns:set', 'A0_ipv6:off\nA0_dns:set\nA1_dns:set',
    'A0_ipv6:on\nA0_dns:set', 'A0_ipv6:off\nA0_dns:skip',
    'A0_ipv6:off\nA0_dns:set\nA0_dns:changed',
    'A0_ipv6:off\nA0_dns:set\nFAKE-PRIVATE-PAYLOAD'])('rejects missing, duplicate, mismatched or foreign receipts', value => {
    expect(() => checkAdapterReceipt(value, [command()])).toThrow()
  })
  it('accepts read-back markers and sanitized numeric API timings', () => {
    const output = 'A0_ipv6:changed\nA0_ipv6:off\nA0_dns:set\nNATIVE_TIMING phase=dns durationMs=3.5\n'
    expect(checkAdapterReceipt(output, [command()])).toBe(output)
  })
})

describe.skipIf(process.platform !== 'win32' || process.arch !== 'x64')('native mutation admission and drain', () => {
  it('keeps cancellation owner until close, even after stdout and process exit', async () => {
    const child = fixture(), controller = new AbortController()
    let settled = false
    const result = runAdapterCommands([command()], controller.signal).then(r => { settled = true; return r })
    await admitted()
    controller.abort()
    child.stdout.write('A0_ipv6:off\nA0_dns:set\n')
    child.emit('exit', 0)
    await Promise.resolve()
    expect(settled).toBe(false)
    child.emit('close', 0)
    expect(await result).toContain('A0_dns:set')
    expect(mocks.spawn).toHaveBeenCalledOnce()
    expect(mocks.stage).toHaveBeenCalledOnce()
    expect(mocks.verify).toHaveBeenCalledOnce()
  })
  it('never dispatches if cancellation arrives during artifact verification', async () => {
    fixture(); const controller = new AbortController()
    mocks.verify.mockImplementation(async () => { controller.abort(); return { hardened: true } })
    await expect(runAdapterCommands([command()], controller.signal)).rejects.toMatchObject({ code: 'physical-lockdown-cancelled-before-dispatch' })
    expect(mocks.spawn).not.toHaveBeenCalled()
  })
  it.each(['crash', 'invalid', 'oversize'])('returns unverified recovery markers after %s without replay', async reason => {
    const child = fixture(), result = runAdapterCommands([command()])
    await admitted()
    child.stdout.write(reason === 'oversize' ? 'x'.repeat(262145) : 'private-path-error')
    child.emit('close', reason === 'crash' ? 1 : 0)
    expect(await result).toBe('A0_ipv6_err: native code=1\nA0_dns_err: native code=1\n')
    expect(mocks.spawn).toHaveBeenCalledOnce()
  })
  it('preserves independent successful restore outcomes in a complete partial-failure receipt', async () => {
    const child = fixture()
    const row: AdapterCommand = { guid, ipv6: 'on', dns: 'reset', servers: [] }
    const result = runAdapterCommands([row, { ...row, guid: '22222222-2222-2222-2222-222222222222' }], undefined, '--restore')
    await admitted()
    const receipt = 'A0_ipv6_err: native code=1168\nA0_dns_err: native code=1168\nA1_ipv6:on\nA1_dns:reset\n'
    child.stdout.write(receipt); child.emit('close', 1)
    expect(await result).toBe(receipt)
    expect(mocks.spawn).toHaveBeenCalledOnce()
  })
  it.each(['missing', 'disabled', 'not-elevated'])('allows only explicit pre-dispatch legacy capability fallback: %s', async reason => {
    fixture()
    if (reason === 'missing') mocks.exists.mockReturnValue(false)
    if (reason === 'disabled') process.env.VPNTE_DISABLE_NATIVE_LOCKDOWN = '1'
    if (reason === 'not-elevated') mocks.elevated.mockResolvedValue(false)
    expect(await runAdapterCommands([command()])).toBeNull()
    expect(mocks.spawn).not.toHaveBeenCalled()
  })
  it('refuses untrusted staging without using legacy mutations', async () => {
    fixture(); mocks.harden.mockResolvedValue({ hardened: false })
    await expect(runAdapterCommands([command()])).rejects.toThrow('untrusted')
    expect(mocks.spawn).not.toHaveBeenCalled()
  })
  it('times trusted preparation separately from spawn and emits no paths or error text', async () => {
    const child = fixture(), result = runAdapterCommands([command()])
    await admitted()
    const records = mocks.log.mock.calls.filter(call => call[2] === 'native adapter preparation timing').map(call => call[3])
    expect(records).toEqual([
      { phase: 'ensure-trust', outcome: 'verified', durationMs: expect.any(Number) },
      { phase: 'stage-hash', outcome: 'reused', durationMs: expect.any(Number) },
      { phase: 'verify-after-stage', outcome: 'verified', durationMs: expect.any(Number) },
      { phase: 'total', outcome: 'verified', durationMs: expect.any(Number) }
    ])
    expect(mocks.log.mock.calls.some(call => call[2] === 'native adapter batch timing')).toBe(false)
    expect(JSON.stringify(records)).not.toMatch(/ProgramData|VPNTE|resources|runtime.exe/)
    child.stdout.write('A0_ipv6:off\nA0_dns:set\n'); child.emit('close', 0)
    await result
    mocks.log.mockClear(); mocks.stage.mockRejectedValueOnce(new Error('FAKE-SECRET C:\\private\\runtime.exe'))
    await expect(runAdapterCommands([command()])).rejects.toThrow('FAKE-SECRET')
    expect(mocks.log.mock.calls.filter(call => call[2] === 'native adapter preparation timing').map(call => call[3])).toEqual([
      { phase: 'ensure-trust', outcome: 'verified', durationMs: expect.any(Number) },
      { phase: 'stage-hash', outcome: 'failed', durationMs: expect.any(Number) },
      { phase: 'total', outcome: 'failed', durationMs: expect.any(Number) }
    ])
    expect(JSON.stringify(mocks.log.mock.calls)).not.toMatch(/FAKE-SECRET|private|runtime.exe/)
  })
  it('preserves mobile IPv6/public Wi-Fi DNS and exact static restore actions', async () => {
    const adapter = { interfaceGuid: guid, ipv6Enabled: true, forcedIpv6Off: false, forcedDnsTo: null, ipv4DnsServers: [], isCellularOrTethering: true }
    expect(await applyNativeAdapterLockdown([adapter], '192.0.2.53', false)).toBe('A0_ipv6:skip\nA0_dns:skip\n')
    expect(mocks.spawn).not.toHaveBeenCalled()
    const child = fixture()
    const operation = restoreNativeAdapterLockdown([{ ...adapter, forcedIpv6Off: true, forcedDnsTo: ['192.0.2.53'], ipv4DnsSource: 'static', ipv4DnsServers: ['192.0.2.1','192.0.2.2'] }], false)
    await admitted()
    expect(child.stdin.read().toString()).toContain('|on|restore|192.0.2.1,192.0.2.2')
    expect(mocks.spawn.mock.calls[0][1]).toEqual(['--restore'])
    child.stdout.write('A0_ipv6:on\nA0_dns:restore\n'); child.emit('close', 0); await operation
  })
})
