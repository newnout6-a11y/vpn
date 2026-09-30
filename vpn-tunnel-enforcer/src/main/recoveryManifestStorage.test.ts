// AT-03-003 / AT-03-012: fail-closed storage boundaries (Windows calls mocked).
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { execFileSync } from 'node:child_process'

const mocks = vi.hoisted(() => ({
  elevated: vi.fn(), read: vi.fn(), open: vi.fn(), rename: vi.fn(), unlink: vi.fn(),
  write: vi.fn(), sync: vi.fn(), close: vi.fn()
}))
vi.mock('./admin', () => ({ execElevated: mocks.elevated }))
vi.mock('fs/promises', () => {
  const api = { open: mocks.open, rename: mocks.rename, unlink: mocks.unlink }
  return { ...api, default: api }
})
vi.mock('child_process', () => {
  const execFile = (...args: any[]) => {
    const callback = args[args.length - 1]
    try { callback(null, { stdout: mocks.read(...args.slice(0, -1)), stderr: '' }) }
    catch (error) { callback(error) }
  }
  return { execFile, default: { execFile } }
})
import { readRecoveryManifest, recordOwnedTunAdapter, recoveryManifestPath, strictRecoveryRequired, writeRecoveryArtifact } from './recoveryManifest'

const platform = Object.getOwnPropertyDescriptor(process, 'platform')!
function decode(command: string) { return Buffer.from(command.split(' ').at(-1)!, 'base64').toString('utf16le') }
beforeEach(() => {
  vi.resetAllMocks()
  Object.defineProperty(process, 'platform', { configurable: true, value: 'win32' })
  mocks.elevated.mockResolvedValue({ stdout: 'RECOVERY_STORAGE_VERIFIED' })
  mocks.read.mockReturnValue('RECOVERY_ARTIFACT_ABSENT')
  mocks.open.mockResolvedValue({ writeFile: mocks.write, sync: mocks.sync, close: mocks.close })
  for (const operation of [mocks.write, mocks.sync, mocks.close, mocks.rename, mocks.unlink]) operation.mockResolvedValue(undefined)
})
afterEach(() => Object.defineProperty(process, 'platform', platform))

describe('trusted recovery storage', () => {
  it.skipIf(process.platform !== 'win32' && !process.env.VPNTE_PWSH).each([
    { driver: 'Wintun Userspace Tunnel', pnp: 'SWD\\Wintun\\fixture', ip: '192.168.250.253', prefix: 30, accepted: true },
    { driver: 'Wintun Userspace Tunnel', pnp: 'ROOT\\NET\\fixture', ip: '192.168.250.253', prefix: 30, accepted: false },
    { driver: 'Physical NIC', pnp: 'SWD\\Wintun\\fixture', ip: '192.168.250.253', prefix: 30, accepted: false },
    { driver: 'Wintun Userspace Tunnel', pnp: 'SWD\\Wintun\\fixture', ip: '192.168.250.254', prefix: 30, accepted: false },
    { driver: 'Wintun Userspace Tunnel', pnp: 'SWD\\Wintun\\fixture', ip: '192.168.250.253', prefix: 24, accepted: false }
  ])('checks native TUN driver/device/subnet before ownership commit: $driver / $pnp / $ip / $prefix (AT-03-002)', async fixture => {
    // Execute the actual read script against fake cmdlets; storage remains mocked.
    mocks.read.mockImplementation((_exe, args) => {
      const json = Buffer.from(JSON.stringify(fixture)).toString('base64')
      const script = `$fixture=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${json}'))|ConvertFrom-Json
function Get-NetAdapter { [pscustomobject]@{Name='Ethernet 5';InterfaceDescription='sing-tun Tunnel';DriverDescription=$fixture.driver;PnPDeviceID=$fixture.pnp;ifIndex=5;InterfaceGuid='00000000-0000-0000-0000-000000000005'} }
function Get-NetIPAddress { [pscustomobject]@{IPAddress=$fixture.ip;PrefixLength=$fixture.prefix} }
${Buffer.from(args.at(-1), 'base64').toString('utf16le')}`
      try {
        return execFileSync(process.env.VPNTE_PWSH || 'powershell.exe', ['-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(script, 'utf16le').toString('base64')], { encoding: 'utf8', timeout: 15000, stdio: ['ignore','pipe','pipe'] })
      } catch { throw new Error('Native TUN identity rejected') }
    })
    if (fixture.accepted) {
      await expect(recordOwnedTunAdapter('Ethernet 5')).resolves.toBeUndefined()
      expect(mocks.rename).toHaveBeenCalledWith(expect.any(String), recoveryManifestPath('tun-owner.json'))
    } else {
      await expect(recordOwnedTunAdapter('Ethernet 5')).rejects.toThrow('identity rejected')
      expect(mocks.open).not.toHaveBeenCalled()
    }
  }, 20000)

  it.each(['../firewall.json', 'x/y', 'x\\y', '', 'a'.repeat(162)])('rejects artifact name %s before system calls', async name => {
    await expect(writeRecoveryArtifact(name, '{}')).rejects.toThrow('name')
    expect(mocks.elevated).not.toHaveBeenCalled()
  })
  it('never resets children or rewrites ACLs of existing directories', async () => {
    await readRecoveryManifest('firewall.json', value => value)
    const script = decode(mocks.elevated.mock.calls[0][0])
    expect(script).toContain('$info.Create($acl)')
    expect(script).toContain('Assert-TrustedArtifact $dir $true')
    expect(script).not.toContain('icacls')
    expect(script).not.toContain('Set-Acl')
    expect(script).toContain('ReparsePoint')
  })
  it('does not turn a failed directory verification into an absent manifest', async () => {
    mocks.elevated.mockRejectedValue(new Error('Untrusted recovery owner'))
    await expect(readRecoveryManifest('firewall.json', value => value)).rejects.toThrow('Untrusted')
    expect(mocks.read).not.toHaveBeenCalled()
    expect(await strictRecoveryRequired()).toBe(true)
  })
  it('requires a verification marker and does not write if it is missing', async () => {
    mocks.elevated.mockResolvedValue({ stdout: '' })
    await expect(writeRecoveryArtifact('firewall.json', '{}')).rejects.toThrow('verification')
    expect(mocks.open).not.toHaveBeenCalled()
  })
  it('only reports absence from a trusted read boundary', async () => {
    expect(await readRecoveryManifest('firewall.json', value => value)).toBeNull()
    const script = Buffer.from(mocks.read.mock.calls[0][1].at(-1), 'base64').toString('utf16le')
    expect(script.indexOf('Assert-TrustedArtifact')).toBeLessThan(script.indexOf('RECOVERY_ARTIFACT_ABSENT'))
  })
  it('propagates corrupt JSON and unsupported schema, retaining strict protection', async () => {
    mocks.read.mockReturnValue('{')
    await expect(readRecoveryManifest('firewall.json', value => value)).rejects.toThrow()
    expect(await strictRecoveryRequired()).toBe(true)
    mocks.read.mockReturnValue('{"schemaVersion":2,"owner":"VPNTE","strictMode":false}')
    expect(await strictRecoveryRequired()).toBe(true)
  })
  it('fsyncs and ACL-verifies temporary data before rename', async () => {
    await writeRecoveryArtifact('firewall.json', '{}')
    expect(mocks.open.mock.calls[0][1]).toBe('wx')
    expect(mocks.sync.mock.invocationCallOrder[0]).toBeLessThan(mocks.elevated.mock.invocationCallOrder[1])
    expect(mocks.elevated.mock.invocationCallOrder[1]).toBeLessThan(mocks.rename.mock.invocationCallOrder[0])
    expect(mocks.rename.mock.calls[0][1]).toBe(recoveryManifestPath('firewall.json'))
  })
  it.each(['write', 'sync', 'close'] as const)('does not commit after a %s failure', async operation => {
    mocks[operation].mockRejectedValue(new Error(operation))
    await expect(writeRecoveryArtifact('firewall.json', '{}')).rejects.toThrow(operation)
    expect(mocks.rename).not.toHaveBeenCalled()
    expect(mocks.unlink).toHaveBeenCalled()
  })
  it('does not commit if file ACL protection fails', async () => {
    mocks.elevated.mockResolvedValueOnce({ stdout: 'RECOVERY_STORAGE_VERIFIED' }).mockRejectedValueOnce(new Error('ACL failure'))
    await expect(writeRecoveryArtifact('firewall.json', '{}')).rejects.toThrow('ACL failure')
    expect(mocks.rename).not.toHaveBeenCalled()
    expect(mocks.unlink).toHaveBeenCalled()
  })
  it('rejects oversized data before elevation', async () => {
    await expect(writeRecoveryArtifact('firewall.json', 'x'.repeat(1048577))).rejects.toThrow('limit')
    expect(mocks.elevated).not.toHaveBeenCalled()
  })
})
