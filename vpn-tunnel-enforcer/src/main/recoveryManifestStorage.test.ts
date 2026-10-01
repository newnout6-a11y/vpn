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
import { ensureRecoveryManifestDir, readRecoveryManifest, readRecoveryArtifact, removeRecoveryManifest, recordOwnedTunAdapter, recoveryManifestPath, strictRecoveryRequired, writeRecoveryArtifact } from './recoveryManifest'

const platform = Object.getOwnPropertyDescriptor(process, 'platform')!
const originalProgramData = process.env.ProgramData
function decode(command: string) { return Buffer.from(command.split(' ').at(-1)!, 'base64').toString('utf16le') }
beforeEach(() => {
  vi.resetAllMocks()
  Object.defineProperty(process, 'platform', { configurable: true, value: 'win32' })
  mocks.elevated.mockResolvedValue({ stdout: 'RECOVERY_STORAGE_VERIFIED' })
  mocks.read.mockReturnValue('RECOVERY_ARTIFACT_ABSENT')
  mocks.open.mockResolvedValue({ writeFile: mocks.write, sync: mocks.sync, close: mocks.close })
  for (const operation of [mocks.write, mocks.sync, mocks.close, mocks.rename, mocks.unlink]) operation.mockResolvedValue(undefined)
})
afterEach(() => {
  Object.defineProperty(process, 'platform', platform)
  if (originalProgramData === undefined) delete process.env.ProgramData
  else process.env.ProgramData = originalProgramData
})

describe('trusted recovery storage', () => {
  it.skipIf(process.platform !== 'win32' && !process.env.VPNTE_PWSH).each([
    { variant: 'trusted', accepted: true }, { variant: 'fileAbsent', accepted: true },
    { variant: 'rootOwner', accepted: false }, { variant: 'directoryAce', accepted: false },
    { variant: 'parentReparse', accepted: false }, { variant: 'fileReparse', accepted: false },
    { variant: 'fileType', accepted: false }, { variant: 'fileOwner', accepted: false },
    { variant: 'unprotected', accepted: false }, { variant: 'oversized', accepted: false },
    { variant: 'fileAce', accepted: false }, { variant: 'fileUnprotected', accepted: false },
    { variant: 'directoryReparse', accepted: false }, { variant: 'environmentMismatch', accepted: false }
  ])('executes the combined native ACL/known-folder/read boundary: $variant (AT-03-012)', async ({ variant, accepted }) => {
    if (variant === 'environmentMismatch') process.env.ProgramData = 'C:\\untrusted-programdata-fixture'
    // Every filesystem cmdlet is a fixture. No ProgramData files/ACLs are changed.
    mocks.read.mockImplementation((_exe, args) => {
      const generated = Buffer.from(args.at(-1), 'base64').toString('utf16le')
      const script = `
$global:variant='${variant}'
$global:fixtureArtifact=${JSON.stringify(recoveryManifestPath('firewall.json')).replace(/\\\\/g, '\\')}
function Test-Path { [CmdletBinding()]param($LiteralPath)
  if($global:variant -eq 'fileAbsent' -and $LiteralPath -eq $global:fixtureArtifact){return $false};return $true
}
function Get-Item { [CmdletBinding()]param($LiteralPath,[switch]$Force)
  $isFile=$LiteralPath -eq $global:fixtureArtifact
  $parent=$LiteralPath -eq [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
  $reparse=($global:variant -eq 'fileReparse' -and $isFile) -or ($global:variant -eq 'parentReparse' -and $parent) -or ($global:variant -eq 'directoryReparse' -and -not $parent -and -not $isFile)
  [pscustomobject]@{PSIsContainer=((-not $isFile) -or $global:variant -eq 'fileType');Attributes=$(if($reparse){[IO.FileAttributes]::ReparsePoint}else{[IO.FileAttributes]::Normal});Length=$(if($global:variant -eq 'oversized' -and $isFile){1048577}else{50})}
}
function Get-Acl { [CmdletBinding()]param($LiteralPath)
  $acl=[pscustomobject]@{AreAccessRulesProtected=($global:variant -ne 'unprotected' -and -not ($global:variant -eq 'fileUnprotected' -and $LiteralPath -eq $global:fixtureArtifact));FixturePath=$LiteralPath}
  $acl|Add-Member ScriptMethod GetOwner {param($type)
    $bad=($global:variant -eq 'fileOwner' -and $this.FixturePath -eq $global:fixtureArtifact) -or ($global:variant -eq 'rootOwner' -and $this.FixturePath -ne $global:fixtureArtifact)
    [pscustomobject]@{Value=$(if($bad){'S-1-5-32-545'}else{'S-1-5-32-544'})}
  }
  $acl|Add-Member ScriptMethod GetAccessRules {param($explicit,$inherited,$type)
    $bad=($global:variant -eq 'directoryAce' -and $this.FixturePath -ne $global:fixtureArtifact) -or ($global:variant -eq 'fileAce' -and $this.FixturePath -eq $global:fixtureArtifact)
    [pscustomobject]@{AccessControlType='Allow';IdentityReference=[pscustomobject]@{Value=$(if($bad){'S-1-5-32-545'}else{'S-1-5-18'})}}
  }
  $acl
}
function Get-Content { [CmdletBinding()]param($LiteralPath,[switch]$Raw,$Encoding) '{"schemaVersion":1,"owner":"VPNTE","strictMode":false}' }
${generated}`
      try {
        return execFileSync(process.env.VPNTE_PWSH || 'powershell.exe',
          ['-NoProfile','-NonInteractive','-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')],
          { encoding: 'utf8', timeout: 15000, stdio: ['ignore','pipe','pipe'] })
      } catch { throw new Error('Native trusted boundary rejected') }
    })
    if (accepted) {
      const value = await readRecoveryManifest('firewall.json', value => value)
      expect(value).toEqual(variant === 'fileAbsent' ? null : { schemaVersion: 1, owner: 'VPNTE', strictMode: false })
    } else await expect(readRecoveryManifest('firewall.json', value => value)).rejects.toThrow('Native trusted boundary rejected')
    expect(mocks.read).toHaveBeenCalledOnce()
    expect(mocks.elevated).not.toHaveBeenCalled()
  }, 20000)
  it.skipIf(process.platform !== 'win32' && !process.env.VPNTE_PWSH).each([
    { driver: 'Wintun Userspace Tunnel', pnp: 'SWD\\Wintun\\fixture', ip: '192.168.250.253', prefix: 30, accepted: true },
    { driver: 'Wintun Userspace Tunnel', pnp: 'SWD\\Wintun\\fixture', ip: '192.168.250.253', prefix: 30, status: 'Disconnected', accepted: false },
    { driver: 'Wintun Userspace Tunnel', pnp: 'ROOT\\NET\\fixture', ip: '192.168.250.253', prefix: 30, accepted: false },
    { driver: 'Physical NIC', pnp: 'SWD\\Wintun\\fixture', ip: '192.168.250.253', prefix: 30, accepted: false },
    { driver: 'Wintun Userspace Tunnel', pnp: 'SWD\\Wintun\\fixture', ip: '192.168.250.254', prefix: 30, accepted: false },
    { driver: 'Wintun Userspace Tunnel', pnp: 'SWD\\Wintun\\fixture', ip: '192.168.250.253', prefix: 24, accepted: false }
  ])('checks native TUN driver/device/subnet before ownership commit: $driver / $pnp / $ip / $prefix (AT-03-002)', async fixture => {
    // Execute the actual read script against fake cmdlets; storage remains mocked.
    mocks.read.mockImplementation((_exe, args) => {
      const json = Buffer.from(JSON.stringify(fixture)).toString('base64')
      const script = `$fixture=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${json}'))|ConvertFrom-Json
function Get-NetAdapter { [pscustomobject]@{Name='Ethernet 5';Status=$(if($fixture.status){$fixture.status}else{'Up'});InterfaceDescription='sing-tun Tunnel';DriverDescription=$fixture.driver;PnPDeviceID=$fixture.pnp;ifIndex=5;InterfaceGuid='00000000-0000-0000-0000-000000000005'} }
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
    await ensureRecoveryManifestDir()
    const script = decode(mocks.elevated.mock.calls[0][0])
    expect(script).toContain('$info.Create($acl)')
    expect(script).toContain('Assert-TrustedArtifact $dir $true')
    expect(script).not.toContain('icacls')
    expect(script).not.toContain('Set-Acl')
    expect(script).toContain('ReparsePoint')
  })
  it('does not turn a failed directory verification into an absent manifest', async () => {
    mocks.read.mockImplementation(() => { throw new Error('Untrusted recovery owner') })
    await expect(readRecoveryManifest('firewall.json', value => value)).rejects.toThrow('Untrusted')
    expect(mocks.elevated).not.toHaveBeenCalled()
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
    expect(script.indexOf('ProgramData environment does not match')).toBeLessThan(script.indexOf('RECOVERY_STORAGE_MISSING'))
    expect(mocks.elevated).not.toHaveBeenCalled()
    expect(mocks.read).toHaveBeenCalledOnce()
  })
  it('bootstraps only checked missing directories and then re-verifies the full read (AT-03-012)', async () => {
    mocks.read.mockReturnValueOnce('RECOVERY_STORAGE_MISSING').mockReturnValueOnce('RECOVERY_ARTIFACT_ABSENT')
    expect(await readRecoveryManifest('firewall.json', value => value)).toBeNull()
    expect(mocks.elevated).toHaveBeenCalledOnce()
    expect(mocks.read).toHaveBeenCalledTimes(2)
    expect(mocks.read.mock.calls[0][1]).toEqual(mocks.read.mock.calls[1][1])
  })
  it('fails closed if storage disappears again after bootstrap (AT-03-012)', async () => {
    mocks.read.mockReturnValue('RECOVERY_STORAGE_MISSING')
    await expect(readRecoveryManifest('firewall.json', value => value)).rejects.toThrow('disappeared')
    expect(mocks.read).toHaveBeenCalledTimes(2)
    expect(mocks.elevated).toHaveBeenCalledOnce()
  })
  it('checks every subsequent read instead of caching directory trust (AT-03-012)', async () => {
    expect(await readRecoveryManifest('firewall.json', value => value)).toBeNull()
    mocks.read.mockImplementationOnce(() => { throw new Error('Recovery ACL must be protected') })
    await expect(readRecoveryManifest('firewall.json', value => value)).rejects.toThrow('ACL')
    expect(mocks.read).toHaveBeenCalledTimes(2)
    expect(mocks.elevated).not.toHaveBeenCalled()
  })
  it.each(['binary', 'remove'])('keeps %s operations inside the combined trust boundary (AT-03-012)', async operation => {
    mocks.read.mockReturnValue(operation === 'binary' ? Buffer.from('fixture').toString('base64') : '')
    if (operation === 'binary') expect(await readRecoveryArtifact('script.ps1')).toEqual(Buffer.from('fixture'))
    else await removeRecoveryManifest('firewall.json')
    const script = Buffer.from(mocks.read.mock.calls[0][1].at(-1), 'base64').toString('utf16le')
    expect(script).toContain('CommonApplicationData')
    expect(script).toContain('Untrusted recovery ACE')
    expect(script).toContain('Assert-TrustedArtifact')
    expect(mocks.read).toHaveBeenCalledOnce()
    expect(mocks.elevated).not.toHaveBeenCalled()
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
