// AT-03-003 / AT-03-012: fail-closed storage boundaries (Windows calls mocked).
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { execFileSync } from 'node:child_process'
import { createHash } from 'crypto'
import { readFileSync, mkdirSync, mkdtempSync, writeFileSync, readdirSync, unlinkSync, rmdirSync } from 'fs'
import { join } from 'path'
import { RECOVERY_QUARANTINE_SCRIPT } from './recoveryPsProtocol'

const mocks = vi.hoisted(() => ({
  elevated: vi.fn(), read: vi.fn(), open: vi.fn(), rename: vi.fn(), unlink: vi.fn(),
  write: vi.fn(), sync: vi.fn(), close: vi.fn(), worker: vi.fn()
}))
vi.mock('./recoveryPsWorker', () => {
  class RecoveryWorkerError extends Error { constructor(public code: string, message: string) { super(message) } }
  return { executeRecoveryOperation: mocks.worker, RecoveryWorkerError }
})
import { RecoveryWorkerError } from './recoveryPsWorker'
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
import { ensureRecoveryManifestDir, readRecoveryManifest, readRecoveryArtifact, removeRecoveryManifest, recordOwnedTunAdapter, recoveryManifestPath, strictRecoveryRequired, writeRecoveryArtifact, RecoveryManifestReadError, quarantineRecoveryManifest } from './recoveryManifest'

const platform = Object.getOwnPropertyDescriptor(process, 'platform')!
const originalProgramData = process.env.ProgramData
function decode(command: string) { return Buffer.from(command.split(' ').at(-1)!, 'base64').toString('utf16le') }
beforeEach(() => {
  vi.resetAllMocks()
  mocks.worker.mockRejectedValue(new RecoveryWorkerError('unavailable', 'fixture unavailable before dispatch'))
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
  it('distinguishes unsupported versions from corrupt trusted content before validation (AT-03-003)', async () => {
    const validate = vi.fn(value => value)
    mocks.read.mockReturnValueOnce('{"schemaVersion":2}').mockReturnValueOnce('{')
    await expect(readRecoveryManifest('firewall.json', validate)).rejects.toMatchObject({ reason: 'unsupported-version' })
    await expect(readRecoveryManifest('firewall.json', validate)).rejects.toBeInstanceOf(RecoveryManifestReadError)
    expect(validate).not.toHaveBeenCalled()
    expect(mocks.elevated).not.toHaveBeenCalled()
  })
  it('quarantines within the checked directory and requires rename read-back (AT-03-003/012)', async () => {
    mocks.elevated.mockResolvedValueOnce({ stdout: 'RECOVERY_ARTIFACT_QUARANTINED' }).mockResolvedValueOnce({ stdout: '' })
    const hash = createHash('sha256').update('{').digest('hex')
    await quarantineRecoveryManifest('firewall.json', hash)
    await expect(quarantineRecoveryManifest('firewall.json', hash)).rejects.toThrow('not confirmed')
    const script = decode(mocks.elevated.mock.calls[0][0])
    expect(script).toContain('Move-Item -LiteralPath')
    expect(script).toContain("$quarantine=$path+'.corrupt-'")
    expect(script).toContain('Untrusted recovery ACE')
    expect(script.indexOf('Recovery manifest changed since rejection')).toBeLessThan(script.indexOf('Move-Item -LiteralPath'))
    expect(script).toContain('[IO.FileShare]::Read -bor [IO.FileShare]::Delete')
  })
  it('uses the privileged typed quarantine operation and never replays uncertain completion (AT-03-003/012)', async () => {
    const hash = createHash('sha256').update('{').digest('hex')
    mocks.worker.mockResolvedValueOnce('RECOVERY_ARTIFACT_QUARANTINED').mockRejectedValueOnce(new RecoveryWorkerError('timeout', 'uncertain quarantine'))
    await quarantineRecoveryManifest('firewall.json', hash)
    await expect(quarantineRecoveryManifest('firewall.json', hash)).rejects.toThrow('uncertain quarantine')
    expect(mocks.worker.mock.calls[0][0]).toEqual({ op: 'quarantine', name: 'firewall.json', contentHash: hash })
    expect(mocks.elevated).not.toHaveBeenCalled()
  })
  it.skipIf(process.platform !== 'win32' && !process.env.VPNTE_PWSH).each(['same', 'changed', 'untrusted'])('executes native quarantine with %s content in an isolated temporary folder (AT-03-003/012)', variant => {
    const root = join(process.cwd(), '.tmp'); mkdirSync(root, { recursive: true })
    const folder = mkdtempSync(join(root, 'quarantine-native-')); const path = join(folder, 'firewall.json')
    const body = variant === 'changed' ? '{"schemaVersion":1}' : '{'
    writeFileSync(path, body, 'utf8')
    const script = `$ErrorActionPreference='Stop'
function Assert-TrustedArtifact($path,$directory) { ${variant === 'untrusted' ? "throw 'Untrusted fixture'" : ''} }
$path='${path.replace(/'/g, "''")}'
$expectedHash='${createHash('sha256').update('{').digest('hex')}'
${RECOVERY_QUARANTINE_SCRIPT}`
    try {
      const invoke = () => execFileSync(process.env.VPNTE_PWSH || 'powershell.exe', ['-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(script, 'utf16le').toString('base64')], { encoding: 'utf8', timeout: 15000, windowsHide: true, stdio: ['ignore','pipe','pipe'] })
      if (variant === 'same') {
        expect(invoke()).toContain('RECOVERY_ARTIFACT_QUARANTINED')
        const files = readdirSync(folder); expect(files).toHaveLength(1)
        expect(files[0]).toMatch(/^firewall\.json\.corrupt-/)
        expect(readFileSync(join(folder, files[0]), 'utf8')).toBe(body)
      } else { expect(invoke).toThrow(); expect(readdirSync(folder)).toEqual(['firewall.json']); expect(readFileSync(path, 'utf8')).toBe(body) }
    } finally { for (const name of readdirSync(folder)) unlinkSync(join(folder, name)); rmdirSync(folder) }
  }, 20000)
  it('preserves nested future-version errors and fingerprints corrupt content (AT-03-003)', async () => {
    mocks.read.mockReturnValue('{"schemaVersion":1}')
    await expect(readRecoveryManifest('firewall.json', () => { throw new RecoveryManifestReadError('unsupported-version', 'nested schema') })).rejects.toMatchObject({ reason: 'unsupported-version' })
    mocks.read.mockReturnValue('{')
    await expect(readRecoveryManifest('firewall.json', value => value)).rejects.toMatchObject({ contentHash: createHash('sha256').update('{').digest('hex') })
    await expect(quarantineRecoveryManifest('firewall.json')).rejects.toThrow('fingerprint')
  })
  it('uses typed worker for fresh reads instead of spawning legacy PowerShell (AT-03-012)', async () => {
    mocks.worker.mockResolvedValueOnce('{"schemaVersion":1}').mockRejectedValueOnce(new RecoveryWorkerError('rejected', 'ACL changed'))
    expect(await readRecoveryManifest('firewall.json', value => value)).toEqual({ schemaVersion: 1 })
    await expect(readRecoveryManifest('firewall.json', value => value)).rejects.toThrow('ACL changed')
    expect(mocks.read).not.toHaveBeenCalled()
    expect(mocks.elevated).not.toHaveBeenCalled()
  })
  it('commits worker-backed writes only after fsync and explicit temporary proof (AT-03-007)', async () => {
    mocks.worker.mockImplementation(async request => request.op === 'ensure' ? 'RECOVERY_STORAGE_VERIFIED' : 'RECOVERY_TEMP_VERIFIED')
    await writeRecoveryArtifact('firewall.json', '{}')
    expect(mocks.worker.mock.calls.map(call => call[0].op)).toEqual(['ensure', 'protect'])
    expect(mocks.sync.mock.invocationCallOrder[0]).toBeLessThan(mocks.worker.mock.invocationCallOrder[1])
    expect(mocks.worker.mock.invocationCallOrder[1]).toBeLessThan(mocks.rename.mock.invocationCallOrder[0])
    expect(mocks.elevated).not.toHaveBeenCalled()
  })
  it.each(['timeout', 'exited', 'protocol', 'rejected', 'closed', 'busy'] as const)('does not replay dispatched %s failures in the legacy path (AT-03-007)', async code => {
    mocks.worker.mockResolvedValueOnce('RECOVERY_STORAGE_VERIFIED').mockRejectedValueOnce(new RecoveryWorkerError(code, 'uncertain or rejected'))
    await expect(writeRecoveryArtifact('firewall.json', '{}')).rejects.toThrow('uncertain or rejected')
    expect(mocks.rename).not.toHaveBeenCalled()
    expect(mocks.elevated).not.toHaveBeenCalled()
    expect(mocks.unlink).toHaveBeenCalled()
  })
  it('does not commit after storage disappearance or an absent temporary proof (AT-03-012)', async () => {
    mocks.worker.mockResolvedValueOnce('RECOVERY_STORAGE_VERIFIED').mockResolvedValueOnce('RECOVERY_STORAGE_MISSING')
    await expect(writeRecoveryArtifact('firewall.json', '{}')).rejects.toThrow('temporary verification')
    expect(mocks.rename).not.toHaveBeenCalled()
  })
  it('rechecks worker storage after explicit absence/bootstrap (AT-03-012)', async () => {
    mocks.worker.mockResolvedValueOnce('RECOVERY_STORAGE_MISSING').mockResolvedValueOnce('RECOVERY_STORAGE_VERIFIED').mockResolvedValueOnce('RECOVERY_ARTIFACT_ABSENT')
    expect(await readRecoveryManifest('firewall.json', value => value)).toBeNull()
    expect(mocks.worker.mock.calls.map(call => call[0].op)).toEqual(['read', 'ensure', 'read'])
    expect(mocks.read).not.toHaveBeenCalled()
  })
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
