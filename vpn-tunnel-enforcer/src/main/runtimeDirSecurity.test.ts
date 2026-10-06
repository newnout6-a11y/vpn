// AT-01-009, F-002/F-104: root DACL is insufficient without a stable namespace.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { win32 } from 'path'
const mocks = vi.hoisted(() => ({ read: vi.fn(), write: vi.fn(), elevated: vi.fn(), log: vi.fn() }))
vi.mock('child_process', () => {
  const execFile = vi.fn()
  ;(execFile as any)[Symbol.for('nodejs.util.promisify.custom')] = mocks.read
  return { execFile, default: { execFile } }
})
vi.mock('./admin', () => ({ execElevated: mocks.write, isProcessElevated: mocks.elevated }))
vi.mock('./appLogger', () => ({ logEvent: mocks.log }))
import { ensureElevatedRuntimeDirHardened, resetRuntimeDirHardeningCache, verifyDirectoryHardened } from './runtimeDirSecurity'
const SYSTEM = 'S-1-5-18', ADMINS = 'S-1-5-32-544', USER = 'S-1-5-21-1-2-3-1001'
const TI = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
const DIR = 'C:\\ProgramData\\VPNTE\\runtime\\0123456789abcdef0123456789abcdef\\tun-runtime'
const ace = (sid = ADMINS, rights = 0x1F01FF, inheritOnly = false, type = 'Allow') => ({ sid, rights, inheritOnly, type })
function acl(path = DIR, directory = true) {
  return { path, owner: ADMINS, protected: true, directory, reparse: false, rules: [ace(), ace(SYSTEM)] }
}
function proof() {
  const ancestors: ReturnType<typeof acl>[] = []
  for (let p = win32.dirname(DIR); ; p = win32.dirname(p)) {
    ancestors.unshift(acl(p))
    if (p === win32.dirname(p)) break
  }
  return { ...acl(), childrenInspected: true, ancestorsInspected: true, ancestors, children: [] as ReturnType<typeof acl>[] }
}
function reply(value = proof()) { mocks.read.mockResolvedValue({ stdout: JSON.stringify(value), stderr: '' }) }
const diagnostic = (reason = 'RuntimeAclNotProtected') => ({ operation: 'validate-acl', path: 'C:\\ProgramData\\VPNTE',
  reason, errorType: 'System.Management.Automation.RuntimeException', hresult: -2146233087, principal: ADMINS, rights: null })
function receipt(value: unknown = diagnostic()) { return 'VPNTE_RUNTIME_FAILURE:' + JSON.stringify(value) }
function script(call: any[], elevated = false) {
  const encoded = elevated ? call[0].split('EncodedCommand ')[1] : call[1][3]
  return Buffer.from(encoded, 'base64').toString('utf16le')
}
beforeEach(() => {
  vi.clearAllMocks(); resetRuntimeDirHardeningCache()
  mocks.elevated.mockResolvedValue(true)
  mocks.write.mockResolvedValue({ stdout: 'HARDENED', stderr: '' })
  reply()
})
afterEach(() => vi.unstubAllEnvs())
describe('verified runtime tree and namespace', () => {
  it('accepts a complete protected tree under an admin-owned parent chain', async () => {
    expect((await verifyDirectoryHardened(DIR)).hardened).toBe(true)
    expect(mocks.write).not.toHaveBeenCalled()
  })
  it.each(['path', 'owner', 'protected', 'directory', 'reparse', 'rules', 'children', 'childrenInspected', 'ancestors', 'ancestorsInspected'])('requires explicit %s proof', async field => {
    const v: any = proof(); delete v[field]; reply(v)
    expect((await verifyDirectoryHardened(DIR)).hardened).toBe(false)
  })
  it.each([null, [], {}, { ancestorsInspected: true }, 'not JSON'])('refuses malformed snapshots: %j', async value => {
    mocks.read.mockResolvedValue({ stdout: typeof value === 'string' ? value : JSON.stringify(value) })
    expect((await verifyDirectoryHardened(DIR)).hardened).toBe(false)
  })
  it.each(['owner', 'path', 'directory', 'reparse', 'protected', 'rules'])('requires explicit ancestor %s metadata', async field => {
    const v: any = proof(); delete v.ancestors[0][field]; reply(v)
    expect((await verifyDirectoryHardened(DIR)).hardened).toBe(false)
  })
  it.each(['sid', 'rights', 'type', 'inheritOnly'])('requires explicit ACE %s metadata', async field => {
    const v: any = proof(); delete v.ancestors[0].rules[0][field]; reply(v)
    expect((await verifyDirectoryHardened(DIR)).hardened).toBe(false)
  })
  it.each([0x40, 0x10000, 0x40000, 0x80000, 0x10000000, 0x1F01FF])('rejects an effective parent mutation right %i even with a protected root', async rights => {
    const v = proof(); v.ancestors[1].rules.push(ace(USER, rights)); reply(v)
    const result = await verifyDirectoryHardened(DIR)
    expect(result.hardened).toBe(false); expect(result.offenders?.join(' ')).toContain(USER)
  })
  it('does not confuse sibling creation or inherit-only creator grants with DELETE_CHILD', async () => {
    const v = proof(); v.ancestors[1].rules.push(ace(USER, 0x116), ace('S-1-3-0', 0x10000000, true), ace(USER, 0xE0010000, true)); reply(v)
    expect((await verifyDirectoryHardened(DIR)).hardened).toBe(true)
  })
  it('accepts TrustedInstaller only as a system ancestor owner/ACE, not runtime owner', async () => {
    const v = proof(); v.ancestors[0].owner = TI; v.ancestors[0].rules.push(ace(TI)); reply(v)
    expect((await verifyDirectoryHardened(DIR)).hardened).toBe(true)
    v.owner = TI; reply(v); expect((await verifyDirectoryHardened(DIR)).hardened).toBe(false)
  })
  it('refuses an ancestor owner that can rewrite the DACL despite read-only ACEs', async () => {
    const v = proof(); v.ancestors[1].owner = USER; reply(v)
    expect((await verifyDirectoryHardened(DIR)).hardened).toBe(false)
  })
  it.each(['missing', 'duplicate', 'out-of-order', 'wrong-path', 'file', 'reparse'])('refuses %s parent-chain proof', async mutation => {
    const v = proof()
    if (mutation === 'missing') v.ancestors.pop()
    if (mutation === 'duplicate') v.ancestors[1] = v.ancestors[0]
    if (mutation === 'out-of-order') v.ancestors.reverse()
    if (mutation === 'wrong-path') v.ancestors[0].path = 'D:\\'
    if (mutation === 'file') v.ancestors[1].directory = false
    if (mutation === 'reparse') v.ancestors[1].reparse = true
    reply(v); expect((await verifyDirectoryHardened(DIR)).hardened).toBe(false)
  })
  it.each([2, 4, 16, 256, 64, 65536, 262144, 524288])('rejects writable root/child right %i', async rights => {
    const v = proof(); v.children.push(acl(DIR + '\\runtime.exe', false)); v.children[0].rules.push(ace(USER, rights)); reply(v)
    expect((await verifyDirectoryHardened(DIR)).hardened).toBe(false)
  })
  it('rejects inheritance-only runtime write grants that would authorize newly staged files', async () => {
    const v = proof(); v.rules.push(ace(USER, 2, true)); reply(v)
    expect((await verifyDirectoryHardened(DIR)).hardened).toBe(false)
  })
  it.each(['user-owner', 'inherited-root', 'root-file', 'root-reparse', 'wrong-root'])('rejects %s root', async mutation => {
    const v = proof()
    if (mutation === 'user-owner') v.owner = USER
    if (mutation === 'inherited-root') v.protected = false
    if (mutation === 'root-file') v.directory = false
    if (mutation === 'root-reparse') v.reparse = true
    if (mutation === 'wrong-root') v.path = 'C:\\elsewhere'
    reply(v); expect((await verifyDirectoryHardened(DIR)).hardened).toBe(false)
  })
  it.each(['out-of-tree', 'duplicate', 'missing-parent', 'reparse', 'user-owner'])('rejects %s child', async mutation => {
    const v = proof(), child = acl(DIR + '\\runtime.exe', false); v.children.push(child)
    if (mutation === 'out-of-tree') child.path = 'C:\\evil.exe'
    if (mutation === 'duplicate') v.children.push(child)
    if (mutation === 'missing-parent') child.path = DIR + '\\missing\\runtime.exe'
    if (mutation === 'reparse') child.reparse = true
    if (mutation === 'user-owner') child.owner = USER
    reply(v); expect((await verifyDirectoryHardened(DIR)).hardened).toBe(false)
  })
  it('accepts inherited admin-only descendants and read-only/Deny user ACEs', async () => {
    const v = proof(), child = acl(DIR + '\\runtime.exe', false)
    child.protected = false; child.rules.push(ace(USER, 0x1200A9), ace(USER, 0x1F01FF, false, 'Deny'))
    v.children.push(child); reply(v); expect((await verifyDirectoryHardened(DIR)).hardened).toBe(true)
  })
  it.each([undefined, -1, NaN, Infinity, 0x100000000, 'FullControl'])('refuses non-authoritative numeric rights %j', async rights => {
    const v: any = proof(); v.rules[0].rights = rights; reply(v)
    expect((await verifyDirectoryHardened(DIR)).hardened).toBe(false)
  })
  it('fails closed on reader/module failure without leaking arbitrary error text', async () => {
    mocks.read.mockRejectedValueOnce(new Error('vless://FAKE-secret@host'))
    const r = await verifyDirectoryHardened(DIR)
    expect(r.hardened).toBe(false); expect(r.message).not.toContain('FAKE-secret')
  })
  it('checks parent-before-child and pins Windows built-in ACL cmdlets', async () => {
    await verifyDirectoryHardened(DIR)
    const s = script(mocks.read.mock.calls[0])
    expect(s).toContain("Join-Path $PSHOME 'Modules\\Microsoft.PowerShell.Security\\Microsoft.PowerShell.Security.psd1'")
    expect(s.indexOf('$ancestors = @(Get-RuntimeAncestors $dir)')).toBeLessThan(s.indexOf('$root = Get-RuntimeAcl $dir'))
    expect(s).toContain('PropagationFlags]::InheritOnly'); expect(s).not.toMatch(/-Recurse|-ErrorAction\s+SilentlyContinue/)
  })
})
describe.skipIf(process.platform !== 'win32')('native read-only PowerShell policy subset (AT-01-009; no elevation)', () => {
  async function run(scriptText: string) {
    const { execFileSync } = await vi.importActual<typeof import('node:child_process')>('node:child_process')
    return execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(scriptText, 'utf16le').toString('base64')], {
      encoding: 'utf8', timeout: 15000, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe']
    }).trim()
  }
  async function inspectionSource() {
    await verifyDirectoryHardened(DIR)
    return script(mocks.read.mock.calls[0])
  }
  it('parses the actual inspection/bootstrap scripts without executing their mutations', async () => {
    const inspect = await inspectionSource()
    mocks.read.mockRejectedValueOnce(new Error('missing'))
    await ensureElevatedRuntimeDirHardened(DIR, 'native-syntax')
    const bootstrap = script(mocks.write.mock.calls[0], true)
    for (const source of [inspect, bootstrap]) {
      const data = Buffer.from(source).toString('base64')
      expect(await run(`$tokens=$null;$errors=$null;$source=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${data}'));$null=[Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors);if($errors.Count){throw ($errors | Out-String)};Write-Output 'PARSED'`)).toBe('PARSED')
    }
  })
  it('refuses forged ProgramData before reading artifacts or executing bootstrap mutations', async () => {
    vi.stubEnv('ProgramData', 'C:\\not-the-known-folder')
    const inspect = await inspectionSource()
    const data = Buffer.from(inspect).toString('base64')
    expect(await run(`$ProgressPreference='SilentlyContinue';$ErrorActionPreference='Stop';$s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${data}'));try{& ([ScriptBlock]::Create($s));throw 'Unexpected acceptance'}catch{if($_.Exception.Message -ne 'RuntimeProgramDataMismatch'){throw};Write-Output 'FORGED_ENV_REFUSED'}`)).toMatch(/^VPNTE_RUNTIME_FAILURE:.*RuntimeProgramDataMismatch.*\r?\nFORGED_ENV_REFUSED$/)
  })
  it('reads and accepts the real system known-folder namespace without changing ACLs', async () => {
    const source = await inspectionSource()
    const helpers = source.slice(0, source.indexOf('$ancestors = @(Get-RuntimeAncestors $dir)'))
    const result = await run(helpers + `\n$known=[Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData);$proof=@(Get-RuntimeAncestors (Join-Path $known 'read-only-probe'));if($proof.Count -lt 2){throw 'Incomplete native namespace'};Write-Output 'NAMESPACE_VERIFIED'`)
    expect(result).toBe('NAMESPACE_VERIFIED')
  })
  it.each(['owner', 'inheritance', 'write-access', 'access-denied'])('emits a native failure receipt for %s with nonzero exit, without mutations (AT-01-002/009)', async kind => {
    const source = await inspectionSource()
    const helpers = source.slice(0, source.indexOf('$ancestors = @(Get-RuntimeAncestors $dir)'))
    const fixture = kind === 'access-denied'
      ? `function Get-Item { [pscustomobject]@{FullName='C:\\ProgramData\\VPNTE';Attributes=[IO.FileAttributes]::Directory} };function Get-Acl { throw [UnauthorizedAccessException]::new('FAKE-secret') };Get-RuntimeAcl 'C:\\ProgramData\\VPNTE'`
      : `$sample=@{path='C:\\ProgramData\\VPNTE';owner='${kind === 'owner' ? USER : ADMINS}';directory=$true;protected=$${kind === 'inheritance' ? 'false' : 'true'};rules=@(@{sid='${USER}';rights=64;type='Allow';inheritOnly=$false})};Assert-RuntimeAcl $sample $false`
    let failure: any
    try { await run(helpers + '\n' + fixture) } catch (error) { failure = error }
    expect(failure?.status).not.toBe(0)
    const stdout = String(failure?.stdout ?? '')
    const detail = JSON.parse(stdout.trim().split(/\r?\n/).find(line => line.startsWith('VPNTE_RUNTIME_FAILURE:'))!.slice('VPNTE_RUNTIME_FAILURE:'.length))
    expect(detail.path).toBe('C:\\ProgramData\\VPNTE')
    expect(detail.operation).toBe(kind === 'access-denied' ? 'read-acl' : 'validate-acl')
    expect(detail.reason).toBe(({ owner: 'RuntimeNamespaceUntrustedOwner', inheritance: 'RuntimeAclNotProtected', 'write-access': 'RuntimeNamespaceUntrustedAccess', 'access-denied': 'PowerShellError' })[kind])
    expect(detail.errorType).toContain(kind === 'access-denied' ? 'UnauthorizedAccessException' : 'RuntimeException')
    expect(stdout).not.toContain('FAKE-secret')
  })
  it('executes the real ACL predicate against DELETE_CHILD, owner, generic and inheritance-only fixtures', async () => {
    const source = await inspectionSource()
    const helpers = source.slice(0, source.indexOf('$ancestors = @(Get-RuntimeAncestors $dir)'))
    const result = await run(helpers + `\n$sample=@{owner='${ADMINS}';directory=$true;protected=$true;rules=@(@{sid='${USER}';rights=64;type='Allow';inheritOnly=$false})};$refused=$false;try{Assert-RuntimeAcl $sample $true}catch{$refused=$true};if(-not $refused){throw 'DELETE_CHILD accepted'};$sample.rules[0].inheritOnly=$true;Assert-RuntimeAcl $sample $true;$sample.rules[0].inheritOnly=$false;$sample.rules[0].rights=278;Assert-RuntimeAcl $sample $true;$sample.owner='${USER}';$refused=$false;try{Assert-RuntimeAcl $sample $true}catch{$refused=$true};if(-not $refused){throw 'Unsafe owner accepted'};$sample.owner='${ADMINS}';$sample.rules[0].rights=268435456;$refused=$false;try{Assert-RuntimeAcl $sample $true}catch{$refused=$true};if(-not $refused){throw 'GENERIC_ALL accepted'};$sample.rules[0].inheritOnly=$true;$refused=$false;try{Assert-RuntimeAcl $sample $false}catch{$refused=$true};if(-not $refused){throw 'Inheritable runtime write accepted'};Write-Output 'POLICY_VERIFIED'`)
    expect(result).toBe('POLICY_VERIFIED')
  })
})

describe('trusted bootstrap, never repair unsafe existing directories', () => {
  it('does not mutate already proven storage', async () => {
    expect((await ensureElevatedRuntimeDirHardened(DIR, 'tun')).hardened).toBe(true)
    expect(mocks.write).not.toHaveBeenCalled()
  })
  it('atomically creates only application components after known-folder/ancestor verification', async () => {
    mocks.read.mockRejectedValueOnce(new Error('missing'))
    expect((await ensureElevatedRuntimeDirHardened(DIR, 'tun')).hardened).toBe(true)
    const s = script(mocks.write.mock.calls[0], true)
    expect(s).toContain('CommonApplicationData'); expect(s).toContain('$info.Create($acl)')
    expect(s).toContain('$acl.SetOwner'); expect(s).toContain('SetAccessRuleProtection($true, $false)')
    expect(s.indexOf('Get-RuntimeAncestors (Join-Path $knownProgramData')).toBeLessThan(s.indexOf('$info.Create($acl)'))
    expect(s).not.toMatch(/Set-Acl|icacls|CreateDirectory\(|-Recurse/)
    expect(s).toContain('Assert-RuntimeAcl $snapshot $false')
    expect(mocks.read).toHaveBeenCalledTimes(2)
  })
  it('cannot authorize a failed bootstrap or bless an unsafe existing tree', async () => {
    const v = proof(); v.owner = USER; reply(v)
    mocks.write.mockRejectedValueOnce(new Error('Untrusted runtime owner'))
    expect((await ensureElevatedRuntimeDirHardened(DIR, 'tun')).hardened).toBe(false)
    expect(mocks.read).toHaveBeenCalledTimes(1)
  })
  it('cannot authorize a failed or incomplete readback', async () => {
    mocks.read.mockRejectedValueOnce(new Error('missing')).mockResolvedValueOnce({ stdout: '{}' })
    expect((await ensureElevatedRuntimeDirHardened(DIR, 'tun')).hardened).toBe(false)
  })
  it('requires an exact successful bootstrap receipt', async () => {
    mocks.read.mockRejectedValueOnce(new Error('missing')); mocks.write.mockResolvedValueOnce({ stdout: 'NOT-HARDENED' })
    expect((await ensureElevatedRuntimeDirHardened(DIR, 'tun')).hardened).toBe(false)
    expect(mocks.read).toHaveBeenCalledTimes(1)
  })
  it('never tries to bootstrap without elevation', async () => {
    mocks.read.mockRejectedValueOnce(new Error('missing')); mocks.elevated.mockResolvedValueOnce(false)
    expect((await ensureElevatedRuntimeDirHardened(DIR, 'tun')).hardened).toBe(false)
    expect(mocks.write).not.toHaveBeenCalled()
  })
  it.each(['RuntimeAclNotProtected', 'RuntimeNamespaceUntrustedOwner', 'RuntimeNamespaceUntrustedAccess', 'PowerShellError'])('logs bounded bootstrap reason/path for %s without raw output (AT-01-002/009)', async reason => {
    mocks.read.mockRejectedValueOnce(new Error('missing'))
    const detail = { ...diagnostic(reason), principal: USER, rights: 64, password: 'FAKE-secret' }
    mocks.write.mockRejectedValueOnce(Object.assign(new Error('vless://FAKE-secret@host -EncodedCommand FAKE-command'), {
      stdout: receipt(detail), stderr: 'FAKE-secret'
    }))
    const result = await ensureElevatedRuntimeDirHardened(DIR, 'tun')
    expect(result.hardened).toBe(false)
    expect(result.diagnostic).toMatchObject({ operation: 'validate-acl', path: 'C:\\ProgramData\\VPNTE', reason, principal: USER, rights: 64 })
    expect(mocks.log).toHaveBeenCalledWith('error', 'runtime-acl', 'tun: runtime bootstrap refused', expect.objectContaining({ dir: DIR, diagnostic: result.diagnostic }))
    expect(JSON.stringify([result, mocks.log.mock.calls])).not.toMatch(/FAKE-secret|FAKE-command|EncodedCommand/)
    expect(mocks.read).toHaveBeenCalledTimes(1)
  })
  it.each(['{broken', receipt({ ...diagnostic(), operation: 'FAKE-secret' }), receipt({ ...diagnostic(), reason: 'FAKE-secret' }), receipt({ ...diagnostic(), path: 'x'.repeat(5000) })])('does not trust a malformed diagnostic receipt (AT-01-002/009)', async stdout => {
    mocks.read.mockRejectedValueOnce(new Error('missing'))
    mocks.write.mockRejectedValueOnce({ stdout, stderr: 'FAKE-secret' })
    const result = await ensureElevatedRuntimeDirHardened(DIR, 'tun')
    expect(result.hardened).toBe(false)
    expect(result.diagnostic?.reason).toBe('DiagnosticUnavailable')
    expect(JSON.stringify(mocks.log.mock.calls)).not.toContain('FAKE-secret')
  })
  it('a failure receipt cannot be hidden by a successful exit/confirmation (AT-01-009)', async () => {
    mocks.read.mockRejectedValueOnce(new Error('missing'))
    mocks.write.mockResolvedValueOnce({ stdout: receipt() + '\nHARDENED' })
    expect((await ensureElevatedRuntimeDirHardened(DIR, 'tun')).hardened).toBe(false)
    expect(mocks.read).toHaveBeenCalledTimes(1)
  })
  it('logs readback failures and uses the direct PowerShell transport for long scripts (AT-01-009)', async () => {
    mocks.read.mockRejectedValueOnce(new Error('missing')).mockRejectedValueOnce({ stdout: receipt(diagnostic('RuntimeNamespaceUntrustedAccess')) })
    const result = await ensureElevatedRuntimeDirHardened(DIR, 'tun')
    expect(result.refusalCode).toBe('namespace-untrusted')
    expect(mocks.log).toHaveBeenCalledWith('error', 'runtime-acl', 'tun: runtime readback refused', { dir: DIR, result })
    expect(mocks.write.mock.calls[0][0]).toMatch(/^powershell\.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand [A-Za-z0-9+/]+={0,2}$/)
  })
  it('rechecks parents on each connection; only concurrent work shares a proof', async () => {
    await Promise.all([ensureElevatedRuntimeDirHardened(DIR, 'tun'), ensureElevatedRuntimeDirHardened(DIR, 'tun')])
    expect(mocks.read).toHaveBeenCalledTimes(1)
    const v = proof(); v.ancestors[1].rules.push(ace(USER, 64)); reply(v); mocks.write.mockRejectedValueOnce(new Error('unsafe parent'))
    expect((await ensureElevatedRuntimeDirHardened(DIR, 'tun')).hardened).toBe(false)
    expect(mocks.read).toHaveBeenCalledTimes(2)
  })
})
