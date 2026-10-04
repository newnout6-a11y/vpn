/**
 * Tests for runtimeDirSecurity — the ACL hardening that keeps an unprivileged
 * process from planting a binary in a directory we later execute from while
 * elevated (finding #1, CWE-379 / CWE-732 / CWE-367).
 *
 * These assert on the PowerShell we generate and on how we interpret the DACL
 * we read back. The properties that actually matter for the security of the fix:
 *   - inheritance is broken (otherwise admin-only rules sit on top of a DACL
 *     that still grants the user Full Control);
 *   - the owner is reassigned (an owner implicitly holds WRITE_DAC and could
 *     just undo the DACL);
 *   - the result is verified by reading the DACL back, not assumed from a
 *     zero exit code;
 *   - a failure is reported, never silently swallowed, and is retried.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'

const execElevatedMock = vi.hoisted(() => vi.fn())
/**
 * The module under test promisifies `execFile` at import time, so the mock has
 * to be callback-shaped for the real `util.promisify` to wrap it. `inspectImpl`
 * is what each call actually returns.
 */
let inspectImpl: () => { stdout: string } = () => ({ stdout: '' })

const execFileMock = vi.hoisted(() => {
  const fn = vi.fn()
  // The real child_process.execFile carries a promisify.custom implementation
  // that resolves to `{ stdout, stderr }`. Without it, promisify() would resolve
  // to the bare first callback argument and the module under test would see
  // `stdout: undefined`. Calling `fn` inside keeps the call history usable.
  ;(fn as any)[Symbol.for('nodejs.util.promisify.custom')] = async (...args: any[]) => {
    fn(...args)
    const { stdout } = (globalThis as any).__vpnteInspectImpl()
    return { stdout, stderr: '' }
  }
  return fn
})
const isProcessElevatedMock = vi.hoisted(() => vi.fn(async () => true))
const logEventMock = vi.hoisted(() => vi.fn())

vi.mock('./admin', () => ({
  execElevated: execElevatedMock,
  isProcessElevated: isProcessElevatedMock
}))

vi.mock('./appLogger', () => ({ logEvent: logEventMock }))

vi.mock('child_process', () => ({
  default: { execFile: execFileMock },
  execFile: execFileMock
}))

vi.mock('fs/promises', async (importOriginal) => {
  const actual = await importOriginal<typeof import('fs/promises')>()
  return {
    ...actual,
    default: actual,
    stat: vi.fn(async () => ({ isDirectory: () => true }))
  }
})

import {
  ensureElevatedRuntimeDirHardened,
  resetRuntimeDirHardeningCache,
  verifyDirectoryHardened
} from './runtimeDirSecurity'

const SID_SYSTEM = 'S-1-5-18'
const SID_ADMINS = 'S-1-5-32-544'
const SID_USER = 'S-1-5-21-1111111111-2222222222-3333333333-1001'

const RUNTIME_DIR = 'C:\\Users\\u\\AppData\\Roaming\\VPN Tunnel Enforcer\\tun-runtime'

function decodeEncodedCommand(text: string): string {
  const marker = 'EncodedCommand'
  const index = text.indexOf(marker)
  if (index === -1) return text
  return Buffer.from(text.slice(index + marker.length).trim(), 'base64').toString('utf16le')
}

// AT-01-009: a clean root is not proof that its descendants were inspected.
const treeProof = { directory: true, reparse: false, childrenInspected: true, children: [] }

/** The DACL shape we consider hardened. */
function hardenedAcl(owner = SID_ADMINS) {
  return JSON.stringify({
    ...treeProof,
    owner,
    protected: true,
    rules: [
      { sid: SID_SYSTEM, rights: 'FullControl', type: 'Allow' },
      { sid: SID_ADMINS, rights: 'FullControl', type: 'Allow' }
    ]
  })
}

/** The default %APPDATA% shape: the interactive user owns it and can write. */
function weakAcl() {
  return JSON.stringify({
    ...treeProof,
    owner: SID_USER,
    protected: false,
    rules: [
      { sid: SID_SYSTEM, rights: 'FullControl', type: 'Allow' },
      { sid: SID_ADMINS, rights: 'FullControl', type: 'Allow' },
      { sid: SID_USER, rights: 'FullControl', type: 'Allow' }
    ]
  })
}

function childAcl(overrides: Record<string, unknown> = {}) {
  const root = JSON.parse(hardenedAcl())
  return { owner: root.owner, protected: false, rules: root.rules,
    path: RUNTIME_DIR + '\\runtime.exe', directory: false, reparse: false, ...overrides }
}
function treeAcl(children: unknown[]) {
  return JSON.stringify({ ...JSON.parse(hardenedAcl()), children })
}

/** Queue of stdout values the mocked inspect calls return, in order. */
let inspectResponses: string[] = []

beforeEach(() => {
  resetRuntimeDirHardeningCache()
  execElevatedMock.mockReset()
  execFileMock.mockClear()
  logEventMock.mockReset()
  isProcessElevatedMock.mockReset()
  isProcessElevatedMock.mockResolvedValue(true)
  inspectResponses = []
  inspectImpl = () => ({ stdout: inspectResponses.shift() ?? hardenedAcl() })
  ;(globalThis as any).__vpnteInspectImpl = () => inspectImpl()
  execElevatedMock.mockResolvedValue({ stdout: 'HARDENED', stderr: '' })
})

describe('ACL PowerShell module authority (AT-01-009)', () => {
  it.each(['inspect', 'harden'])('pins the builtin Security manifest before %s operations', async operation => {
    let script: string
    if (operation === 'harden') {
      inspectResponses = [weakAcl(), hardenedAcl()]
      await ensureElevatedRuntimeDirHardened(RUNTIME_DIR, 'tun-runtime')
      script = decodeEncodedCommand(String(execElevatedMock.mock.calls[0][0]))
    } else {
      await verifyDirectoryHardened(RUNTIME_DIR)
      script = Buffer.from(execFileMock.mock.calls[0][1][4], 'base64').toString('utf16le')
    }
    const pinnedImport = "Import-Module -Name (Join-Path $PSHOME 'Modules\\Microsoft.PowerShell.Security\\Microsoft.PowerShell.Security.psd1') -ErrorAction Stop;"
    expect(script.startsWith(pinnedImport)).toBe(true)
    expect(script.match(/\bImport-Module\b/g)).toHaveLength(1)
    expect(script).not.toMatch(/Import-Module\s+(?:-Name\s+)?['"]?Microsoft\.PowerShell\.Security(?:['"]|\s|;|$)/)
    expect(script).not.toMatch(/\$env:PSModulePath\s*=|SetEnvironmentVariable|Set-Item\s+Env:/i)
  })
  it('does not treat a module import error as native ACL refusal proof', async () => {
    inspectImpl = () => { throw new Error('Pinned Security module import failed') }
    const result = await verifyDirectoryHardened(RUNTIME_DIR)
    expect(result.hardened).toBe(false)
    expect(result.message).toContain('Pinned Security module import failed')
    expect(result.offenders).toBeUndefined()
    expect(execElevatedMock).not.toHaveBeenCalled()
  })
  it('fails closed without accepting readback when the hardening prelude cannot import', async () => {
    inspectResponses = [weakAcl()]
    execElevatedMock.mockRejectedValueOnce(new Error('Pinned Security module import failed'))
    const result = await ensureElevatedRuntimeDirHardened(RUNTIME_DIR, 'tun-runtime')
    expect(result.hardened).toBe(false)
    expect(result.message).toContain('Pinned Security module import failed')
    expect(execFileMock).toHaveBeenCalledTimes(1)
  })
})

describe('verifyDirectoryHardened', () => {
  it.each(['childrenInspected', 'children', 'directory', 'reparse', 'rules', 'protected'])('requires explicit %s proof (AT-01-009)', async field => {
    const snapshot = JSON.parse(hardenedAcl()); delete snapshot[field]
    inspectResponses = [JSON.stringify(snapshot)]
    expect((await verifyDirectoryHardened(RUNTIME_DIR)).hardened).toBe(false)
  })
  it.each([
    { childrenInspected: false }, { children: null }, { children: {} }, { reparse: true },
    { directory: false }, { rules: [] }, { rules: [{ sid: SID_USER }] },
    { rules: [{ sid: SID_USER, rights: '2032127', type: 'Allow' }] },
    { rules: [{ sid: SID_USER, rights: 'FullControl', type: 'Unknown' }] }
  ])('rejects malformed or incomplete tree/ACL proof (AT-01-009): %j', async patch => {
    inspectResponses = [JSON.stringify({ ...JSON.parse(hardenedAcl()), ...patch })]
    expect((await verifyDirectoryHardened(RUNTIME_DIR)).hardened).toBe(false)
  })
  it.each([false, true])('rejects a user-owned child, directory=%s (AT-01-009)', async directory => {
    inspectResponses = [treeAcl([childAcl({ owner: SID_USER, directory })])]
    const result = await verifyDirectoryHardened(RUNTIME_DIR)
    expect(result.hardened).toBe(false)
    expect(result.offenders?.join(' ')).toContain('runtime.exe')
    expect(result.offenders?.join(' ')).toContain(SID_USER)
  })
  it.each(['WriteData', 'AppendData', 'WriteExtendedAttributes', 'WriteAttributes', 'Delete', 'DeleteSubdirectoriesAndFiles', 'ChangePermissions', 'TakeOwnership'])('rejects child write right %s (AT-01-009)', async rights => {
    const child = childAcl(); child.rules = [...child.rules, { sid: SID_USER, rights, type: 'Allow' }]
    inspectResponses = [treeAcl([child])]
    expect((await verifyDirectoryHardened(RUNTIME_DIR)).hardened).toBe(false)
  })
  it.each([false, true])('rejects a child reparse point before accepting its ACL, directory=%s (AT-01-009)', async directory => {
    inspectResponses = [treeAcl([childAcl({ directory, reparse: true })])]
    expect((await verifyDirectoryHardened(RUNTIME_DIR)).hardened).toBe(false)
  })
  it.each(['owner', 'rules', 'path', 'reparse', 'directory', 'protected'])('does not infer missing child %s proof (AT-01-009)', async field => {
    const child: Record<string, unknown> = childAcl(); delete child[field]
    inspectResponses = [treeAcl([child])]
    expect((await verifyDirectoryHardened(RUNTIME_DIR)).hardened).toBe(false)
  })
  it('accepts inherited child ACLs only under a protected, fully inspected clean tree (AT-01-009)', async () => {
    const child = childAcl({ path: RUNTIME_DIR + '\\nested\\runtime.exe' })
    child.rules = [...child.rules, { sid: SID_USER, rights: 'ReadAndExecute, Synchronize', type: 'Allow' }]
    inspectResponses = [treeAcl([childAcl({ path: RUNTIME_DIR + '\\nested', directory: true }), child])]
    expect((await verifyDirectoryHardened(RUNTIME_DIR)).hardened).toBe(true)
  })
  it.each([
    [childAcl({ path: 'C:\\unrelated\\runtime.exe' })],
    [childAcl({ path: RUNTIME_DIR + '\\missing-parent\\runtime.exe' })],
    [childAcl(), childAcl()]
  ])('rejects out-of-tree, incomplete or duplicate child paths (AT-01-009): %j', async (...children) => {
    inspectResponses = [treeAcl(children)]
    expect((await verifyDirectoryHardened(RUNTIME_DIR)).hardened).toBe(false)
  })
  it('uses a checked manual walk and never recursive enumeration (AT-01-009)', async () => {
    await verifyDirectoryHardened(RUNTIME_DIR)
    const script = Buffer.from(execFileMock.mock.calls[0][1][4], 'base64').toString('utf16le')
    expect(script).toContain("$root['childrenInspected'] = $true")
    expect(script).toContain('Get-ChildItem -LiteralPath')
    expect(script).toContain('ReparsePoint')
    expect(script).not.toMatch(/-Recurse|-ErrorAction\s+SilentlyContinue/)
  })
  it('fails closed when the read-back cannot establish the owner (AT-01-009)', async () => {
    inspectResponses = [JSON.stringify({ ...treeProof, owner: null, protected: true, rules: [] })]
    expect((await verifyDirectoryHardened(RUNTIME_DIR)).hardened).toBe(false)
  })
  it('accepts a protected admin-only DACL', async () => {
    inspectResponses = [hardenedAcl()]
    const result = await verifyDirectoryHardened(RUNTIME_DIR)

    expect(result.hardened).toBe(true)
    expect(result.owner).toBe(SID_ADMINS)
  })

  it('rejects a DACL granting the interactive user write access', async () => {
    inspectResponses = [weakAcl()]
    const result = await verifyDirectoryHardened(RUNTIME_DIR)

    expect(result.hardened).toBe(false)
    expect(result.offenders?.some(o => o.includes(SID_USER))).toBe(true)
  })

  it('rejects a user-owned directory even when no explicit write rule remains', async () => {
    // The owner implicitly holds WRITE_DAC: they can grant themselves write
    // access at will, so an admin-only rule list is not enough on its own.
    inspectResponses = [
      JSON.stringify({
        ...treeProof,
        owner: SID_USER,
        protected: true,
        rules: [
          { sid: SID_SYSTEM, rights: 'FullControl', type: 'Allow' },
          { sid: SID_ADMINS, rights: 'FullControl', type: 'Allow' }
        ]
      })
    ]
    const result = await verifyDirectoryHardened(RUNTIME_DIR)

    expect(result.hardened).toBe(false)
    expect(result.offenders?.some(o => o.includes('owner'))).toBe(true)
  })

  it('rejects an inherited DACL even when it currently looks clean', async () => {
    inspectResponses = [
      JSON.stringify({
        ...treeProof,
        owner: SID_ADMINS,
        protected: false,
        rules: [{ sid: SID_ADMINS, rights: 'FullControl', type: 'Allow' }]
      })
    ]
    const result = await verifyDirectoryHardened(RUNTIME_DIR)

    expect(result.hardened).toBe(false)
    expect(result.message).toContain('наследуется')
  })

  it('treats read-only access for the user as acceptable', async () => {
    // We do not care who can read the runtime directory — only who can write to
    // it or re-permission it.
    inspectResponses = [
      JSON.stringify({
        ...treeProof,
        owner: SID_ADMINS,
        protected: true,
        rules: [
          { sid: SID_ADMINS, rights: 'FullControl', type: 'Allow' },
          { sid: SID_USER, rights: 'ReadAndExecute, Synchronize', type: 'Allow' }
        ]
      })
    ]
    const result = await verifyDirectoryHardened(RUNTIME_DIR)

    expect(result.hardened).toBe(true)
  })

  it('does not mistake a Deny rule for a grant', async () => {
    inspectResponses = [
      JSON.stringify({
        ...treeProof,
        owner: SID_ADMINS,
        protected: true,
        rules: [
          { sid: SID_ADMINS, rights: 'FullControl', type: 'Allow' },
          { sid: SID_USER, rights: 'FullControl', type: 'Deny' }
        ]
      })
    ]
    const result = await verifyDirectoryHardened(RUNTIME_DIR)

    expect(result.hardened).toBe(true)
  })

  it('handles a single-rule DACL that ConvertTo-Json emitted as an object', async () => {
    inspectResponses = [
      JSON.stringify({
        ...treeProof,
        owner: SID_ADMINS,
        protected: true,
        rules: { sid: SID_ADMINS, rights: 'FullControl', type: 'Allow' }
      })
    ]
    const result = await verifyDirectoryHardened(RUNTIME_DIR)

    expect(result.hardened).toBe(true)
  })

  it('reports unhardened when the ACL cannot be read', async () => {
    inspectImpl = () => {
      throw new Error('Access is denied')
    }
    const result = await verifyDirectoryHardened(RUNTIME_DIR)

    expect(result.hardened).toBe(false)
    expect(result.message).toContain('Access is denied')
  })
})

describe('ensureElevatedRuntimeDirHardened', () => {
  it.each(['Runtime child owner reset failed', 'Runtime child ACL reset failed', 'Runtime child owner readback failed', 'Runtime child ACL readback failed'])('rejects child hardening failure: %s (AT-01-009)', async message => {
    inspectResponses = [treeAcl([childAcl({ owner: SID_USER })])]
    execElevatedMock.mockRejectedValueOnce(new Error(message))
    const result = await ensureElevatedRuntimeDirHardened(RUNTIME_DIR, 'tun-runtime')
    expect(result.hardened).toBe(false)
    expect(result.message).toContain(message)
    expect(execFileMock).toHaveBeenCalledTimes(1)
  })
  it('aborts on a reparse preflight failure instead of accepting the clean root (AT-01-009)', async () => {
    inspectResponses = [treeAcl([childAcl({ reparse: true })])]
    execElevatedMock.mockRejectedValueOnce(new Error('Runtime path is a reparse point'))
    expect((await ensureElevatedRuntimeDirHardened(RUNTIME_DIR, 'tun-runtime')).hardened).toBe(false)
    const script = decodeEncodedCommand(String(execElevatedMock.mock.calls[0][0]))
    expect(script.indexOf('$children = @(Get-RuntimeChildren $dir)')).toBeLessThan(script.indexOf('Set-Acl -LiteralPath $dir'))
  })
  it('repairs children even when the root itself is already clean (AT-01-009)', async () => {
    inspectResponses = [treeAcl([childAcl({ owner: SID_USER })]), treeAcl([childAcl()])]
    const result = await ensureElevatedRuntimeDirHardened(RUNTIME_DIR, 'tun-runtime')
    expect(result.hardened).toBe(true)
    expect(execElevatedMock).toHaveBeenCalledTimes(1)
    expect(execFileMock).toHaveBeenCalledTimes(2)
  })
  it.each([
    childAcl({ owner: SID_USER }), childAcl({ reparse: true }),
    childAcl({ rules: [{ sid: SID_USER, rights: 'FullControl', type: 'Allow' }] })
  ])('fails closed if a child remains untrusted after successful hardening (AT-01-009): %j', async child => {
    inspectResponses = [treeAcl([childAcl({ owner: SID_USER })]), treeAcl([child])]
    expect((await ensureElevatedRuntimeDirHardened(RUNTIME_DIR, 'tun-runtime')).hardened).toBe(false)
    expect(execElevatedMock).toHaveBeenCalledTimes(1)
  })
  it('does not accept a legacy root-only readback after hardening (AT-01-009)', async () => {
    const legacy = JSON.parse(hardenedAcl()); delete legacy.childrenInspected
    inspectResponses = [weakAcl(), JSON.stringify(legacy)]
    expect((await ensureElevatedRuntimeDirHardened(RUNTIME_DIR, 'tun-runtime')).hardened).toBe(false)
  })
  it('rechecks child ownership after an earlier successful connection (AT-01-009)', async () => {
    inspectResponses = [treeAcl([childAcl()]), treeAcl([childAcl({ owner: SID_USER })])]
    expect((await ensureElevatedRuntimeDirHardened(RUNTIME_DIR, 'tun-runtime')).hardened).toBe(true)
    isProcessElevatedMock.mockResolvedValue(false)
    expect((await ensureElevatedRuntimeDirHardened(RUNTIME_DIR, 'tun-runtime')).hardened).toBe(false)
    expect(execFileMock).toHaveBeenCalledTimes(2)
  })
  it('shares only concurrent work, not a completed proof (AT-01-009)', async () => {
    const results = await Promise.all([
      ensureElevatedRuntimeDirHardened(RUNTIME_DIR, 'tun-runtime'),
      ensureElevatedRuntimeDirHardened(RUNTIME_DIR, 'tun-runtime')
    ])
    expect(results.every(result => result.hardened)).toBe(true)
    expect(execFileMock).toHaveBeenCalledTimes(1)
    await ensureElevatedRuntimeDirHardened(RUNTIME_DIR, 'tun-runtime')
    expect(execFileMock).toHaveBeenCalledTimes(2)
  })
  it('skips the elevated call when the directory is already hardened', async () => {
    inspectResponses = [hardenedAcl()]
    const result = await ensureElevatedRuntimeDirHardened(RUNTIME_DIR, 'tun-runtime')

    expect(result.hardened).toBe(true)
    expect(execElevatedMock).not.toHaveBeenCalled()
  })

  it('breaks inheritance and reassigns the owner', async () => {
    inspectResponses = [weakAcl(), hardenedAcl()]
    const result = await ensureElevatedRuntimeDirHardened(RUNTIME_DIR, 'tun-runtime')

    expect(result.hardened).toBe(true)
    expect(execElevatedMock).toHaveBeenCalledTimes(1)
    const script = decodeEncodedCommand(String(execElevatedMock.mock.calls[0][0]))

    // Protect from inheritance WITHOUT copying the inherited rules in — the
    // second argument being false is the load-bearing part.
    expect(script).toContain('SetAccessRuleProtection($true, $false)')
    // Owner reassignment: without it the user keeps implicit WRITE_DAC.
    expect(script).toContain('$acl.SetOwner($admins)')
    // Well-known SIDs, not localized names.
    expect(script).toContain(SID_SYSTEM)
    expect(script).toContain(SID_ADMINS)
    // AT-01-009: repair each checked child without following its target.
    expect(script).toContain('/setowner')
    expect(script).toContain('/reset /L')
    expect(script).not.toMatch(/\/T\b|-Recurse|-ErrorAction\s+SilentlyContinue/)
    expect(script).not.toContain('"$dir\\*"')
    expect(script).not.toMatch(/icacls\s+\$dir\s+\/reset/)
    expect(script.indexOf('$children = @(Get-RuntimeChildren $dir)')).toBeLessThan(script.indexOf('Set-Acl -LiteralPath $dir'))
    const commands = script.split('\n').filter(line => /^\s*& icacls/.test(line))
    expect(commands).toHaveLength(2)
    expect(commands.every(line => /\/L\b/.test(line))).toBe(true)
    expect(script).toContain('Runtime child owner reset failed')
    expect(script).toContain('Runtime child ACL reset failed')
    expect(script).toContain('Runtime child owner readback failed')
    expect(script).toContain('Runtime child ACL readback failed')
    expect(script).toContain('$components.Push($candidate)')
    expect(script).toContain('Get-Item -LiteralPath ($components.Pop())')
    expect(script).toContain('$info.Create($acl)')
    expect(script).not.toContain('New-Item -ItemType Directory')
    // Paths are passed literally so spaces and brackets survive.
    expect(script).toContain('-LiteralPath $dir')
    expect(script).toContain(RUNTIME_DIR)
  })

  it('does not revert its own Set-Acl by resetting $dir itself', async () => {
    // Regression for the bug above, independent of the assertion in the test
    // before this one: scan the whole script for ANY icacls invocation whose
    // target is the bare directory variable (with or without quotes) rather
    // than a child glob.
    inspectResponses = [weakAcl(), hardenedAcl()]
    await ensureElevatedRuntimeDirHardened(RUNTIME_DIR, 'tun-runtime')
    const script = decodeEncodedCommand(String(execElevatedMock.mock.calls[0][0]))

    const icaclsLines = script.split('\n').filter(line => /icacls/i.test(line))
    expect(icaclsLines.length).toBeGreaterThan(0)
    for (const line of icaclsLines) {
      expect(line).not.toMatch(/icacls\s+\$dir\s/)
      expect(line).not.toMatch(/icacls\s+"\$dir"\s/)
    }
  })

  it('verifies the DACL after writing instead of trusting the exit code', async () => {
    // Script "succeeds" but the DACL still grants the user write access.
    inspectResponses = [weakAcl(), weakAcl()]
    const result = await ensureElevatedRuntimeDirHardened(RUNTIME_DIR, 'tun-runtime')

    expect(execElevatedMock).toHaveBeenCalledTimes(1)
    expect(result.hardened).toBe(false)
    expect(result.offenders?.some(o => o.includes(SID_USER))).toBe(true)
    expect(logEventMock).toHaveBeenCalledWith(
      'error',
      'runtime-acl',
      expect.stringContaining('still not admin-only'),
      expect.anything()
    )
  })

  it('reports failure loudly when the elevated script throws', async () => {
    inspectResponses = [weakAcl()]
    execElevatedMock.mockRejectedValueOnce(new Error('UAC declined'))
    const result = await ensureElevatedRuntimeDirHardened(RUNTIME_DIR, 'tun-runtime')

    expect(result.hardened).toBe(false)
    expect(result.message).toContain('UAC declined')
    expect(logEventMock).toHaveBeenCalledWith(
      'error',
      'runtime-acl',
      expect.stringContaining('ACL hardening failed'),
      expect.anything()
    )
  })

  it('does not pretend to harden when the process is not elevated', async () => {
    isProcessElevatedMock.mockResolvedValue(false)
    inspectResponses = [weakAcl()]
    const result = await ensureElevatedRuntimeDirHardened(RUNTIME_DIR, 'tun-runtime')

    expect(result.hardened).toBe(false)
    expect(result.message).toContain('нет прав администратора')
    expect(execElevatedMock).not.toHaveBeenCalled()
  })

  it('reads ACL again before every later connection (AT-01-009)', async () => {
    inspectResponses = [weakAcl(), hardenedAcl()]
    const first = await ensureElevatedRuntimeDirHardened(RUNTIME_DIR, 'tun-runtime')
    const elevatedCallsAfterFirst = execElevatedMock.mock.calls.length
    const inspectCallsAfterFirst = execFileMock.mock.calls.length

    const second = await ensureElevatedRuntimeDirHardened(RUNTIME_DIR, 'tun-runtime')

    expect(first.hardened).toBe(true)
    expect(second.hardened).toBe(true)
    expect(execElevatedMock.mock.calls.length).toBe(elevatedCallsAfterFirst)
    expect(execFileMock.mock.calls.length).toBe(inspectCallsAfterFirst + 1)
  })

  it('rejects a weakened directory after an earlier successful connection (AT-01-009)', async () => {
    inspectResponses = [hardenedAcl(), weakAcl()]
    expect((await ensureElevatedRuntimeDirHardened(RUNTIME_DIR, 'tun-runtime')).hardened).toBe(true)
    isProcessElevatedMock.mockResolvedValue(false)
    expect((await ensureElevatedRuntimeDirHardened(RUNTIME_DIR, 'tun-runtime')).hardened).toBe(false)
  })

  it('retries after a failure instead of caching it', async () => {
    // First attempt fails (transient — a file still locked by a dying sing-box),
    // second succeeds. Caching the failure would leave the directory weak for
    // the rest of the process lifetime.
    inspectResponses = [weakAcl(), weakAcl(), weakAcl(), hardenedAcl()]
    const first = await ensureElevatedRuntimeDirHardened(RUNTIME_DIR, 'tun-runtime')
    const second = await ensureElevatedRuntimeDirHardened(RUNTIME_DIR, 'tun-runtime')

    expect(first.hardened).toBe(false)
    expect(second.hardened).toBe(true)
    expect(execElevatedMock).toHaveBeenCalledTimes(2)
  })

  it('escapes single quotes in the directory path', async () => {
    const oddDir = "C:\\Users\\O'Brien\\AppData\\Roaming\\VPNTE\\tun-runtime"
    inspectResponses = [weakAcl(), hardenedAcl()]
    await ensureElevatedRuntimeDirHardened(oddDir, 'tun-runtime')

    const script = decodeEncodedCommand(String(execElevatedMock.mock.calls[0][0]))
    expect(script).toContain("O''Brien")
    // The raw single quote would terminate the PowerShell literal early.
    expect(script).not.toContain("'C:\\Users\\O'Brien")
  })
})
