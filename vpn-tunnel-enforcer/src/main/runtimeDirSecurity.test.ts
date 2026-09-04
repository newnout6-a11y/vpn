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

/** The DACL shape we consider hardened. */
function hardenedAcl(owner = SID_ADMINS) {
  return JSON.stringify({
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
    owner: SID_USER,
    protected: false,
    rules: [
      { sid: SID_SYSTEM, rights: 'FullControl', type: 'Allow' },
      { sid: SID_ADMINS, rights: 'FullControl', type: 'Allow' },
      { sid: SID_USER, rights: 'FullControl', type: 'Allow' }
    ]
  })
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

describe('verifyDirectoryHardened', () => {
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
    // Existing children must lose their own explicit ACEs...
    expect(script).toContain('/reset /T')
    // ...but the reset must target children only, NEVER `$dir` itself.
    // `icacls /reset` makes its target inherit from *its own* parent — run on
    // `$dir` itself that immediately undoes the `Set-Acl` two lines above,
    // re-inheriting the still-writable-by-the-user parent DACL. This was a
    // real, live bug: every "hardening succeeded" run was silently reverting
    // itself before the read-back verification ever ran.
    expect(script).toContain('icacls "$dir\\*"')
    expect(script).not.toMatch(/icacls\s+\$dir\s+\/reset/)
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

  it('caches success so repeat connects cost nothing', async () => {
    inspectResponses = [weakAcl(), hardenedAcl()]
    const first = await ensureElevatedRuntimeDirHardened(RUNTIME_DIR, 'tun-runtime')
    const elevatedCallsAfterFirst = execElevatedMock.mock.calls.length
    const inspectCallsAfterFirst = execFileMock.mock.calls.length

    const second = await ensureElevatedRuntimeDirHardened(RUNTIME_DIR, 'tun-runtime')

    expect(first.hardened).toBe(true)
    expect(second.hardened).toBe(true)
    expect(execElevatedMock.mock.calls.length).toBe(elevatedCallsAfterFirst)
    expect(execFileMock.mock.calls.length).toBe(inspectCallsAfterFirst)
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
