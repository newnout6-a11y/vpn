// AT-01-009, F-002/F-104: end-to-end check of the runtime ACL bootstrap through the REAL elevated helper.
// It creates a throw-away instance directory under the real %ProgramData%\VPNTE\runtime, so it runs only when the
// process is already elevated (the GitHub Windows runner is; an ordinary developer session is not and skips it).
import { execFileSync } from 'node:child_process'
import { existsSync, rmSync } from 'node:fs'
import { randomBytes } from 'node:crypto'
import { afterAll, describe, expect, it, vi } from 'vitest'

vi.mock('electron', () => ({ app: { getPath: () => '', isPackaged: false } }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))

function isElevated(): boolean {
  if (process.platform !== 'win32') return false
  try {
    execFileSync('net', ['session'], { stdio: 'ignore', windowsHide: true, timeout: 15000 })
    return true
  } catch { return false }
}

const elevated = isElevated()
const BS = String.fromCharCode(92)
const programData = process.env.ProgramData || 'C:' + BS + 'ProgramData'
const instance = randomBytes(16).toString('hex')
const instanceDir = [programData, 'VPNTE', 'runtime', instance].join(BS)
const dir = instanceDir + BS + 'tun-runtime'

describe.runIf(elevated)('runtime ACL bootstrap through the real elevated helper', () => {
  afterAll(async () => {
    const { stopElevatedPsHelper } = await import('./elevatedPsHelper')
    stopElevatedPsHelper()
    // Remove only the throw-away instance directory this test created.
    if (instanceDir.toLowerCase().includes(BS + 'vpnte' + BS + 'runtime' + BS + instance)) {
      rmSync(instanceDir, { recursive: true, force: true })
    }
  })

  it('creates the protected directory and the readback accepts it', async () => {
    const { ensureElevatedRuntimeDirHardened, verifyDirectoryHardened } = await import('./runtimeDirSecurity')
    const created = await ensureElevatedRuntimeDirHardened(dir, 'elevated-itest')
    expect(created.diagnostic).toBeUndefined()
    expect(created.hardened).toBe(true)
    expect(existsSync(dir)).toBe(true)
    expect((await verifyDirectoryHardened(dir)).hardened).toBe(true)
  }, 120_000)
})
