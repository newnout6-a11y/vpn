// AT-01-009, F-002/F-104: one shared path contract, no legacy execution fallback.
import { afterEach, describe, expect, it, vi } from 'vitest'
import { win32 } from 'path'
const fixture = vi.hoisted(() => ({ userData: 'C:\\Users\\fixture\\AppData\\Roaming\\VPNTE' }))
vi.mock('electron', () => ({ app: { getPath: () => fixture.userData } }))
import { getPrivilegedRuntimeDir } from './runtimePaths'
afterEach(() => { vi.unstubAllEnvs(); fixture.userData = 'C:\\Users\\fixture\\AppData\\Roaming\\VPNTE' })
describe('privileged runtime locations', () => {
  it('uses distinct typed directories under a per-instance ProgramData namespace', () => {
    vi.stubEnv('ProgramData', 'C:\\ProgramData')
    for (const name of ['tun-runtime', 'external-proxy-runtime', 'traffic-forensics'] as const) {
      const path = getPrivilegedRuntimeDir(name)
      expect(path).toMatch(/^C:\\ProgramData\\VPNTE\\runtime\\[a-f0-9]{32}\\/)
      expect(win32.basename(path)).toBe(name)
      expect(path).not.toContain('fixture')
    }
  })
  it('separates userData roots but normalizes case/trailing separators', () => {
    const first = getPrivilegedRuntimeDir('tun-runtime')
    fixture.userData = fixture.userData.toUpperCase() + '\\'
    expect(getPrivilegedRuntimeDir('tun-runtime')).toBe(first)
    fixture.userData = 'C:\\Users\\other\\AppData\\Roaming\\VPNTE'
    expect(getPrivilegedRuntimeDir('tun-runtime')).not.toBe(first)
  })
  it.each(['relative', '\\\\host\\share', 'C:\\bad\npath'])('rejects malformed ProgramData %j', value => {
    vi.stubEnv('ProgramData', value)
    expect(() => getPrivilegedRuntimeDir('tun-runtime')).toThrow('ProgramData')
  })
  it('rejects an untyped path component before any filesystem operation', () => {
    expect(() => getPrivilegedRuntimeDir('../escape' as any)).toThrow('runtime name')
  })
})
