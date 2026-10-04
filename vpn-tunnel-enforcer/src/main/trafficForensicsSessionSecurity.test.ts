// AT-01-009, F-002/F-104: stored paths must not redirect elevated script writes.
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { join } from 'path'
const fixture = vi.hoisted(() => ({ read: vi.fn(), write: vi.fn(), mkdir: vi.fn(), exec: vi.fn(), spawn: vi.fn() }))
const ROOT = 'C:\\trusted-fixture\\traffic-forensics'
vi.mock('electron', () => ({ app: { getVersion: () => 'test' } }))
vi.mock('./runtimePaths', () => ({ getPrivilegedRuntimeDir: () => ROOT }))
vi.mock('./admin', () => ({ execElevated: fixture.exec }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./settings', () => ({ settingsStore: { get: () => ({ deepTrafficInspectionEnabled: true }) } }))
vi.mock('./runtimeDirSecurity', () => ({ ensureElevatedRuntimeDirHardened: vi.fn(), verifyDirectoryHardened: vi.fn() }))
vi.mock('child_process', () => ({ spawn: fixture.spawn, default: { spawn: fixture.spawn } }))
vi.mock('fs/promises', () => {
  const api = { readFile: fixture.read, writeFile: fixture.write, mkdir: fixture.mkdir, appendFile: vi.fn(), readdir: vi.fn(), rm: vi.fn() }
  return { ...api, default: api }
})
beforeEach(() => { vi.resetModules(); vi.clearAllMocks() })
describe('forensics session path boundary', () => {
  it.each(['legacy-session', 'foreign-session', 'traversal-id', 'foreign-etl'])('rejects %s before filesystem writes or elevated execution', async mutation => {
    const sessionId = 'fixture'
    const sessionDir = join(ROOT, 'sessions', sessionId)
    const manifest = { sessionId, sessionDir, etlPath: join(sessionDir, 'pktmon.etl'), running: true, engine: 'pktmon' }
    if (mutation === 'legacy-session') manifest.sessionDir = 'C:\\Users\\fixture\\AppData\\Roaming\\VPNTE\\traffic-forensics\\sessions\\fixture'
    if (mutation === 'foreign-session') manifest.sessionDir = 'C:\\foreign-session'
    if (mutation === 'traversal-id') manifest.sessionId = '..'
    if (mutation === 'foreign-etl') manifest.etlPath = 'C:\\foreign-capture.etl'
    fixture.read.mockResolvedValue(JSON.stringify(manifest))
    const { stopTrafficForensicsSession } = await import('./trafficForensics')
    await expect(stopTrafficForensicsSession('fixture-stop')).rejects.toThrow('RuntimeSecurityAclError')
    expect(fixture.write).not.toHaveBeenCalled()
    expect(fixture.mkdir).not.toHaveBeenCalled()
    expect(fixture.exec).not.toHaveBeenCalled()
    expect(fixture.spawn).not.toHaveBeenCalled()
  })
})
