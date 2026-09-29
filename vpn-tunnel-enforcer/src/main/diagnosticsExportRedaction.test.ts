import { afterEach, describe, expect, it, vi } from 'vitest'
import { mkdtemp, readFile, rm, writeFile } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'

vi.mock('electron', () => ({
  app: { getPath: vi.fn(() => '/tmp'), getVersion: vi.fn(() => 'test') },
  dialog: {}
}))

vi.mock('./settings', () => ({ settingsStore: { get: vi.fn() } }))
vi.mock('./systemDiagnostics', () => ({ runSystemDiagnostics: vi.fn() }))
vi.mock('./trafficForensics', () => ({ stageTrafficForensicsArtifacts: vi.fn() }))
vi.mock('./tunController', () => ({ getTunRuntimeDir: vi.fn(() => '/tmp/missing') }))
vi.mock('./systemNetwork', () => ({ getTunNetworkBaselineManifestPath: vi.fn(() => '/tmp/missing') }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn(), getFullLogs: vi.fn() }))
vi.mock('./vpnProfiles', () => ({
  redactSensitiveConfig: (value: any) => {
    if (!value || typeof value !== 'object') return value
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [
      key,
      /password|uuid|private.?key/i.test(key) ? '<redacted>' : item
    ]))
  },
  redactSensitiveText: (value: string) => value.replaceAll('FAKE-SECRET', '<redacted>')
}))

import { redactStagedDiagnostics } from './diagnosticsExport'

describe('diagnostics final secret scan (AT-01-002)', () => {
  let dir = ''
  afterEach(async () => {
    if (dir) await rm(dir, { recursive: true, force: true })
  })

  it('scrubs copied JSON and text immediately before compression', async () => {
    dir = await mkdtemp(join(tmpdir(), 'vpnte-diagnostics-redaction-'))
    await writeFile(join(dir, 'copied-manifest.json'), JSON.stringify({ password: 'FAKE-SECRET' }))
    await writeFile(join(dir, 'third-party.log'), 'argv contained FAKE-SECRET')
    await redactStagedDiagnostics(dir)
    expect(await readFile(join(dir, 'copied-manifest.json'), 'utf8')).not.toContain('FAKE-SECRET')
    expect(await readFile(join(dir, 'third-party.log'), 'utf8')).not.toContain('FAKE-SECRET')
  })
})