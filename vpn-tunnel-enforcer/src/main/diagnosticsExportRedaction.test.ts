import { afterEach, describe, expect, it, vi } from 'vitest'
import { mkdtemp, readFile, readdir, rm, writeFile } from 'fs/promises'
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
vi.mock('./systemNetwork', () => ({ validateNetworkBackupManifest: (value: unknown) => value }))
vi.mock('./firewallKillSwitch', () => ({ validateFirewallManifest: (value: unknown) => value }))
vi.mock('./physicalAdapterLockdown', () => ({ validateLockdownManifest: (value: unknown) => value }))
vi.mock('./recoveryManifest', () => ({ readRecoveryManifest: vi.fn(), validateBootRecoveryReport: (value: unknown) => value }))
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

import { redactStagedDiagnostics, stageRecoveryManifests } from './diagnosticsExport'
import { readRecoveryManifest } from './recoveryManifest'

describe('diagnostics final secret scan (AT-01-002)', () => {
  let dir = ''
  afterEach(async () => {
    if (dir) await rm(dir, { recursive: true, force: true })
  })

  it('reads only canonical recovery artifacts and redacts before writing staged files', async () => {
    dir = await mkdtemp(join(tmpdir(), 'vpnte-diagnostics-recovery-'))
    vi.mocked(readRecoveryManifest).mockResolvedValue({ password: 'FAKE-SECRET', owner: 'VPNTE' })
    await stageRecoveryManifests(dir)
    const names = vi.mocked(readRecoveryManifest).mock.calls.slice(-4).map(([name]) => name)
    expect(names).toEqual(['latest-tun-network-baseline.json', 'firewall.json', 'latest-physical-adapter-lockdown.json', 'recovery-result.json'])
    for (const name of await readdir(dir)) {
      expect(await readFile(join(dir, name), 'utf8')).not.toContain('FAKE-SECRET')
    }
    expect(await readFile(join(dir, 'killswitch-manifest.json'), 'utf8')).toContain('<redacted>')
  })

  it('reports absent/untrusted evidence without fallback to AppData or staging error secrets', async () => {
    dir = await mkdtemp(join(tmpdir(), 'vpnte-diagnostics-recovery-'))
    vi.mocked(readRecoveryManifest).mockReset()
      .mockRejectedValueOnce(new Error('FAKE-SECRET attacker content in an error'))
      .mockResolvedValue(null)
    await stageRecoveryManifests(dir)
    expect(await readdir(dir)).toEqual(['recovery-artifacts-status.json'])
    const statuses = JSON.parse(await readFile(join(dir, 'recovery-artifacts-status.json'), 'utf8'))
    expect(statuses[0]).toEqual({ artifact: 'latest-tun-network-baseline.json', status: 'unavailable-or-untrusted' })
    expect(statuses.slice(1).every((s: any) => s.status === 'absent')).toBe(true)
    expect(JSON.stringify(statuses)).not.toContain('FAKE-SECRET')
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