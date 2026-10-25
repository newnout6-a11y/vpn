import { describe, it, expect, vi } from 'vitest'
vi.mock('electron', () => ({ app: { getPath: () => '/unused' } }))
vi.mock('./admin', () => ({ execElevated: vi.fn() }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
import { validateFirewallManifest, validateSavedProfiles, getKillSwitchManifestPath } from './firewallKillSwitch'
const profiles = [
  { name: 'Domain', defaultOutbound: 'Block' },
  { name: 'Private', defaultOutbound: 'Allow' },
  { name: 'Public', defaultOutbound: 'NotConfigured' }
]
const manifest = () => ({ schemaVersion: 1, owner: 'VPNTE', operationId: '12345678-1234-1234-1234-123456789abc',
  phase: 'active', strictMode: false, createdAt: 1, ruleNames: ['VPNTE-killswitch-allow-app'],
  singboxExePath: 'C:\\VPNTE\\sing-box.exe', savedProfiles: profiles })
describe('trusted firewall schema (AT-03-003, AT-03-012; F-186)', () => {
  it('retains all original policies including Block and NotConfigured', () => {
    expect(validateFirewallManifest(manifest()).savedProfiles).toEqual(profiles)
  })
  it.each([null, {}, { ...manifest(), schemaVersion: 2 }, { ...manifest(), owner: 'attacker' },
    { ...manifest(), ruleNames: ['foreign-rule'] }, { ...manifest(), savedProfiles: profiles.slice(1) },
    { ...manifest(), savedProfiles: [profiles[0], profiles[0], profiles[2]] },
    { ...manifest(), savedProfiles: [{ name: "Public'; Write-Output 'injected'", defaultOutbound: 'Allow' }, ...profiles.slice(1)] },
    { ...manifest(), savedProfiles: [{ name: 'Domain', defaultOutbound: 'Allow; whoami' }, ...profiles.slice(1)] }
  ])('rejects invalid, partial or injected manifests before effects', value => {
    expect(() => validateFirewallManifest(value)).toThrow()
  })
  it('rejects a forged policy snapshot', () => { expect(() => validateSavedProfiles([])).toThrow() })
  it('preserves exact approved helper paths without mutating legacy journals (AT-03-003/012)', () => {
    expect(validateFirewallManifest(manifest())).not.toHaveProperty('programRules')
    const programRules = [{ name: 'VPNTE-killswitch-allow-proxy-0', program: 'C:\\ProgramData\\VPNTE\\tun-runtime\\vpnte-xray.exe' }]
    const value = validateFirewallManifest({ ...manifest(), programRules })
    expect(value.programRules).toEqual(programRules)
    expect(value.programRules).not.toBe(programRules)
  })
  it.each([null, {}, [{ name: 'foreign', program: 'C:\\xray.exe' }],
    [{ name: 'VPNTE-killswitch-allow-app', program: 'C:\\xray.exe' }],
    ...['Any', '*', 'xray.exe', '\\\\server\\share\\xray.exe', 'C:\\..\\xray.exe', 'C:\\folder\\.\\xray.exe',
      'C:\\xray.exe:other.exe', 'C:\\xray.exe\n', 'C:\\xray.dll'].map(program => [{ name: 'VPNTE-killswitch-allow-proxy-0', program }]),
    [{ name: 'VPNTE-killswitch-allow-proxy-0', program: 'C:\\xray.exe' }, { name: 'VPNTE-killswitch-allow-proxy-0', program: 'C:\\other.exe' }]
  ])('rejects invalid or ambiguous approved program metadata %j (AT-03-009/012)', programRules => {
    expect(() => validateFirewallManifest({ ...manifest(), programRules })).toThrow('Invalid firewall program rules')
  })
  it('retains valid independent recovery steps after damaged program metadata (AT-03-003/007)', () => {
    const rejected: string[] = []
    const restored = validateFirewallManifest({ ...manifest(), programRules: [{ name: 'foreign', program: 'Any' }] }, rejected)
    expect(restored.savedProfiles).toEqual(profiles)
    expect(restored.programRules).toEqual([])
    expect(rejected).toEqual(['firewall program scopes: invalid or conflicting snapshot; skipped'])
  })
  it('never selects AppData as an authoritative source', () => {
    expect(getKillSwitchManifestPath()).toMatch(/VPNTE[\\/]manifests[\\/]firewall\.json$/)
  })
})
