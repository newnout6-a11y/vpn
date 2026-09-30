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
  it('never selects AppData as an authoritative source', () => {
    expect(getKillSwitchManifestPath()).toMatch(/VPNTE[\\/]manifests[\\/]firewall\.json$/)
  })
})
