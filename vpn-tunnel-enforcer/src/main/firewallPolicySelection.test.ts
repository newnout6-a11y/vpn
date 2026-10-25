// AT-03-007: the elevated helper policy is chosen by the caller, not guessed from the first line of the script.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const state = vi.hoisted(() => ({ calls: [] as Array<{ script: string; policy: string }>, readOwnership: vi.fn(),
  readManifest: vi.fn(), wfpPresence: vi.fn() }))

vi.mock('electron', () => ({ app: { getPath: () => 'C:\\VPNTE' },
  BrowserWindow: { getAllWindows: () => [] }, dialog: { showMessageBox: vi.fn(async () => ({})) } }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./recoveryPsWorker', () => ({ executeRecoveryOperation: state.readOwnership }))
vi.mock('./recoveryManifest', async importOriginal => ({
  ...await importOriginal<typeof import('./recoveryManifest')>(),
  readRecoveryManifest: state.readManifest
}))
vi.mock('./elevatedPsHelper', () => ({
  isElevatedPsHelperRunning: () => true,
  execElevatedPs: async (script: string, _timeout: number, policy: string) => {
    state.calls.push({ script, policy })
    return { stdout: script.includes('WFP-PRESENCE') ? 'WFP:0' : '0', stderr: '', exitCode: 0 }
  }
}))
// The WFP module builds its own scripts; here it hands the runner a body without the usual loader prefix.
vi.mock('./wfpIpv6', async importOriginal => ({
  ...await importOriginal<typeof import('./wfpIpv6')>(),
  hasWfpIpv6Protection: async (run: (script: string) => Promise<{ stdout: string }>) => {
    const present = await state.wfpPresence()
    await run('# WFP-PRESENCE')
    return present
  }
}))

import { isKillSwitchActive } from './firewallKillSwitch'

const platform = Object.getOwnPropertyDescriptor(process, 'platform')!

describe('firewall kill-switch helper policy', () => {
  beforeEach(() => {
    state.calls = []
    state.readOwnership.mockReset().mockResolvedValue('0')
    state.readManifest.mockReset().mockResolvedValue(null)
    state.wfpPresence.mockReset().mockResolvedValue(false)
    Object.defineProperty(process, 'platform', { value: 'win32' })
  })
  afterEach(() => { Object.defineProperty(process, 'platform', platform) })

  it('sends WFP scripts with the wfp-ipv6 policy whatever their first line is', async () => {
    expect(await isKillSwitchActive()).toBe(false)
    const wfp = state.calls.find(call => call.script.includes('WFP-PRESENCE'))
    expect(wfp?.policy).toBe('wfp-ipv6')
  })

  it.each([['0', false], ['1', true]])('uses the bounded ownership worker result %s without the mutation helper', async (count, active) => {
    state.readOwnership.mockResolvedValueOnce(count)
    expect(await isKillSwitchActive({ probeWfp: false })).toBe(active)
    expect(state.readOwnership).toHaveBeenCalledExactlyOnceWith({ op: 'inspect-owned-firewall-rules' }, 15000)
    expect(state.calls).toHaveLength(0)
  })

  it('sends fallback firewall rule scripts with the firewall-killswitch policy after a worker failure', async () => {
    state.readOwnership.mockRejectedValueOnce(new Error('fixture ownership read failed'))
    expect(await isKillSwitchActive({ probeWfp: false })).toBe(false)
    expect(state.readOwnership).toHaveBeenCalledExactlyOnceWith({ op: 'inspect-owned-firewall-rules' }, 15000)
    expect(state.calls).toHaveLength(1)
    expect(state.calls[0].script).toContain('Get-VpnteFirewallRuleNames')
    expect(state.calls[0].policy).toBe('firewall-killswitch')
  })

  it('overlaps all fresh reads and waits for their physical settlement (AT-03-004/007)', async () => {
    let releaseManifest!: () => void, releaseWfp!: () => void
    state.readManifest.mockReturnValue(new Promise(resolve => { releaseManifest = () => resolve(null) }))
    state.wfpPresence.mockReturnValue(new Promise(resolve => { releaseWfp = () => resolve(false) }))
    let settled = false
    const pending = isKillSwitchActive().then(value => { settled = true; return value })
    await vi.waitFor(() => expect(state.wfpPresence).toHaveBeenCalledOnce())
    expect(state.readManifest).toHaveBeenCalledOnce()
    expect(state.readOwnership).toHaveBeenCalledOnce()
    releaseManifest()
    await Promise.resolve(); await Promise.resolve()
    expect(settled).toBe(false)
    releaseWfp()
    expect(await pending).toBe(false)
  })

  it('keeps an ACL refusal authoritative and drains other reads before rejecting (AT-03-003/007)', async () => {
    const aclError = new Error('untrusted manifest ACL')
    state.readManifest.mockRejectedValue(aclError)
    state.readOwnership.mockResolvedValue('1')
    let release!: () => void, settled = false
    state.wfpPresence.mockReturnValue(new Promise(resolve => { release = () => resolve(false) }))
    const pending = isKillSwitchActive().catch(error => { settled = true; return error })
    await vi.waitFor(() => expect(state.wfpPresence).toHaveBeenCalledOnce())
    expect(settled).toBe(false)
    release()
    expect(await pending).toBe(aclError)
  })

  it.each(['manifest', 'rules', 'neither'])('preserves result/error precedence with %s evidence (AT-03-007)', async evidence => {
    if (evidence === 'manifest') state.readManifest.mockResolvedValue({ owner: 'VPNTE' })
    if (evidence === 'rules') state.readOwnership.mockResolvedValue('1')
    const error = new Error('WFP read failed')
    state.wfpPresence.mockRejectedValue(error)
    if (evidence === 'neither') await expect(isKillSwitchActive()).rejects.toBe(error)
    else expect(await isKillSwitchActive()).toBe(true)
  })
})
