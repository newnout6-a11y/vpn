// AT-03-001/003: failed and out-of-order status IPC cannot retain verified state.
import { describe, expect, it, vi } from 'vitest'
import { useAppStore } from './store'
import type { FirewallKillSwitchStatus } from '../shared/ipc-types'
const verified: FirewallKillSwitchStatus = { state: 'verified', cleanupRequired: true, reason: 'policy-verified' }
const inactive: FirewallKillSwitchStatus = { state: 'inactive', cleanupRequired: false, reason: 'no-owned-protection' }
function deferred() {
  let resolve!: (value: FirewallKillSwitchStatus) => void
  let reject!: (error: Error) => void
  const promise = new Promise<FirewallKillSwitchStatus>((ok, fail) => { resolve = ok; reject = fail })
  return { promise, resolve, reject }
}
describe('firewall status refresh', () => {
  it('invalidates a previous verification immediately and records failure', async () => {
    const reply = deferred()
    ;(window as any).electronAPI = { getFirewallKillSwitchStatus: () => reply.promise }
    useAppStore.setState({ firewallKillSwitchStatus: verified })
    const request = useAppStore.getState().refreshFirewallKillSwitchStatus()
    expect(useAppStore.getState().firewallKillSwitchStatus).toMatchObject({ state: 'unknown', reason: 'checking' })
    reply.reject(new Error('IPC lost')); await request
    expect(useAppStore.getState().firewallKillSwitchStatus).toMatchObject({ state: 'unknown', reason: 'unavailable' })
  })
  it.each(['verified', 'rejected'] as const)('ignores an older %s reply after a newer inactive result', async kind => {
    const older = deferred(), newer = deferred()
    ;(window as any).electronAPI = { getFirewallKillSwitchStatus: vi.fn().mockReturnValueOnce(older.promise).mockReturnValueOnce(newer.promise) }
    const first = useAppStore.getState().refreshFirewallKillSwitchStatus()
    const second = useAppStore.getState().refreshFirewallKillSwitchStatus()
    newer.resolve(inactive); await second
    if (kind === 'verified') older.resolve(verified)
    else older.reject(new Error('old failure'))
    await first
    expect(useAppStore.getState().firewallKillSwitchStatus).toEqual(inactive)
  })
  it.each([{ active: true }, { state: 'inactive', cleanupRequired: true }, null])('refuses an old or malformed IPC contract %#', async value => {
    ;(window as any).electronAPI = { getFirewallKillSwitchStatus: vi.fn().mockResolvedValue(value) }
    await useAppStore.getState().refreshFirewallKillSwitchStatus()
    expect(useAppStore.getState().firewallKillSwitchStatus.state).toBe('unknown')
  })
  it('invalidates pending verification before a manual firewall mutation', async () => {
    const reply = deferred()
    ;(window as any).electronAPI = { getFirewallKillSwitchStatus: () => reply.promise }
    const request = useAppStore.getState().refreshFirewallKillSwitchStatus()
    useAppStore.getState().invalidateFirewallKillSwitchStatus()
    reply.resolve(verified); await request
    expect(useAppStore.getState().firewallKillSwitchStatus).toMatchObject({ state: 'unknown', reason: 'checking' })
  })
})
