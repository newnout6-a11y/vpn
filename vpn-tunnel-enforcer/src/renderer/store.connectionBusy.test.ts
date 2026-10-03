/**
 * Tests for the global `connectionBusy` flag in the app store.
 *
 * Regression context (finding U1): `connecting`/`disconnecting` used to be
 * LOCAL React useState inside Dashboard. Switching tabs mid-connect
 * unmounted those components and the busy state was lost. On return the power
 * button re-enabled while the tunnel was still starting → a second click
 * double-started the tunnel and broke routing.
 *
 * The fix moves the transition into this global Zustand store so it survives
 * component unmount. These tests pin the store contract the UI relies on:
 *   1. default is idle (null)
 *   2. it can be set to either transition value and read back
 *   3. it is independent from tunRunning (the whole point — busy must persist
 *      while tunRunning is still false during a start)
 */

import { describe, it, expect, beforeEach, vi } from 'vitest'
import { applyTerminalTunStatus, useAppStore } from './store'

function reset() {
  useAppStore.setState({ globalToasts: [], restartingProgress: null, connectionCancelling: false, serverSwitchingName: null })
  useAppStore.getState().setConnectionBusy(null)
  useAppStore.getState().setTunRunning(false)
}

describe('store.connectionBusy', () => {
  // AT-00-003 / AT-00-008: cleanup owns the busy state until its IPC completes.
  it('keeps cancellation busy across terminal status updates until explicitly finished', () => {
    useAppStore.getState().setConnectionCancelling(true)
    useAppStore.getState().setTunRunning(false)
    useAppStore.getState().setConnectionBusy(null)
    expect(useAppStore.getState().connectionBusy).toBe('disconnecting')
    expect(useAppStore.getState().connectionCancelling).toBe(true)
    useAppStore.getState().setConnectionCancelling(false)
    useAppStore.getState().setConnectionBusy(null)
    expect(useAppStore.getState().connectionBusy).toBeNull()
  })
  beforeEach(reset)

  it.each(['stopped', 'killswitch-active'])('applies final %s while selection is pending (AT-00-008)', status => {
    useAppStore.setState({ mode: 'hard', tunRunning: true, vpnIp: '198.51.100.1', publicIp: '198.51.100.1',
      publicIpVerdict: 'passed', serverSwitchingName: 'Norway', firewallKillSwitchActive: status === 'killswitch-active' })
    useAppStore.getState().setConnectionCancelling(true)
    applyTerminalTunStatus(status)
    const store = useAppStore.getState()
    expect(store.tunRunning).toBe(false)
    expect(store.mode).toBe('off')
    expect(store.vpnIp).toBeNull()
    expect(store.publicIp).toBeNull()
    expect(store.publicIpVerdict).toBe('not-checked')
    expect(store.firewallKillSwitchActive).toBe(status === 'killswitch-active')
    expect(store.serverSwitchingName).toBe('Norway')
    expect(store.connectionCancelling).toBe(true)
    expect(store.connectionBusy).toBe('disconnecting')
    store.acknowledgeServerSwitchCancellation()
    store.setServerSwitchingName(null)
    expect(useAppStore.getState().connectionCancelling).toBe(false)
    expect(useAppStore.getState().connectionBusy).toBeNull()
    expect(useAppStore.getState().tunRunning).toBe(false)
  })

  it.each(['adapting', 'stopping', 'running', 'proxy-down', 'restarting:1/3'])('does not apply a final reset for %s (AT-00-008)', status => {
    useAppStore.setState({ mode: 'hard', tunRunning: true, vpnIp: '198.51.100.1', serverSwitchingName: 'Norway' })
    applyTerminalTunStatus(status)
    expect(useAppStore.getState().tunRunning).toBe(true)
    expect(useAppStore.getState().mode).toBe('hard')
    expect(useAppStore.getState().vpnIp).toBe('198.51.100.1')
  })

  it('does not release an unrelated cancellation when an idle picker clears its name (AT-00-003)', () => {
    useAppStore.getState().setConnectionCancelling(true)
    useAppStore.getState().setServerSwitchingName(null)
    expect(useAppStore.getState().connectionCancelling).toBe(true)
    expect(useAppStore.getState().connectionBusy).toBe('disconnecting')
  })

  it('holds cancellation if selection settles before the cancellation requests are acknowledged (AT-00-007)', () => {
    useAppStore.getState().setServerSwitchingName('Norway')
    useAppStore.getState().setConnectionCancelling(true)
    useAppStore.getState().setServerSwitchingName(null)
    expect(useAppStore.getState().connectionCancelling).toBe(true)
    expect(useAppStore.getState().connectionBusy).toBe('disconnecting')
    useAppStore.getState().acknowledgeServerSwitchCancellation()
    expect(useAppStore.getState().connectionCancelling).toBe(false)
    expect(useAppStore.getState().connectionBusy).toBeNull()
  })

  it('defaults to null (idle)', () => {
    expect(useAppStore.getState().connectionBusy).toBeNull()
  })

  it('can be set to connecting and disconnecting and read back', () => {
    useAppStore.getState().setConnectionBusy('connecting')
    expect(useAppStore.getState().connectionBusy).toBe('connecting')

    useAppStore.getState().setConnectionBusy('disconnecting')
    expect(useAppStore.getState().connectionBusy).toBe('disconnecting')

    useAppStore.getState().setConnectionBusy(null)
    expect(useAppStore.getState().connectionBusy).toBeNull()
  })

  it('survives a tunRunning toggle while a connect is still in flight', () => {
    // Simulate: user clicks connect (busy=connecting) BEFORE the tunnel comes
    // up. tunRunning is still false. This is the exact window where switching
    // tabs used to lose the busy state.
    useAppStore.getState().setConnectionBusy('connecting')
    expect(useAppStore.getState().tunRunning).toBe(false)
    // The store value is global, so a remount (which just re-reads the store)
    // would still see 'connecting'.
    expect(useAppStore.getState().connectionBusy).toBe('connecting')

    // Tunnel finally comes up — UI clears the flag explicitly.
    useAppStore.getState().setTunRunning(true)
    useAppStore.getState().setConnectionBusy(null)
    expect(useAppStore.getState().tunRunning).toBe(true)
    expect(useAppStore.getState().connectionBusy).toBeNull()
  })

  it('is not auto-cleared by setTunRunning (UI owns the clear)', () => {
    // setTunRunning resets restartingProgress but must NOT touch connectionBusy,
    // otherwise a 'running' status arriving before the start IPC resolves would
    // prematurely re-enable the button.
    useAppStore.getState().setConnectionBusy('connecting')
    useAppStore.getState().setTunRunning(true)
    expect(useAppStore.getState().connectionBusy).toBe('connecting')
  })

  it('keeps the UI busy while auto-restart progress is active', () => {
    useAppStore.getState().setConnectionBusy('connecting')
    useAppStore.getState().setRestarting('1/3')
    useAppStore.getState().setConnectionBusy(null)

    expect(useAppStore.getState().connectionBusy).toBe('connecting')

    useAppStore.getState().setRestarting(null)
    useAppStore.getState().setConnectionBusy(null)
    expect(useAppStore.getState().connectionBusy).toBeNull()
  })

  it('caps global toasts and clears dismissed toast timers', () => {
    vi.useFakeTimers()
    try {
      for (let i = 0; i < 25; i++) {
        useAppStore.getState().addGlobalToast('info', `Toast ${i}`)
      }

      expect(useAppStore.getState().globalToasts).toHaveLength(20)
      const id = useAppStore.getState().globalToasts[0].id
      useAppStore.getState().dismissGlobalToast(id)
      expect(useAppStore.getState().globalToasts.some((toast) => toast.id === id)).toBe(false)

      vi.advanceTimersByTime(4000)
      expect(useAppStore.getState().globalToasts).toHaveLength(0)
    } finally {
      vi.useRealTimers()
    }
  })
})
