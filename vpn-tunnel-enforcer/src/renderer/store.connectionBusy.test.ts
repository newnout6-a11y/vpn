/**
 * Tests for the global `connectionBusy` flag in the app store.
 *
 * Regression context (finding U1): `connecting`/`disconnecting` used to be
 * LOCAL React useState inside Dashboard/HeroStatus. Switching tabs mid-connect
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

import { describe, it, expect, beforeEach } from 'vitest'
import { useAppStore } from './store'

function reset() {
  useAppStore.getState().setConnectionBusy(null)
  useAppStore.getState().setTunRunning(false)
}

describe('store.connectionBusy', () => {
  beforeEach(reset)

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
})
