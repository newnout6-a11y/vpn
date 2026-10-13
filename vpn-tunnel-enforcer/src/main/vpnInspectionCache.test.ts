// AT-09-014: inspecting a key must not persist it as directVpnInput (runtime behaviour, not a source scan).
import { describe, expect, it } from 'vitest'
import { cacheInspectionResult } from './vpnInspectionCache'

const profile = { name: 'a', protocol: 'vless', outbound: { type: 'vless' } }

/** A settings store that merges patches the way settingsStore.save does. */
function makeStore(initial: Record<string, unknown>) {
  const state = { ...initial }
  const saved: Array<Record<string, unknown>> = []
  return { state, saved, save: (patch: Record<string, unknown>) => { saved.push(patch); Object.assign(state, patch) } }
}

describe('cacheInspectionResult', () => {
  it('caches a valid inspection without touching the saved key', () => {
    const store = makeStore({ directVpnInput: 'vless://existing', directVpnCachedProfiles: [] })
    cacheInspectionResult(store.save, ' vless://new ', { profiles: [profile], source: 'text' }, 1234)
    expect(store.state.directVpnInput).toBe('vless://existing')
    expect(store.saved).toEqual([{ directVpnCachedInput: 'vless://new', directVpnCachedSource: 'text', directVpnCachedAt: 1234, directVpnCachedProfiles: [profile] }])
  })

  it('records only the timestamp for a rejected input and keeps the cached servers and the saved key', () => {
    const store = makeStore({ directVpnInput: 'vless://existing', directVpnCachedProfiles: [profile] })
    cacheInspectionResult(store.save, 'garbage', { profiles: [], source: 'text' }, 99)
    expect(store.state.directVpnInput).toBe('vless://existing')
    expect(store.state.directVpnCachedProfiles).toEqual([profile])
    expect(store.saved).toEqual([{ directVpnCachedAt: 99 }])
  })

  it('never writes a directVpnInput key for either outcome', () => {
    const store = makeStore({})
    cacheInspectionResult(store.save, 'x', { profiles: [profile], source: 's' })
    cacheInspectionResult(store.save, 'y', { profiles: [], source: 's' })
    expect(store.saved.every((patch) => !('directVpnInput' in patch))).toBe(true)
  })
})
