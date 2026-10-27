import { describe, expect, it } from 'vitest'
import { deriveSwissState, type SwissState, type SwissStateInput } from './swissState'

const idle: SwissStateInput = {
  cancelling: false, switching: false, connecting: false, disconnecting: false, restarting: false,
  connected: false, leak: false, tunnelState: null, proxyDown: false, degraded: false, verdict: null,
}
const live: Partial<SwissStateInput> = { connected: true, tunnelState: 'running', verdict: 'passed' }

const cases: Array<[string, Partial<SwissStateInput>, SwissState]> = [
  ['nothing running', {}, 'exposed'],
  ['a leak only counts while connected', { leak: true }, 'exposed'],
  ['an unknown tunnel alerts even when not connected', { tunnelState: 'unknown' }, 'alert'],
  ['connected, healthy, IP verified', { ...live }, 'secure'],
  ['connected, IP not verified yet', { ...live, verdict: 'not-checked' }, 'verify'],
  ['connected, IP indeterminate', { ...live, verdict: 'indeterminate' }, 'verify'],
  ['degraded beats verify', { ...live, verdict: 'not-checked', degraded: true }, 'degraded'],
  ['blocked beats degraded', { ...live, degraded: true, proxyDown: true }, 'blocked'],
  ['alert beats blocked', { ...live, proxyDown: true, tunnelState: 'blocked' }, 'alert'],
  ['leak beats alert', { ...live, tunnelState: 'error', leak: true }, 'leak'],
  ['restart beats a leak', { ...live, leak: true, restarting: true }, 'restart'],
  ['closing beats restart', { ...live, restarting: true, disconnecting: true }, 'closing'],
  ['linking beats closing', { disconnecting: true, connecting: true }, 'linking'],
  ['switch beats linking', { ...live, connecting: true, switching: true }, 'switch'],
  ['cancel beats everything', { ...live, leak: true, switching: true, connecting: true, cancelling: true }, 'cancel'],
]

describe('deriveSwissState', () => {
  it.each(cases)('%s', (_name, over, expected) => {
    expect(deriveSwissState({ ...idle, ...over })).toBe(expected)
  })
})
