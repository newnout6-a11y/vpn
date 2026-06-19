import { describe, expect, it } from 'vitest'
import { displayedServerPing } from './Servers'

describe('displayedServerPing', () => {
  it('uses per-row server ping when present', () => {
    expect(displayedServerPing({ ping: 120 }, { ping: 80 })).toBe(80)
  })

  it('falls back to persisted profile ping', () => {
    expect(displayedServerPing({ ping: 120 })).toBe(120)
  })

  it('never receives or displays health-check latency', () => {
    const healthLatencyThatMustNotBeShown = 3
    expect(displayedServerPing({ ping: 120 }, { ping: null })).not.toBe(healthLatencyThatMustNotBeShown)
    expect(displayedServerPing({ ping: 120 }, { ping: null })).toBe(120)
  })
})
