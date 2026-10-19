// AT-00-005/010, F-143: versioned event schema and legacy compatibility.
import { describe, expect, it } from 'vitest'
import { isAppEvent } from './app-event'

const legacy = { ts: '2026-10-19T12:00:00.000Z', level: 'info', scope: 'test', message: 'event' }
const current = { ...legacy, version: 1, monotonicMs: 0, clockId: 'process-clock',
  source: 'unknown', owner: 'unknown', route: 'unconfirmed', confidence: 'indeterminate' }
describe('application event schema', () => {
  it('accepts legacy and current events', () => {
    expect(isAppEvent(legacy)).toBe(true)
    expect(isAppEvent(current)).toBe(true)
  })
  it.each([null, [], {}, { ...legacy, ts: 'broken' }, { ...legacy, level: 'success' },
    { ...legacy, monotonicMs: -1 }, { ...legacy, clockId: 1 }, { ...legacy, correlationId: 'secret' },
    { ...current, version: 2 }, { ...current, version: null }, { ...current, source: 'fake' },
    { ...current, owner: 'fake' }, { ...current, route: 'fake' }, { ...current, confidence: 'fake' },
    { ...current, monotonicMs: undefined }, { ...current, monotonicMs: NaN }, { ...current, clockId: undefined }
  ])('rejects invalid or unsupported records %#', value => expect(isAppEvent(value)).toBe(false))
})
