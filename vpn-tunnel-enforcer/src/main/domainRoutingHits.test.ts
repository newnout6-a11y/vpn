// AT-06-003 / F-011: user domain rules get hit counts from the connection sampler.
import { beforeEach, describe, expect, it, vi } from 'vitest'

const rules = vi.hoisted(() => ({ list: [] as any[] }))

vi.mock('electron', () => ({ ipcMain: { handle: vi.fn() }, dialog: {} }))
vi.mock('electron-store', () => ({ default: class { get() { return rules.list } set() {} } }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./tunController', () => ({ tunController: { getStatus: () => ({ running: false }) } }))

import { createHitRecorder, domainRoutingService } from './domainRouting'
import { mergeConnectionSample, type SamplerSeen } from './trafficConnections'

const rule = (id: string, pattern: string, priority: number) => ({ id, pattern, action: 'direct', priority, hitCount: 0 })

beforeEach(() => { rules.list = [] })

describe('createHitRecorder', () => {
  it('returns null when there are no rules, so the sampler skips the work', () => {
    expect(createHitRecorder()).toBeNull()
  })

  it('counts a matching host once per call against the highest-priority matching rule only', () => {
    rules.list = [rule('exact', 'cdn.hits.example', 0), rule('wild', '*.hits.example', 1)]
    const record = createHitRecorder()!
    record('cdn.hits.example')
    record('img.hits.example')
    record('img.hits.example')
    record('unrelated.example')
    const counts = Object.fromEntries(domainRoutingService.getRules().map((r) => [r.id, r.hitCount]))
    expect(counts).toEqual({ exact: 1, wild: 2 })
  })
})

describe('hit counts from the connection sampler', () => {
  it('counts each new connection once, not on repeated polls', () => {
    rules.list = [rule('r1', '*.sampler.example', 0)]
    const record = createHitRecorder()!
    const domains = {}
    const seen: SamplerSeen = new Map()
    const snap = { connections: [{ id: 'c1', metadata: { host: 'a.sampler.example' }, upload: 1, download: 1 }] }
    mergeConnectionSample(domains, snap, seen, new Set(), 1000, record)
    mergeConnectionSample(domains, snap, seen, new Set(), 2000, record)
    mergeConnectionSample(domains, { connections: [...snap.connections, { id: 'c2', metadata: { host: 'b.sampler.example' } }] }, seen, new Set(), 3000, record)
    expect(domainRoutingService.getRules().find((r) => r.id === 'r1')?.hitCount).toBe(2)
  })
})
