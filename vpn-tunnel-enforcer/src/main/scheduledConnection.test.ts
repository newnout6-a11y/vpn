// AT-00-003/007, AT-10-006: production scheduled entrypoint + real admission lane.
import { describe, expect, it, vi } from 'vitest'
import { ConnectionLifecycle } from './connectionLifecycle'
import { runScheduledConnection } from './scheduledConnection'

function held<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>(done => { resolve = done })
  return { promise, resolve }
}

describe('scheduled connection admission', () => {
  it.each(['soft', 'hard'] as const)('manual stop fences late proxy detection and profile selection for %s', async mode => {
    const detected = held<{ proxyAddr: string; proxyType: 'http' } | null>()
    const cleanup = vi.fn(async () => ({ success: true })), lane = new ConnectionLifecycle(vi.fn(), cleanup)
    const actions = { resolveProxy: vi.fn(() => detected.promise), selectProfile: vi.fn(), startDirect: vi.fn(), startProxy: vi.fn() }
    const scheduled = runScheduledConnection(lane, { mode, profileId: 'old-scheduled-profile' }, actions)
    const stopped = lane.stop(cleanup)
    detected.resolve({ proxyAddr: '127.0.0.1:8080', proxyType: 'http' })
    expect(await scheduled).toMatchObject({ success: false, category: 'cancelled' })
    await stopped
    expect(actions.selectProfile).not.toHaveBeenCalled()
    expect(actions.startProxy).not.toHaveBeenCalled()
    expect(cleanup).toHaveBeenCalledOnce()
  })

  it('does not begin scheduled detection or selection while manual startup owns admission', async () => {
    const gate = held<void>(), lane = new ConnectionLifecycle(vi.fn())
    const manual = lane.start(async owner => { await owner.wait(gate.promise); return { success: true } })
    const actions = { resolveProxy: vi.fn(), selectProfile: vi.fn(), startDirect: vi.fn(), startProxy: vi.fn() }
    expect(await runScheduledConnection(lane, { mode: 'direct', profileId: 'scheduled' }, actions)).toMatchObject({ success: false, category: 'conflict' })
    expect(actions.selectProfile).not.toHaveBeenCalled()
    expect(actions.startDirect).not.toHaveBeenCalled()
    gate.resolve()
    await manual
  })

  it.each(['soft', 'hard', 'direct'] as const)('runs %s through the same schedule owner and selects before startup', async mode => {
    const lane = new ConnectionLifecycle(vi.fn()), events: string[] = []
    const start = vi.fn(async owner => { expect(owner.operation.owner).toBe('schedule'); events.push('start'); return { success: true } })
    const actions = {
      resolveProxy: vi.fn(async () => ({ proxyAddr: '127.0.0.1:8080', proxyType: 'http' as const })),
      selectProfile: vi.fn(() => { events.push('select'); return true }), startDirect: start, startProxy: start
    }
    expect(await runScheduledConnection(lane, { mode, profileId: 'scheduled' }, actions)).toMatchObject({ success: true })
    expect(events).toEqual(['select', 'start'])
    expect(actions.resolveProxy).toHaveBeenCalledTimes(mode === 'direct' ? 0 : 1)
  })

  it('fails closed if the scheduled profile was deleted; it does not start an unrelated profile', async () => {
    const lane = new ConnectionLifecycle(vi.fn())
    const actions = { resolveProxy: vi.fn(), selectProfile: vi.fn(() => false), startDirect: vi.fn(), startProxy: vi.fn() }
    expect(await runScheduledConnection(lane, { mode: 'direct', profileId: 'missing' }, actions)).toMatchObject({ success: false, error: 'Профиль расписания недоступен' })
    expect(actions.startDirect).not.toHaveBeenCalled()
    expect(lane.operation).toMatchObject({ owner: 'schedule', status: 'error' })
  })
})
