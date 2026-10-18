// AT-00-005: async isolation, nested scope restoration and late native drain.
import { afterEach, expect, it, vi } from 'vitest'
import { currentCorrelationId, withCorrelation } from './actionCorrelation'
import { ConnectionLifecycle } from './connectionLifecycle'

const a = 'ipc_00000000000040008000000000000001', b = 'ipc_00000000000040008000000000000002'
afterEach(() => vi.useRealTimers())

it('restores nested action scopes after synchronous and async failure', async () => {
  expect(currentCorrelationId()).toBeUndefined()
  await withCorrelation(a, async () => {
    expect(currentCorrelationId()).toBe(a)
    expect(() => withCorrelation(b, () => { throw new Error('nested failure') })).toThrow('nested failure')
    expect(currentCorrelationId()).toBe(a)
    await expect(withCorrelation(b, async () => { await Promise.resolve(); throw new Error('async failure') })).rejects.toThrow('async failure')
    expect(currentCorrelationId()).toBe(a)
  })
  expect(currentCorrelationId()).toBeUndefined()
})

it.each(['raw-secret', '00000000-0000-4000-8000-000000000001', a + '\n'])('refuses noncanonical or credential-shaped action context %s', value => {
  const effect = vi.fn()
  expect(() => withCorrelation(value, effect)).toThrow('Invalid action correlation')
  expect(effect).not.toHaveBeenCalled()
  expect(currentCorrelationId()).toBeUndefined()
})

it('keeps timeout recovery under the original action after its caller has returned', async () => {
  vi.useFakeTimers()
  let release!: () => void
  const gate = new Promise<void>(done => { release = done }), seen: Array<string | undefined> = []
  const cleanup = async () => { seen.push(currentCorrelationId()); return { success: true } }
  const lane = new ConnectionLifecycle(() => {}, cleanup, () => seen.push(currentCorrelationId()))
  const started = withCorrelation(a, () => lane.start(async owner => {
    seen.push(currentCorrelationId())
    await owner.wait(gate)
    throw new Error('Cancelled continuation ran')
  }, { timeoutMs: 50 }))
  vi.advanceTimersByTime(50)
  expect(await started).toMatchObject({ code: 'OPERATION_TIMEOUT' })
  expect(currentCorrelationId()).toBeUndefined()
  const stopped = lane.stop(cleanup, { owner: 'recovery' })
  release()
  await stopped
  expect(seen.length).toBeGreaterThanOrEqual(5)
  expect(new Set(seen)).toEqual(new Set([a]))
})

it('attributes a separate manual stop to its new action while cancelling the old start', async () => {
  let release!: () => void
  const gate = new Promise<void>(done => { release = done })
  const events: Array<{ kind: string; id: string | undefined }> = [], cleanup = vi.fn(async () => {
    expect(currentCorrelationId()).toBe(b)
    return { success: true }
  })
  const lane = new ConnectionLifecycle(() => {}, undefined, operation => events.push({ kind: operation.kind, id: currentCorrelationId() }))
  const started = withCorrelation(a, () => lane.start(async owner => { await owner.wait(gate); return { success: true } }))
  const stopped = withCorrelation(b, () => lane.stop(cleanup))
  expect(await started).toMatchObject({ code: 'OPERATION_CANCELLED' })
  release()
  await stopped
  expect(events.filter(event => event.kind === 'connect').map(event => event.id)).toEqual([a, a])
  expect(events.filter(event => event.kind === 'disconnect').map(event => event.id)).toEqual([b, b])
  expect(currentCorrelationId()).toBeUndefined()
})
