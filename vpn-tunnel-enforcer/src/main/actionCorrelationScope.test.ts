// AT-00-005: async isolation, nested scope restoration and late native drain.
import { afterEach, expect, it, vi } from 'vitest'
import { currentCorrelationId, currentActionMetadata, withCorrelation } from './actionCorrelation'
import { ConnectionLifecycle } from './connectionLifecycle'

const a = 'ipc_00000000000040008000000000000001', b = 'ipc_00000000000040008000000000000002'
afterEach(() => vi.useRealTimers())

it('orders admitted start and stop timestamps across a system clock correction (AT-00-005)', async () => {
  const lane = new ConnectionLifecycle(() => {})
  const wall = vi.spyOn(Date, 'now').mockReturnValue(1792368000000)
  try {
    await lane.start(async () => ({ success: true }))
    const startedAt = lane.operation!.startedAt
    wall.mockReturnValue(1792364400000)
    await lane.stop(async () => ({ success: true }))
    expect(lane.operation!.startedAt).toBeGreaterThanOrEqual(startedAt)
  } finally { wall.mockRestore() }
})

it('isolates action metadata, restores nested owner and returns a defensive context snapshot (AT-00-005)', async () => {
  await withCorrelation(a, async () => {
    expect(currentActionMetadata()).toEqual({ source: 'tray', owner: 'manual' })
    const snapshot = currentActionMetadata()!
    snapshot.owner = 'recovery'
    expect(currentActionMetadata()?.owner).toBe('manual')
    withCorrelation(a, () => expect(currentActionMetadata()).toEqual({ source: 'tray', owner: 'recovery' }), { owner: 'recovery' })
    expect(currentActionMetadata()).toEqual({ source: 'tray', owner: 'manual' })
    await withCorrelation(b, async () => {
      await Promise.resolve()
      expect(currentActionMetadata()).toEqual({ source: 'ipc', owner: 'unknown' })
    })
    expect(currentActionMetadata()).toEqual({ source: 'tray', owner: 'manual' })
  }, { source: 'tray', owner: 'manual' })
  expect(currentActionMetadata()).toBeUndefined()
})

it.each([{ source: 'raw-secret' }, { owner: 'raw-secret' }, { owner: 'constructor' }])('refuses invalid action metadata %j (AT-00-005)', metadata => {
  const effect = vi.fn()
  expect(() => withCorrelation(a, effect, metadata as never)).toThrow('Invalid action metadata')
  expect(effect).not.toHaveBeenCalled()
  expect(currentActionMetadata()).toBeUndefined()
})

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

it.each(['sync', 'resolved', 'rejected'] as const)('expires %s action context before a detached native timer fires (AT-00-005)', async kind => {
  let observe!: (id: string | undefined) => void
  const observed = new Promise<string | undefined>(done => { observe = done })
  const arm = () => { setTimeout(() => observe(currentCorrelationId()), 5) }
  if (kind === 'sync') withCorrelation(a, arm)
  else {
    const result = withCorrelation(a, async () => {
      arm()
      await Promise.resolve()
      expect(currentCorrelationId()).toBe(a)
      if (kind === 'rejected') throw new Error('Action failed')
    })
    if (kind === 'rejected') await expect(result).rejects.toThrow('Action failed')
    else await result
  }
  expect(await observed).toBeUndefined()
  expect(currentActionMetadata()).toBeUndefined()
})

it('expires recurring tunnel work after startup completes (AT-00-005)', async () => {
  let observe!: (id: string | undefined) => void
  const observed = new Promise<string | undefined>(done => { observe = done })
  let timer: ReturnType<typeof setInterval> | undefined
  try {
    const lane = new ConnectionLifecycle(() => {})
    await withCorrelation(a, () => lane.start(async () => {
      timer = setInterval(() => observe(currentCorrelationId()), 5)
      expect(currentCorrelationId()).toBe(a)
      return { success: true }
    }))
    expect(await observed).toBeUndefined()
  } finally { clearInterval(timer) }
})

it('keeps late native drain correlated after caller cancellation and expires its detached work afterwards (AT-00-005)', async () => {
  let release!: () => void, observe!: (id: string | undefined) => void
  const gate = new Promise<void>(done => { release = done })
  const observed = new Promise<string | undefined>(done => { observe = done })
  const lane = new ConnectionLifecycle(() => {})
  const started = withCorrelation(a, () => lane.start(async () => {
    await gate // Native work can ignore AbortSignal while the caller has returned.
    expect(currentCorrelationId()).toBe(a)
    setTimeout(() => observe(currentCorrelationId()), 5)
    return { success: true }
  }))
  const stopped = withCorrelation(b, () => lane.stop(async () => ({ success: true })))
  expect(await started).toMatchObject({ code: 'OPERATION_CANCELLED' })
  release()
  await stopped
  expect(await observed).toBeUndefined()
})
