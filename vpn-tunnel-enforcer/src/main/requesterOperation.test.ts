// AT-00-003/005/007: production requester ownership and registry, controlled I/O.
import { EventEmitter } from 'node:events'
import type { WebContents } from 'electron'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { OperationRegistry } from './operationRegistry'
import { cancelRequesterOperation as cancel, runRequesterOperation as run } from './requesterOperation'

const id = 'd5abf17e-bf69-4f23-9e3c-b69ed0b32089'
const sender = () => Object.assign(new EventEmitter(), { isDestroyed: () => false }) as unknown as WebContents
let registry: OperationRegistry
const releases = new Set<() => void>()
function held() {
  let release!: () => void
  const promise = new Promise<void>(done => { release = done })
  releases.add(release)
  return { promise, release }
}
beforeEach(() => { registry = new OperationRegistry() })
afterEach(async () => {
  const closed = registry.close()
  for (const release of releases) release()
  releases.clear(); await closed
})

describe('requester operation ownership', () => {
  it('refuses cancellation at terminal commit before wrapper cleanup', async () => {
    const owner = sender()
    const task = run(owner, id, (signal, admitted) => registry.run('import', async lease => {
      admitted(lease)
      const saved = lease.commit(() => 'saved')
      expect(cancel(owner, id)).toBe(false)
      return saved
    }, { signal }))
    expect(await task).toBe('saved')
  })
  it('cancels its own token before result/progress receipt and retains physical drain', async () => {
    const owner = sender(), foreign = sender(), gate = held(), commit = vi.fn()
    const task = run(owner, id, (signal, admitted) => registry.run('import', async lease => {
      admitted(lease)
      await lease.wait(gate.promise)
      return lease.commit(commit)
    }, { signal }))
    const operation = registry.list()[0]
    const rejected = expect(task).rejects.toMatchObject({ category: 'cancelled' })
    expect(operation.operationId).not.toBe(id)
    expect(cancel(foreign, id)).toBe(false)
    expect(cancel(owner, id.toUpperCase())).toBe(true)
    await rejected
    expect(registry.isBusy('import')).toBe(true)
    expect(cancel(owner, id)).toBe(false)
    gate.release(); await registry.close()
    expect(commit).not.toHaveBeenCalled()
    expect(registry.list()[0]).toMatchObject({ operationId: operation.operationId, correlationId: operation.correlationId, status: 'cancelled' })
    expect(owner.eventNames()).toEqual([])
  })

  it('rejects a duplicate without replacing the original owner', async () => {
    const owner = sender(), gate = held(), duplicate = vi.fn()
    const task = run(owner, id, (signal, admitted) => registry.run('refresh', lease => { admitted(lease); return lease.wait(gate.promise) }, { signal }))
    const rejected = expect(task).rejects.toMatchObject({ category: 'cancelled' })
    await expect(run(owner, id, duplicate)).rejects.toMatchObject({ category: 'conflict' })
    expect(duplicate).not.toHaveBeenCalled()
    expect(cancel(owner, id)).toBe(true)
    await rejected
  })

  it('does not let legacy completion remove the newer token registry', async () => {
    const owner = sender(), legacyGate = held(), ownedGate = held()
    const legacy = run(owner, undefined, () => legacyGate.promise)
    const owned = run(owner, id, (signal, admitted) => registry.run('refresh', lease => { admitted(lease); return lease.wait(ownedGate.promise) }, { signal }))
    const rejected = expect(owned).rejects.toMatchObject({ category: 'cancelled' })
    legacyGate.release(); await legacy
    expect(cancel(owner, id)).toBe(true)
    await rejected
  })

  it.each(['', 'invalid', null, '3744ec8d-3fa9-12a5-b948-9de88472264e'])('rejects malformed ID %s before effects', async value => {
    const owner = sender(), effect = vi.fn()
    await expect(run(owner, value, effect)).rejects.toMatchObject({ category: 'validation' })
    expect(() => cancel(owner, value)).toThrow()
    expect(effect).not.toHaveBeenCalled()
    expect(owner.eventNames()).toEqual([])
  })

  it('forgets completed tokens and retains document cancellation for legacy calls', async () => {
    const owner = sender()
    expect(await run(owner, id, async () => 'saved')).toBe('saved')
    expect(cancel(owner, id)).toBe(false)
    const gate = held()
    const task = run(owner, undefined, signal => registry.run('refresh', lease => lease.wait(gate.promise), { signal }))
    const rejected = expect(task).rejects.toMatchObject({ category: 'cancelled' })
    owner.emit('did-navigate')
    await rejected
    expect(owner.eventNames()).toEqual([])
  })
})
