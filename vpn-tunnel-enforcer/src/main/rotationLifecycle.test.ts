// AT-00-002/003/007: one rotation identity owns preflight, restart and physical drain.
import { describe, expect, it, vi } from 'vitest'
import { ConnectionLifecycle } from './connectionLifecycle'
import { OperationRegistry } from './operationRegistry'
import { TunnelStateMachine } from './tunnelStateMachine'
import { withCorrelation } from './actionCorrelation'

function held<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>(done => { resolve = done })
  return { promise, resolve }
}
function harness() {
  const evidence = { running: false, pid: null as number | null, softApplied: false }
  const fsm = new TunnelStateMachine(() => evidence)
  const cleanup = vi.fn(async () => { evidence.running = false; evidence.pid = null; evidence.softApplied = false; return { success: true } })
  const observer = vi.fn(), cancel = vi.fn()
  const lane = new ConnectionLifecycle(cancel, cleanup, observer, fsm)
  const registry = new OperationRegistry()
  const run = (effect: Parameters<ConnectionLifecycle['rotate']>[1], timeoutMs = 120_000) =>
    withCorrelation('ipc_3d49f22af56f4eb795812df333b9aa55', () => registry.run('rotation', lease => lane.rotate(lease, effect), { owner: 'rotation', timeoutMs }))
  return { evidence, fsm, lane, registry, cleanup, observer, cancel, run }
}

describe('rotation in the main connection lane', () => {
  it('uses the registry identity and correlation in the real FSM, including idle selection', async () => {
    const h = harness()
    const result = await h.run(async owner => {
      expect(h.lane.operation).toMatchObject({ operationId: h.registry.list()[0].operationId, kind: 'rotation', owner: 'rotation', correlationId: 'ipc_3d49f22af56f4eb795812df333b9aa55' })
      expect(h.fsm.snapshot.transition).toBe('reconnecting')
      return owner.complete(() => ({ success: true, newProfile: 'b' }))
    })
    expect(result).toEqual({ success: true, newProfile: 'b' })
    expect(h.registry.list()).toHaveLength(1)
    expect(h.registry.list()[0].status).toBe('success')
    expect(h.fsm.snapshot).toMatchObject({ state: 'disconnected', transition: null, operation: { status: 'success' } })
    expect(h.observer).not.toHaveBeenCalled() // registry is the sole audit owner
  })

  it.each(['cancel', 'timeout', 'close'] as const)('keeps native ownership after prompt %s and ignores late completion', async cause => {
    const h = harness(), native = held<void>(), entered = held<void>(), publish = vi.fn()
    const pending = h.run(async owner => { owner.beginRestart(); entered.resolve(); await owner.wait(native.promise); return owner.complete(() => { publish(); return { success: true } }) }, 30)
    const observed = pending.catch(error => error)
    await entered.promise
    let closing: Promise<void> | undefined
    if (cause === 'cancel') h.registry.cancel(h.registry.list()[0].operationId)
    if (cause === 'close') closing = h.registry.close()
    expect(await observed).toMatchObject({ category: cause === 'timeout' ? 'timeout' : 'cancelled' })
    expect(h.lane.operation).toMatchObject({ status: cause === 'timeout' ? 'error' : 'cancelled', category: cause === 'timeout' ? 'timeout' : 'cancelled' })
    expect(h.lane.busy).toBe(true)
    expect(h.cleanup).not.toHaveBeenCalled()
    expect(await h.lane.start(async () => ({ success: true }))).toMatchObject({ category: 'conflict' })
    native.resolve()
    await closing
    await vi.waitFor(() => expect(h.registry.isBusy('rotation')).toBe(false))
    expect(h.cleanup).toHaveBeenCalledOnce()
    expect(publish).not.toHaveBeenCalled()
    expect(h.fsm.snapshot).toMatchObject({ state: 'disconnected', transition: null })
  })

  it('manual startup preempts rotation but waits for restart and cleanup before its effects', async () => {
    const h = harness(), native = held<void>(), entered = held<void>(), manualEffect = vi.fn(async () => {
      h.evidence.running = true; h.evidence.pid = 20; return { success: true }
    })
    const rotation = h.run(async owner => { entered.resolve(); await owner.wait(native.promise); return owner.complete(() => ({ success: true })) }).catch(error => error)
    await entered.promise
    const manual = h.lane.start(manualEffect)
    expect(await rotation).toMatchObject({ category: 'cancelled' })
    expect(manualEffect).not.toHaveBeenCalled()
    native.resolve()
    expect(await manual).toEqual({ success: true })
    expect(h.cleanup).toHaveBeenCalledOnce()
    expect(h.fsm.snapshot).toMatchObject({ state: 'connected', transition: null, pid: 20 })
  })

  it('preserves a confirmed live tunnel when preflight is cancelled before touching native state', async () => {
    const h = harness(), probe = held<void>(), entered = held<void>()
    await h.lane.start(async () => { h.evidence.running = true; h.evidence.pid = 10; return { success: true } })
    const pending = h.run(async owner => { entered.resolve(); await owner.wait(probe.promise); return owner.complete(() => ({ success: true })) }).catch(error => error)
    await entered.promise
    h.registry.cancel(h.registry.list()[0].operationId)
    expect(await pending).toMatchObject({ category: 'cancelled' })
    expect(h.fsm.snapshot).toMatchObject({ state: 'connected', transition: null, pid: 10, operation: { status: 'cancelled' } })
    expect(h.cleanup).not.toHaveBeenCalled(); expect(h.cancel).not.toHaveBeenCalled()
    probe.resolve(); await h.registry.close()
    expect(h.cleanup).not.toHaveBeenCalled()
    expect(h.evidence.running).toBe(true)
  })

  it('retains confirmed Soft protection during cancelled rotation preflight', async () => {
    const h = harness(), probe = held<void>(), entered = held<void>()
    await h.lane.start(async () => { h.evidence.softApplied = true; return { success: true } })
    const pending = h.run(async owner => { entered.resolve(); await owner.wait(probe.promise); return owner.complete(() => ({ success: true })) }).catch(error => error)
    await entered.promise; h.registry.cancel(h.registry.list()[0].operationId)
    expect(await pending).toMatchObject({ category: 'cancelled' })
    expect(h.fsm.snapshot).toMatchObject({ state: 'connected', mode: 'soft', transition: null })
    probe.resolve(); await h.registry.close()
    expect(h.cleanup).not.toHaveBeenCalled(); expect(h.evidence.softApplied).toBe(true)
  })

  it.each(['pid', 'lost-runtime', 'fault'] as const)('does not retain the previous protection after %s evidence changed during preflight', async changed => {
    const h = harness(), probe = held<void>(), entered = held<void>()
    await h.lane.start(async () => { h.evidence.running = true; h.evidence.pid = 10; return { success: true } })
    const pending = h.run(async owner => { entered.resolve(); await owner.wait(probe.promise); return owner.complete(() => ({ success: true })) }).catch(error => error)
    await entered.promise
    if (changed === 'pid') h.evidence.pid = 20
    if (changed === 'lost-runtime') { h.evidence.running = false; h.evidence.pid = null }
    if (changed === 'fault') h.fsm.fault('unknown')
    h.registry.cancel(h.registry.list()[0].operationId)
    expect(await pending).toMatchObject({ category: 'cancelled' })
    probe.resolve(); await h.registry.close()
    expect(h.cleanup).toHaveBeenCalledOnce()
    expect(h.fsm.snapshot).toMatchObject({ state: 'disconnected', transition: null })
  })

  it('cannot commit while a retained native effect is still pending', async () => {
    const h = harness(), native = held<void>()
    const pending = h.run(async owner => { owner.retain(native.promise); return owner.complete(() => ({ success: true })) }).catch(error => error)
    await Promise.resolve()
    expect(h.registry.list()[0].status).toBe('running')
    native.resolve()
    expect(await pending).toMatchObject({ category: 'conflict' })
    expect(h.registry.list()[0].status).toBe('error')
  })

  it('rejects rotation during a higher priority startup without any rotation effect', async () => {
    const h = harness(), native = held<void>(), effect = vi.fn()
    const manual = h.lane.start(async owner => { await owner.wait(native.promise); return { success: false } })
    await expect(h.run(effect)).rejects.toMatchObject({ category: 'conflict' })
    expect(effect).not.toHaveBeenCalled()
    native.resolve(); await manual
  })

  it.each(['autopilot', 'adaptive-retry'] as const)('rotation preempts %s and waits for physical cleanup', async owner => {
    const h = harness(), native = held<void>(), effect = vi.fn(async (rotation: Parameters<Parameters<ConnectionLifecycle['rotate']>[1]>[0]) => rotation.complete(() => ({ success: true as const })))
    const previous = h.lane.start(async startup => { await startup.wait(native.promise); return { success: true } }, { owner })
    const next = h.run(effect)
    expect(await previous).toMatchObject({ category: 'cancelled' })
    expect(effect).not.toHaveBeenCalled()
    native.resolve()
    expect(await next).toEqual({ success: true })
    expect(h.cleanup).toHaveBeenCalledOnce()
    expect(effect).toHaveBeenCalledOnce()
  })

  it('does not turn terminal selection into cancelled if abort arrives during commit', async () => {
    const h = harness()
    expect(await h.run(async owner => owner.complete(() => {
      h.registry.cancel(h.registry.list()[0].operationId)
      return { success: true }
    }))).toEqual({ success: true })
    expect(h.registry.list()[0].status).toBe('success')
  })

  it('requires runtime confirmation before reporting a live rotation success', async () => {
    const h = harness()
    await h.lane.start(async () => { h.evidence.running = true; h.evidence.pid = 10; return { success: true } })
    await expect(h.run(async owner => {
      h.evidence.running = false; h.evidence.pid = null
      return owner.complete(() => ({ success: true }))
    })).rejects.toThrow('Rotation confirmation missing')
    expect(h.registry.list()[0].status).toBe('error')
    expect(h.fsm.snapshot.state).not.toBe('connected')
  })
})
