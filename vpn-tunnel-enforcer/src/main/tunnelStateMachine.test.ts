// AT-00-002/008, F-019/F-195: production FSM and real connection admission.
import { describe, expect, it, vi } from 'vitest'
import assert from 'node:assert/strict'
import fc from 'fast-check'
import { ConnectionLifecycle } from './connectionLifecycle'
import { TunnelStateMachine } from './tunnelStateMachine'
import { connectionFailure } from '../shared/operation'
import { IPC_ERRORS, IpcFault, type IpcErrorCategory } from '../shared/ipc-result'

function harness() {
  const evidence = { running: false, pid: null as number | null, softApplied: false }
  const snapshots: unknown[] = []
  const model = new TunnelStateMachine(() => ({ ...evidence }), snapshot => snapshots.push(snapshot))
  const cleanup = vi.fn(async () => { evidence.running = false; evidence.pid = null; evidence.softApplied = false; return { success: true } })
  const lane = new ConnectionLifecycle(vi.fn(), cleanup, undefined, model)
  const connect = () => lane.start(async () => { evidence.running = true; evidence.pid = 123; model.runtimeChanged('running'); return { success: true } })
  return { model, lane, evidence, snapshots, cleanup, connect }
}

describe('canonical tunnel state', () => {
  it('confirms cancelled server-switch cleanup only from a complete current native stop receipt (AT-00-002/003/008)', async () => {
    const h = harness()
    await h.connect()
    h.model.nativeStartBegan(1)
    h.evidence.running = false; h.evidence.pid = null
    h.model.runtimeChanged('adapting')
    h.model.nativeStartBegan(2)
    h.model.nativeStartFinished({ generation: 2, success: false })
    h.model.runtimeChanged('stopped')
    expect(h.model.snapshot.state).toBe('unknown')
    const receipt = { generation: 2, preserveNetworkProtection: false, result: { success: true as const,
      networkCleanup: { baseline: true, firewall: true, adapters: true } } }
    for (const step of ['baseline', 'firewall', 'adapters'] as const) {
      h.model.nativeStopFinished({ ...receipt, result: { success: true, networkCleanup: { ...receipt.result.networkCleanup, [step]: false } } })
      expect(h.model.snapshot.state).toBe('unknown')
    }
    h.model.nativeStopFinished({ ...receipt, generation: 1 })
    h.model.nativeStopFinished({ ...receipt, preserveNetworkProtection: true })
    h.model.nativeStopFinished({ ...receipt, result: { success: true } })
    expect(h.model.snapshot.state).toBe('unknown')
    h.model.nativeStopFinished(receipt)
    expect(h.model.snapshot).toMatchObject({ state: 'disconnected', transition: null, cleanupRequired: false, mode: null })
    expect(await h.connect()).toMatchObject({ success: true })
    expect(h.model.snapshot.state).toBe('connected')
  })

  it('does not let native stop receipts overtake an active connection owner or live runtime (AT-00-003)', async () => {
    const h = harness()
    h.model.nativeStartBegan(1)
    const receipt = { generation: 1, preserveNetworkProtection: false, result: { success: true as const,
      networkCleanup: { baseline: true, firewall: true, adapters: true } } }
    await h.lane.start(async () => {
      const before = h.model.snapshot
      expect(h.model.nativeStopFinished(receipt).success).toBe(false)
      expect(h.model.snapshot).toEqual(before)
      h.evidence.running = true; h.evidence.pid = 123
      return { success: true }
    })
    expect(h.model.nativeStopFinished(receipt).success).toBe(false)
    expect(h.model.snapshot.state).toBe('connected')
  })

  it.each(['internal', 'permission', 'network', 'conflict', 'validation'] as const)('keeps confirmed Soft protection on returned %s refresh failure, and requires fresh evidence next time (AT-00-002/008)', async category => {
    const h = harness()
    await h.lane.start(async () => { h.evidence.softApplied = true; return { success: true } })
    expect(await h.lane.start(async owner => {
      expect(h.model.confirmRetainedSoft(owner.operation.operationId)).toEqual({ success: true })
      return connectionFailure(category)
    }, { refreshSoft: true })).toMatchObject({ success: false })
    expect(h.model.snapshot).toMatchObject({ state: 'connected', mode: 'soft', transition: null, operation: { status: 'error' } })
    await h.lane.start(async () => ({ success: false }), { refreshSoft: true })
    expect(h.model.snapshot.state).toBe('error')
  })

  it.each(Object.keys(IPC_ERRORS) as IpcErrorCategory[])('invalidates Soft read-back before a later thrown %s failure (AT-00-002/004)', async category => {
    const h = harness()
    await h.lane.start(async () => { h.evidence.softApplied = true; return { success: true } })
    const fault = new IpcFault(category)
    await expect(h.lane.start(async owner => {
      expect(h.model.confirmRetainedSoft(owner.operation.operationId).success).toBe(true)
      throw fault
    }, { refreshSoft: true })).rejects.toBe(fault)
    expect(h.model.snapshot.state).not.toBe('connected')
    expect(h.lane.operation?.category).toBe(category)
  })

  it.each(['initial', 'native', 'stale', 'fault', 'lost-env', 'internal'] as const)('does not invent retained Soft protection for %s (AT-00-002)', async failure => {
    const h = harness()
    if (failure === 'native') {
      await h.connect()
      const before = h.model.snapshot
      expect(h.model.confirmRetainedSoft(before.operation!.operationId)).toMatchObject({ success: false })
      expect(h.model.snapshot).toEqual(before)
      return
    }
    else if (failure !== 'initial') await h.lane.start(async () => { h.evidence.softApplied = true; return { success: true } })
    const refresh = h.lane.start(async owner => {
      if (failure === 'fault') h.model.fault('unknown')
      if (failure === 'lost-env') h.evidence.softApplied = false
      const id = failure === 'stale' ? 'previous-operation' : owner.operation.operationId
      const before = h.model.snapshot
      const result = h.model.confirmRetainedSoft(id)
      if (failure === 'internal') {
        expect(result.success).toBe(true)
        throw new Error('later internal error')
      }
      expect(result).toMatchObject({ success: false, code: 'FSM_INVALID_TRANSITION' })
      expect(h.model.snapshot).toEqual(before)
      return { success: false }
    }, { refreshSoft: true })
    if (failure === 'internal') await expect(refresh).rejects.toThrow('later internal error')
    else await refresh
    expect(h.model.snapshot.state).not.toBe('connected')
  })

  it.each(['native', 'fault', 'cancel'] as const)('invalidates confirmed Soft retention on later %s (AT-00-002/003)', async failure => {
    const h = harness()
    await h.lane.start(async () => { h.evidence.softApplied = true; return { success: true } })
    let id = ''
    const refresh = h.lane.start(async owner => {
      id = owner.operation.operationId
      expect(h.model.confirmRetainedSoft(id).success).toBe(true)
      if (failure === 'native') { h.evidence.running = true; h.evidence.pid = 123 }
      else if (failure === 'fault') h.model.fault('unknown')
      else await new Promise<void>(resolve => owner.signal.addEventListener('abort', () => resolve(), { once: true }))
      return { success: false }
    }, { refreshSoft: true })
    const stop = failure === 'cancel' ? h.lane.stop(h.cleanup) : null
    await refresh
    if (stop) await stop
    expect(h.model.snapshot.state).not.toBe('connected')
    const before = h.model.snapshot
    expect(h.model.confirmRetainedSoft(id)).toMatchObject({ success: false })
    expect(h.model.snapshot).toEqual(before)
  })

  it('keeps native running separate from connected until every main effect finishes', async () => {
    const h = harness()
    let release!: () => void
    const gate = new Promise<void>(done => { release = done })
    const task = h.lane.start(async owner => {
      h.evidence.running = true; h.evidence.pid = 123
      h.model.runtimeChanged('running')
      await owner.wait(gate)
      return { success: true }
    })
    expect(h.model.snapshot).toMatchObject({ state: 'disconnected', transition: 'connecting', processState: 'running' })
    release()
    await task
    expect(h.model.snapshot).toMatchObject({ state: 'connected', transition: null, health: 'ok', pid: 123 })
  })

  it.each(['error', 'blocked', 'unknown'] as const)('does not erase %s on watchdog or competing-interface running', async state => {
    const h = harness()
    await h.connect()
    h.model.fault(state)
    h.model.runtimeChanged('running')
    h.model.runtimeChanged('competing-tun-cleared')
    expect(h.model.snapshot.state).toBe(state)
    expect(h.model.snapshot.health).toBeNull()
  })

  it('requires a successful owned recovery to clear a fault', async () => {
    const h = harness()
    await h.connect()
    h.model.fault('blocked')
    await h.lane.stop(h.cleanup, { owner: 'recovery' })
    expect(h.model.snapshot.state).toBe('disconnected')
    await h.connect()
    expect(h.model.snapshot.state).toBe('connected')
  })

  it('rejects a second connect before any effects and leaves the snapshot unchanged', async () => {
    const h = harness(), effect = vi.fn()
    await h.connect()
    const before = h.model.snapshot
    expect(await h.lane.start(effect)).toMatchObject({ success: false, category: 'conflict' })
    expect(effect).not.toHaveBeenCalled()
    expect(h.model.snapshot).toEqual(before)
  })

  it('rejects Soft refresh over a native connection without effects or snapshot changes', async () => {
    const h = harness(), effect = vi.fn()
    await h.connect()
    const before = h.model.snapshot
    expect(await h.lane.start(effect, { refreshSoft: true })).toMatchObject({ success: false, category: 'conflict' })
    expect(effect).not.toHaveBeenCalled()
    expect(h.model.snapshot).toEqual(before)
  })

  it('rejects unconfirmed successful start/stop instead of publishing protection or clean exit', async () => {
    const h = harness()
    await expect(h.lane.start(async () => ({ success: true }))).rejects.toThrow('Connection confirmation missing')
    expect(h.model.snapshot.state).toBe('error')
    await h.connect()
    await expect(h.lane.stop(async () => ({ success: true }))).rejects.toThrow('Runtime cleanup confirmation missing')
    expect(h.model.snapshot.state).toBe('error')
  })

  it('uses degraded only inside connected and keeps proxy failure separate from process liveness', async () => {
    const h = harness()
    await h.connect()
    h.model.runtimeChanged('proxy-down')
    expect(h.model.snapshot).toMatchObject({ state: 'connected', health: 'degraded', proxyStatus: 'proxy-down', processState: 'running' })
    h.model.fault('unknown')
    expect(h.model.snapshot.health).toBeNull()
  })

  it('does not confirm a restart from a raw running event; requires the actual startup receipt', async () => {
    const h = harness()
    await h.connect()
    h.model.runtimeChanged('adapting')
    h.model.nativeStartBegan(1)
    h.model.runtimeChanged('running')
    expect(h.model.snapshot.transition).toBe('reconnecting')
    h.model.nativeStartFinished({ generation: 1, success: true })
    expect(h.model.snapshot).toMatchObject({ state: 'connected', transition: null })
  })

  it('ignores a late native receipt after manual stop, and rejected transitions do not mutate state', async () => {
    const h = harness()
    await h.connect()
    h.model.runtimeChanged('adapting')
    h.model.nativeStartBegan(1)
    await h.lane.stop(h.cleanup)
    const before = h.model.snapshot
    expect(h.model.nativeStartFinished({ generation: 1, success: true })).toMatchObject({ success: false, code: 'FSM_INVALID_TRANSITION', category: 'conflict' })
    expect(h.model.snapshot).toEqual(before)
  })

  it('confirms Soft only after its owned env apply, without inventing a native PID', async () => {
    const h = harness()
    await h.lane.start(async () => { h.evidence.softApplied = true; return { success: true } })
    expect(h.model.snapshot).toMatchObject({ state: 'connected', mode: 'soft', processState: 'stopped', pid: null })
    await h.lane.stop(h.cleanup)
    expect(h.model.snapshot.state).toBe('disconnected')
  })

  it('rejects the old receipt while a later native restart owns confirmation', async () => {
    const h = harness()
    await h.connect()
    h.model.runtimeChanged('adapting'); h.model.nativeStartBegan(1)
    h.model.nativeStartBegan(2)
    const before = h.model.snapshot
    expect(h.model.nativeStartFinished({ generation: 1, success: true })).toMatchObject({ success: false, category: 'conflict' })
    expect(h.model.snapshot).toEqual(before)
    expect(h.model.nativeStartFinished({ generation: 2, success: true }).success).toBe(true)
    expect(h.model.snapshot.transition).toBeNull()
  })

  it('fails closed without stranding the lane if evidence or observers fail', async () => {
    const model = new TunnelStateMachine(() => { throw new Error('evidence unavailable') }, () => { throw new Error('observer failed') })
    const lane = new ConnectionLifecycle(vi.fn(), undefined, undefined, model)
    await expect(lane.start(async () => ({ success: true }))).rejects.toThrow('Connection confirmation missing')
    expect(lane.busy).toBe(false)
    expect(model.snapshot).toMatchObject({ state: 'unknown', cleanupRequired: true, transition: null })
    await expect(lane.stop(async () => ({ success: true }))).rejects.toThrow('Runtime cleanup confirmation missing')
    expect(lane.busy).toBe(false)
  })

  it('does not report disconnected with a live unowned process or connected after lost evidence', async () => {
    const h = harness()
    h.evidence.running = true; h.evidence.pid = 123
    h.model.runtimeChanged('running')
    expect(h.model.snapshot).toMatchObject({ state: 'unknown', cleanupRequired: true })
    await h.lane.stop(h.cleanup)
    await h.connect()
    h.evidence.running = false; h.evidence.pid = null
    h.model.runtimeChanged('competing-tun-cleared')
    expect(h.model.snapshot).toMatchObject({ state: 'unknown', health: null, cleanupRequired: true })
  })

  it('compensates runtime effects when main cannot confirm the successful start', async () => {
    const h = harness()
    await expect(h.lane.start(async () => { h.evidence.running = true; return { success: true } })).rejects.toThrow('Connection confirmation missing')
    expect(h.cleanup).toHaveBeenCalledOnce()
    expect(h.evidence).toMatchObject({ running: false, pid: null, softApplied: false })
    expect(h.model.snapshot).toMatchObject({ state: 'error', transition: null })
  })

  it('retains a transient evidence failure until owned recovery even when the getter recovers', async () => {
    let unreadable = false
    const os = { running: false, pid: null as number | null, softApplied: false }
    const model = new TunnelStateMachine(() => { if (unreadable) throw new Error('query denied'); return os })
    const lane = new ConnectionLifecycle(() => {}, undefined, undefined, model)
    await expect(lane.start(async () => {
      unreadable = true; model.runtimeChanged('running'); unreadable = false
      os.running = true; os.pid = 123
      return { success: true }
    })).rejects.toThrow('Connection confirmation missing')
    expect(model.snapshot).toMatchObject({ state: 'unknown', transition: null })
  })

  it('walks every connect/disconnect/crash/retry tour through depth six against a fake PID/TUN ledger (partial AT-00-002)', async () => {
    // Alphabet order fixes the traversal. Timeout/cancel tours remain separate
    // fault-injection tests; this does not claim real Windows resource evidence.
    for (let tour = 0; tour < 4 ** 6; tour++) {
      const os = { running: false, pid: null as number | null, softApplied: false, tun: false }
      const model = new TunnelStateMachine(() => os)
      const lane = new ConnectionLifecycle(() => {}, undefined, undefined, model)
      let encoded = tour, expected = 'disconnected', effects = 0
      for (let depth = 0; depth < 6; depth++, encoded = Math.floor(encoded / 4)) {
        const event = encoded % 4
        if (event === 0 || event === 3) {
          const before = model.snapshot, count = effects
          const result = await lane.start(async () => {
            effects++; assert.equal(os.pid, null)
            os.running = true; os.pid = 123; os.tun = true
            model.runtimeChanged('running')
            return { success: true }
          })
          if (expected === 'connected') {
            assert.equal(result.success, false); assert.equal(effects, count)
            assert.deepEqual(model.snapshot, before)
          } else { assert.equal(result.success, true); expected = 'connected' }
        } else if (event === 1) {
          await lane.stop(async () => {
            os.running = false; os.pid = null; os.tun = false
            return { success: true }
          })
          expected = 'disconnected'
        } else {
          os.running = false; os.pid = null; os.tun = false
          model.runtimeChanged('error'); expected = 'error'
        }
        assert.equal(model.snapshot.state, expected)
        assert.equal(model.snapshot.transition, null)
        assert.equal(os.tun, os.pid !== null)
        assert.equal(lane.busy, false)
        const beforeInvalid = model.snapshot
        assert.equal(model.runtimeChanged('invalid-event').success, false)
        assert.deepEqual(model.snapshot, beforeInvalid)
      }
    }
  }, 30_000)

  it('serializes seeded 200 commands from ten async workers without leaking fake PID/TUN resources (AT-00-007)', async () => {
    let nextPid = 100, running = false, pid: number | null = null, tun = false
    const history: { operationId: string; status: string }[] = []
    const model = new TunnelStateMachine(() => ({ running, pid, softApplied: false }))
    const cleanup = async () => { running = false; pid = null; tun = false; return { success: true } }
    const lane = new ConnectionLifecycle(() => {}, cleanup, event => history.push(event), model)
    const commands = fc.sample(fc.integer({ min: 0, max: 2 }), { seed: 0x5eed003, numRuns: 200 })
    expect(new Set(commands)).toEqual(new Set([0, 1, 2]))
    // disconnect and cancel share the production stop primitive, which aborts pending starts.
    commands[199] = 1 // The final command is an explicit accepted disconnect.
    const results: { success: boolean; category?: string }[] = []
    for (let batch = 0; batch < 20; batch++) {
      await Promise.all(commands.slice(batch * 10, batch * 10 + 10).map(command => command === 0
        ? lane.start(async owner => {
          assert.equal(pid, null)
          running = true; pid = ++nextPid; tun = true
          try { await owner.wait(Promise.resolve()); return { success: true } }
          finally { if (owner.signal.aborted) await cleanup() }
        })
        : lane.stop(cleanup)).map(async task => { results.push(await task) }))
      assert.equal(lane.busy, false)
      assert.equal(tun, pid !== null)
      assert.equal(model.snapshot.state === 'connected', running)
    }
    expect(results).toHaveLength(200)
    for (const result of results) if (!result.success) expect(['conflict', 'cancelled']).toContain(result.category)
    expect(model.snapshot).toMatchObject({ state: 'disconnected', pid: null, transition: null })
    expect(tun).toBe(false)
    for (const id of new Set(history.map(event => event.operationId))) {
      expect(history.filter(event => event.operationId === id && event.status === 'running')).toHaveLength(1)
      expect(history.filter(event => event.operationId === id && event.status !== 'running')).toHaveLength(1)
    }
  })
})
