// AT-00-002/007: complete event alphabet, real lane/FSM, fake native resources.
import { afterEach, expect, it, vi } from 'vitest'
import assert from 'node:assert/strict'
import { ConnectionLifecycle } from './connectionLifecycle'
import { TunnelStateMachine } from './tunnelStateMachine'
import type { ConnectionOperation } from '../shared/operation'

afterEach(() => vi.useRealTimers())

function assertLedger(events: ConnectionOperation[], expected: Record<'connect' | 'disconnect', number>, pending: number, label = '') {
  const byId = new Map<string, ConnectionOperation[]>()
  for (const operation of events) {
    const history = byId.get(operation.operationId) ?? []
    history.push(operation); byId.set(operation.operationId, history)
  }
  let running = 0
  const recorded = { connect: 0, disconnect: 0 }
  for (const history of byId.values()) {
    assert.equal(history[0].status, 'running', label)
    const kind = history[0].kind
    assert.ok(kind === 'connect' || kind === 'disconnect', 'rotation has its own managed registry ledger')
    recorded[kind]++
    assert.ok(history.length <= 2, label)
    if (history.length === 1) running++
    else assert.notEqual(history[1].status, 'running', label)
  }
  // Expected admissions come from model commands, never from observer output.
  assert.deepEqual(recorded, expected, label)
  assert.equal(running, pending, label)
}

it.each(['connect', 'disconnect'] as const)('rejects an audit trail missing the entire %s operation', async missing => {
  const events: ConnectionOperation[] = []
  const lane = new ConnectionLifecycle(() => {}, undefined, operation => {
    if (operation.kind !== missing) events.push(operation)
  })
  await lane.start(async () => ({ success: true }))
  await lane.stop(async () => ({ success: true }))
  assert.throws(() => assertLedger(events, { connect: 1, disconnect: 1 }, 0))
})

it('walks every connect/complete/disconnect/crash/timeout/cancel/retry tour through depth six (AT-00-002)', async () => {
  vi.useFakeTimers()
  const alphabet = ['connect', 'complete', 'disconnect', 'crash', 'timeout', 'cancel', 'retry'] as const
  const seed = 0x5eed002, total = alphabet.length ** 6
  for (let tour = 0; tour < total; tour++) {
    const os = { running: false, pid: null as number | null, tun: false, softApplied: false }
    const events: ConnectionOperation[] = []
    const admitted = { connect: 0, disconnect: 0 }
    const model = new TunnelStateMachine(() => os)
    const cleanup = async () => { os.running = false; os.pid = null; os.tun = false; return { success: true } }
    const lane = new ConnectionLifecycle(() => {}, cleanup, operation => events.push(operation), model)
    type Outcome = { success?: boolean; code?: string; error?: unknown }
    let pending: { release: () => void; result: Promise<Outcome>; crashed: boolean } | null = null
    let expected: 'disconnected' | 'connected' | 'error' = 'disconnected'
    let encoded = (tour + seed) % total
    const label = `seed=${seed}; tour=${encoded}`
    const invalidTerminal = (category?: 'timeout' | 'cancelled') => model.operationChanged({
      version: 1, operationId: 'not-owned', correlationId: 'not-owned', kind: 'connect', owner: 'manual',
      startedAt: 0, deadline: null, status: category === 'cancelled' ? 'cancelled' : category ? 'error' : 'success', category
    })
    for (let depth = 0; depth < 6; depth++, encoded = Math.floor(encoded / alphabet.length)) {
      const event = alphabet[encoded % alphabet.length]
      if (event === 'connect' || event === 'retry') {
        if (pending || expected === 'connected') {
          const before = model.snapshot
          const result = await lane.start(async () => { throw new Error('Rejected connect ran effects') })
          assert.equal(result.success, false, label)
          assert.equal('code' in result && result.code, 'OPERATION_CONFLICT', label)
          assert.deepEqual(model.snapshot, before, label)
        } else {
          admitted.connect++
          let release!: () => void
          const gate = new Promise<void>(resolve => { release = resolve })
          const result = lane.start(async owner => {
            assert.equal(os.pid, null, label)
            os.running = true; os.pid = 123; os.tun = true
            model.runtimeChanged('running')
            await owner.wait(gate)
            return { success: true }
          }, { timeoutMs: 100 }).then(value => value, error => ({ error }))
          pending = { release, result, crashed: false }
        }
      } else if (event === 'crash') {
        os.running = false; os.pid = null; os.tun = false
        model.runtimeChanged('error')
        if (pending) pending.crashed = true
        expected = 'error'
      } else if (event === 'complete') {
        if (pending) {
          pending.release()
          const result: Outcome = await pending.result
          if (pending.crashed) {
            assert.ok(result.error instanceof Error, label)
            assert.equal(result.error.message, 'Connection confirmation missing', label)
            expected = 'error'
          } else {
            assert.equal(result.success, true, label)
            expected = 'connected'
          }
          pending = null
        } else {
          const before = model.snapshot
          assert.equal(invalidTerminal().success, false, label)
          assert.deepEqual(model.snapshot, before, label)
        }
      } else if (event === 'disconnect' || pending) {
        admitted.disconnect++
        let stopping: Promise<unknown>
        if (event === 'timeout') {
          vi.advanceTimersByTime(100)
          stopping = lane.stop(cleanup, { owner: 'recovery' })
        } else stopping = lane.stop(cleanup)
        if (pending) {
          const beforeDrain = { ...os }
          assert.equal((await pending.result).code, event === 'timeout' ? 'OPERATION_TIMEOUT' : 'OPERATION_CANCELLED', label)
          assert.equal(lane.busy, true, label)
          assert.equal(lane.starting, true, label)
          assert.deepEqual(os, beforeDrain, label)
          pending.release()
        }
        await stopping
        pending = null
        expected = 'disconnected'
      } else {
        const before = model.snapshot
        const result = invalidTerminal(event === 'timeout' ? 'timeout' : 'cancelled')
        assert.deepEqual(result, { success: false, code: 'FSM_INVALID_TRANSITION', category: 'conflict' }, label)
        assert.deepEqual(model.snapshot, before, label)
      }

      const snapshot = model.snapshot
      assert.equal(snapshot.state, expected, label)
      assert.equal(snapshot.transition, pending ? 'connecting' : null, label)
      assert.equal(snapshot.processState, os.pid === null ? 'stopped' : 'running', label)
      assert.equal(os.tun, os.pid !== null, label)
      assert.equal(lane.busy, pending !== null, label)
      if (!pending && expected === 'disconnected') assert.equal(os.pid, null, label)
      if (expected === 'connected') assert.equal(os.running, true, label)

      assertLedger(events, admitted, pending ? 1 : 0, label)
      const beforeInvalid = model.snapshot
      assert.deepEqual(model.runtimeChanged('invalid-event'), { success: false, code: 'FSM_INVALID_TRANSITION', category: 'conflict' }, label)
      assert.equal(invalidTerminal().success, false, label)
      assert.deepEqual(model.snapshot, beforeInvalid, label)
    }
    admitted.disconnect++
    const stopped = lane.stop(cleanup)
    pending?.release()
    if (pending) await pending.result
    await stopped
    assert.equal(os.pid, null, label)
    assert.equal(os.tun, false, label)
    assert.equal(lane.busy, false, label)
    assertLedger(events, admitted, 0, label)
  }
  expect(vi.getTimerCount()).toBe(0)
}, 120_000)
