// AT-00-003/007, AT-02-002/009: test the runner's oracles; these are NOT the real network run.
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { setTimeout as delay } from 'node:timers/promises'
import { performance } from 'node:perf_hooks'
import { assertStable, deadline, runScenario } from './real-vpn-scenario.mjs'

const original = { id: 'a', name: 'A', groupId: 'g', server: 'example.test', port: 443 }
const target = { ...original, id: 'b', name: 'B' }
const options = { original, target, cancelAfterMs: 0, timeoutMs: 1000 }
function fixture(overrides = {}) {
  let connected = false, activeId = original.id, connects = 0, selectionCount = 0, pending
  let revision = 0
  const calls = [], results = []
  const status = () => ({ running: connected, lifecycle: { revision: ++revision,
    transition: null, cleanupRequired: connected, state: connected ? 'connected' : 'disconnected',
    processState: connected ? 'running' : 'stopped', pid: connected ? 123 : null } })
  const driver = {
    async invoke(method, ...args) {
      calls.push([method, ...args])
      if (method === 'getSettings') return { connectionMode: 'directVpn' }
      if (method === 'saveSettings') return args[0]
      if (method === 'getTunStatus') return status()
      if (method === 'serversGetActive') return { activeId, profile: activeId === original.id ? original : target }
      if (method === 'serversPingOne') return overrides.ping === undefined ? 0 : overrides.ping
      if (method === 'startDirectVpn') {
        if (++connects === 2) return new Promise(resolve => { pending = resolve })
        connected = true; return { success: true }
      }
      if (method === 'stopTun') { connected = false; return { success: true } }
      if (method === 'cancelTun') {
        connected = false
        pending(overrides.cancelResult ?? { success: false, category: 'cancelled' })
        pending = null
        return { success: true }
      }
      if (method === 'serversSelect') {
        if (++selectionCount === 2) return new Promise(resolve => { pending = resolve })
        activeId = args[0]; return undefined
      }
      if (method === 'serversCancelSwitch') {
        const complete = () => { activeId = overrides.wrongRestore ? original.id : target.id; pending({ cancelled: true }); pending = null }
        if (overrides.restoreGate) void overrides.restoreGate.then(complete)
        else complete()
        return { cancelled: true }
      }
      throw new Error('Unexpected method')
    },
    async waitTransition(kind) { while (!pending) await delay(1); calls.push(['transition', kind]) },
    async proof(pid) {
      return { runtimeProcessCount: connected ? (overrides.connectedCount ?? 2) : (overrides.orphan ? 1 : 0), tunProcessCount: connected ? 1 : 0,
        matchingPid: pid === 123, adapterUp: connected, interfaceAddressCount: connected ? 2 : 0 }
    }
  }
  const step = async (name, action) => { results.push({ name, ...await action() }) }
  return { driver, calls, results, step }
}

test('exact user sequence calls production API names, saves settings and accepts a 0 ms ping', async () => {
  const f = fixture()
  await runScenario(f.driver, options, f.step)
  assert.deepEqual(f.results.map(r => r.name), ['connect', 'disconnect', 'connect-cancel', 'connect-again',
    'switch', 'switch-back-cancel', 'switch-back', 'ping'])
  const actions = f.calls.filter(([name]) => ['startDirectVpn', 'stopTun', 'cancelTun', 'serversSelect', 'serversCancelSwitch', 'serversPingOne'].includes(name))
  assert.deepEqual(actions.map(([name, ...args]) => [name, ...args]), [
    ['startDirectVpn'], ['stopTun'], ['startDirectVpn'], ['cancelTun'], ['startDirectVpn'],
    ['serversSelect', 'b'], ['serversSelect', 'a'], ['serversCancelSwitch'], ['serversSelect', 'a'],
    ['serversPingOne', original.server, original.port]
  ])
  assert.equal(f.calls.filter(([name]) => name === 'saveSettings').length, 3)
  assert.equal(f.results.at(-1).pingMs, 0)
  assert.ok(f.results.find(r => r.name === 'switch-back-cancel').cancelToSettledMs >= 0)
})

test('endpoint pair and TLS oracles run after the unchanged action timer boundary', async t => {
  let clock = 0
  t.mock.method(performance, 'now', () => clock)
  const f = fixture(), invoke = f.driver.invoke, proof = f.driver.proof, requirements = []
  f.driver.invoke = async (...args) => { clock += 10; return invoke(...args) }
  f.driver.proof = async (pid, context) => {
    requirements.push(context.requireEndpointPair)
    clock += 1000
    return proof(pid)
  }
  await runScenario(f.driver, options, f.step)
  assert.deepEqual(requirements, [false, false, false, false, true, true, true, false])
  assert.ok(f.results.every(result => result.elapsedMs < 1000), 'Oracle time entered an action measurement')
})

test('exhausted scenario budget refuses new work while leaving cleanup usable (AT-00-003)', async t => {
  let clock = 0
  t.mock.method(performance, 'now', () => clock)
  const f = fixture(), invoke = f.driver.invoke
  f.driver.invoke = async (...args) => {
    const result = await invoke(...args)
    if (args[0] === 'getSettings') clock = 1000
    return result
  }
  await assert.rejects(runScenario(f.driver, { ...options, scenarioTimeoutMs: 100 }, f.step), /budget exhausted/)
  assert.ok(!f.calls.some(([method]) => method === 'startDirectVpn' || method === 'saveSettings'))
  assert.equal((await f.driver.invoke('stopTun')).success, true)
})

test('budget exhaustion still cancels and drains the admitted owner before cleanup (AT-00-003/007)', async t => {
  let clock = 0
  t.mock.method(performance, 'now', () => clock)
  const f = fixture(), transition = f.driver.waitTransition
  f.driver.waitTransition = async (...args) => { await transition(...args); clock = 1000 }
  await assert.rejects(runScenario(f.driver, { ...options, scenarioTimeoutMs: 100 }, f.step), /budget exhausted/)
  assert.ok(f.calls.some(([method]) => method === 'cancelTun'))
  assert.equal(f.calls.filter(([method]) => method === 'startDirectVpn').length, 2)
  assert.equal((await f.driver.invoke('stopTun')).success, true)
})

test('cancel acknowledgement alone does not release the next switch', async () => {
  let restore
  const gate = new Promise(resolve => { restore = resolve })
  const f = fixture({ restoreGate: gate })
  const run = runScenario(f.driver, options, f.step)
  await deadline((async () => { while (!f.calls.some(([method]) => method === 'serversCancelSwitch')) await delay(1) })(), 1000, 'cancel admission')
  assert.equal(f.results.length, 5)
  assert.equal(f.calls.filter(([method]) => method === 'serversSelect').length, 2)
  restore()
  await run
  assert.equal(f.results.length, 8)
})

for (const cancelResult of [{ success: true }, { success: false, category: 'network' }]) {
  test('cancelled connect must return a cancellation, not success or a network failure: ' + JSON.stringify(cancelResult), async () => {
    const f = fixture({ cancelResult })
    await assert.rejects(runScenario(f.driver, options, f.step))
    assert.equal(f.results.length, 2)
  })
}
test('restoring the requested target instead of the old server fails', async () => {
  const f = fixture({ wrongRestore: true })
  await assert.rejects(runScenario(f.driver, options, f.step), /Selected profile/)
  assert.equal(f.results.length, 5)
})
test('disconnected with an orphaned native process fails the independent oracle', async () => {
  const f = fixture({ orphan: true })
  await assert.rejects(runScenario(f.driver, options, f.step), /Runtime remains/)
})
test('an extra native runtime cannot pass as a healthy connection', async () => {
  const f = fixture({ connectedCount: 3 })
  await assert.rejects(runScenario(f.driver, options, f.step), /Unexpected number/)
})
test('unreachable ping cannot yield PASS', async () => {
  const f = fixture({ ping: null })
  await assert.rejects(runScenario(f.driver, options, f.step), /ping failed/)
})
test('transient, dirty, missing and contradictory snapshots fail', () => {
  const valid = { running: true, lifecycle: { transition: null, state: 'connected', processState: 'running', cleanupRequired: true, pid: 2 } }
  assertStable(valid, true)
  assert.throws(() => assertStable({}, true))
  for (const patch of [{ transition: 'connecting' }, { state: 'unknown' }, { processState: 'stopped' }, { pid: null }]) {
    assert.throws(() => assertStable({ ...valid, lifecycle: { ...valid.lifecycle, ...patch } }, true))
  }
  assert.throws(() => assertStable({ running: false, lifecycle: { transition: null, state: 'disconnected', processState: 'stopped', cleanupRequired: true } }, false))
  assert.throws(() => assertStable({ running: false, lifecycle: { transition: null, state: 'disconnected', processState: 'stopped', cleanupRequired: false, pid: 123 } }, false))
})
test('an expired deadline fails and does not silently report a completed operation', async () => {
  await assert.rejects(deadline(new Promise(() => {}), 5, 'test'), /deadline exceeded/)
  assert.equal(await deadline(Promise.resolve(7), 100, 'fast'), 7)
})
