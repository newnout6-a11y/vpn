// AT-00-003/005/007, AT-02-002/009: the same public IPC as Dashboard and ProfileSelectorInline.
import assert from 'node:assert/strict'
import { performance } from 'node:perf_hooks'
import { setTimeout as delay } from 'node:timers/promises'

export async function deadline(promise, ms, label) {
  let timer
  try {
    return await Promise.race([promise, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(`${label}: deadline exceeded`)), ms)
    })])
  } finally { clearTimeout(timer) }
}

export function assertStable(status, connected) {
  const s = status.lifecycle
  assert.ok(s, 'Canonical lifecycle snapshot is required')
  assert.equal(s.transition, null, 'Operation is still in progress')
  // Active protection owns OS mutations that WILL need cleanup on disconnect.
  if (!connected) {
    assert.equal(s.cleanupRequired, false, 'Network cleanup remains outstanding')
    assert.equal(s.pid, null, 'Disconnected snapshot retains a runtime PID')
  }
  assert.equal(s.state, connected ? 'connected' : 'disconnected')
  assert.equal(s.processState, connected ? 'running' : 'stopped')
  assert.equal(status.running, connected)
  if (connected) assert.ok(Number.isInteger(s.pid) && s.pid > 0, 'No live runtime PID')
}

export async function runScenario(driver, { original, target, cancelAfterMs = 500, timeoutMs = 90_000 }, step) {
  const invoke = (method, ...args) => deadline(driver.invoke(method, ...args), timeoutMs, method)
  const verify = async (connected, profileId) => {
    const status = await invoke('getTunStatus')
    assertStable(status, connected)
    assert.equal((await invoke('serversGetActive')).activeId, profileId, 'Selected profile was not restored/committed')
    const os = await driver.proof(connected ? status.lifecycle.pid : 0)
    if (!connected) assert.equal(os.runtimeProcessCount, 0, 'Runtime remains after stop')
    assert.equal(os.tunProcessCount, connected ? 1 : 0)
    assert.equal(os.adapterUp, connected, 'OS adapter disagrees with canonical state')
    if (connected) {
      assert.ok(os.runtimeProcessCount >= 1 && os.runtimeProcessCount <= 2, 'Unexpected number of runtime processes')
      assert.equal(os.matchingPid, true, 'Canonical PID does not own the real bundled runtime')
      assert.ok(os.interfaceAddressCount > 0, 'TUN has no OS addresses')
    }
    return { revision: status.lifecycle.revision, state: status.lifecycle.state, os }
  }
  const connect = async () => {
    // Dashboard first checks selection and saves the current settings, then starts Direct VPN.
    assert.ok((await invoke('serversGetActive')).profile)
    await invoke('saveSettings', await invoke('getSettings'))
    return invoke('startDirectVpn')
  }
  const timed = async (name, action, connected, profileId) => step(name, async () => {
    const startedAt = new Date().toISOString(), start = performance.now()
    const result = await action()
    const elapsedMs = Math.round(performance.now() - start)
    const evidence = await verify(connected, profileId)
    return { startedAt, elapsedMs, ...result, ...evidence }
  })
  const success = async action => {
    assert.equal((await action).success, true, 'Application rejected the action; see application log')
  }
  const cancel = async (start, method, transition, isSwitch) => {
    const revision = (await invoke('getTunStatus')).lifecycle.revision
    let settled = false
    // Attach rejection handling immediately; cancellation must drain the original owner too.
    const pending = Promise.resolve().then(start).then(
      value => { settled = true; return { value } }, error => { settled = true; return { error } })
    await deadline(driver.waitTransition(transition, revision), timeoutMs, 'transition admission')
    await delay(cancelAfterMs)
    assert.equal(settled, false, 'Cancellation missed the operation; reduce --cancel-after-ms')
    const cancelStart = performance.now()
    const acknowledgement = await invoke(method)
    const acknowledgementMs = Math.round(performance.now() - cancelStart)
    assert.equal(isSwitch ? acknowledgement.cancelled : acknowledgement.success, true)
    const terminal = await deadline(pending, timeoutMs, 'cancelled owner completion')
    assert.ok(!terminal.error, 'Cancelled owner rejected instead of returning its terminal result')
    if (isSwitch) assert.equal(terminal.value?.cancelled, true, 'Selection did not finish as cancelled')
    else {
      assert.equal(terminal.value?.success, false, 'Cancelled connect completed as success')
      assert.equal(terminal.value?.category, 'cancelled', 'Connect failed for a reason other than cancellation')
    }
    return { acknowledgementMs, cancelToSettledMs: Math.round(performance.now() - cancelStart) }
  }

  await timed('connect', async () => { await success(connect()) }, true, original.id)
  await timed('disconnect', async () => { await success(invoke('stopTun')) }, false, original.id)
  await timed('connect-cancel', () => cancel(connect, 'cancelTun', 'connecting', false), false, original.id)
  await timed('connect-again', async () => { await success(connect()) }, true, original.id)
  await timed('switch', async () => {
    assert.notEqual((await invoke('serversSelect', target.id))?.cancelled, true)
  }, true, target.id)
  await timed('switch-back-cancel', () => cancel(() => invoke('serversSelect', original.id),
    'serversCancelSwitch', 'reconnecting', true), true, target.id)
  await timed('switch-back', async () => {
    assert.notEqual((await invoke('serversSelect', original.id))?.cancelled, true)
  }, true, original.id)
  await timed('ping', async () => {
    // Exactly the selected-profile TCP ping, not an unrelated ICMP request.
    const { profile } = await invoke('serversGetActive')
    const pingMs = await invoke('serversPingOne', profile.server, profile.port)
    assert.ok(typeof pingMs === 'number' && Number.isFinite(pingMs) && pingMs >= 0, 'Selected-server ping failed')
    return { pingMs }
  }, true, original.id)
}
