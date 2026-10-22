// AT-00-005, AT-01-001: live evidence, concurrent owners and no credential/error echo.
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { mkdtemp, mkdir, readFile, rm } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { test } from 'node:test'
import { setTimeout as delay } from 'node:timers/promises'
import { createProgressLog, safeAppEvent, safeSnapshot, safeElectronDiagnostic, safeActionResult } from './real-vpn-log.mjs'

test('start and heartbeat are visible before an action finishes; file matches the live stream', { timeout: 3000 }, async t => {
  const temp = resolve(dirname(fileURLToPath(import.meta.url)), '../.tmp')
  await mkdir(temp, { recursive: true })
  const dir = await mkdtemp(join(temp, 'real-vpn-log-test-'))
  t.after(() => rm(dir, { recursive: true }))
  const path = join(dir, 'progress.log'), lines = []
  const log = createProgressLog(path, { write: line => lines.push(line), heartbeatMs: 10 })
  t.after(() => log.close())
  let finish
  const pending = log.run('ipc/startDirectVpn', () => new Promise(resolve => { finish = resolve }))
  assert.match(lines.join(''), /"event":"started"/)
  assert.ok(!lines.join('').includes('"event":"finished"'))
  while (!lines.some(line => line.includes('"event":"waiting"'))) await delay(5)
  assert.equal(readFileSync(path, 'utf8'), lines.join(''))
  finish({ input: 'FAKE-PRIVATE-PAYLOAD' })
  assert.deepEqual(await pending, { input: 'FAKE-PRIVATE-PAYLOAD' })
  const error = new Error('FAKE-PRIVATE-PAYLOAD')
  error.category = 'network'
  await assert.rejects(log.run('ipc/serversAdd', () => { throw error }), e => e === error)
  await log.run('ipc/startDirectVpn', async () => ({ success: false, category: 'conflict', error: 'FAKE-PRIVATE-PAYLOAD' }))
  log.close()
  assert.match(lines.join(''), /"event":"failed"/)
  assert.match(lines.join(''), /"event":"failed"[^\n]+"category":"network"/)
  assert.match(lines.join(''), /"success":false,"category":"conflict"/)
  assert.ok(!lines.join('').includes('FAKE-PRIVATE-PAYLOAD'))
  assert.equal(await readFile(path, 'utf8'), lines.join(''))
})

test('domain failures and IPC rejections expose only fixed outcome labels', () => {
  assert.deepEqual(safeActionResult({ success: false, category: 'network', error: 'FAKE-PRIVATE-PAYLOAD' }), { success: false, category: 'network' })
  assert.deepEqual(safeActionResult({ cancelled: true, error: { category: 'cancelled', message: 'FAKE-PRIVATE-PAYLOAD' } }), { cancelled: true, category: 'cancelled' })
  assert.deepEqual(safeActionResult({ success: 'FAKE-PRIVATE-PAYLOAD', category: 'FAKE-PRIVATE-PAYLOAD' }), {})
  assert.deepEqual(safeActionResult(null), {})
  const base = { ts: '2026-10-21T16:00:00.000Z', scope: 'ipc-security', message: 'IPC request rejected' }
  assert.deepEqual(safeAppEvent({ ...base, details: { channel: 'start-direct-vpn', status: 'error', reason: 'untrusted-sender', error: 'FAKE-PRIVATE-PAYLOAD' } }),
    { at: base.ts, scope: base.scope, message: base.message, reason: 'untrusted-sender', status: 'error', channel: 'start-direct-vpn' })
  const safe = safeAppEvent({ ...base, details: { channel: 'FAKE-PRIVATE-PAYLOAD', reason: 'FAKE-PRIVATE-PAYLOAD' } })
  assert.ok(!JSON.stringify(safe).includes('FAKE-PRIVATE-PAYLOAD'))
  const failed = safeAppEvent({ ...base, scope: 'tun', message: 'failed to prepare TUN runtime',
    details: { message: 'decode config: unknown field FAKE-PRIVATE-PAYLOAD', stack: 'vless://PRIVATE' } })
  assert.deepEqual(failed, { at: base.ts, scope: 'tun', message: 'failed to prepare TUN runtime', errorKind: 'unknown-config-field' })
})

test('admission refusal is logged before dispatch and does not prevent subsequent cleanup (AT-00-003)', async t => {
  const temp = resolve(dirname(fileURLToPath(import.meta.url)), '../.tmp')
  await mkdir(temp, { recursive: true })
  const dir = await mkdtemp(join(temp, 'real-vpn-admission-test-'))
  t.after(() => rm(dir, { recursive: true }))
  let cleanup = false, dispatched = false
  const lines = [], log = createProgressLog(join(dir, 'progress.log'), { write: line => lines.push(line), admit: () => {
    if (!cleanup) throw new Error('budget exhausted')
  } })
  t.after(() => log.close())
  await assert.rejects(log.run('prepare/launch', () => { dispatched = true }), /budget exhausted/)
  assert.equal(dispatched, false)
  assert.match(lines.at(-1), /"event":"failed"/)
  cleanup = true
  await log.run('cleanup/shutdown', () => { dispatched = true })
  assert.equal(dispatched, true)
})

test('native Electron crash diagnostics retain only source location and severity', () => {
  assert.deepEqual(safeElectronDiagnostic('[123:1021/165511.846:FATAL:electron\\shell\\common\\node_bindings.cc(42)] Check failed: FAKE-PRIVATE-PAYLOAD vless://PRIVATE'),
    { severity: 'FATAL', sourceFile: 'node_bindings.cc', sourceLine: 42, checkFailed: true })
  assert.deepEqual(safeElectronDiagnostic('[123:ERROR:gin/v8_initializer.cc:767] FAKE-PRIVATE-PAYLOAD'),
    { severity: 'ERROR', sourceFile: 'v8_initializer.cc', sourceLine: 767, checkFailed: false })
  assert.equal(safeElectronDiagnostic('FAKE-PRIVATE-PAYLOAD vless://PRIVATE'), null)
  assert.equal(safeElectronDiagnostic('[123:ERROR:gpu_process_host.cc(1029)] GPU process launch failed: error_code=18 FAKE-PRIVATE-PAYLOAD').gpuCode, 18)
})

test('adapter lockdown diagnostics retain verified failure markers without topology or warning text', () => {
  const base = { ts: '2026-10-21T16:00:00.000Z', scope: 'tun', message: 'adapter lockdown result' }
  const result = safeAppEvent({ ...base, details: { applied: true, adapters: 2,
    warnings: ['FAKE-PRIVATE-PAYLOAD: A0_dns_err: private address; A1_ipv6_err: private adapter',
      'TRANS_teredo_err: FAKE-PRIVATE-PAYLOAD', 'DNS_PARALLEL_err: private value'] } })
  assert.deepEqual(result, { at: base.ts, scope: 'tun', message: base.message, adapters: 2, applied: true,
    lockdownIssues: ['adapter-ipv6', 'adapter-dns', 'dns-parallel-queries', 'teredo'] })
  assert.equal(safeAppEvent({ ...base, scope: 'phys-lockdown', message: 'DNS registry snapshot failed; refusing mutation without baseline',
    details: { message: 'Unsupported DNS registry snapshot value: FAKE-PRIVATE-PAYLOAD' } }).errorKind, 'dns-policy-value')
  assert.ok(!JSON.stringify(result).includes('FAKE-PRIVATE-PAYLOAD'))
  assert.deepEqual(safeAppEvent({ ...base, message: 'physical adapter lockdown threw', details: {
    name: 'Error', message: 'Invalid transition snapshot FAKE-PRIVATE-PAYLOAD',
    stack: 'at private (D:\\private\\app.asar\\out\\main\\index.js:1234:56) FAKE-PRIVATE-PAYLOAD' } }),
  { at: base.ts, scope: 'tun', message: 'physical adapter lockdown threw', errorKind: 'transition-snapshot',
    errorName: 'Error', sourceLocations: [{ line: 1234, column: 56 }] })
  assert.deepEqual(safeAppEvent({ ...base, message: 'physical adapter lockdown threw',
    details: { message: 'Invalid adapter snapshot: ifIndex, ipv4DnsServers FAKE-PRIVATE-PAYLOAD' } }).invalidFields, ['ifIndex', 'ipv4DnsServers'])
})

test('runtime exit diagnostics retain only fixed causes for direct and nested errors', () => {
  const event = { ts: '2026-10-21T16:00:00.000Z', scope: 'tun', message: 'owned runtime status probe failed' }
  const error = { name: 'RecoveryWorkerError', code: 'rejected', message: 'Cannot prove runtime exit: executable path unavailable FAKE-PRIVATE-PAYLOAD',
    stack: 'at private (D:\\private\\app.asar\\out\\main\\index.js:100:20) FAKE-PRIVATE-PAYLOAD' }
  for (const details of [error, { error }]) {
    const result = safeAppEvent({ ...event, details })
    assert.deepEqual(result, { at: event.ts, scope: 'tun', message: event.message,
      errorKind: 'runtime-path-unavailable', errorName: 'RecoveryWorkerError', workerError: 'rejected', sourceLocations: [{ line: 100, column: 20 }] })
    assert.ok(!JSON.stringify(result).includes('FAKE-PRIVATE-PAYLOAD'))
  }
  assert.equal(safeAppEvent({ ...event, message: 'stop step completed', details: { error: 'Error: Owned runtime status response is invalid FAKE-PRIVATE-PAYLOAD' } }).errorKind, 'runtime-status-invalid')
  assert.equal(safeAppEvent({ ...event, details: { error: { code: 'FAKE-PRIVATE-PAYLOAD' } } }).workerError, undefined)
})

test('native PID fallback is observable without publishing the error or executable path', () => {
  const event = { ts: '2026-10-21T16:00:00.000Z', scope: 'tun', message: 'native runtime PID unavailable, using PowerShell',
    details: { error: { message: 'FAKE-PRIVATE-PAYLOAD', path: 'C:\\private\\runtime.exe' } } }
  assert.deepEqual(safeAppEvent(event), { at: event.ts, scope: event.scope, message: event.message })
  assert.deepEqual(safeAppEvent({ ...event, details: { name: 'Error', message: 'FAKE-PRIVATE-PAYLOAD',
    stack: 'FAKE-PRIVATE-PAYLOAD C:\\private\\runtime.exe' } }),
  { at: event.ts, scope: event.scope, message: event.message, errorName: 'Error' })
})

test('native route timings and refusal expose no destination, adapter or private error', () => {
  const event = { ts: '2026-10-21T16:00:00.000Z', scope: 'tun', message: 'native route selection timing',
    details: { durationMs: 8, indexes: [7, 8, 7], adapter: 'FAKE-PRIVATE-PAYLOAD', destination: 'private.example' } }
  assert.deepEqual(safeAppEvent(event), { at: event.ts, scope: event.scope, message: event.message, durationMs: 8 })
  assert.deepEqual(safeAppEvent({ ...event, message: 'native route selection unavailable, using PowerShell',
    details: { name: 'Error', message: 'FAKE-PRIVATE-PAYLOAD', stack: 'C:\\private\\app.js FAKE-PRIVATE-PAYLOAD' } }),
  { at: event.ts, scope: event.scope, message: 'native route selection unavailable, using PowerShell', errorName: 'Error' })
})

test('native runtime presence exposes only timings and fixed diagnostics', () => {
  const event = { ts: '2026-10-22T08:00:00.000Z', scope: 'tun', message: 'native runtime status timing',
    details: { durationMs: 6, runtimeDir: 'C:\\private', processes: ['FAKE-PRIVATE-PAYLOAD'], running: false } }
  assert.deepEqual(safeAppEvent(event), { at: event.ts, scope: event.scope, message: event.message, durationMs: 6 })
  assert.deepEqual(safeAppEvent({ ...event, message: 'native runtime status unavailable, using PowerShell',
    details: { name: 'Error', message: 'FAKE-PRIVATE-PAYLOAD', stack: 'C:\\private' } }),
  { at: event.ts, scope: event.scope, message: 'native runtime status unavailable, using PowerShell', errorName: 'Error' })
})

test('protected transition timing excludes private reason, IP and provider data', () => {
  const event = { ts: '2026-10-22T08:00:00.000Z', scope: 'ip-monitor', message: 'protected transition IP baseline refreshed',
    details: { elapsedMs: 4500, attempt: 2, reason: 'FAKE-PRIVATE-PAYLOAD', ip: 'private', provider: 'private' } }
  assert.deepEqual(safeAppEvent(event), { at: event.ts, scope: event.scope, message: event.message, elapsedMs: 4500, attempt: 2 })
  assert.deepEqual(safeAppEvent({ ...event, message: 'protected transition IP baseline not checked', details: { ...event.details, attempt: 99 } }),
    { at: event.ts, scope: event.scope, message: 'protected transition IP baseline not checked', elapsedMs: 4500 })
})

test('native runtime fallback diagnostics publish fixed categories without private messages', () => {
  for (const [message, kind] of [
    ['runtime PID: executable path unavailable', 'runtime-path-unavailable'],
    ['runtime PID: incomplete process enumeration', 'runtime-process-enumeration'],
    ['Native owned runtime state response is invalid', 'runtime-status-invalid'],
    ['Owned runtime status deadline exceeded', 'native-timeout']
  ]) {
    const event = { ts: '2026-10-22T08:00:00.000Z', scope: 'tun', message: 'native runtime status unavailable, using PowerShell',
      details: { name: 'NativeHostError', message: `${message}: FAKE-PRIVATE-PAYLOAD`, stack: 'C:\\private' } }
    assert.deepEqual(safeAppEvent(event), { at: event.ts, scope: event.scope, message: event.message, errorKind: kind })
  }
})

test('concurrent connect/cancel calls retain separate IDs and elapsed time', async t => {
  const temp = resolve(dirname(fileURLToPath(import.meta.url)), '../.tmp')
  await mkdir(temp, { recursive: true })
  const dir = await mkdtemp(join(temp, 'real-vpn-log-test-'))
  t.after(() => rm(dir, { recursive: true }))
  const lines = [], log = createProgressLog(join(dir, 'progress.log'), { write: line => lines.push(JSON.parse(line.slice(line.indexOf('{')))) })
  t.after(() => log.close())
  let finish
  const connect = log.run('ipc/startDirectVpn', () => new Promise(resolve => { finish = resolve }))
  await log.run('ipc/cancelTun', async () => {})
  assert.deepEqual(lines.map(e => [e.event, e.id]), [['started', 1], ['started', 2], ['finished', 2]])
  finish()
  await connect
  assert.deepEqual(lines.at(-1).id, 1)
  assert.ok(lines.at(-1).elapsedMs >= 0)
})

test('only known application events and numeric timings enter public logs', () => {
  const event = { ts: '2026-10-21T16:00:00.000Z', scope: 'tun', message: 'start timing',
    details: { totalMs: 123, error: 'FAKE-PRIVATE-PAYLOAD', server: 'secret.example', sourceUri: 'vless://PRIVATE' } }
  assert.deepEqual(safeAppEvent(event), { at: event.ts, scope: 'tun', message: event.message, totalMs: 123 })
  assert.equal(safeAppEvent({ ...event, message: 'FAKE-PRIVATE-PAYLOAD' }), null)
  assert.equal(safeAppEvent({ ...event, scope: 'FAKE-PRIVATE-PAYLOAD' }), null)
  assert.equal(safeAppEvent({ ...event, ts: 'invalid' }), null)
  assert.equal(safeAppEvent(null), null)
  assert.equal(safeAppEvent({ ...event, scope: 'toString' }), null)
  const correlationId = 'ipc_' + 'a'.repeat(32), clockId = 'clock_' + 'b'.repeat(24)
  assert.deepEqual(safeAppEvent({ ...event, correlationId, clockId, monotonicMs: 42 }).clockId, clockId)
  assert.deepEqual(safeAppEvent({ ...event, correlationId }).correlationId, correlationId)
  assert.equal(safeAppEvent({ ...event, message: 'startup failed; saved configuration retained', scope: 'app',
    details: { code: 'STARTUP_FAILED', error: 'FAKE-PRIVATE-PAYLOAD' } }).code, 'STARTUP_FAILED')
  assert.deepEqual(safeAppEvent({ ...event, details: { phaseDurations: {
    'wait-tun-interface': { durationMs: 12, error: 'FAKE-PRIVATE-PAYLOAD' }, 'stop-xray': 8,
    'FAKE-PRIVATE-PAYLOAD': 3, 'prepare-runtime': 'FAKE-PRIVATE-PAYLOAD' } } }).phaseDurations,
  { 'wait-tun-interface': 12, 'stop-xray': 8 })
  const safe = safeAppEvent({ ...event, scope: 'ipc', message: 'start-direct-vpn failed',
    correlationId: 'FAKE-PRIVATE-PAYLOAD', clockId: 'FAKE-PRIVATE-PAYLOAD', details: { ms: 'FAKE-PRIVATE-PAYLOAD' } })
  assert.ok(!JSON.stringify(safe).includes('FAKE-PRIVATE-PAYLOAD'))
  assert.ok(!JSON.stringify(safeSnapshot({ state: 'FAKE-PRIVATE-PAYLOAD', transition: 'FAKE-PRIVATE-PAYLOAD',
    operation: { correlationId: 'FAKE-PRIVATE-PAYLOAD', status: 'FAKE-PRIVATE-PAYLOAD' } })).includes('FAKE-PRIVATE-PAYLOAD'))
})

test('public correlation accepts only prefixed identifiers, never credential-shaped UUIDs (AT-00-005)', () => {
  const event = { ts: '2026-10-21T16:00:00.000Z', scope: 'tun', message: 'start timing' }
  for (const id of ['aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', '-'.repeat(36), 'clock_' + 'a'.repeat(24)]) {
    assert.equal(safeSnapshot({ operation: { correlationId: id } }).correlationId, null)
    assert.equal(safeAppEvent({ ...event, correlationId: id }).correlationId, undefined)
  }
  for (const id of ['ipc_' + 'a'.repeat(32), 'op_' + 'b'.repeat(32)]) {
    assert.equal(safeSnapshot({ operation: { correlationId: id } }).correlationId, id)
    assert.equal(safeAppEvent({ ...event, correlationId: id }).correlationId, id)
    assert.equal(safeAppEvent({ ...event, clockId: id }).clockId, undefined)
  }
  assert.equal(safeAppEvent({ ...event, clockId: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' }).clockId, undefined)
})
