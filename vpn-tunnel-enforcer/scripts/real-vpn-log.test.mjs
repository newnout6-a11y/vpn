// AT-00-005, AT-01-001: live evidence, concurrent owners and no credential/error echo.
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { mkdtemp, mkdir, readFile, rm } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { test } from 'node:test'
import { setTimeout as delay } from 'node:timers/promises'
import { createProgressLog, safeAppEvent, safeSnapshot, safeElectronDiagnostic } from './real-vpn-log.mjs'

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
  await assert.rejects(log.run('ipc/serversAdd', () => { throw error }), e => e === error)
  log.close()
  assert.match(lines.join(''), /"event":"failed"/)
  assert.ok(!lines.join('').includes('FAKE-PRIVATE-PAYLOAD'))
  assert.equal(await readFile(path, 'utf8'), lines.join(''))
})

test('native Electron crash diagnostics retain only source location and severity', () => {
  assert.deepEqual(safeElectronDiagnostic('[123:1021/165511.846:FATAL:electron\\shell\\common\\node_bindings.cc(42)] Check failed: FAKE-PRIVATE-PAYLOAD vless://PRIVATE'),
    { severity: 'FATAL', sourceFile: 'node_bindings.cc', sourceLine: 42, checkFailed: true })
  assert.deepEqual(safeElectronDiagnostic('[123:ERROR:gin/v8_initializer.cc:767] FAKE-PRIVATE-PAYLOAD'),
    { severity: 'ERROR', sourceFile: 'v8_initializer.cc', sourceLine: 767, checkFailed: false })
  assert.equal(safeElectronDiagnostic('FAKE-PRIVATE-PAYLOAD vless://PRIVATE'), null)
  assert.equal(safeElectronDiagnostic('[123:ERROR:gpu_process_host.cc(1029)] GPU process launch failed: error_code=18 FAKE-PRIVATE-PAYLOAD').gpuCode, 18)
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
