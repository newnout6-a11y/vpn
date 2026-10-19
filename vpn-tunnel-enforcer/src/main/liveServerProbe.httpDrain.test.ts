// AT-00-003: production HTTP attempts retain request, response and socket until close.
import { EventEmitter } from 'node:events'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
const state = vi.hoisted(() => ({ request: vi.fn(), attempts: [] as any[], factory: null as ((options: any, reply: any) => any) | null }))
vi.mock('electron', () => ({ app: { getPath: () => '/tmp/test-userdata' }, ipcMain: { handle: vi.fn() } }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./settings', () => ({ settingsStore: { get: () => ({ disableGeoLookup: true }) } }))
vi.mock('./serverPicker', () => ({ serverPicker: { getProfiles: () => [], getActiveProfile: () => null } }))
vi.mock('./tunController', () => ({ tunController: { getStatus: () => ({ running: false }) } }))
vi.mock('http', async original => ({ ...await original<typeof import('http')>(), request: state.request }))
vi.mock('https', async original => ({ ...await original<typeof import('https')>(), request: state.request }))
import { probeHttp } from './liveServerProbe'
const flush = async () => { for (let i = 0; i < 50; i++) await Promise.resolve() }
const tasks = new Set<Promise<unknown>>()
function resource() { return Object.assign(new EventEmitter(), { destroy: vi.fn() }) }
function observe<T>(promise: Promise<T>) { const result = { settled: false, value: undefined as T | undefined }; const task = promise.then(value => { result.settled = true; result.value = value }); tasks.add(task); return { result, task } }
function respond(index = 0, statusCode = 200, headers = {}) {
  const attempt = state.attempts[index], response = Object.assign(resource(), { statusCode, headers, httpVersion: '1.1' })
  attempt.response = response; attempt.reply(response); return response
}
function close(index = 0) { const attempt = state.attempts[index]; attempt.response?.emit('close'); attempt.req.emit('close'); attempt.socket.emit('close') }
beforeEach(() => {
  vi.useFakeTimers(); state.attempts = []; state.factory = null
  state.request.mockReset().mockImplementation((options, reply) => {
    if (state.factory) return state.factory(options, reply)
    const req = Object.assign(resource(), { end: vi.fn() }), socket = resource()
    const attempt = { options, reply, req, socket, response: undefined }; state.attempts.push(attempt)
    queueMicrotask(() => req.emit('socket', socket)); return req
  })
})
afterEach(async () => {
  for (let i = 0; i < 8; i++) { for (let j = 0; j < state.attempts.length; j++) close(j); await flush(); if (vi.isFakeTimers()) await vi.runOnlyPendingTimersAsync() }
  await Promise.allSettled(tasks); tasks.clear(); vi.useRealTimers()
})
describe('HTTP raw drain', () => {
  it.each(['cancel', 'timeout', 'request-error', 'response-error', 'end', 'cap'])('waits for all raw closes after %s', async boundary => {
    const controller = new AbortController(), { result, task } = observe(probeHttp('192.0.2.1', 8443, true, 'probe.example', controller.signal))
    await flush(); const attempt = state.attempts[0], response = respond()
    response.emit('data', Buffer.from('x'))
    if (boundary === 'cancel') controller.abort()
    if (boundary === 'timeout') await vi.advanceTimersByTimeAsync(3501)
    if (boundary === 'request-error') attempt.req.emit('error', new Error('request failed'))
    if (boundary === 'response-error') response.emit('error', new Error('response failed'))
    if (boundary === 'end') response.emit('end')
    if (boundary === 'cap') response.emit('data', Buffer.alloc(9000))
    await flush(); expect(result.settled).toBe(false)
    attempt.req.emit('close'); response.emit('close'); await flush(); expect(result.settled).toBe(false)
    attempt.socket.emit('close'); await task
    expect(result.value?.status).toBe(['end', 'cap'].includes(boundary) ? 'ok' : boundary === 'cancel' ? 'skipped' : 'error')
    expect(attempt.req.eventNames()).toEqual([]); expect(response.eventNames()).toEqual([]); expect(attempt.socket.eventNames()).toEqual([])
    if (boundary === 'cap') expect(result.value?.bodySize).toBe(8192)
  })
  it.each([302, 405])('drains HTTP %s before starting the next attempt', async code => {
    const { result, task } = observe(probeHttp('192.0.2.1', 8443, false, 'probe.example'))
    await flush(); respond(0, code, code === 302 ? { location: '/next?value=1' } : {})
    await flush(); expect(state.request).toHaveBeenCalledOnce()
    close(); await flush(); expect(state.request).toHaveBeenCalledTimes(2)
    expect(state.attempts[1].options).toMatchObject({ method: code === 302 ? 'HEAD' : 'GET', path: code === 302 ? '/next?value=1' : '/', host: '192.0.2.1', port: 8443 })
    respond(1, 204).emit('end'); close(1); await task
    expect(result.value?.statusCode).toBe(204)
  })
  it('does not follow a redirect after cancellation during the old attempt drain', async () => {
    const controller = new AbortController(), { result, task } = observe(probeHttp('192.0.2.1', 80, false, 'probe.example', controller.signal))
    await flush(); respond(0, 302, { location: '/next' }); controller.abort(); close(); await task
    expect(state.request).toHaveBeenCalledOnce(); expect(result.value?.status).toBe('skipped')
  })
  it('destroys and drains a response arriving after cancellation, without a success result', async () => {
    const controller = new AbortController(), { result, task } = observe(probeHttp('192.0.2.1', 80, false, 'probe.example', controller.signal))
    await flush(); controller.abort(); const response = respond()
    expect(response.destroy).toHaveBeenCalledOnce(); response.emit('error', new Error('late response reset')); response.emit('end'); close(); await task
    expect(result.value?.status).toBe('skipped')
  })
  it('handles premature close and synchronous factory failure without hanging', async () => {
    const { task, result } = observe(probeHttp('192.0.2.1', 80, false)); await flush(); close(); await task
    expect(result.value?.status).toBe('error')
    state.request.mockImplementation(() => { throw new Error('sync HTTP init') })
    expect((await probeHttp('192.0.2.1', 80, false)).error).toBe('sync HTTP init')
  })
  it('preserves measured duration while close drains and does not start an already cancelled request', async () => {
    const { task, result } = observe(probeHttp('192.0.2.1', 80, false)); await flush()
    await vi.advanceTimersByTimeAsync(10); respond().emit('end')
    await vi.advanceTimersByTimeAsync(250); expect(result.settled).toBe(false); close(); await task
    expect(result.value?.durationMs).toBe(10)
    const controller = new AbortController(); controller.abort()
    expect((await probeHttp('192.0.2.1', 80, false, undefined, controller.signal)).status).toBe('skipped')
    expect(state.request).toHaveBeenCalledOnce()
  })
  it.each(['normal', 'cancel'])('native HTTP %s drains real requests, responses and sockets', async boundary => {
    vi.useRealTimers()
    const actual = await vi.importActual<typeof import('http')>('http')
    const peers = new Set<import('net').Socket>(), closed: boolean[] = [], controller = new AbortController()
    const watch = (resource: EventEmitter) => { const index = closed.push(false) - 1; resource.once('close', () => { closed[index] = true }) }
    const server = actual.createServer((req, res) => {
      if (req.method === 'HEAD') { res.writeHead(405); res.end(); return }
      if (boundary === 'cancel') { res.writeHead(200); res.flushHeaders(); return }
      res.end('body')
    })
    server.on('connection', socket => { peers.add(socket); socket.once('close', () => peers.delete(socket)) })
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
    state.factory = (options, reply) => {
      const req = actual.request(options, response => { watch(response); reply(response); if (boundary === 'cancel' && options.method === 'GET') queueMicrotask(() => controller.abort()) })
      watch(req); req.once('socket', socket => watch(socket)); return req
    }
    try {
      const result = await probeHttp('127.0.0.1', (server.address() as import('net').AddressInfo).port, false, 'probe.example', controller.signal)
      expect(result.status).toBe(boundary === 'normal' ? 'ok' : 'skipped')
      expect(closed.length).toBe(6); expect(closed.every(Boolean)).toBe(true)
      if (boundary === 'normal') expect(result.bodySize).toBe(4)
    } finally { controller.abort(); for (const peer of peers) peer.destroy(); server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())) }
  }, 15_000)
})
