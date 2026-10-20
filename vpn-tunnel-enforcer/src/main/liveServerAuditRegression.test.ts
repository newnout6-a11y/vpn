import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { EventEmitter } from 'node:events'

const mocks = vi.hoisted(() => ({
  handlers: new Map<string, Function>(),
  resolve4: vi.fn().mockResolvedValue([]),
  saved: [] as any[],
  previous: {
    dns: { a: ['192.0.2.1'], aaaa: [] },
    reachability: { status: 'ok' },
    openPorts: [{ port: 443, open: true }]
  },
  cancelDns: vi.fn(),
  identity: vi.fn(() => new Error('SAN mismatch'))
}))

vi.mock('electron', () => ({
  app: { getPath: () => { throw new Error('Audit: disk persistence disabled') } },
  ipcMain: { handle: (channel: string, fn: Function) => mocks.handlers.set(channel, fn) }
}))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./settings', () => ({ settingsStore: { get: () => ({ disableGeoLookup: true }) } }))
vi.mock('./serverPicker', () => ({
  serverPicker: {
    getProfiles: () => [],
    getActiveProfile: () => null
  }
}))
vi.mock('./tunController', () => ({
  tunController: {
    getStatus: () => ({ running: false })
  }
}))
vi.mock('dns', () => {
  const promises = {
    resolve4: mocks.resolve4,
    resolve6: async () => [],
    resolveCname: async () => [],
    reverse: async () => []
  }
  Object.assign(promises, { Resolver: class {
    resolve4 = promises.resolve4
    resolve6 = promises.resolve6
    resolveCname = promises.resolveCname
    reverse = promises.reverse
    cancel() { mocks.cancelDns() }
  } })
  return { promises, default: { promises } }
})
vi.mock('tls', async (importOriginal) => {
  const actual = await importOriginal<typeof import('tls')>()
  const { EventEmitter } = await import('node:events')
  const connect = (_options: unknown, ready: () => void) => {
    const socket = Object.assign(new EventEmitter(), {
      destroy: vi.fn(() => { queueMicrotask(() => socket.emit('close')); return socket }),
      getPeerCertificate: () => ({
        subject: { CN: 'unrelated.example' },
        subjectaltname: 'DNS:unrelated.example'
      }),
      getProtocol: () => 'TLSv1.3',
      getCipher: () => ({ name: 'test' }),
      authorized: false,
      authorizationError: 'DEPTH_ZERO_SELF_SIGNED_CERT',
      alpnProtocol: 'h2'
    })
    socket.once('secureConnect', ready)
    queueMicrotask(() => socket.emit('secureConnect'))
    return socket
  }
  return {
    ...actual,
    checkServerIdentity: mocks.identity,
    connect,
    default: {
      ...actual,
      checkServerIdentity: mocks.identity,
      connect
    }
  }
})

import { probeTls, registerLiveServerProbeIpcHandlers, runLiveServerCheck } from './liveServerProbe'
import { computeHistoryDiff, liveServerHistory } from './liveServerHistory'
import { isStoredLiveCheck } from './liveServerHistorySchema'
import { redactSensitiveConfig } from './vpnProfiles'
import { withCorrelation } from './actionCorrelation'
import { operations } from './operations'

describe('Live Server Audit Regressions: Defect Verifications', () => {
  beforeEach(() => {
    mocks.saved.length = 0
    mocks.identity.mockClear()
  })

  // Defect 4: TLS Identity Verification for IP
  it('Defect 4: verifies identity against IP and correctly marks hostnameVerified: false on SAN mismatch', async () => {
    const result = await probeTls('192.0.2.1', 443)
    // Identity checker must have been invoked with target host ('192.0.2.1')
    expect(mocks.identity).toHaveBeenCalled()
    expect(result.hostnameVerified).toBe(false)
    expect(result.authorized).toBe(false)
    expect(result.authorizationError).toBe('DEPTH_ZERO_SELF_SIGNED_CERT')
    expect(result.alpnProtocol).toBe('h2')
  })

  // Defect 6: Untested Ports not marked closed
  it('Defect 6: does not mark untested ports as closed when switching extended -> basic', () => {
    const before = {
      startedAt: '2026-09-20T10:00:00Z',
      openPorts: [{ port: 443, open: true }, { port: 8443, open: true }]
    }
    const after = {
      startedAt: '2026-09-20T10:01:00Z',
      openPorts: [{ port: 443, open: true }]
    }
    const diff = computeHistoryDiff(after as any, before as any)
    // 8443 was not tested in "after", so it should NOT be marked closed
    expect(diff?.closedPorts).toEqual([])
    expect(diff?.portsChanged).toBe(false)
  })

  // Defect 1: Addressable Cancellation by requestId
  it('Defect 1: addressable cancellation by requestId aborts the matching active probe', async () => {
    registerLiveServerProbeIpcHandlers()
    let release!: Function
    mocks.resolve4.mockImplementationOnce(() => new Promise((resolve) => { release = resolve }))

    const reqId = 'audit-req-unique-123'
    const pending = mocks.handlers.get('server:live-check')!(
      {},
      { profileId: 'audit-p1', host: 'audit.invalid', port: 443, requestId: reqId }
    )
    const cancelled = expect(pending).rejects.toMatchObject({ category: 'cancelled' })

    // Attempting cancel with non-existent ID fails gracefully
    const unknownCancel = await mocks.handlers.get('server:live-check-cancel')!({}, 'wrong-id')
    expect(unknownCancel.cancelled).toBe(false)

    // Cancelling with exact requestId succeeds
    const response = await mocks.handlers.get('server:live-check-cancel')!({}, reqId)
    expect(response.cancelled).toBe(true)

    release([])
    await cancelled
    expect(mocks.saved).toHaveLength(0)
  })

  // Defect 3 & 7: Unique UUIDs per check and diff attached before history save
  it('Defect 3 & 7: assigns distinct IDs to distinct runs and attaches changesFromPrevious before saving', async () => {
    const save = vi.spyOn(liveServerHistory, 'addCheck').mockImplementation((check) => {
      mocks.saved.push(JSON.parse(JSON.stringify(check)))
    })
    const prev = vi.spyOn(liveServerHistory, 'getPreviousSuccessfulCheck').mockReturnValue(mocks.previous as any)

    // AT-00-003/005: cancelled checks are never history fixtures. Complete two
    // real loopback checks to verify identity and persistence ordering instead.
    const server = localHttp.createServer((_req, res) => { res.writeHead(204); res.end() })
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
    try {
      const options = { profileId: 'audit-p2', host: '127.0.0.1', port: (server.address() as any).port }
      const correlationId = 'ipc_11111111111141118111111111111111'
      const a = await withCorrelation(correlationId, () => runLiveServerCheck(options))
      const b = await withCorrelation(correlationId, () => runLiveServerCheck(options))
      expect(a.id).not.toBe(b.id)
      for (const check of [a, b]) {
        expect(isStoredLiveCheck(check)).toBe(true)
        expect(check.id).toMatch(/^op_[0-9a-f]{32}$/i)
        expect(check.cancelled).toBe(false)
        expect(check.infrastructure?.changesFromPrevious?.ipChanged).toBe(true)
      }
      expect(mocks.saved).toHaveLength(2)
      expect(mocks.saved[0].infrastructure.changesFromPrevious.ipChanged).toBe(true)
      expect(mocks.saved[1].infrastructure.changesFromPrevious.ipChanged).toBe(true)
      // The real serializer and production redactor must preserve distinct
      // receipts and the action key, while cancellation UUIDs stay internal.
      const redacted = JSON.parse(JSON.stringify(redactSensitiveConfig(mocks.saved)))
      expect(redacted.map((check: any) => check.operationKey)).toEqual([a.id, b.id])
      expect(redacted.map((check: any) => check.correlationId)).toEqual([correlationId, correlationId])
      for (const check of [a, b]) {
        const operation = operations.list().find(item => item.operationKey === check.id)!
        expect(JSON.stringify(redacted)).not.toContain(operation.operationId)
      }
    } finally {
      server.closeAllConnections()
      await new Promise<void>(resolve => server.close(() => resolve()))
      save.mockRestore(); prev.mockRestore()
    }
  })
})

vi.mock('child_process', async (importOriginal) => {
  const actual = await importOriginal<typeof import('child_process')>()
  const { EventEmitter } = await import('node:events')
  const spawn = () => {
    const child = Object.assign(new EventEmitter(), { stdout: new EventEmitter(), kill: vi.fn() })
    queueMicrotask(() => {
      child.stdout.emit('data', Buffer.from('Tracing route to 192.0.2.1\r\n  1  * * * Request timed out.\r\nTrace complete.\r\n'))
      child.emit('close', 0)
    })
    return child
  }
  return { ...actual, spawn, default: { ...actual, spawn } }
})
import { probeHttp, probeRoute } from './liveServerProbe'
import * as localHttp from 'node:http'

describe('Second review: residual defects, observed behavior', () => {
  it('does not treat timeout as closed', () => {
    const before = { openPorts: [{ port: 443, open: true, state: 'open' }] }
    const after = { openPorts: [{ port: 443, open: false, state: 'timeout' }] }
    expect(computeHistoryDiff(after as any, before as any)?.closedPorts).toEqual([])
  })
  it('does not infer target reached from Trace complete', async () => {
    const platform = Object.getOwnPropertyDescriptor(process, 'platform')!
    Object.defineProperty(process, 'platform', { value: 'win32', configurable: true })
    try {
      const result = await probeRoute('192.0.2.1')
      expect(result.reachedTarget).toBe(false)
      expect(result.hopDetails?.[0]).toContain('Request timed out')
    } finally { Object.defineProperty(process, 'platform', platform) }
  })
  it('HTTP overall deadline stops an active slow body', async () => {
    let interval: ReturnType<typeof setInterval> | undefined
    const server = localHttp.createServer((req, res) => {
      if (req.method === 'HEAD') { res.writeHead(405); res.end(); return }
      res.writeHead(200)
      res.flushHeaders()
      let chunks = 0
      interval = setInterval(() => { res.write('x'); if (++chunks === 40) { clearInterval(interval); res.end() } }, 100)
    })
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
    try {
      const port = (server.address() as any).port
      const result = await probeHttp('127.0.0.1', port, false, 'audit.example')
      expect(result.status).toBe('error')
      expect(result.error).toContain('deadline')
      expect(result.durationMs).toBeLessThan(4100)
    } finally {
      clearInterval(interval)
      server.closeAllConnections()
      await new Promise<void>(resolve => server.close(() => resolve()))
    }
  }, 8000)
})

it('isolates cancellation by sender and rejects duplicate IDs', async () => {
  registerLiveServerProbeIpcHandlers()
  let release!: (value: unknown[]) => void
  mocks.resolve4.mockImplementation(() => new Promise(resolve => { release = resolve }))
  const owner = Object.assign(new EventEmitter(), { id: 71 })
  const other = Object.assign(new EventEmitter(), { id: 72 })
  const run = mocks.handlers.get('server:live-check')!
  const cancel = mocks.handlers.get('server:live-check-cancel')!
  const options = { requestId: 'same-id', host: 'audit.invalid', port: 443 }
  const pending = run({ sender: owner }, options)
  const cancelled = expect(pending).rejects.toMatchObject({ category: 'cancelled' })
  await expect(run({ sender: owner }, options)).rejects.toMatchObject({ category: 'conflict' })
  expect((await cancel({ sender: other }, 'same-id')).cancelled).toBe(false)
  expect((await cancel({ sender: owner }, 'same-id')).cancelled).toBe(true)
  expect(owner.listenerCount('destroyed')).toBe(1)
  release([]) // Native cancellation initiates cleanup; the raw query must also settle.
  await cancelled
  expect(mocks.cancelDns).toHaveBeenCalled()
  await vi.waitFor(() => expect(owner.listenerCount('destroyed')).toBe(0))
  mocks.resolve4.mockResolvedValue([])
})
it.each(['timeout', 'filtered'])('does not classify %s as a closed port', state => {
  const previous = { openPorts: [{ port: 443, open: true, state: 'open' }] }
  expect(computeHistoryDiff({ openPorts: [{ port: 443, open: false, state }] } as any, previous as any)?.closedPorts).toEqual([])
  expect(computeHistoryDiff({ openPorts: [{ port: 443, open: false, state: 'closed' }] } as any, previous as any)?.closedPorts).toEqual([443])
})
it('follows same-authority redirect preserving query on the original port', async () => {
  const requests: string[] = []
  const server = localHttp.createServer((req, res) => {
    requests.push(`${req.headers.host}${req.url}`)
    if (req.url === '/') { res.writeHead(302, { location: '/next?probe=1' }); res.end() }
    else { res.writeHead(204); res.end() }
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  try {
    const port = (server.address() as any).port
    const result = await probeHttp('127.0.0.1', port, false, 'audit.example')
    expect(result.statusCode).toBe(204)
    expect(result.targetPort).toBe(port)
    expect(requests).toEqual([`audit.example:${port}/`, `audit.example:${port}/next?probe=1`])
  } finally { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())) }
})
