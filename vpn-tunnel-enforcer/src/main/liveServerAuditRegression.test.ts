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
  return { promises, default: { promises } }
})
vi.mock('tls', async () => {
  const { EventEmitter } = await import('node:events')
  return {
    checkServerIdentity: mocks.identity,
    connect: (_opts: unknown, callback: Function) => {
      const socket = Object.assign(new EventEmitter(), {
        destroy: vi.fn(),
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
      queueMicrotask(() => callback())
      return socket
    }
  }
})

import { probeTls, registerLiveServerProbeIpcHandlers, runLiveServerCheck } from './liveServerProbe'
import { computeHistoryDiff, liveServerHistory } from './liveServerHistory'

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

    // Attempting cancel with non-existent ID fails gracefully
    const unknownCancel = await mocks.handlers.get('server:live-check-cancel')!({}, 'wrong-id')
    expect(unknownCancel.cancelled).toBe(false)

    // Cancelling with exact requestId succeeds
    const response = await mocks.handlers.get('server:live-check-cancel')!({}, reqId)
    expect(response.cancelled).toBe(true)

    release([])
    const checkResult = await pending
    expect(checkResult.error).toMatch(/cancelled|aborted/i)
  })

  // Defect 3 & 7: Unique UUIDs per check and diff attached before history save
  it('Defect 3 & 7: assigns distinct IDs to distinct runs and attaches changesFromPrevious before saving', async () => {
    const save = vi.spyOn(liveServerHistory, 'addCheck').mockImplementation((check) => {
      mocks.saved.push(JSON.parse(JSON.stringify(check)))
    })
    const prev = vi.spyOn(liveServerHistory, 'getPreviousSuccessfulCheck').mockReturnValue(mocks.previous as any)

    const controller = new AbortController()
    controller.abort()

    const optionsA = { profileId: 'audit-p2', host: '192.0.2.2', port: 443 }
    const optionsB = { profileId: 'audit-p2', host: '192.0.2.2', port: 443 }

    const a = await runLiveServerCheck(optionsA, controller.signal)
    const b = await runLiveServerCheck(optionsB, controller.signal)

    // Defect 3: IDs must be unique UUIDs
    expect(a.id).not.toBe(b.id)
    expect(a.id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i)
    expect(b.id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i)

    // Defect 7: changesFromPrevious must be present in saved history snapshots
    expect(a.infrastructure?.changesFromPrevious?.ipChanged).toBe(true)
    expect(mocks.saved[0].infrastructure?.changesFromPrevious).toBeDefined()
    expect(mocks.saved[0].infrastructure.changesFromPrevious.ipChanged).toBe(true)

    save.mockRestore()
    prev.mockRestore()
  })
})
