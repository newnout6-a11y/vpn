import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { join } from 'path'
import { rmSync, existsSync } from 'fs'
import { tmpdir } from 'os'
import {
  liveServerHistory,
  sanitizeLiveCheckForStorage,
  computeHistoryDiff,
  MAX_HISTORY_PER_TARGET
} from './liveServerHistory'
import type { LiveServerCheck } from '../shared/ipc-types'

function makeMockCheck(overrides: Partial<LiveServerCheck> = {}): LiveServerCheck {
  return {
    id: 'check-1',
    profileId: 'p-1',
    host: 'vpn.example.com',
    port: 443,
    mode: 'basic',
    startedAt: '2026-09-20T10:00:00.000Z',
    finishedAt: '2026-09-20T10:00:01.000Z',
    durationMs: 1000,
    dns: {
      status: 'ok',
      durationMs: 50,
      a: ['1.2.3.4'],
      aaaa: [],
      cnameChain: []
    },
    reachability: {
      status: 'ok',
      durationMs: 100,
      tcpReachable: true,
      port: 443
    },
    latency: {
      min: 40,
      avg: 50,
      median: 48,
      max: 60,
      jitter: 5,
      loss: 0,
      samples: [40, 48, 52, 60],
      samplesAttempted: 4,
      method: 'tcp'
    },
    tls: {
      status: 'ok',
      durationMs: 80,
      fingerprint: 'AA:BB:CC:DD',
      validTo: '2027-01-01T00:00:00.000Z',
      daysRemaining: 100
    },
    asn: {
      asn: 'AS12345',
      org: 'Example ISP',
      network: '1.2.3.0/24',
      country: 'Germany'
    },
    openPorts: [
      { port: 443, open: true, state: 'open', service: 'HTTPS' }
    ],
    findings: [],
    ...overrides
  }
}

describe('liveServerHistory', () => {
  const testStorage = join(tmpdir(), `test-live-history-${Date.now()}.json`)

  beforeEach(() => {
    liveServerHistory.init(testStorage)
  })

  afterEach(() => {
    if (existsSync(testStorage)) {
      try { rmSync(testStorage) } catch {}
    }
  })

  it('sanitizes secrets from evidence in findings before storage', () => {
    const rawCheck = makeMockCheck({
      findings: [
        {
          code: 'TEST_FINDING',
          severity: 'info',
          title: 'Test',
          detail: 'No secrets should remain',
          evidence: {
            host: 'vpn.example.com',
            userUuid: 'secret-uuid-1234',
            privateKey: 'secret-key-5678',
            serverPassword: 'super-password',
            shortId: 'sid-999',
            normalValue: 42
          }
        }
      ]
    })

    const sanitized = sanitizeLiveCheckForStorage(rawCheck)
    const evidence = sanitized.findings[0].evidence!

    expect(evidence.host).toBe('vpn.example.com')
    expect(evidence.normalValue).toBe(42)
    expect(evidence.userUuid).toBeUndefined()
    expect(evidence.privateKey).toBeUndefined()
    expect(evidence.serverPassword).toBeUndefined()
    expect(evidence.shortId).toBeUndefined()
  })

  it('caps history per profile at MAX_HISTORY_PER_TARGET (20)', () => {
    for (let i = 1; i <= 25; i++) {
      liveServerHistory.addCheck(
        makeMockCheck({
          id: `check-${i}`,
          startedAt: new Date(Date.now() + i * 1000).toISOString()
        })
      )
    }

    const history = liveServerHistory.getHistory({ profileId: 'p-1' })
    expect(history.length).toBe(MAX_HISTORY_PER_TARGET)
    expect(history[0].id).toBe('check-25')
  })

  it('retrieves previous successful check', () => {
    const check1 = makeMockCheck({ id: 'c-1', startedAt: '2026-09-20T10:00:00.000Z' })
    const check2 = makeMockCheck({
      id: 'c-2',
      startedAt: '2026-09-20T10:05:00.000Z',
      reachability: { status: 'error', durationMs: 50, tcpReachable: false, port: 443 },
      dns: { status: 'error', durationMs: 20, a: [], aaaa: [], cnameChain: [] }
    })

    liveServerHistory.addCheck(check1)
    liveServerHistory.addCheck(check2)

    const prev = liveServerHistory.getPreviousSuccessfulCheck('p-1')
    expect(prev).not.toBeNull()
    expect(prev?.id).toBe('c-1')
  })

  describe('computeHistoryDiff', () => {
    it('detects IP changes', () => {
      const prev = makeMockCheck({ dns: { status: 'ok', durationMs: 10, a: ['1.2.3.4'], aaaa: [], cnameChain: [] } })
      const curr = makeMockCheck({ dns: { status: 'ok', durationMs: 10, a: ['5.6.7.8'], aaaa: [], cnameChain: [] } })

      const diff = computeHistoryDiff(curr, prev)
      expect(diff?.ipChanged).toBe(true)
      expect(diff?.previousIps).toEqual(['1.2.3.4'])
      expect(diff?.currentIps).toEqual(['5.6.7.8'])
    })

    it('detects TLS certificate fingerprint change', () => {
      const prev = makeMockCheck({ tls: { status: 'ok', durationMs: 10, fingerprint: 'FINGERPRINT_OLD' } })
      const curr = makeMockCheck({ tls: { status: 'ok', durationMs: 10, fingerprint: 'FINGERPRINT_NEW' } })

      const diff = computeHistoryDiff(curr, prev)
      expect(diff?.tlsCertChanged).toBe(true)
      expect(diff?.previousTlsFingerprint).toBe('FINGERPRINT_OLD')
      expect(diff?.currentTlsFingerprint).toBe('FINGERPRINT_NEW')
    })

    it('detects ASN and country change', () => {
      const prev = makeMockCheck({
        asn: { asn: 'AS111', org: 'ISP 1', network: '1.0.0.0/8', country: 'Germany' }
      })
      const curr = makeMockCheck({
        asn: { asn: 'AS222', org: 'ISP 2', network: '2.0.0.0/8', country: 'Netherlands' }
      })

      const diff = computeHistoryDiff(curr, prev)
      expect(diff?.asnChanged).toBe(true)
      expect(diff?.countryChanged).toBe(true)
      expect(diff?.previousAsn).toBe('AS111')
      expect(diff?.currentAsn).toBe('AS222')
      expect(diff?.previousCountry).toBe('Germany')
      expect(diff?.currentCountry).toBe('Netherlands')
    })

    it('detects latency spike (avg > 1.5x and > 50ms difference)', () => {
      const prev = makeMockCheck({
        latency: { min: 40, avg: 50, median: 48, max: 60, jitter: 5, loss: 0, samples: [50], samplesAttempted: 1, method: 'tcp' }
      })
      const curr = makeMockCheck({
        latency: { min: 140, avg: 150, median: 148, max: 160, jitter: 15, loss: 0, samples: [150], samplesAttempted: 1, method: 'tcp' }
      })

      const diff = computeHistoryDiff(curr, prev)
      expect(diff?.latencySpike).toBe(true)
      expect(diff?.previousAvgLatency).toBe(50)
      expect(diff?.currentAvgLatency).toBe(150)
    })

    it('detects closed and newly opened ports', () => {
      const prev = makeMockCheck({
        openPorts: [
          { port: 80, open: true, state: 'open' },
          { port: 443, open: true, state: 'open' },
          { port: 8443, open: false, state: 'closed' }
        ]
      })
      const curr = makeMockCheck({
        openPorts: [
          { port: 80, open: false, state: 'closed' },
          { port: 443, open: true, state: 'open' },
          { port: 8443, open: true, state: 'open' }
        ]
      })

      const diff = computeHistoryDiff(curr, prev)
      expect(diff?.portsChanged).toBe(true)
      expect(diff?.closedPorts).toEqual([80])
      expect(diff?.newOpenPorts).toEqual([8443])
    })

    it('does not mark untested ports as closed when moving from extended to basic mode', () => {
      const prevExtended = makeMockCheck({
        openPorts: [
          { port: 443, open: true, state: 'open' },
          { port: 8443, open: true, state: 'open' }
        ]
      })
      const currBasic = makeMockCheck({
        openPorts: [
          { port: 443, open: true, state: 'open' }
        ]
      })

      const diff = computeHistoryDiff(currBasic, prevExtended)
      expect(diff?.portsChanged).toBe(false)
      expect(diff?.closedPorts).toEqual([])
    })
  })
})
