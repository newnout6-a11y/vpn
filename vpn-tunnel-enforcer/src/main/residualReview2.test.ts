import { it, expect, vi, describe } from 'vitest'
import { EventEmitter } from 'node:events'
import { isPublicIp, isPublicIpv4, openTcpViaSocks } from './keyHealthChecker'
import { withHandshakeWorkerLock, probePmtu, evaluateLiveCheckFindings, queryDoH } from './liveServerProbe'
import { SocksClient } from 'socks'

describe('Residual Review 2 Audit Fixes', () => {
  describe('P1. IPv6 and reserved IP validation (isPublicIp)', () => {
    it('rejects IPv4-mapped IPv6 addresses with private/reserved IPs', () => {
      expect(isPublicIp('::ffff:192.168.1.1')).toBe(false)
      expect(isPublicIp('::ffff:10.0.0.1')).toBe(false)
      expect(isPublicIp('::ffff:127.0.0.1')).toBe(false)
      expect(isPublicIp('::ffff:100.64.0.1')).toBe(false)
      expect(isPublicIp('::ffff:192.0.2.1')).toBe(false)
    })

    it('rejects CGNAT range 100.64.0.0/10', () => {
      expect(isPublicIp('100.64.0.1')).toBe(false)
      expect(isPublicIp('100.100.50.1')).toBe(false)
      expect(isPublicIp('100.127.255.254')).toBe(false)
      // Outside 100.64.0.0/10:
      expect(isPublicIp('100.63.255.255')).toBe(true)
      expect(isPublicIp('100.128.0.1')).toBe(true)
    })

    it('rejects RFC 5737 IPv4 documentation ranges (TEST-NET-1, 2, 3)', () => {
      expect(isPublicIp('192.0.2.1')).toBe(false)
      expect(isPublicIp('198.51.100.1')).toBe(false)
      expect(isPublicIp('203.0.113.1')).toBe(false)
    })

    it('rejects RFC 3849 IPv6 documentation range 2001:db8::/32', () => {
      expect(isPublicIp('2001:db8::1')).toBe(false)
      expect(isPublicIp('2001:0db8:0000:0000:0000:0000:0000:0001')).toBe(false)
      expect(isPublicIp('2001:db8:ffff:ffff:ffff:ffff:ffff:ffff')).toBe(false)
    })

    it('rejects benchmarking and discard IPv4/IPv6 ranges', () => {
      expect(isPublicIp('198.18.0.1')).toBe(false)
      expect(isPublicIp('198.19.255.1')).toBe(false)
      expect(isPublicIp('100::1')).toBe(false)
      expect(isPublicIp('2001:2::1')).toBe(false)
    })

    it('accepts genuine public IPv4 and IPv6 addresses', () => {
      expect(isPublicIp('8.8.8.8')).toBe(true)
      expect(isPublicIp('1.1.1.1')).toBe(true)
      expect(isPublicIp('142.250.180.206')).toBe(true)
      expect(isPublicIp('2606:4700:4700::1111')).toBe(true)
      expect(isPublicIp('2001:4860:4860::8888')).toBe(true)
    })
  })

  describe('P1. SOCKS connection cancellation (openTcpViaSocks)', () => {
    it('immediately rejects if signal is already aborted', async () => {
      const ctrl = new AbortController()
      ctrl.abort()
      await expect(
        openTcpViaSocks({ host: '127.0.0.1', port: 1080 }, '1.1.1.1', 443, 1000, ctrl.signal)
      ).rejects.toThrow('Cancelled')
    })

    it('cancels pending SOCKS connection on abort and destroys late socket', async () => {
      const ctrl = new AbortController()
      const mockDestroy = vi.fn()
      const mockSocket: any = { destroy: mockDestroy }

      vi.spyOn(SocksClient, 'createConnection').mockImplementation(() => {
        return new Promise((resolve) => {
          setTimeout(() => {
            resolve({ socket: mockSocket } as any)
          }, 50)
        })
      })

      const promise = openTcpViaSocks({ host: '127.0.0.1', port: 1080 }, '1.1.1.1', 443, 1000, ctrl.signal)

      // Trigger abort while createConnection is pending
      setTimeout(() => ctrl.abort(), 10)

      await expect(promise).rejects.toThrow('Cancelled')

      // Wait for late createConnection to fulfill and verify destroy was called
      await new Promise(r => setTimeout(r, 60))
      expect(mockDestroy).toHaveBeenCalled()

      vi.restoreAllMocks()
    })
  })

  describe('P1. Handshake worker queue deadline & cancellation', () => {
    it('cancels queued request when signal aborts while waiting for lease', async () => {
      let releaseFirst: () => void = () => {}
      const firstHold = new Promise<void>((r) => { releaseFirst = r })

      // First task holds the lock
      const p1 = withHandshakeWorkerLock(async () => {
        await firstHold
        return 'first-done'
      })

      // Second task enters queue with AbortSignal
      const ctrl = new AbortController()
      const p2 = withHandshakeWorkerLock(async () => 'second-done', { signal: ctrl.signal })

      // Abort second while waiting
      ctrl.abort()
      await expect(p2).rejects.toThrow('Cancelled')

      // Unblock first, verify it finishes normally
      releaseFirst()
      expect(await p1).toBe('first-done')
    })

    it('times out queued request when lease wait exceeds queueTimeoutMs', async () => {
      let releaseFirst: () => void = () => {}
      const firstHold = new Promise<void>((r) => { releaseFirst = r })

      const p1 = withHandshakeWorkerLock(async () => {
        await firstHold
        return 'first-done'
      })

      // Second task waits with short 30ms queueTimeoutMs
      const p2 = withHandshakeWorkerLock(async () => 'second-done', { queueTimeoutMs: 30 })

      await expect(p2).rejects.toThrow(/queue lease timeout/)

      releaseFirst()
      expect(await p1).toBe('first-done')
    })
  })

  describe('P1. PMTU basic validation', () => {
    it('skips PMTU gracefully for invalid or empty host', async () => {
      const res = await probePmtu('')
      expect(res.status).toBe('skipped')
    })
  })

  describe('P2. DoH mixed A/AAAA classification', () => {
    it('returns status: partial when A succeeds and AAAA fails', async () => {
      vi.stubGlobal('fetch', vi.fn().mockImplementation((url: string) => {
        if (url.endsWith('type=AAAA')) {
          // AAAA fails with SERVFAIL (Status: 2)
          return Promise.resolve({
            ok: true,
            json: async () => ({
              Status: 2,
              AD: false
            })
          })
        }
        if (url.endsWith('type=A')) {
          return Promise.resolve({
            ok: true,
            json: async () => ({
              Status: 0,
              AD: true,
              Answer: [{ name: 'example.com', type: 1, TTL: 300, data: '93.184.216.34' }]
            })
          })
        }
        return Promise.reject(new Error('unknown url'))
      }))

      const doh = await queryDoH('cloudflare-doh', 'Cloudflare DoH', 'https://cloudflare-dns.com/dns-query', 'example.com')
      expect(doh.status).toBe('partial')
      expect(doh.records.length).toBe(1)
      expect(doh.records[0].type).toBe('A')
      expect(doh.error).toContain('AAAA: SERVFAIL')

      vi.unstubAllGlobals()
    })
  })

  describe('P2. Separation of Handshake and Egress findings', () => {
    it('generates EGRESS_VERIFICATION_FAILED when egress fails even if handshake ok', () => {
      const findings = evaluateLiveCheckFindings({
        handshake: { status: 'ok', protocol: 'vless', durationMs: 50 },
        egress: { status: 'error', error: 'Reflectors unreachable', reflectors: [], durationMs: 100 }
      } as any)

      expect(findings.some(f => f.code === 'EGRESS_VERIFICATION_FAILED')).toBe(true)
      expect(findings.some(f => f.code === 'TUNNEL_HANDSHAKE_FAILED')).toBe(false)
    })

    it('generates EGRESS_PARTIAL when egress status is partial', () => {
      const findings = evaluateLiveCheckFindings({
        handshake: { status: 'ok', protocol: 'vless', durationMs: 50 },
        egress: { status: 'partial', error: 'ipify failed', reflectors: [], durationMs: 100 }
      } as any)

      expect(findings.some(f => f.code === 'EGRESS_PARTIAL')).toBe(true)
    })
  })
})
