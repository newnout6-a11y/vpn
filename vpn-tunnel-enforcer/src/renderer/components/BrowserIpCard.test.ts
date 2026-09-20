import { describe, it, expect } from 'vitest'
import { isPrivateIp, unwrapIpv4Mapped, summarize } from './BrowserIpCard'

describe('BrowserIpCard IP helpers', () => {
  describe('unwrapIpv4Mapped', () => {
    it('unwraps dot-decimal IPv4-mapped IPv6 address', () => {
      expect(unwrapIpv4Mapped('::ffff:192.168.1.10')).toBe('192.168.1.10')
      expect(unwrapIpv4Mapped('0:0:0:0:0:ffff:10.0.0.1')).toBe('10.0.0.1')
      expect(unwrapIpv4Mapped('::ffff:8.8.8.8')).toBe('8.8.8.8')
    })

    it('unwraps hex-encoded IPv4-mapped IPv6 address', () => {
      expect(unwrapIpv4Mapped('::ffff:c0a8:010a')).toBe('192.168.1.10')
      expect(unwrapIpv4Mapped('0:0:0:0:0:ffff:7f00:0001')).toBe('127.0.0.1')
    })

    it('preserves native IPv4 and standard IPv6 strings', () => {
      expect(unwrapIpv4Mapped('1.1.1.1')).toBe('1.1.1.1')
      expect(unwrapIpv4Mapped('2606:4700:4700::1111')).toBe('2606:4700:4700::1111')
    })
  })

  describe('isPrivateIp', () => {
    it('recognizes standard private IPv4 and IPv6 addresses', () => {
      expect(isPrivateIp('10.0.0.1')).toBe(true)
      expect(isPrivateIp('192.168.0.1')).toBe(true)
      expect(isPrivateIp('172.16.0.1')).toBe(true)
      expect(isPrivateIp('172.31.255.255')).toBe(true)
      expect(isPrivateIp('127.0.0.1')).toBe(true)
      expect(isPrivateIp('169.254.1.1')).toBe(true)
      expect(isPrivateIp('::1')).toBe(true)
      expect(isPrivateIp('::')).toBe(true)
      expect(isPrivateIp('fe80::1')).toBe(true)
      expect(isPrivateIp('fd12:3456:789a::1')).toBe(true)
    })

    it('correctly classifies IPv4-mapped IPv6 addresses as private or public', () => {
      // Jev defect: ::ffff:192.168.1.10 must be treated as private, not public
      expect(isPrivateIp('::ffff:192.168.1.10')).toBe(true)
      expect(isPrivateIp('::ffff:10.1.2.3')).toBe(true)
      expect(isPrivateIp('::ffff:172.20.0.1')).toBe(true)
      expect(isPrivateIp('0:0:0:0:0:ffff:192.168.1.100')).toBe(true)
      expect(isPrivateIp('::ffff:c0a8:010a')).toBe(true)

      // Public IPv4-mapped IPv6 must be false
      expect(isPrivateIp('::ffff:8.8.8.8')).toBe(false)
      expect(isPrivateIp('::ffff:1.1.1.1')).toBe(false)
    })

    it('rejects public IPv4 and IPv6 addresses', () => {
      expect(isPrivateIp('8.8.8.8')).toBe(false)
      expect(isPrivateIp('172.32.0.1')).toBe(false)
      expect(isPrivateIp('2606:4700:4700::1111')).toBe(false)
    })
  })

  describe('summarize WebRTC candidate classification', () => {
    it('places IPv4-mapped IPv6 candidates into webRtcLocalIps and not webRtcPublicIps', () => {
      const summary = summarize({
        browserIpv4: '198.51.100.1',
        browserIpv6: null,
        nodeIp: '198.51.100.1',
        webRtcCandidates: [
          { type: 'host', address: '::ffff:192.168.1.10', protocol: 'udp' },
          { type: 'srflx', address: '198.51.100.1', protocol: 'udp' }
        ],
        webRtcError: null,
        tunRunning: true
      })

      expect(summary.webRtcLocalIps).toContain('192.168.1.10')
      expect(summary.webRtcPublicIps).not.toContain('192.168.1.10')
      expect(summary.webRtcPublicIps).toEqual(['198.51.100.1'])
      // Should not claim that an unexpected public IP leaked
      expect(summary.details.some(d => d.includes('WebRTC показал другие публичные адреса'))).toBe(false)
    })
  })
})
