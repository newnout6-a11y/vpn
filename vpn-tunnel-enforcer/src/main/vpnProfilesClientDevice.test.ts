import { describe, expect, it } from 'vitest'
import {
  applyClientDeviceToOutbound,
  buildSubscriptionHwid,
  getSubscriptionUserAgents,
  normalizeSubscriptionRedirectLocation,
  resolveVpnProfiles
} from './vpnProfiles'

describe('client device identity', () => {
  it('builds stable but device-specific subscription HWIDs', () => {
    const pc = buildSubscriptionHwid('pc')
    const android = buildSubscriptionHwid('android')
    const ios = buildSubscriptionHwid('ios')
    const mac = buildSubscriptionHwid('mac')

    expect(buildSubscriptionHwid('pc')).toBe(pc)
    expect(buildSubscriptionHwid('android')).toBe(android)
    expect(buildSubscriptionHwid('ios')).toBe(ios)
    expect(buildSubscriptionHwid('mac')).toBe(mac)
    expect(new Set([pc, android, ios, mac]).size).toBe(4)
  })

  it('uses Happ-style user agents first for device modes', () => {
    expect(getSubscriptionUserAgents('pc')[0]).toMatch(/^Happ\/3\.22\.1\/Windows\/[a-f0-9]{16}$/)
    expect(getSubscriptionUserAgents('android')[0]).toMatch(/^Happ\/3\.22\.1\/Android\/[a-f0-9]{16}$/)
    expect(getSubscriptionUserAgents('ios')[0]).toMatch(/^Happ\/3\.22\.1\/iOS\/[a-f0-9]{16}$/)
    expect(getSubscriptionUserAgents('mac')[0]).toMatch(/^Happ\/3\.22\.1\/macOS\/[a-f0-9]{16}$/)
  })

  it('sets matching uTLS fingerprints only when TLS exists', () => {
    const tlsOutbound = { type: 'vless', tls: { enabled: true, server_name: 'example.com' } }
    expect(applyClientDeviceToOutbound(tlsOutbound, 'pc').tls.utls.fingerprint).toBe('chrome')
    expect(applyClientDeviceToOutbound(tlsOutbound, 'android').tls.utls.fingerprint).toBe('android')
    expect(applyClientDeviceToOutbound(tlsOutbound, 'ios').tls.utls.fingerprint).toBe('ios')
    expect(applyClientDeviceToOutbound(tlsOutbound, 'mac').tls.utls.fingerprint).toBe('safari')

    const plain = { type: 'shadowsocks', server: '1.2.3.4', server_port: 8388 }
    expect(applyClientDeviceToOutbound(plain, 'android')).toEqual(plain)
  })

  it('normalizes subscription redirect locations that curl -L cannot follow', () => {
    const base = 'https://sub.example.com/a/b?token=1'

    expect(normalizeSubscriptionRedirectLocation('URL: https://panel.example.com/sub', base)).toBe('https://panel.example.com/sub')
    expect(normalizeSubscriptionRedirectLocation('URL%3A%20https%3A%2F%2Fpanel.example.com%2Fsub', base)).toBe('https://panel.example.com/sub')
    expect(normalizeSubscriptionRedirectLocation('happ%3A%2F%2Fadd%2Fhttps%253A%252F%252Fsub.example.com%252Freal', base)).toBe('happ://add/https%3A%2F%2Fsub.example.com%2Freal')
    expect(normalizeSubscriptionRedirectLocation('mantaray%3A%2F%2Fcrypt%2Fsecret-payload', base)).toBe('mantaray://crypt/secret-payload')
    expect(normalizeSubscriptionRedirectLocation('//cdn.example.com/sub', base)).toBe('https://cdn.example.com/sub')
    expect(normalizeSubscriptionRedirectLocation('../real-sub', base)).toBe('https://sub.example.com/real-sub')
  })

  it('rejects encrypted MantaRay links without leaking the crypt payload', async () => {
    await expect(resolveVpnProfiles('mantaray://crypt/super-secret-payload')).rejects.toThrow(/зашифрованная подписка MantaRay/i)
    await expect(resolveVpnProfiles('mantaray://crypt/super-secret-payload')).rejects.not.toThrow(/super-secret-payload/)
  })
})
