import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import axios from 'axios'

vi.mock('axios')
vi.mock('./appLogger', () => ({
  logEvent: vi.fn()
}))

import {
  ipMonitor,
  IP_CHECK_URLS,
  fetchPublicIpFrom,
  fetchPublicIp,
  setIpMonitorRecoveryCallback
} from './ipMonitor'

describe('ipMonitor multi-provider configuration', () => {
  it('contains the expected multi-provider check URLs', () => {
    expect(IP_CHECK_URLS).toContain('https://cloudflare.com/cdn-cgi/trace')
    expect(IP_CHECK_URLS).toContain('https://api.ipify.org?format=json')
    expect(IP_CHECK_URLS).toContain('https://icanhazip.com')
    expect(IP_CHECK_URLS).toContain('https://api.myip.com')
    expect(IP_CHECK_URLS.length).toBeGreaterThanOrEqual(4)
  })
})

describe('fetchPublicIpFrom provider parsing', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    setIpMonitorRecoveryCallback(null)
  })

  afterEach(() => {
    setIpMonitorRecoveryCallback(null)
  })

  it('parses Cloudflare cdn-cgi/trace format (IPv4)', async () => {
    const traceBody = [
      'fl=84f22',
      'h=cloudflare.com',
      'ip=203.0.113.195',
      'ts=1726246345.123',
      'visit_scheme=https',
      'uag=Mozilla/5.0'
    ].join('\n')

    vi.mocked(axios.get).mockResolvedValueOnce({ data: traceBody } as any)

    const ip = await fetchPublicIpFrom('https://cloudflare.com/cdn-cgi/trace')
    expect(ip).toBe('203.0.113.195')
  })

  it('parses Cloudflare cdn-cgi/trace format (IPv6)', async () => {
    const traceBody = [
      'fl=84f22',
      'h=cloudflare.com',
      'ip=2001:db8::1',
      'ts=1726246345.123'
    ].join('\n')

    vi.mocked(axios.get).mockResolvedValueOnce({ data: traceBody } as any)

    const ip = await fetchPublicIpFrom('https://cloudflare.com/cdn-cgi/trace')
    expect(ip).toBe('2001:db8::1')
  })

  it('parses JSON format with ip field (api.ipify.org / api.myip.com)', async () => {
    vi.mocked(axios.get).mockResolvedValueOnce({ data: '{"ip":"198.51.100.42","country":"Germany"}' } as any)

    const ip = await fetchPublicIpFrom('https://api.myip.com')
    expect(ip).toBe('198.51.100.42')
  })

  it('parses JSON format when axios returns an object directly', async () => {
    vi.mocked(axios.get).mockResolvedValueOnce({ data: { ip: '198.51.100.77' } } as any)

    const ip = await fetchPublicIpFrom('https://api.ipify.org?format=json')
    expect(ip).toBe('198.51.100.77')
  })

  it('parses plain text format (icanhazip.com)', async () => {
    vi.mocked(axios.get).mockResolvedValueOnce({ data: '203.0.113.88\n' } as any)

    const ip = await fetchPublicIpFrom('https://icanhazip.com')
    expect(ip).toBe('203.0.113.88')
  })

  it('rejects invalid or non-IP responses', async () => {
    vi.mocked(axios.get).mockResolvedValueOnce({ data: '<html>502 Bad Gateway</html>' } as any)

    await expect(fetchPublicIpFrom('https://icanhazip.com')).rejects.toThrow('response did not contain a valid IP')
  })

  it('invokes recovery callback on successful IP fetch', async () => {
    const recoveryFn = vi.fn()
    setIpMonitorRecoveryCallback(recoveryFn)

    vi.mocked(axios.get).mockResolvedValueOnce({ data: '{"ip":"198.51.100.99"}' } as any)

    const ip = await fetchPublicIpFrom('https://api.myip.com')
    expect(ip).toBe('198.51.100.99')
    expect(recoveryFn).toHaveBeenCalledWith('ipMonitor')
  })
})

describe('fetchPublicIp multi-provider racing and failover', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('succeeds even if one provider fails with HTTP 429 rate limit', async () => {
    vi.mocked(axios.get).mockImplementation(async (url) => {
      if (typeof url === 'string' && url.includes('ipify')) {
        const err = new Error('Request failed with status code 429')
        ;(err as any).response = { status: 429 }
        throw err
      }
      if (typeof url === 'string' && url.includes('icanhazip')) {
        return { data: '198.51.100.12\n' } as any
      }
      // other providers delay
      await new Promise((r) => setTimeout(r, 100))
      return { data: '{"ip":"198.51.100.12"}' } as any
    })

    const ip = await fetchPublicIp()
    expect(ip).toBe('198.51.100.12')
  })

  it('returns null when all providers fail', async () => {
    vi.mocked(axios.get).mockRejectedValue(new Error('Network unreachable'))

    const ip = await fetchPublicIp()
    expect(ip).toBeNull()
  })
})
