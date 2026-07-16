import { afterEach, describe, expect, it, vi } from 'vitest'

const axiosGetMock = vi.hoisted(() => vi.fn())

vi.mock('axios', () => ({
  default: {
    get: axiosGetMock,
    isAxiosError: () => false
  }
}))

import {
  EXTERNAL_PROXY_HTTPS_CHECK_URL,
  EXTERNAL_PROXY_IP_CHECK_URL,
  EXTERNAL_PROXY_IP_CHECK_FALLBACK_URL,
  isRecoverableExternalProxyTransportError,
  probeExternalProxy
} from './externalProxyHealth'

afterEach(() => {
  axiosGetMock.mockReset()
})

describe('probeExternalProxy', () => {
  it('requires an IP result and a separate HTTPS request through the supplied proxy', async () => {
    axiosGetMock
      .mockResolvedValueOnce({ data: '{"ip":"198.51.100.77"}' })
      .mockResolvedValueOnce({ data: 'fl=1' })

    const result = await probeExternalProxy('http://127.0.0.1:17990')

    expect(result.egressIp).toBe('198.51.100.77')
    expect(result.latencyMs).toEqual(expect.any(Number))
    expect(axiosGetMock).toHaveBeenNthCalledWith(1, EXTERNAL_PROXY_IP_CHECK_URL, expect.objectContaining({
      proxy: { protocol: 'http', host: '127.0.0.1', port: 17990 }
    }))
    expect(axiosGetMock).toHaveBeenNthCalledWith(2, EXTERNAL_PROXY_HTTPS_CHECK_URL, expect.objectContaining({
      proxy: { protocol: 'http', host: '127.0.0.1', port: 17990 }
    }))
  })

  it('classifies timeout and EOF errors as restartable transport failures', () => {
    expect(isRecoverableExternalProxyTransportError(new Error('ConnectTimeout after 10000ms'))).toBe(true)
    expect(isRecoverableExternalProxyTransportError(new Error('EOF'))).toBe(true)
    expect(isRecoverableExternalProxyTransportError(new Error('HTTP 429'))).toBe(false)
  })

  it('uses the backup IP endpoint without treating one provider outage as a proxy outage', async () => {
    axiosGetMock
      .mockRejectedValueOnce(new Error('ipify unavailable'))
      .mockResolvedValueOnce({ data: 'fl=1' })
      .mockResolvedValueOnce({ data: '{"ip":"203.0.113.91"}' })

    const result = await probeExternalProxy('http://127.0.0.1:17990')

    expect(result.egressIp).toBe('203.0.113.91')
    expect(axiosGetMock).toHaveBeenCalledWith(EXTERNAL_PROXY_IP_CHECK_FALLBACK_URL, expect.any(Object))
  })
})
