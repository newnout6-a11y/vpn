import { describe, expect, it, vi, beforeEach } from 'vitest'
import * as dns from 'dns'

const { mockResolve4, mockResolve6, mockReverse } = vi.hoisted(() => ({
  mockResolve4: vi.fn(),
  mockResolve6: vi.fn(),
  mockReverse: vi.fn()
}))

vi.mock('dns', async (importOriginal) => {
  const actual = await importOriginal<typeof import('dns')>()
  const promises = {
    ...actual.promises,
    resolve4: mockResolve4,
    resolve6: mockResolve6,
    reverse: mockReverse
  }
  return {
    ...actual,
    default: { ...actual, promises },
    promises
  }
})

vi.mock('axios', () => ({
  default: { get: vi.fn() },
  get: vi.fn()
}))

import { resolveHost } from './serverProbe'

describe('serverProbe resolveHost', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('recognizes pure IPv4 address immediately without DNS lookup', async () => {
    const res = await resolveHost('192.168.1.1')
    expect(res).toEqual(['192.168.1.1'])
    expect(mockResolve4).not.toHaveBeenCalled()
    expect(mockResolve6).not.toHaveBeenCalled()
  })

  it('recognizes pure IPv6 address immediately without DNS lookup', async () => {
    const res = await resolveHost('2001:db8::1')
    expect(res).toEqual(['2001:db8::1'])
    expect(mockResolve4).not.toHaveBeenCalled()
    expect(mockResolve6).not.toHaveBeenCalled()
  })

  it('handles bracketed IPv6 with port without breaking', async () => {
    const res = await resolveHost('[2606:4700:4700::1111]:8443')
    expect(res).toEqual(['2606:4700:4700::1111'])
    expect(mockResolve4).not.toHaveBeenCalled()
    expect(mockResolve6).not.toHaveBeenCalled()
  })

  it('strips port from domain:port and resolves DNS correctly', async () => {
    mockResolve4.mockResolvedValueOnce(['104.21.5.10'])
    mockResolve6.mockResolvedValueOnce(['2606:4700::104'])

    const res = await resolveHost('vpn.example.com:8443')
    expect(mockResolve4).toHaveBeenCalledWith('vpn.example.com')
    expect(mockResolve6).toHaveBeenCalledWith('vpn.example.com')
    expect(res).toEqual(['104.21.5.10', '2606:4700::104'])
  })

  it('handles standard domain name resolution', async () => {
    mockResolve4.mockResolvedValueOnce(['1.2.3.4'])
    mockResolve6.mockResolvedValueOnce([])

    const res = await resolveHost('server.myvpn.org')
    expect(mockResolve4).toHaveBeenCalledWith('server.myvpn.org')
    expect(res).toEqual(['1.2.3.4'])
  })
})
