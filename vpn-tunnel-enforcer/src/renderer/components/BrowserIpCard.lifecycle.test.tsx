import '@testing-library/jest-dom/vitest'
import { it, expect, vi, afterEach } from 'vitest'
import { render, fireEvent, screen, waitFor, act, cleanup } from '@testing-library/react'
import { BrowserIpCard, summarize, isPrivateIp, unwrapIpv4Mapped } from './BrowserIpCard'
import { useAppStore } from '../store'
afterEach(() => { cleanup(); vi.unstubAllGlobals() })
it('normalizes mapped form of expected public IPv4', () => {
  const result = summarize({ browserIpv4: '8.8.8.8', browserIpv6: null, nodeIp: '8.8.8.8',
    webRtcCandidates: [{ address: '::ffff:8.8.8.8', type: 'srflx', protocol: 'udp' }], webRtcError: null, tunRunning: true })
  expect(result.summary).toBe('ok')
  expect(result.details.some(d => d.includes('другие публичные'))).toBe(false)
})
it('recognizes alternative valid compressed IPv4-mapped representation', () => {
  expect(isPrivateIp('0::ffff:c0a8:010a')).toBe(true)
})
it('old unmounted check cannot overwrite new component result', async () => {
  let resolveOld!: Function
  let calls = 0
  vi.stubGlobal('RTCPeerConnection', undefined)
  vi.stubGlobal('fetch', vi.fn(async (url: string) => ({ ok: true, json: async () => ({ ip: url.includes('api6.') ? null : (++calls === 1 ? '8.8.8.8' : '8.8.4.4') }) })))
  ;(window as any).electronAPI = { getPublicIp: vi.fn()
    .mockImplementationOnce(() => new Promise(r => { resolveOld = r }))
    .mockResolvedValueOnce({ ip: '8.8.4.4' }) }
  useAppStore.setState({ browserIpCheck: null, publicIp: null, tunRunning: true, logs: [] })
  const old = render(<BrowserIpCard />)
  fireEvent.click(screen.getByText('Проверить браузер'))
  await act(async () => {})
  old.unmount()
  render(<BrowserIpCard />)
  fireEvent.click(screen.getByText('Проверить браузер'))
  await waitFor(() => expect(useAppStore.getState().browserIpCheck?.browserIpv4).toBe('8.8.4.4'))
  await act(async () => { resolveOld({ ip: '8.8.8.8' }) })
  expect(useAppStore.getState().browserIpCheck?.browserIpv4).toBe('8.8.4.4')
})

it('normalizes native IPv6 and ignores malformed IP candidates', () => {
  expect(unwrapIpv4Mapped('2001:0DB8:0000:0:0:0:0:0001')).toBe(unwrapIpv4Mapped('2001:db8::1'))
  expect(isPrivateIp('febf::1')).toBe(true)
  expect(isPrivateIp('fc.invalid')).toBe(false)
  const result = summarize({ browserIpv4: '8.8.8.8', browserIpv6: null, nodeIp: '8.8.8.8',
    webRtcCandidates: [{ address: '999.1.2.3', type: 'host', protocol: 'udp' }], webRtcError: null, tunRunning: true })
  expect(result.webRtcPublicIps).toEqual([])
})
