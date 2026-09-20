import '@testing-library/jest-dom/vitest'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { LiveServerCheckSection } from './LiveServerCheckSection'
import type { LiveServerCheck } from '../../shared/ipc-types'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (_key: string, fallback?: string) => fallback || _key
  })
}))

const mockCheckResult: LiveServerCheck = {
  id: 'live-test-1',
  profileId: 'prof-123',
  host: 'vpn.mock.net',
  port: 443,
  mode: 'basic',
  startedAt: '2026-09-20T11:00:00.000Z',
  finishedAt: '2026-09-20T11:00:01.200Z',
  durationMs: 1200,
  dns: {
    status: 'ok',
    durationMs: 45,
    a: ['104.21.5.1'],
    aaaa: ['2606:4700::1'],
    cnameChain: ['edge.cf.com'],
    ttl: 300
  },
  reachability: {
    status: 'ok',
    durationMs: 80,
    tcpReachable: true,
    port: 443
  },
  latency: {
    min: 30,
    avg: 35,
    median: 34,
    max: 42,
    jitter: 4,
    loss: 0,
    samples: [30, 34, 35, 38, 42],
    samplesAttempted: 5,
    method: 'tcp'
  },
  tls: {
    status: 'ok',
    durationMs: 65,
    subject: 'vpn.mock.net',
    issuer: "Let's Encrypt",
    validFrom: '2026-01-01',
    validTo: '2026-12-31',
    daysRemaining: 102,
    hostnameVerified: true,
    protocol: 'TLSv1.3',
    cipher: 'TLS_AES_256_GCM_SHA384',
    fingerprint: '11:22:33:44:55:66'
  },
  http: {
    status: 'ok',
    durationMs: 70,
    statusCode: 200,
    serverHeader: 'cloudflare',
    confidence: 'low'
  },
  openPorts: [
    { port: 443, open: true, state: 'open', service: 'HTTPS' }
  ],
  findings: [
    {
      code: 'DNS_MULTI_IP',
      severity: 'info',
      title: 'Несколько IP-адресов в DNS',
      detail: 'Хост резолвится в 2 адреса'
    }
  ]
}

describe('<LiveServerCheckSection />', () => {
  beforeEach(() => {
    ;(globalThis as any).window.electronAPI = {
      serverLiveCheck: vi.fn().mockResolvedValue(mockCheckResult),
      serverLiveCheckCancel: vi.fn().mockResolvedValue({ cancelled: true }),
      serverLiveCheckHistory: vi.fn().mockResolvedValue([mockCheckResult])
    }
  })

  afterEach(() => {
    cleanup()
    vi.clearAllMocks()
  })

  it('renders title and mode switchers', async () => {
    render(<LiveServerCheckSection profileId="prof-123" host="vpn.mock.net" port={443} />)

    await waitFor(() => {
      expect(window.electronAPI.serverLiveCheckHistory).toHaveBeenCalled()
    })

    expect(screen.getByText('Live-проверка и аудит endpoint')).toBeInTheDocument()
    expect(screen.getByText('Базовая')).toBeInTheDocument()
    expect(screen.getByText('Расширенная')).toBeInTheDocument()
    expect(screen.getByText('Проверить')).toBeInTheDocument()
  })

  it('toggles between basic and extended mode', async () => {
    render(<LiveServerCheckSection profileId="prof-123" host="vpn.mock.net" port={443} />)

    await waitFor(() => {
      expect(window.electronAPI.serverLiveCheckHistory).toHaveBeenCalled()
    })

    const extendedBtn = screen.getByText('Расширенная')
    fireEvent.click(extendedBtn)

    expect(
      screen.getByText(/Расширенная проверка выполняет зондирование портов/i)
    ).toBeInTheDocument()
  })

  it('runs live check on button click and displays findings and diagnostic blocks', async () => {
    render(<LiveServerCheckSection profileId="prof-123" host="vpn.mock.net" port={443} />)

    await waitFor(() => {
      expect(window.electronAPI.serverLiveCheckHistory).toHaveBeenCalled()
    })

    const checkBtn = screen.getByText('Проверить')
    fireEvent.click(checkBtn)

    await waitFor(() => {
      expect(window.electronAPI.serverLiveCheck).toHaveBeenCalledWith({
        profileId: 'prof-123',
        host: 'vpn.mock.net',
        port: 443,
        mode: 'basic'
      })
    })

    await waitFor(() => {
      expect(screen.getByText('Endpoint отвечает по TCP')).toBeInTheDocument()
      expect(screen.getByText('Несколько IP-адресов в DNS')).toBeInTheDocument()
      expect(screen.getByText('DNS_MULTI_IP')).toBeInTheDocument()
      expect(screen.getByText('104.21.5.1')).toBeInTheDocument()
      expect(screen.getByText('35 ms')).toBeInTheDocument()
      expect(screen.getByText('TLS Сертификат')).toBeInTheDocument()
    })
  })

  it('allows toggling check history', async () => {
    render(<LiveServerCheckSection profileId="prof-123" host="vpn.mock.net" port={443} />)

    // Wait for history to load
    await waitFor(() => {
      expect(window.electronAPI.serverLiveCheckHistory).toHaveBeenCalled()
    })

    // History button shows count
    const historyBtn = await screen.findByTitle('История проверок')
    expect(historyBtn).toBeInTheDocument()

    fireEvent.click(historyBtn)

    expect(screen.getByText('Недавние проверки (до 20)')).toBeInTheDocument()
  })
})
