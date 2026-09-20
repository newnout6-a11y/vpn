import '@testing-library/jest-dom/vitest'
import { describe, it, expect, vi, afterEach } from 'vitest'
import { render, fireEvent, screen, waitFor, cleanup, act } from '@testing-library/react'
import { LiveServerCheckSection } from './LiveServerCheckSection'
import type { LiveServerCheck } from '../../shared/ipc-types'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (_key: string, fallback?: string) => fallback || _key })
}))

afterEach(cleanup)

const makeMockCheck = (id: string, ip: string, extras?: Partial<LiveServerCheck>): LiveServerCheck => ({
  id,
  profileId: 'p1',
  host: 'audit.invalid',
  port: 443,
  mode: 'basic',
  startedAt: '2026-09-20T10:00:00Z',
  finishedAt: '2026-09-20T10:00:01Z',
  durationMs: 1000,
  dns: { status: 'ok', durationMs: 10, a: [ip], aaaa: [], cnameChain: [] },
  reachability: { status: 'ok', durationMs: 15, port: 443, tcpReachable: true },
  findings: [],
  ...extras
})

describe('LiveServerCheckSection UI Regressions', () => {
  // Defect 2: Old cancelled or slow request must NOT overwrite newer results
  it('Defect 2: an old cancelled request does not overwrite the newer result', async () => {
    let resolveOld!: (value: any) => void
    let resolveNew!: (value: any) => void

    const api = {
      serverLiveCheckHistory: vi.fn().mockResolvedValue([]),
      serverLiveCheckCancel: vi.fn().mockResolvedValue({ cancelled: true }),
      serverLiveCheck: vi.fn()
        .mockImplementationOnce(() => new Promise((r) => { resolveOld = r }))
        .mockImplementationOnce(() => new Promise((r) => { resolveNew = r }))
    }
    ;(window as any).electronAPI = api

    render(<LiveServerCheckSection profileId="p1" host="audit.invalid" port={443} />)
    await act(async () => {})

    // Start 1st check
    fireEvent.click(screen.getByText('Проверить'))

    // Cancel 1st check
    fireEvent.click(screen.getByText('Отмена'))
    await waitFor(() => expect(screen.getByText('Проверить')).toBeInTheDocument())

    // Start 2nd check
    fireEvent.click(screen.getByText('Проверить'))

    // Resolve 2nd check with 192.0.2.2
    await act(async () => {
      resolveNew(makeMockCheck('uuid-2', '192.0.2.2'))
    })
    expect(screen.getByText('192.0.2.2')).toBeInTheDocument()

    // Old 1st check belatedly resolves with 192.0.2.1
    await act(async () => {
      resolveOld(makeMockCheck('uuid-1', '192.0.2.1'))
    })

    // The newer result (192.0.2.2) MUST NOT be overwritten!
    expect(screen.getByText('192.0.2.2')).toBeInTheDocument()
    expect(screen.queryByText('192.0.2.1')).not.toBeInTheDocument()
  })

  // Defect 3: History items retain distinct IDs and do not collapse to 1 entry
  it('Defect 3: successive runs create distinct history items and increment history counter', async () => {
    const check1 = makeMockCheck('uuid-1', '192.0.2.1')
    const check2 = makeMockCheck('uuid-2', '192.0.2.2')

    ;(window as any).electronAPI = {
      serverLiveCheckHistory: vi.fn().mockResolvedValue([check1]),
      serverLiveCheck: vi.fn().mockResolvedValue(check2),
      serverLiveCheckCancel: vi.fn()
    }

    render(<LiveServerCheckSection profileId="p1" host="audit.invalid" port={443} />)
    await screen.findByText('192.0.2.1')

    // Click check to run check 2
    fireEvent.click(screen.getByText('Проверить'))
    await screen.findByText('192.0.2.2')

    // History button should now reflect 2 checks, not 1
    const historyBtn = screen.getByTitle('История проверок')
    expect(historyBtn).toHaveTextContent('2')
  })

  // Defect 8: Route diagnostics block is rendered in UI
  it('Defect 8: displays route diagnostics card when route hops are present', async () => {
    const checkWithRoute = makeMockCheck('uuid-route', '192.0.2.10', {
      route: {
        status: 'ok',
        durationMs: 120,
        hops: 2,
        reachedTarget: true,
        hopDetails: [
          '1    2 ms    2 ms    2 ms  10.0.0.1',
          '2   15 ms   15 ms   15 ms  192.0.2.10'
        ]
      }
    })

    ;(window as any).electronAPI = {
      serverLiveCheckHistory: vi.fn().mockResolvedValue([]),
      serverLiveCheck: vi.fn().mockResolvedValue(checkWithRoute),
      serverLiveCheckCancel: vi.fn()
    }

    render(<LiveServerCheckSection profileId="p1" host="audit.invalid" port={443} />)
    await act(async () => {})

    fireEvent.click(screen.getByText('Проверить'))
    await screen.findByText('192.0.2.10')

    // Must render the route card
    expect(screen.getByText('Маршрут до endpoint')).toBeInTheDocument()
    expect(screen.getByText(/10\.0\.0\.1/)).toBeInTheDocument()
    expect(screen.getByText('Достигнут')).toBeInTheDocument()
  })

  // Defect 9: TCP connect failure rate is correctly displayed and labeled
  it('Defect 9: displays TCP connection failure rate metric accurately', async () => {
    const checkWithLatency = makeMockCheck('uuid-lat', '192.0.2.20', {
      latency: {
        avg: 45,
        min: 40,
        median: 44,
        max: 52,
        jitter: 3,
        loss: 0.2,
        connectionFailureRate: 0.2,
        samples: [40, 42, 45, 52],
        samplesAttempted: 5,
        samplesSucceeded: 4,
        pathType: 'direct',
        method: 'tcp'
      }
    })

    ;(window as any).electronAPI = {
      serverLiveCheckHistory: vi.fn().mockResolvedValue([]),
      serverLiveCheck: vi.fn().mockResolvedValue(checkWithLatency),
      serverLiveCheckCancel: vi.fn()
    }

    render(<LiveServerCheckSection profileId="p1" host="audit.invalid" port={443} />)
    await act(async () => {})

    fireEvent.click(screen.getByText('Проверить'))
    await screen.findByText('192.0.2.20')

    // Must display connection failure rate, not misleading generic packet loss
    expect(screen.getByText('Отказы TCP соединений:')).toBeInTheDocument()
    expect(screen.getByText('20% (1/5)')).toBeInTheDocument()
    expect(screen.getByText(/Маршрут выбран ОС/i)).toBeInTheDocument()
  })
})

it('Second review: failed history load for B clears A and offers retry', async () => {
  const oldCheck = makeMockCheck('old-profile-a', '192.0.2.1')
  ;(window as any).electronAPI = {
    serverLiveCheckHistory: vi.fn().mockResolvedValueOnce([oldCheck]).mockRejectedValueOnce(new Error('B history failed')),
    serverLiveCheckCancel: vi.fn().mockResolvedValue({ cancelled: true }), serverLiveCheck: vi.fn()
  }
  const view = render(<LiveServerCheckSection profileId="p1" host="a.example" port={443} />)
  await screen.findByText('192.0.2.1')
  view.rerender(<LiveServerCheckSection profileId="p2" host="b.example" port={443} />)
  await act(async () => {})
  expect(screen.queryByText('192.0.2.1')).not.toBeInTheDocument()
  expect(screen.queryByTitle('История проверок')).not.toBeInTheDocument()
  expect(screen.getByText('Повторить загрузку истории')).toBeInTheDocument()
})

it('sanitizes traceroute hops with OEM replacement characters to standard ms in UI', async () => {
  const checkWithCorruptedHops = makeMockCheck('uuid-corrupt-hops', '13.143.252.2', {
    route: {
      status: 'ok',
      durationMs: 36,
      hops: 1,
      reachedTarget: true,
      hopDetails: [
        '1  <1 \uFFFD\uFFFD  <1 \uFFFD\uFFFD  <1 \uFFFD\uFFFD  13.143.252.2'
      ]
    }
  })

  ;(window as any).electronAPI = {
    serverLiveCheckHistory: vi.fn().mockResolvedValue([checkWithCorruptedHops]),
    serverLiveCheck: vi.fn().mockResolvedValue(checkWithCorruptedHops),
    serverLiveCheckCancel: vi.fn()
  }

  render(<LiveServerCheckSection profileId="p-corrupt" host="corrupt.test" port={443} />)
  await screen.findByText('13.143.252.2')

  // The hop must be sanitized without replacement character diamonds
  expect(screen.getByText('1 <1 ms <1 ms <1 ms 13.143.252.2')).toBeInTheDocument()
  expect(screen.queryByText(/\uFFFD/)).not.toBeInTheDocument()
})

it('formats raw 429 status error into user-friendly localized message in UI banner', async () => {
  const checkWith429 = makeMockCheck('uuid-429', '13.143.252.2', {
    infrastructure: {
      status: 'error',
      error: 'Request failed with status code 429',
      endpointCountry: 'Japan'
    }
  })

  ;(window as any).electronAPI = {
    serverLiveCheckHistory: vi.fn().mockResolvedValue([checkWith429]),
    serverLiveCheck: vi.fn().mockResolvedValue(checkWith429),
    serverLiveCheckCancel: vi.fn()
  }

  render(<LiveServerCheckSection profileId="p-429" host="rate-limited.test" port={443} />)
  await screen.findByText('13.143.252.2')

  // The raw 429 message must NOT appear
  expect(screen.queryByText('Request failed with status code 429')).not.toBeInTheDocument()
  // The clean localized banner MUST appear
  expect(
    screen.getByText('Превышен лимит запросов к сервису геолокации (429). Повторите попытку позже.')
  ).toBeInTheDocument()
})

