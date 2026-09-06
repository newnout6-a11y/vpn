import '@testing-library/jest-dom/vitest'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import type { ConnectionLogEntry } from '../../shared/ipc-types'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (k: string, o?: Record<string, unknown>) =>
      k === 'logs.connections' ? 'Подключения' : typeof o?.count === 'number' ? `${o.count} ${k}` : k,
    i18n: { language: 'ru', changeLanguage: vi.fn() }
  })
}))
vi.mock('../components/PageTip', () => ({ PageTip: () => null }))

import { Logs } from './Logs'
import { useAppStore } from '../store'

const now = Date.now()
const ENTRIES: ConnectionLogEntry[] = [
  {
    id: 's1', startedAt: now - 3_600_000, endedAt: now - 60_000,
    profileName: 'netherlandsvless1', profileId: 'p1', mode: 'direct',
    bytesDown: 5_000_000, bytesUp: 900_000,
    disconnectReason: 'crash',
    errorMessage: 'Ядро VPN неожиданно завершилось',
    outcome: {
      kind: 'singbox-crash',
      headline: 'Ядро VPN (sing-box) неожиданно завершилось (код 1) после 3 попыток авто-перезапуска',
      evidence: { singboxExitCode: 1, autoRestartAttempts: 3, adaptiveMode: 'tls-compatibility', killSwitchEngaged: true }
    }
  },
  {
    id: 'f1', startedAt: now - 120_000, endedAt: now - 120_000,
    profileName: 'germanyvless1', profileId: 'p2', mode: 'direct',
    bytesDown: 0, bytesUp: 0,
    disconnectReason: 'error',
    errorMessage: 'Нет выбранного сервера',
    outcome: { kind: 'start-failed', headline: 'Не удалось запустить: Нет выбранного сервера', evidence: { hint: 'Нет выбранного сервера' } }
  },
  {
    id: 'legacy1', startedAt: now - 7_200_000, endedAt: now - 6_000_000,
    profileName: 'oldserver', profileId: 'p3', mode: 'hard',
    bytesDown: 1000, bytesUp: 1000,
    disconnectReason: 'user'
  }
]

beforeEach(() => {
  useAppStore.setState({ logs: [], globalToasts: [] as any })
  ;(globalThis as any).window.electronAPI = {
    connectionHistoryList: vi.fn().mockResolvedValue(ENTRIES),
    connectionHistoryFilter: vi.fn().mockResolvedValue(ENTRIES),
    connectionHistoryStats: vi.fn().mockResolvedValue({
      totalTimeMs: 3_600_000, totalBytesDown: 5_001_000, totalBytesUp: 901_000, entryCount: 2
    }),
    getFullLogs: vi.fn().mockResolvedValue([])
  }
})
afterEach(() => {
  cleanup()
  vi.clearAllMocks()
})

describe('<Logs/> connection history outcomes', () => {
  it('splits real sessions from start failures', async () => {
    render(<Logs />)
    await screen.findByText('netherlandsvless1')

    // real sessions table shows the crash + the legacy row, not the start failure
    expect(screen.getByText('netherlandsvless1')).toBeInTheDocument()
    expect(screen.getByText('oldserver')).toBeInTheDocument()
    expect(screen.queryByText('germanyvless1')).not.toBeInTheDocument()

    // start-failures section is collapsed but present
    expect(screen.getByText('logs.startFailuresTitle')).toBeInTheDocument()
  })

  it('shows an outcome chip and expands a row to the evidence detail', async () => {
    render(<Logs />)
    const row = (await screen.findByText('netherlandsvless1')).closest('tr')!

    // chip label
    expect(within(row).getByText('logs.outcome.singbox-crash')).toBeInTheDocument()

    // not expanded yet
    expect(screen.queryByText(/после 3 попыток/)).not.toBeInTheDocument()

    fireEvent.click(row)

    await waitFor(() => expect(screen.getByText(/после 3 попыток/)).toBeInTheDocument())
    // evidence rows rendered
    expect(screen.getByText('logs.outcomeEvidence.singboxExitCode')).toBeInTheDocument()
    expect(screen.getByText('logs.outcomeEvidence.autoRestartAttempts')).toBeInTheDocument()
    expect(screen.getByText('logs.copyDiagnostics')).toBeInTheDocument()
  })

  it('reveals start failures when the section is toggled', async () => {
    render(<Logs />)
    await screen.findByText('netherlandsvless1')

    fireEvent.click(screen.getByText('logs.startFailuresTitle'))
    await waitFor(() => expect(screen.getByText('germanyvless1')).toBeInTheDocument())
    expect(screen.getByText('Не удалось запустить: Нет выбранного сервера')).toBeInTheDocument()
  })

  it('falls back to the legacy reason label for rows with no structured outcome', async () => {
    render(<Logs />)
    const row = (await screen.findByText('oldserver')).closest('tr')!
    expect(within(row).getByText('logs.outcome.user-stop')).toBeInTheDocument()
  })
})
