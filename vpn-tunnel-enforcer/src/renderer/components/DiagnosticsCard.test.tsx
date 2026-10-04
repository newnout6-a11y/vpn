// AT-08-004/005, F-198: unknown provider cleanup must not be advertised as stopped.
import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { ReactNode } from 'react'
const fixture = vi.hoisted(() => ({ status: vi.fn() }))
vi.mock('../store', () => ({ useAppStore: (select: (state: any) => unknown) => select({
  leakSelfTestResult: null, lastMainError: null, exportingDiagnostics: false,
  addLog: vi.fn(), setLeakSelfTestResult: vi.fn(), setExportingDiagnostics: vi.fn()
}) }))
vi.mock('../design-system', () => ({
  MacCard: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  MacButton: ({ children, onClick, disabled }: { children: ReactNode; onClick: () => void; disabled?: boolean }) => <button onClick={onClick} disabled={disabled}>{children}</button>
}))
import { DiagnosticsCard } from './DiagnosticsCard'
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

describe('capture cleanup visibility', () => {
  it('shows unknown cleanup when the status request itself fails', async () => {
    fixture.status.mockRejectedValue(new Error('inspection failed'))
    const previous = window.electronAPI
    Object.assign(window, { electronAPI: { getTrafficForensicsStatus: fixture.status } })
    try {
      render(<DiagnosticsCard />)
      expect(await screen.findByText('ОСТАНОВКА НЕ ПОДТВЕРЖДЕНА')).toBeTruthy()
      expect(screen.getByRole('alert').textContent).toContain('Не удалось проверить состояние захвата')
      expect(screen.queryByText('СБОР ОСТАНОВЛЕН')).toBeNull()
    } finally { Object.assign(window, { electronAPI: previous }) }
  })
  it.each([true, false])('shows unconfirmed cleanup instead of success when running=%s', async running => {
    fixture.status.mockResolvedValue({ running, enabled: false, cleanupPending: true, lastError: 'Capture stop remains unconfirmed', health: {} })
    const api = { getTrafficForensicsStatus: fixture.status }
    const previous = window.electronAPI
    Object.assign(window, { electronAPI: api })
    try {
      render(<DiagnosticsCard />)
      expect(await screen.findByText('ОСТАНОВКА НЕ ПОДТВЕРЖДЕНА')).toBeTruthy()
      expect(screen.getByRole('alert').textContent).toContain('Capture stop remains unconfirmed')
      expect(screen.queryByText('СБОР ОСТАНОВЛЕН')).toBeNull()
    } finally { Object.assign(window, { electronAPI: previous }) }
  })
})
