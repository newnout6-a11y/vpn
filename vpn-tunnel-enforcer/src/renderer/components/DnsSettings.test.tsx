import '@testing-library/jest-dom/vitest'
import { afterEach, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { DnsSettings } from './DnsSettings'
vi.mock('react-i18next', () => ({ useTranslation: () => ({ t: (key: string) => key }) }))
afterEach(cleanup)
const profiles = [
  { id: 'a', name: 'A', primary: '1.1.1.1', type: 'plain', isBuiltin: true },
  { id: 'b', name: 'B', primary: '8.8.8.8', type: 'plain', isBuiltin: true, isSelected: true }
]
it('restores persisted selection and preserves it after rejected switch', async () => {
  ;(window as any).electronAPI = { dnsList: vi.fn().mockResolvedValue(profiles), dnsGetActive: vi.fn().mockResolvedValue('b'), dnsSelect: vi.fn().mockRejectedValue(new Error('denied')) }
  const view = render(<DnsSettings />)
  await waitFor(() => expect(screen.getByRole('radio', { name: 'B' })).toHaveAttribute('aria-checked', 'true'))
  fireEvent.click(screen.getByRole('radio', { name: 'A' }))
  expect(await screen.findByRole('alert')).toHaveTextContent('Не удалось переключить')
  await waitFor(() => expect(screen.getByRole('radio', { name: 'B' })).toHaveAttribute('aria-disabled', 'false'))
  expect(screen.getByRole('radio', { name: 'B' })).toHaveAttribute('aria-checked', 'true')
  view.unmount()
  render(<DnsSettings />)
  await waitFor(() => expect(screen.getByRole('radio', { name: 'B' })).toHaveAttribute('aria-checked', 'true'))
})
it('uses selected list fallback when active IPC fails', async () => {
  ;(window as any).electronAPI = { dnsList: vi.fn().mockResolvedValue(profiles), dnsGetActive: vi.fn().mockRejectedValue(new Error('offline')) }
  render(<DnsSettings />)
  await waitFor(() => expect(screen.getByRole('radio', { name: 'B' })).toHaveAttribute('aria-checked', 'true'))
})
it('respects explicit null active profile over stale list flag', async () => {
  ;(window as any).electronAPI = { dnsList: vi.fn().mockResolvedValue(profiles), dnsGetActive: vi.fn().mockResolvedValue(null) }
  render(<DnsSettings />)
  await screen.findAllByRole('radio')
  expect(screen.getAllByRole('radio').every(element => element.getAttribute('aria-checked') === 'false')).toBe(true)
})
