// AT-00-009/AT-12-002: production navigation has no planned-feature controls.
import '@testing-library/jest-dom/vitest'
import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { Sidebar } from './Sidebar'
import { useAppStore } from '../store'

vi.mock('react-i18next', () => ({ useTranslation: () => ({ t: (key: string) => key }) }))
afterEach(cleanup)

it.each([false, true])('hides WP-12 navigation with advancedMode=%s, including forged saved flags', advancedMode => {
  const settings = useAppStore.getState().settings
  useAppStore.setState({ settings: { ...settings, advancedMode,
    plannedFeatures: { mihomo: true, amneziawg: true, 'process-monitor': true, 'browser-boxes': true }
  } as typeof settings })
  try {
    const { container } = render(<Sidebar currentPage="dashboard" onNavigate={vi.fn()} />)
    expect(screen.getByText('sidebar.dashboard')).toBeVisible()
    expect(container.textContent).not.toMatch(/mihomo|amnezia|browser.box|process.monitor/i)
    expect(screen.getAllByRole('button')).toHaveLength(advancedMode ? 10 : 9)
  } finally { useAppStore.setState({ settings }) }
})
