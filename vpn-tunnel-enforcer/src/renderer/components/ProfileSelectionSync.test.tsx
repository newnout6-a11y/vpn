// AT-00-003/007/008, F-019/F-021: rendered pickers follow terminal backend truth.
import '@testing-library/jest-dom/vitest'
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { ElectronAPI } from '../../shared/electron-api'
import type { ServerProfile } from '../../shared/ipc-types'
import { ProfileSelectorInline } from './ProfileSelectorInline'
import { DashboardSide } from './DashboardSide'
import { Servers } from '../pages/Servers'
import { emitServerChanged } from '../nav'
import { useAppStore } from '../store'

vi.mock('react-i18next', () => ({ useTranslation: () => ({
  t: (key: string, fallback?: unknown) => typeof fallback === 'string' ? fallback : key,
  i18n: { language: 'ru' }
}) }))
vi.mock('./CountryFlagIcon', () => ({ CountryFlagIcon: () => null }))
vi.mock('./ForeignVpnBanner', () => ({ ForeignVpnBanner: () => null }))
vi.mock('./ServerDetailModal', () => ({ ServerDetailModal: () => null }))
vi.mock('./LiveServerBatchComparison', () => ({ LiveServerBatchComparison: () => null }))

function deferred<T>() {
  let resolve!: (value: T) => void, reject!: (reason: Error) => void
  const promise = new Promise<T>((ok, fail) => { resolve = ok; reject = fail })
  return { promise, resolve, reject }
}
const group = { id: 'manual', name: 'Manual', source: 'manual', status: 'active', importedAt: 1 }
const profiles: ServerProfile[] = ['Sweden', 'Norway'].map(name => ({
  id: name, name, protocol: 'vless', server: 'fixture.example', port: 443, status: 'unknown', groupId: group.id
}))
let activeId: string | null
beforeEach(() => {
  localStorage.clear()
  activeId = 'Sweden'
  vi.spyOn(window, 'scrollTo').mockImplementation(() => undefined)
  useAppStore.setState({ tunRunning: true, mode: 'hard', connectionBusy: null,
    serverSwitchingName: null, connectionCancelling: false, restartingProgress: null,
    logs: [], globalToasts: [], settings: { ...useAppStore.getState().settings, connectionMode: 'directVpn' } })
  window.electronAPI = {
    serversList: vi.fn(async () => profiles), serversGetActive: vi.fn(async () => ({ activeId })),
    serversSelect: vi.fn(async () => undefined), groupsList: vi.fn(async () => [group]),
    trafficHistoryList: vi.fn(async () => []), logRenderer: vi.fn(async () => undefined)
  } as unknown as ElectronAPI
})
afterEach(() => { cleanup(); vi.restoreAllMocks() })

const surfaces = ['inline', 'sidebar', 'servers'] as const
type Surface = typeof surfaces[number]
function draw(surface: Surface) { render(surface === 'inline' ? <ProfileSelectorInline /> : surface === 'sidebar' ? <DashboardSide /> : <Servers />) }
function current(surface: Surface, name: string) {
  if (surface === 'inline') expect(screen.getByRole('button', { name: /Текущий профиль/ })).toHaveTextContent(name)
  else if (surface === 'sidebar') expect(screen.getByRole('button', { name: new RegExp(`^${name}`), pressed: true })).toBeInTheDocument()
  else expect(within(screen.getByRole('group', { name })).getByRole('button', { pressed: true })).toBeInTheDocument()
}
async function select(surface: Surface) {
  if (surface === 'inline') fireEvent.click(await screen.findByRole('button', { name: /Текущий профиль/ }))
  const button = surface === 'servers'
    ? within(await screen.findByRole('group', { name: 'Norway' })).getByRole('button', { name: 'servers.select' })
    : await screen.findByRole('button', { name: /^Norway/ })
  await act(async () => fireEvent.click(button))
}

describe.each(surfaces)('%s authoritative profile selection', surface => {
  it.each(['success', 'cancelled', 'failure'] as const)('keeps old selection during staging and refreshes terminal %s', async outcome => {
    const held = deferred<void | { cancelled: true }>()
    vi.mocked(window.electronAPI.serversSelect).mockReturnValueOnce(held.promise)
    draw(surface)
    await waitFor(() => current(surface, 'Sweden'))
    await select(surface)
    expect(useAppStore.getState().serverSwitchingName).toBe('Norway')
    // The backend's tentative selection is not a committed upstream.
    activeId = 'Norway'
    await act(async () => emitServerChanged())
    current(surface, 'Sweden')
    await act(async () => {
      if (outcome === 'failure') held.reject(new Error('Restoration unavailable'))
      else if (outcome === 'cancelled') { activeId = 'Sweden'; held.resolve({ cancelled: true }) }
      else held.resolve()
    })
    await waitFor(() => current(surface, outcome === 'cancelled' ? 'Sweden' : 'Norway'))
    expect(useAppStore.getState().serverSwitchingName).toBeNull()
    expect(useAppStore.getState().logs.some(log => log.message.includes('Переподключаемся'))).toBe(false)
    expect(useAppStore.getState().globalToasts.some(toast => toast.title === 'Переподключение')).toBe(false)
    if (surface === 'servers') expect(useAppStore.getState().globalToasts.some(toast => toast.variant === 'error')).toBe(outcome === 'failure')
    else expect(useAppStore.getState().logs.some(log => log.level === 'error')).toBe(outcome === 'failure')
  })

  it('ignores an older active-profile response after a newer refresh completed', async () => {
    draw(surface)
    await waitFor(() => current(surface, 'Sweden'))
    const stale = deferred<{ activeId: string; profile: ServerProfile | null }>()
    vi.mocked(window.electronAPI.serversGetActive).mockReturnValueOnce(stale.promise)
    await act(async () => emitServerChanged())
    activeId = 'Norway'
    await act(async () => emitServerChanged())
    await waitFor(() => current(surface, 'Norway'))
    await act(async () => stale.resolve({ activeId: 'Sweden', profile: null }))
    current(surface, 'Norway')
  })

  it('releases switching state before a slow list refresh finishes', async () => {
    draw(surface)
    await waitFor(() => current(surface, 'Sweden'))
    const slow = deferred<typeof profiles>()
    vi.mocked(window.electronAPI.serversSelect).mockImplementationOnce(async () => {
      activeId = 'Norway'
      vi.mocked(window.electronAPI.serversList).mockReturnValueOnce(slow.promise)
    })
    await select(surface)
    await waitFor(() => current(surface, 'Norway'))
    expect(useAppStore.getState().serverSwitchingName).toBeNull()
    await act(async () => slow.resolve(profiles))
  })
})

it('does not label the first saved profile selected when backend has no selection', async () => {
  activeId = null
  render(<ProfileSelectorInline />)
  await waitFor(() => expect(window.electronAPI.serversList).toHaveBeenCalled())
  expect(screen.getByRole('button', { name: /Текущий профиль/ })).toHaveTextContent('Профиль не выбран')
})

it('synchronizes other mounted pickers after a failed selection with a committed backend candidate', async () => {
  const held = deferred<void | { cancelled: true }>()
  vi.mocked(window.electronAPI.serversSelect).mockReturnValueOnce(held.promise)
  render(<><div data-testid="inline"><ProfileSelectorInline /></div><div data-testid="sidebar"><DashboardSide /></div></>)
  const inline = within(screen.getByTestId('inline')), sidebar = within(screen.getByTestId('sidebar'))
  await waitFor(() => expect(sidebar.getByRole('button', { name: /^Sweden/, pressed: true })).toBeInTheDocument())
  fireEvent.click(inline.getByRole('button', { name: /Текущий профиль/ }))
  fireEvent.click(await inline.findByRole('button', { name: /^Norway/ }))
  activeId = 'Norway'
  await act(async () => held.reject(new Error('Previous slot cleanup unavailable')))
  await waitFor(() => expect(sidebar.getByRole('button', { name: /^Norway/, pressed: true })).toBeInTheDocument())
  expect(inline.getByRole('button', { name: /Текущий профиль/ })).toHaveTextContent('Norway')
  expect(useAppStore.getState().serverSwitchingName).toBeNull()
})
