import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useAppStore } from '../store'
import '../styles/swiss.css'

export type SidebarPage = 'dashboard' | 'apps' | 'servers' | 'speedtest' | 'availability' | 'trafficHistory' | 'schedule' | 'logs' | 'settings' | 'maintenance'

interface SidebarProps {
  currentPage: string
  onNavigate: (page: SidebarPage) => void
}

type ConnectionStatus = 'connected' | 'disconnected' | 'connecting'

/** «Пломба» navigation: wordmark, numbered index, live status + clock. */
export function Sidebar({ currentPage, onNavigate }: SidebarProps) {
  const { t } = useTranslation()
  const tunRunning = useAppStore(s => s.tunRunning)
  const restartingProgress = useAppStore(s => s.restartingProgress)
  const detecting = useAppStore(s => s.detecting)
  const advancedMode = useAppStore(s => s.settings?.advancedMode === true)

  const connectionStatus: ConnectionStatus = (() => {
    if (tunRunning) return 'connected'
    if (restartingProgress !== null || detecting) return 'connecting'
    return 'disconnected'
  })()

  const navItems: Array<{ id: SidebarPage; label: string }> = [
    { id: 'dashboard', label: t('sidebar.dashboard') },
    { id: 'apps', label: t('sidebar.apps') },
    { id: 'servers', label: t('sidebar.servers') },
    { id: 'speedtest', label: t('sidebar.speedTest') },
    { id: 'availability', label: t('sidebar.availability', 'Доступность') },
    { id: 'trafficHistory', label: t('sidebar.trafficHistory') },
    { id: 'schedule', label: t('sidebar.schedule') },
    { id: 'logs', label: t('sidebar.logs') },
    { id: 'settings', label: t('sidebar.settings') },
    ...(advancedMode ? [{ id: 'maintenance' as const, label: t('sidebar.maintenance', 'Починка') }] : [])
  ]

  const statusLabels: Record<ConnectionStatus, string> = {
    connected: t('sidebar.statusConnected'),
    disconnected: t('sidebar.statusDisconnected'),
    connecting: t('sidebar.statusConnecting')
  }

  return (
    <aside className="c-swiss swiss-sidebar flex h-full shrink-0 flex-col border-r border-[var(--rule)] bg-[var(--paper)] p-5 text-[var(--ink)]">
      <div className="swiss-brand">
        Tunnel
        <br />
        Enforcer
      </div>
      <div className="swiss-mono mt-1.5 text-[10px] text-[var(--mute)]">windows / x64</div>

      <nav className="mt-10 flex flex-col">
        {navItems.map((item, i) => (
          <button
            key={item.id}
            type="button"
            onClick={() => onNavigate(item.id)}
            aria-current={item.id === currentPage ? 'page' : undefined}
            className="swiss-nav-item"
            data-perch={'nav-' + item.id}
            data-perch-x="0.8"
            data-perch-scale="0.4"
          >
            <span className="swiss-nav-num swiss-mono">{String(i + 1).padStart(2, '0')}</span>
            <span className="swiss-nav-label">{item.label}</span>
            <span className="swiss-nav-mark" aria-hidden="true" />
          </button>
        ))}
      </nav>

      <div className="mt-auto flex items-center gap-2 border-t border-[var(--rule)] pt-3" data-perch="clock" data-perch-x="0.55" data-perch-scale="0.5">
        <span
          aria-hidden="true"
          className={
            'h-2.5 w-2.5 shrink-0 ' +
            (connectionStatus === 'connected'
              ? 'bg-[var(--signal)]'
              : connectionStatus === 'connecting'
                ? 'blink bg-[var(--signal)]'
                : 'border-2 border-[var(--ink)]')
          }
        />
        <span className="swiss-mono min-w-0 truncate text-[11px] font-bold uppercase tracking-[0.06em]">{statusLabels[connectionStatus]}</span>
        <span className="swiss-mono ml-auto text-[11px] text-[var(--mute)]">
          <Clock />
        </span>
      </div>
    </aside>
  )
}

function Clock() {
  const [now, setNow] = useState(() => new Date())
  useEffect(() => {
    const id = window.setInterval(() => setNow(new Date()), 1000)
    return () => window.clearInterval(id)
  }, [])
  const hh = String(now.getHours()).padStart(2, '0')
  const mm = String(now.getMinutes()).padStart(2, '0')
  return (
    <span className="tabular-nums">
      {hh}
      <span className={now.getSeconds() % 2 ? 'opacity-30' : ''}>:</span>
      {mm}
    </span>
  )
}
