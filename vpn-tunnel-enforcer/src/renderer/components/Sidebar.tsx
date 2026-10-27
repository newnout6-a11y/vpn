import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { cn } from '../design-system/utils'
import { useAppStore } from '../store'
import { version as appVersion } from '../../../package.json'
import '../styles/swiss.css'

export type SidebarPage = 'dashboard' | 'apps' | 'servers' | 'speedtest' | 'availability' | 'trafficHistory' | 'schedule' | 'logs' | 'settings' | 'maintenance'

interface SidebarProps {
  currentPage: string
  onNavigate: (page: SidebarPage) => void
}

/** «Пломба» navigation: wordmark, numbered index, clock. */
export function Sidebar({ currentPage, onNavigate }: SidebarProps) {
  const { t } = useTranslation()
  const advancedMode = useAppStore(s => s.settings?.advancedMode === true)

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

  return (
    <aside className="c-swiss swiss-sidebar flex h-full shrink-0 flex-col border-r border-[var(--rule)] bg-[var(--paper)] p-5 text-[var(--ink)]">
      <div className="swiss-brand">
        Tunnel
        <br />
        Enforcer
      </div>
      {/* Version comes from package.json, so it follows every release */}
      <div className="swiss-mono mt-1.5 text-[10px] text-[var(--mute)]">
        {'v' + appVersion + ' / ' + t('sidebar.platform', 'win-x64')}
      </div>

      <nav className="mt-10 flex flex-col">
        {navItems.map((item, i) => (
          <button
            key={item.id}
            type="button"
            onClick={() => onNavigate(item.id)}
            aria-current={item.id === currentPage ? 'page' : undefined}
            className="swiss-nav-item"
            data-perch={'nav-' + item.id}
            data-perch-y="bottom"
            data-perch-x="0.85"
            data-perch-scale="0.3"
            data-perch-fit="gap"
          >
            <span className="swiss-nav-num swiss-mono">{String(i + 1).padStart(2, '0')}</span>
            <span className="swiss-nav-label">{item.label}</span>
            <span className="swiss-nav-mark" aria-hidden="true" />
          </button>
        ))}
      </nav>

      {/* Just the clock: the slab already says whether protection is on */}
      <div className="mt-auto pt-3" data-perch="clock" data-perch-x="0.55" data-perch-scale="0.5">
        <span className="swiss-mono text-[15px] font-medium text-[var(--mute)]">
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
