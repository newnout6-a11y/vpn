import { LayoutDashboard, AppWindow, Server, Calendar, FileText, Settings, Zap, Globe, Search } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { MacSidebar, type ConnectionStatus, type SidebarItem } from '../design-system'
import { useAppStore } from '../store'

export type SidebarPage = 'dashboard' | 'apps' | 'servers' | 'speedtest' | 'availability' | 'trafficHistory' | 'schedule' | 'logs' | 'settings'

interface SidebarProps {
  currentPage: string
  onNavigate: (page: SidebarPage) => void
}

export function Sidebar({ currentPage, onNavigate }: SidebarProps) {
  const { t } = useTranslation()
  const tunRunning = useAppStore(s => s.tunRunning)
  const restartingProgress = useAppStore(s => s.restartingProgress)
  const detecting = useAppStore(s => s.detecting)

  // Derive connection status for the MacSidebar indicator
  const connectionStatus: ConnectionStatus = (() => {
    if (tunRunning) return 'connected'
    if (restartingProgress !== null || detecting) return 'connecting'
    return 'disconnected'
  })()

  const navItems: SidebarItem[] = [
    { id: 'dashboard', label: t('sidebar.dashboard'), icon: <LayoutDashboard className="w-5 h-5" /> },
    { id: 'apps', label: t('sidebar.apps'), icon: <AppWindow className="w-5 h-5" /> },
    { id: 'servers', label: t('sidebar.servers'), icon: <Server className="w-5 h-5" /> },
    { id: 'speedtest', label: t('sidebar.speedTest'), icon: <Zap className="w-5 h-5" /> },
    { id: 'availability', label: t('sidebar.availability', 'Доступность'), icon: <Search className="w-5 h-5" /> },
    { id: 'trafficHistory', label: t('sidebar.trafficHistory'), icon: <Globe className="w-5 h-5" /> },
    { id: 'schedule', label: t('sidebar.schedule'), icon: <Calendar className="w-5 h-5" /> },
    { id: 'logs', label: t('sidebar.logs'), icon: <FileText className="w-5 h-5" /> },
    { id: 'settings', label: t('sidebar.settings'), icon: <Settings className="w-5 h-5" /> },
  ]

  const statusLabels = {
    connected: t('sidebar.statusConnected'),
    disconnected: t('sidebar.statusDisconnected'),
    connecting: t('sidebar.statusConnecting'),
  } as const

  return (
    <MacSidebar
      items={navItems}
      activeId={currentPage}
      onSelect={(id) => onNavigate(id as SidebarPage)}
      connectionStatus={connectionStatus}
      statusLabels={statusLabels}
    />
  )
}
