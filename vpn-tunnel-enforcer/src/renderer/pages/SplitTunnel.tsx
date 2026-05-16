import { useState, useEffect, useCallback, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { Search, FolderOpen, Trash2 } from 'lucide-react'
import { MacCard, MacInput, MacButton, MacBadge } from '../design-system'
import { PageTip } from '../components/PageTip'
import type { SplitTunnelApp } from '../../shared/ipc-types'

type Rule = SplitTunnelApp['rule']

/**
 * Split Tunneling page — allows users to manage per-app VPN routing rules.
 * Fetches apps from main process, displays them with search filtering,
 * and provides rule selectors (VPN / Direct / None) for each app.
 */
export function SplitTunnel() {
  const { t } = useTranslation()
  const [apps, setApps] = useState<SplitTunnelApp[]>([])
  const [search, setSearch] = useState('')
  const [loading, setLoading] = useState(true)
  const [addingApp, setAddingApp] = useState(false)

  // Fetch apps from main process on mount
  useEffect(() => {
    async function fetchApps() {
      try {
        const result = await window.electronAPI.splitTunnelGetApps()
        setApps(result)
      } catch (err) {
        console.error('Failed to fetch split tunnel apps:', err)
      } finally {
        setLoading(false)
      }
    }
    fetchApps()
  }, [])

  // Filter apps by search query (case-insensitive)
  const filteredApps = useMemo(() => {
    if (!search.trim()) return apps
    const query = search.toLowerCase()
    return apps.filter((app) => app.name.toLowerCase().includes(query))
  }, [apps, search])

  // Handle rule change for an app
  const handleRuleChange = useCallback(async (appId: string, rule: Rule) => {
    try {
      await window.electronAPI.splitTunnelSetRule(appId, rule)
      setApps((prev) =>
        prev.map((app) => (app.id === appId ? { ...app, rule } : app))
      )
    } catch (err) {
      console.error('Failed to set split tunnel rule:', err)
    }
  }, [])

  // Handle adding an app via file dialog
  const handleAddApp = useCallback(async () => {
    setAddingApp(true)
    try {
      const result = await window.electronAPI.splitTunnelAddApp('')
      if (result) {
        setApps((prev) => {
          // Avoid duplicates
          if (prev.some((a) => a.id === result.id)) return prev
          return [...prev, result]
        })
      }
    } catch (err) {
      console.error('Failed to add app:', err)
    } finally {
      setAddingApp(false)
    }
  }, [])

  // Handle removing an app
  const handleRemoveApp = useCallback(async (appId: string) => {
    try {
      await window.electronAPI.splitTunnelRemoveApp(appId)
      setApps((prev) => prev.filter((app) => app.id !== appId))
    } catch (err) {
      console.error('Failed to remove app:', err)
    }
  }, [])

  return (
    <div className="space-y-6 max-w-4xl">
      {/* Onboarding tip */}
      <PageTip tipKey="splitTunnel">{t('tips.splitTunnel')}</PageTip>

      {/* Header */}
      <div>
        <h2 className="text-2xl font-semibold text-[var(--color-text)]">
          {t('splitTunneling.title')}
        </h2>
        <p className="text-sm text-[var(--color-text-secondary)] mt-1">
          {t('splitTunneling.description')}
        </p>
      </div>

      {/* Search and Add controls */}
      <div className="flex items-end gap-3">
        <div className="flex-1">
          <MacInput
            placeholder={t('splitTunneling.searchPlaceholder')}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            leftIcon={<Search className="w-4 h-4" />}
          />
        </div>
        <MacButton
          variant="secondary"
          onClick={handleAddApp}
          loading={addingApp}
          className="shrink-0"
        >
          <FolderOpen className="w-4 h-4 mr-2" />
          {t('splitTunneling.addApp')}
        </MacButton>
      </div>

      {/* App list */}
      {loading ? (
        <div className="text-center py-12 text-[var(--color-text-secondary)]">
          {t('common.loading')}
        </div>
      ) : filteredApps.length === 0 ? (
        <div className="text-center py-12 text-[var(--color-text-secondary)]">
          {search.trim() ? t('common.noResults') : t('splitTunneling.noApps')}
        </div>
      ) : (
        <div className="space-y-2">
          {filteredApps.map((app) => (
            <AppRow
              key={app.id}
              app={app}
              onRuleChange={handleRuleChange}
              onRemove={handleRemoveApp}
              t={t}
            />
          ))}
        </div>
      )}
    </div>
  )
}

// ─── App Row Component ───────────────────────────────────────────────────────

interface AppRowProps {
  app: SplitTunnelApp
  onRuleChange: (appId: string, rule: Rule) => void
  onRemove: (appId: string) => void
  t: (key: string) => string
}

const RULES: { value: Rule; labelKey: string; variant: 'info' | 'success' | 'neutral' }[] = [
  { value: 'vpn', labelKey: 'splitTunneling.ruleVpn', variant: 'info' },
  { value: 'direct', labelKey: 'splitTunneling.ruleDirect', variant: 'success' },
  { value: 'none', labelKey: 'splitTunneling.ruleNone', variant: 'neutral' },
]

function AppRow({ app, onRuleChange, onRemove, t }: AppRowProps) {
  return (
    <MacCard className="flex items-center gap-4 !p-3">
      {/* App icon */}
      <div className="w-9 h-9 rounded-[var(--radius-sm)] bg-[var(--color-border)] flex items-center justify-center shrink-0 overflow-hidden">
        {app.icon ? (
          <img
            src={`data:image/png;base64,${app.icon}`}
            alt={app.name}
            className="w-7 h-7 object-contain"
          />
        ) : (
          <span className="text-xs font-semibold text-[var(--color-text-secondary)]">
            {app.name.charAt(0).toUpperCase()}
          </span>
        )}
      </div>

      {/* App info */}
      <div className="flex-1 min-w-0">
        <div className="text-sm font-medium text-[var(--color-text)] truncate">
          {app.name}
        </div>
        <div className="text-xs text-[var(--color-text-secondary)] truncate">
          {app.path}
        </div>
      </div>

      {/* Rule selector */}
      <div className="flex items-center gap-1.5 shrink-0">
        {RULES.map(({ value, labelKey, variant }) => (
          <button
            key={value}
            onClick={() => onRuleChange(app.id, value)}
            className="focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] rounded-full"
          >
            <MacBadge
              variant={app.rule === value ? variant : 'neutral'}
              className={`cursor-pointer transition-opacity duration-150 ${
                app.rule === value ? 'opacity-100' : 'opacity-50 hover:opacity-75'
              }`}
            >
              {t(labelKey)}
            </MacBadge>
          </button>
        ))}
      </div>

      {/* Remove button */}
      <button
        onClick={() => onRemove(app.id)}
        className="p-1.5 rounded-[var(--radius-sm)] text-[var(--color-text-secondary)] hover:text-[var(--color-danger)] hover:bg-[var(--color-danger)]/10 transition-colors duration-150 shrink-0"
        title={t('common.remove')}
      >
        <Trash2 className="w-4 h-4" />
      </button>
    </MacCard>
  )
}
