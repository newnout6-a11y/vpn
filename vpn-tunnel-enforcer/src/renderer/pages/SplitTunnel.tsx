import { useState, useEffect, useCallback, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { Search, FolderOpen, Trash2, TerminalSquare, Plus, Loader2 } from 'lucide-react'
import { MacCard, MacInput, MacButton, MacBadge } from '../design-system'
import { PageTip } from '../components/PageTip'
import { useAppStore } from '../store'
import type { SplitTunnelApp } from '../../shared/ipc-types'

type Rule = SplitTunnelApp['rule']

function hasCorruptPathText(value: string): boolean {
  return /[\uFFFD\u3400-\u9fff\uac00-\ud7af]/.test(value)
}

function safePathFallbackName(name: string): string {
  const cleaned = String(name || 'app')
    .replace(/[\uFFFD\u3400-\u9fff\uac00-\ud7af]+/g, ' ')
    .replace(/[<>:"/\\|?*]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
  return cleaned || 'app'
}

function cleanPathSegment(segment: string, fallbackName: string, isLeaf: boolean): string {
  const extMatch = isLeaf ? segment.match(/(\.[A-Za-z0-9]{1,8})$/) : null
  const ext = extMatch?.[1] ?? ''
  const stem = ext ? segment.slice(0, -ext.length) : segment
  const cleaned = stem
    .replace(/[\uFFFD\u3400-\u9fff\uac00-\ud7af]+/g, ' ')
    .replace(/[<>:"/\\|?*]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
  const fallback = safePathFallbackName(fallbackName)
  const nextStem = cleaned.length >= 2 && /[A-Za-zА-Яа-я0-9]/.test(cleaned) ? cleaned : fallback
  return `${nextStem}${ext || (isLeaf ? '.exe' : '')}`
}

export function displaySplitTunnelPath(app: Pick<SplitTunnelApp, 'kind' | 'name' | 'path'>): string {
  if (app.kind === 'process') return app.path
  const rawPath = String(app.path || '')
  if (!rawPath || !hasCorruptPathText(rawPath)) return rawPath

  const separator = rawPath.includes('\\') ? '\\' : '/'
  const parts = rawPath.split(/[\\/]+/)
  return parts
    .map((part, index) =>
      hasCorruptPathText(part)
        ? cleanPathSegment(part, app.name, index === parts.length - 1)
        : part
    )
    .join(separator)
}

/**
 * Split Tunneling page — allows users to manage per-app VPN routing rules.
 * Fetches apps from main process, displays them with search filtering,
 * and provides rule selectors (VPN / Direct / None) for each app.
 */
export function SplitTunnel() {
  const { t } = useTranslation()
  const addLog = useAppStore((s) => s.addLog)
  const [apps, setApps] = useState<SplitTunnelApp[]>([])
  const [search, setSearch] = useState('')
  const [loading, setLoading] = useState(true)
  const [addingApp, setAddingApp] = useState(false)
  const [cmdName, setCmdName] = useState('')
  const [addingCmd, setAddingCmd] = useState(false)
  const [pendingRuleById, setPendingRuleById] = useState<Record<string, Rule>>({})

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
    const current = apps.find((app) => app.id === appId)
    if (!current || current.rule === rule || pendingRuleById[appId]) return

    setPendingRuleById((prev) => ({ ...prev, [appId]: rule }))
    try {
      await window.electronAPI.splitTunnelSetRule(appId, rule)
      setApps((prev) =>
        prev.map((app) => (app.id === appId ? { ...app, rule } : app))
      )
    } catch (err: any) {
      console.error('Failed to set split tunnel rule:', err)
      useAppStore.getState().addGlobalToast('error', 'Ошибка', `Не удалось изменить правило: ${err?.message || err}`)
    } finally {
      setPendingRuleById((prev) => {
        const next = { ...prev }
        delete next[appId]
        return next
      })
    }
  }, [apps, pendingRuleById])

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
    } catch (err: any) {
      console.error('Failed to add app:', err)
      useAppStore.getState().addGlobalToast('error', 'Ошибка', `Не удалось добавить приложение: ${err?.message || err}`)
    } finally {
      setAddingApp(false)
    }
  }, [])

  // Handle removing an app
  const handleRemoveApp = useCallback(async (appId: string) => {
    try {
      await window.electronAPI.splitTunnelRemoveApp(appId)
      setApps((prev) => prev.filter((app) => app.id !== appId))
    } catch (err: any) {
      console.error('Failed to remove app:', err)
      useAppStore.getState().addGlobalToast('error', 'Ошибка', `Не удалось удалить приложение: ${err?.message || err}`)
    }
  }, [])

  // Handle adding a bare command/process name to bypass the VPN.
  const handleAddCommand = useCallback(async () => {
    const raw = cmdName.trim()
    if (!raw) return
    setAddingCmd(true)
    try {
      const result = await window.electronAPI.splitTunnelAddProcess(raw)
      if (result) {
        setApps((prev) => {
          const idx = prev.findIndex((a) => a.id === result.id)
          if (idx !== -1) {
            // Existing entry — replace (rule may have flipped to 'direct').
            const next = [...prev]
            next[idx] = result
            return next
          }
          return [...prev, result]
        })
        setCmdName('')
        addLog('info', t(
          'splitTunneling.commandAdded',
          `Команда «${result.name}» теперь идёт мимо VPN.`
        ))
      }
    } catch (err: any) {
      addLog('error', `${t('splitTunneling.commandAddFailed', 'Не удалось добавить команду')}: ${err?.message ?? err}`)
    } finally {
      setAddingCmd(false)
    }
  }, [cmdName, addLog, t])

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

      {/* Bypass a terminal command / CLI tool by name. For commands that
          aren't installed "apps" with a fixed path (curl, git, yt-dlp, …) —
          the user types the command name and it routes around the VPN. */}
      <MacCard className="!p-4 space-y-3">
        <div className="flex items-start gap-2.5">
          <TerminalSquare className="w-4 h-4 mt-0.5 text-[var(--color-accent)] shrink-0" />
          <div className="min-w-0">
            <h3 className="text-sm font-medium text-[var(--color-text)]">
              {t('splitTunneling.bypassCommandTitle', 'Команда мимо VPN')}
            </h3>
            <p className="text-xs text-[var(--color-text-secondary)] mt-0.5">
              {t(
                'splitTunneling.bypassCommandHint',
                'Укажите имя процесса (например curl.exe, git.exe, yt-dlp), и его трафик пойдёт напрямую, минуя VPN. Работает по имени исполняемого файла, а не по конкретному запуску.'
              )}
            </p>
          </div>
        </div>
        <div className="flex items-end gap-3">
          <div className="flex-1">
            <MacInput
              placeholder={t('splitTunneling.bypassCommandPlaceholder', 'curl.exe')}
              value={cmdName}
              onChange={(e) => setCmdName(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  e.preventDefault()
                  handleAddCommand()
                }
              }}
              leftIcon={<TerminalSquare className="w-4 h-4" />}
            />
          </div>
          <MacButton
            variant="primary"
            onClick={handleAddCommand}
            loading={addingCmd}
            disabled={!cmdName.trim()}
            className="shrink-0"
          >
            <Plus className="w-4 h-4 mr-2" />
            {t('splitTunneling.bypassCommandAdd', 'Добавить')}
          </MacButton>
        </div>
      </MacCard>

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
        <MacCard className="!p-0 overflow-hidden">
          <div className="hidden sm:grid grid-cols-[minmax(0,1fr)_minmax(260px,320px)_40px] gap-3 px-4 py-2.5 border-b border-[var(--color-border)]/70 text-[11px] font-medium uppercase tracking-wide text-[var(--color-text-secondary)]">
            <span>Приложение</span>
            <span>Маршрут</span>
            <span className="sr-only">Действия</span>
          </div>
          <div className="divide-y divide-[var(--color-border)]/60">
            {filteredApps.map((app) => (
              <AppRow
                key={app.id}
                app={app}
                pendingRule={pendingRuleById[app.id]}
                onRuleChange={handleRuleChange}
                onRemove={handleRemoveApp}
                t={t}
              />
            ))}
          </div>
        </MacCard>
      )}
    </div>
  )
}

// ─── App Row Component ───────────────────────────────────────────────────────

interface AppRowProps {
  app: SplitTunnelApp
  pendingRule?: Rule
  onRuleChange: (appId: string, rule: Rule) => void
  onRemove: (appId: string) => void
  t: (key: string) => string
}

const RULES: { value: Rule; labelKey: string; hint: string; activeClass: string }[] = [
  {
    value: 'vpn',
    labelKey: 'splitTunneling.ruleVpn',
    hint: 'Через VPN',
    activeClass: 'bg-[var(--color-accent)] text-white shadow-sm'
  },
  {
    value: 'direct',
    labelKey: 'splitTunneling.ruleDirect',
    hint: 'Мимо VPN',
    activeClass: 'bg-[var(--color-success)] text-white shadow-sm'
  },
  {
    value: 'none',
    labelKey: 'splitTunneling.ruleNone',
    hint: 'Без правила',
    activeClass: 'bg-[var(--color-border-strong)] text-[var(--color-text)]'
  },
]

function AppRow({ app, pendingRule, onRuleChange, onRemove, t }: AppRowProps) {
  const isProcess = app.kind === 'process'
  const displayedRule = pendingRule ?? app.rule
  const isPending = !!pendingRule
  const displayPath = isProcess ? t('splitTunneling.commandSubtitle') : displaySplitTunnelPath(app)
  return (
    <div
      className={`grid grid-cols-[minmax(0,1fr)_auto] sm:grid-cols-[minmax(0,1fr)_minmax(260px,320px)_40px] items-center gap-3 px-4 py-3 transition-colors duration-150 ${
        isPending ? 'bg-[var(--color-accent)]/5' : 'hover:bg-[var(--color-border)]/25'
      }`}
    >
      {/* App icon (terminal glyph for command/process entries) */}
      <div className="min-w-0 flex items-center gap-3">
        <div className="w-9 h-9 rounded-[var(--radius-sm)] bg-[var(--color-border)] flex items-center justify-center shrink-0 overflow-hidden">
          {isProcess ? (
            <TerminalSquare className="w-5 h-5 text-[var(--color-accent)]" />
          ) : app.icon ? (
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
        <div className="min-w-0">
          <div className="text-sm font-medium text-[var(--color-text)] truncate flex items-center gap-2">
            <span className="truncate" title={app.name}>{app.name}</span>
            {isProcess && (
              <MacBadge variant="info" className="!text-[10px] !px-1.5 !py-0 shrink-0">
                {t('splitTunneling.commandTag')}
              </MacBadge>
            )}
          </div>
          <div
            className="text-xs text-[var(--color-text-secondary)] truncate"
            title={displayPath}
          >
            {displayPath}
          </div>
        </div>
      </div>

      {/* Rule selector */}
      <div className="col-span-2 sm:col-span-1 justify-self-stretch sm:justify-self-auto flex items-center rounded-[var(--radius-sm)] border border-[var(--color-border)] bg-[var(--color-card)]/70 p-0.5">
        {RULES.map(({ value, labelKey, hint, activeClass }) => (
          <button
            key={value}
            type="button"
            onClick={() => onRuleChange(app.id, value)}
            disabled={isPending}
            title={hint}
            aria-pressed={displayedRule === value}
            className={`relative flex-1 px-2.5 py-1.5 text-xs font-medium rounded-[calc(var(--radius-sm)-2px)] transition-colors duration-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] disabled:cursor-wait ${
              displayedRule === value
                ? activeClass
                : 'text-[var(--color-text-secondary)] hover:text-[var(--color-text)] hover:bg-[var(--color-border)]/45'
            }`}
          >
            <span className="inline-flex items-center justify-center gap-1.5">
              {pendingRule === value && <Loader2 className="w-3 h-3 animate-spin" />}
              {t(labelKey)}
            </span>
          </button>
        ))}
      </div>

      {/* Remove button */}
      <button
        onClick={() => onRemove(app.id)}
        disabled={isPending}
        className="justify-self-end p-1.5 rounded-[var(--radius-sm)] text-[var(--color-text-secondary)] hover:text-[var(--color-danger)] hover:bg-[var(--color-danger)]/10 transition-colors duration-150 shrink-0 disabled:opacity-45 disabled:cursor-wait"
        title={t('common.remove')}
      >
        <Trash2 className="w-4 h-4" />
      </button>
    </div>
  )
}
