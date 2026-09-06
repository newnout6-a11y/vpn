import { Fragment, useEffect, useState, useMemo, useCallback, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { useAppStore } from '../store'
import {
  Search,
  Download,
  ArrowUpDown,
  ArrowUp,
  ArrowDown,
  Clock,
  Activity,
  FileText,
  Trash2,
  ChevronRight,
  Copy,
  Check,
  Power,
  LogOut,
  Repeat,
  CalendarClock,
  ArrowLeftRight,
  PlugZap,
  KeyRound,
  ServerCrash,
  ShieldAlert,
  Wifi,
  Moon,
  CircleSlash,
  HelpCircle
} from 'lucide-react'
import { MacCard, MacInput, MacButton, MacSelect } from '../design-system'
import { PageTip } from '../components/PageTip'
import type { ConnectionLogEntry, SessionOutcome, SessionOutcomeKind } from '../../shared/ipc-types'

// ─── Types ───────────────────────────────────────────────────────────────────

type DisconnectReason = ConnectionLogEntry['disconnectReason']
type SortField = 'startedAt' | 'endedAt' | 'profileName' | 'mode' | 'duration' | 'traffic' | 'disconnectReason'
type SortDirection = 'asc' | 'desc'

interface ParsedLogEntry {
  ts: string
  level: string
  scope: string
  msg: string
}

interface AggregatedStats {
  totalTimeMs: number
  totalBytesDown: number
  totalBytesUp: number
  entryCount: number
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function formatDuration(ms: number): string {
  if (ms <= 0) return '—'
  const totalSeconds = Math.floor(ms / 1000)
  const hours = Math.floor(totalSeconds / 3600)
  const minutes = Math.floor((totalSeconds % 3600) / 60)
  const seconds = totalSeconds % 60
  if (hours > 0) return `${hours}h ${minutes}m`
  if (minutes > 0) return `${minutes}m ${seconds}s`
  return `${seconds}s`
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB']
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1)
  const value = bytes / Math.pow(1024, i)
  return `${value.toFixed(i === 0 ? 0 : 1)} ${units[i]}`
}

function formatDateTime(ts: number | null): string {
  if (ts == null) return '—'
  return new Date(ts).toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  })
}

// ─── Disconnect Reason Options ───────────────────────────────────────────────

const ALL_REASONS: DisconnectReason[] = ['user', 'error', 'rotation', 'schedule', 'crash']
const RAW_LOG_POLL_INTERVAL_MS = 10_000

// ─── Session outcome presentation ───────────────────────────────────────────

type OutcomeTone = 'ok' | 'muted' | 'info' | 'warn' | 'bad'

const TONE_CLASS: Record<OutcomeTone, string> = {
  ok: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/25',
  muted: 'text-[var(--color-text-secondary)] bg-[var(--color-border)]/40 border-[var(--color-border)]',
  info: 'text-sky-400 bg-sky-500/10 border-sky-500/25',
  warn: 'text-amber-400 bg-amber-500/10 border-amber-500/25',
  bad: 'text-red-400 bg-red-500/10 border-red-500/25'
}

const OUTCOME_META: Record<SessionOutcomeKind, { tone: OutcomeTone; Icon: typeof Power }> = {
  'user-stop': { tone: 'ok', Icon: Power },
  'app-quit': { tone: 'muted', Icon: LogOut },
  'server-switch': { tone: 'info', Icon: ArrowLeftRight },
  rotation: { tone: 'info', Icon: Repeat },
  schedule: { tone: 'info', Icon: CalendarClock },
  'proxy-unreachable': { tone: 'warn', Icon: PlugZap },
  'server-rejected-key': { tone: 'bad', Icon: KeyRound },
  'server-down': { tone: 'bad', Icon: ServerCrash },
  'singbox-crash': { tone: 'bad', Icon: ServerCrash },
  killswitch: { tone: 'bad', Icon: ShieldAlert },
  'tun-setup-failed': { tone: 'bad', Icon: CircleSlash },
  'network-lost': { tone: 'warn', Icon: Wifi },
  'system-sleep': { tone: 'warn', Icon: Moon },
  'start-failed': { tone: 'bad', Icon: CircleSlash },
  unknown: { tone: 'muted', Icon: HelpCircle }
}

/** Legacy rows (no `outcome`) — synthesise a kind from the coarse reason. */
function legacyKind(reason: DisconnectReason): SessionOutcomeKind {
  switch (reason) {
    case 'user': return 'user-stop'
    case 'rotation': return 'rotation'
    case 'schedule': return 'schedule'
    case 'crash': return 'killswitch'
    default: return 'unknown'
  }
}

function isStartFailure(entry: ConnectionLogEntry): boolean {
  return entry.outcome?.kind === 'start-failed' || (entry.endedAt != null && entry.endedAt - entry.startedAt < 1000 && entry.bytesDown === 0 && entry.bytesUp === 0 && (entry.disconnectReason === 'error'))
}

function buildDiagnosticsText(entry: ConnectionLogEntry): string {
  const lines: string[] = []
  lines.push(`Профиль: ${entry.profileName} (${entry.mode})`)
  lines.push(`Начало: ${new Date(entry.startedAt).toISOString()}`)
  if (entry.endedAt != null) lines.push(`Конец: ${new Date(entry.endedAt).toISOString()}`)
  lines.push(`Трафик: ↓${entry.bytesDown} / ↑${entry.bytesUp} байт`)
  if (entry.outcome) {
    lines.push(`Итог: ${entry.outcome.kind} — ${entry.outcome.headline}`)
    if (entry.outcome.evidence) {
      lines.push('Детали:')
      for (const [k, v] of Object.entries(entry.outcome.evidence)) {
        if (v !== null && v !== undefined && v !== '') lines.push(`  ${k}: ${v}`)
      }
    }
  } else {
    lines.push(`Причина: ${entry.disconnectReason}`)
    if (entry.errorMessage) lines.push(`Сообщение: ${entry.errorMessage}`)
  }
  return lines.join('\n')
}

// ─── Component ───────────────────────────────────────────────────────────────

export function Logs() {
  const { t } = useTranslation()

  // ─── State ─────────────────────────────────────────────────────────────────
  const [entries, setEntries] = useState<ConnectionLogEntry[]>([])
  const [loading, setLoading] = useState(false)
  const [clearingLogs, setClearingLogs] = useState(false)
  const [rawLogs, setRawLogs] = useState<ParsedLogEntry[]>([])
  const [rawLogsLoading, setRawLogsLoading] = useState(false)
  const [rawLogsError, setRawLogsError] = useState<string | null>(null)
  const rawLogsFetchInFlightRef = useRef(false)
  const rendererLogs = useAppStore(s => s.logs)
  const mainLogs = useMemo(() => [...rawLogs].reverse(), [rawLogs])
  const uiLogs = useMemo(() => [...rendererLogs].slice(-100).reverse(), [rendererLogs])

  // Filters
  const [selectedReasons, setSelectedReasons] = useState<DisconnectReason[]>([])
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')
  const [searchText, setSearchText] = useState('')

  // Sorting
  const [sortField, setSortField] = useState<SortField>('startedAt')
  const [sortDirection, setSortDirection] = useState<SortDirection>('desc')

  // Row expansion + "copy diagnostics" feedback
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [copiedId, setCopiedId] = useState<string | null>(null)
  const [showStartFailures, setShowStartFailures] = useState(false)

  // Stats
  const [statsPeriod, setStatsPeriod] = useState<'day' | 'week' | 'month'>('day')
  const [stats, setStats] = useState<AggregatedStats | null>(null)

  // ─── Data Loading ──────────────────────────────────────────────────────────

  const loadEntries = useCallback(async () => {
    setLoading(true)
    try {
      const filters: Record<string, unknown> = {}
      if (selectedReasons.length > 0) {
        filters.levels = selectedReasons
      }
      if (dateFrom) {
        filters.dateFrom = new Date(dateFrom).getTime()
      }
      if (dateTo) {
        // Set to end of day
        filters.dateTo = new Date(dateTo).getTime() + 24 * 60 * 60 * 1000 - 1
      }
      if (searchText.trim()) {
        filters.text = searchText.trim()
      }

      const hasFilters = Object.keys(filters).length > 0
      const result = hasFilters
        ? await window.electronAPI.connectionHistoryFilter(filters)
        : await window.electronAPI.connectionHistoryList()
      setEntries(result || [])
    } catch {
      setEntries([])
    } finally {
      setLoading(false)
    }
  }, [selectedReasons, dateFrom, dateTo, searchText])

  const loadStats = useCallback(async () => {
    try {
      const result = await window.electronAPI.connectionHistoryStats(statsPeriod)
      setStats(result)
    } catch {
      setStats(null)
    }
  }, [statsPeriod])

  useEffect(() => {
    loadEntries()
  }, [loadEntries])

  useEffect(() => {
    loadStats()
  }, [loadStats])

  // ─── Sorting Logic ─────────────────────────────────────────────────────────

  const sortedEntries = useMemo(() => {
    const sorted = [...entries]
    sorted.sort((a, b) => {
      let cmp = 0
      switch (sortField) {
        case 'startedAt':
          cmp = a.startedAt - b.startedAt
          break
        case 'endedAt':
          cmp = (a.endedAt ?? 0) - (b.endedAt ?? 0)
          break
        case 'profileName':
          cmp = a.profileName.localeCompare(b.profileName)
          break
        case 'mode':
          cmp = a.mode.localeCompare(b.mode)
          break
        case 'duration': {
          const durA = a.endedAt != null ? a.endedAt - a.startedAt : 0
          const durB = b.endedAt != null ? b.endedAt - b.startedAt : 0
          cmp = durA - durB
          break
        }
        case 'traffic':
          cmp = (a.bytesDown + a.bytesUp) - (b.bytesDown + b.bytesUp)
          break
        case 'disconnectReason':
          cmp = a.disconnectReason.localeCompare(b.disconnectReason)
          break
      }
      return sortDirection === 'asc' ? cmp : -cmp
    })
    return sorted
  }, [entries, sortField, sortDirection])

  // Real sessions vs "never came up" attempts — shown in separate lists so the
  // history table stays about actual connections.
  const sessionEntries = useMemo(() => sortedEntries.filter((e) => !isStartFailure(e)), [sortedEntries])
  const startFailures = useMemo(() => sortedEntries.filter(isStartFailure), [sortedEntries])

  const outcomeFor = useCallback(
    (entry: ConnectionLogEntry): { kind: SessionOutcomeKind; headline: string; outcome: SessionOutcome | null } => {
      if (entry.outcome) return { kind: entry.outcome.kind, headline: entry.outcome.headline, outcome: entry.outcome }
      const kind = legacyKind(entry.disconnectReason)
      return { kind, headline: entry.errorMessage || t(`logs.outcome.${kind}`), outcome: null }
    },
    [t]
  )

  const copyDiagnostics = useCallback(async (entry: ConnectionLogEntry) => {
    try {
      await navigator.clipboard.writeText(buildDiagnosticsText(entry))
      setCopiedId(entry.id)
      setTimeout(() => setCopiedId((cur) => (cur === entry.id ? null : cur)), 1500)
    } catch {
      /* clipboard blocked — no-op */
    }
  }, [])

  // ─── Handlers ──────────────────────────────────────────────────────────────

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDirection((d) => (d === 'asc' ? 'desc' : 'asc'))
    } else {
      setSortField(field)
      setSortDirection('desc')
    }
  }

  const toggleReason = (reason: DisconnectReason) => {
    setSelectedReasons((prev) =>
      prev.includes(reason) ? prev.filter((r) => r !== reason) : [...prev, reason]
    )
  }

  const handleExportCsv = async () => {
    try {
      const csv = await window.electronAPI.connectionHistoryExportCsv()
      const blob = new Blob([csv], { type: 'text/csv' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `connection-history-${new Date().toISOString().slice(0, 10)}.csv`
      a.click()
      URL.revokeObjectURL(url)
    } catch (err: any) {
      console.error('CSV export failed:', err)
      useAppStore.getState().addGlobalToast('error', 'Экспорт не удался', err?.message || 'Ошибка экспорта CSV')
    }
  }

  const handleExportJson = async () => {
    try {
      const json = await window.electronAPI.connectionHistoryExportJson()
      const blob = new Blob([json], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `connection-history-${new Date().toISOString().slice(0, 10)}.json`
      a.click()
      URL.revokeObjectURL(url)
    } catch (err: any) {
      console.error('JSON export failed:', err)
      useAppStore.getState().addGlobalToast('error', 'Экспорт не удался', err?.message || 'Ошибка экспорта JSON')
    }
  }

  // ─── Reason label helper ───────────────────────────────────────────────────

  const reasonLabel = (reason: DisconnectReason): string => {
    const map: Record<DisconnectReason, string> = {
      user: t('logs.reasonUser'),
      error: t('logs.reasonError'),
      rotation: t('logs.reasonRotation'),
      schedule: t('logs.reasonSchedule'),
      crash: t('logs.reasonCrash')
    }
    return map[reason]
  }

  const handleClearLogs = async () => {
    if (!window.confirm('Очистить историю подключений, app/sing-box логи, snapshots и traffic-forensics артефакты?')) return
    setClearingLogs(true)
    try {
      await Promise.all([
        window.electronAPI.clearAppLog(),
        window.electronAPI.connectionHistoryClear(),
        window.electronAPI.trafficHistoryClear(),
        window.electronAPI.clearDiagnosticArtifacts()
      ])
      setEntries([])
      setRawLogs([])
      setStats(null)
      useAppStore.getState().addGlobalToast('success', 'Логи очищены', 'История, runtime-логи и диагностические артефакты удалены')
    } catch (err: any) {
      useAppStore.getState().addGlobalToast('error', 'Ошибка', `Не удалось очистить: ${err?.message || err}`)
    } finally {
      setClearingLogs(false)
    }
  }

  const loadRawLogs = useCallback(async (background = false) => {
    if (rawLogsFetchInFlightRef.current) return
    rawLogsFetchInFlightRef.current = true
    if (!background) setRawLogsLoading(true)
    setRawLogsError(null)
    try {
      const snapshots = await window.electronAPI.getFullLogs()
      if (Array.isArray(snapshots)) {
        // Find app.log (current session)
        const appLog = snapshots.find((s: any) => s.name === 'app.log')
        if (appLog?.content) {
          // Parse each JSON line into a readable format
          const lines = appLog.content.split('\n').filter(Boolean).slice(-300)
          const parsed: ParsedLogEntry[] = []
          for (const line of lines) {
            try {
              const entry = JSON.parse(line)
              const ts = entry.ts ? new Date(entry.ts).toLocaleTimeString('ru-RU') : ''
              const level = entry.level || 'info'
              const scope = entry.scope || ''
              const msg = entry.message || ''
              // Skip IPC debug noise (get-traffic-forensics-status, etc.)
              if (level === 'debug' && scope === 'ipc') continue
              if (msg.includes('traffic-forensics-status')) continue
              parsed.push({ ts, level, scope, msg })
            } catch {
              // Non-JSON line (sing-box log, etc.)
              parsed.push({ ts: '', level: 'info', scope: '', msg: line.slice(0, 200) })
            }
          }
          setRawLogs(parsed)
        } else {
          setRawLogs([])
        }
      } else {
        setRawLogs([])
      }
    } catch (err: any) {
      const message = `Не удалось загрузить логи: ${err?.message || err}`
      setRawLogsError(message)
      setRawLogs([])
    } finally {
      rawLogsFetchInFlightRef.current = false
      if (!background) setRawLogsLoading(false)
    }
  }, [])

  useEffect(() => {
    let timer: number | null = null

    const stopPolling = () => {
      if (timer === null) return
      window.clearInterval(timer)
      timer = null
    }

    const startPolling = () => {
      if (timer !== null || document.visibilityState !== 'visible') return
      void loadRawLogs()
      timer = window.setInterval(() => {
        void loadRawLogs(true)
      }, RAW_LOG_POLL_INTERVAL_MS)
    }

    const onVisibilityChange = () => {
      if (document.visibilityState === 'visible') startPolling()
      else stopPolling()
    }

    startPolling()
    document.addEventListener('visibilitychange', onVisibilityChange)
    return () => {
      stopPolling()
      document.removeEventListener('visibilitychange', onVisibilityChange)
    }
  }, [loadRawLogs])


  // ─── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="xl:grid xl:grid-cols-[minmax(0,1fr)_420px] xl:gap-5 xl:items-start">
      <div className="space-y-5 min-w-0">
        {/* Onboarding tip */}
        <PageTip tipKey="logs">{t('tips.logs')}</PageTip>

        {/* Header */}
        <div className="flex items-start justify-between gap-3">
          <div>
            <h2 className="text-2xl font-semibold text-[var(--color-text)]">
              {t('logs.title')}
            </h2>
            <p className="text-sm text-[var(--color-text-secondary)] mt-1">
              {t('logs.description')}
            </p>
          </div>
          <div className="flex flex-wrap justify-end gap-2">
            <MacButton variant="secondary" size="sm" onClick={handleExportCsv}>
              <Download size={14} className="mr-1.5" />
              {t('logs.exportCsv')}
            </MacButton>
            <MacButton variant="secondary" size="sm" onClick={handleExportJson}>
              <FileText size={14} className="mr-1.5" />
              {t('logs.exportJson')}
            </MacButton>
            <MacButton variant="ghost" size="sm" onClick={handleClearLogs} loading={clearingLogs}>
              <Trash2 size={14} className="mr-1.5" />
              {t('logs.clear', 'Очистить')}
            </MacButton>
          </div>
        </div>

        {/* Filter Controls */}
        <MacCard>
          <div className="flex flex-wrap items-end gap-4">
          {/* Disconnect Reason Multi-Select */}
          <div className="flex flex-col gap-1.5">
            <label className="text-sm font-medium text-[var(--color-text)]">
              {t('logs.reason')}
            </label>
            <div className="flex flex-wrap gap-1.5">
              {ALL_REASONS.map((reason) => (
                <button
                  key={reason}
                  onClick={() => toggleReason(reason)}
                  className={`
                    px-2.5 py-1 text-xs rounded-[var(--radius-sm)] border
                    transition-all duration-[var(--transition-fast)]
                    ${selectedReasons.includes(reason)
                      ? 'bg-[var(--color-accent)] text-white border-[var(--color-accent)]'
                      : 'bg-[var(--color-card)] text-[var(--color-text-secondary)] border-[var(--color-border)] hover:border-[var(--color-accent)]'
                    }
                  `}
                >
                  {reasonLabel(reason)}
                </button>
              ))}
            </div>
          </div>

          {/* Date Range */}
          <div className="flex gap-2">
            <MacInput
              type="date"
              label={t('logs.dateFrom')}
              value={dateFrom}
              onChange={(e) => setDateFrom(e.target.value)}
              className="w-36"
            />
            <MacInput
              type="date"
              label={t('logs.dateTo')}
              value={dateTo}
              onChange={(e) => setDateTo(e.target.value)}
              className="w-36"
            />
          </div>

          {/* Text Search */}
          <div className="flex-1 min-w-[200px]">
            <MacInput
              label={t('logs.filter')}
              placeholder={t('logs.search')}
              value={searchText}
              onChange={(e) => setSearchText(e.target.value)}
              leftIcon={<Search size={14} />}
            />
          </div>
          </div>
        </MacCard>

        {/* Summary Statistics */}
        <MacCard>
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-[var(--color-text)] flex items-center gap-2">
              <Activity size={16} />
              {t('logs.stats')}
            </h3>
            <MacSelect
              options={[
                { value: 'day', label: t('logs.periodDay') },
                { value: 'week', label: t('logs.periodWeek') },
                { value: 'month', label: t('logs.periodMonth') }
              ]}
              value={statsPeriod}
              onChange={(v) => setStatsPeriod(v as 'day' | 'week' | 'month')}
              className="w-32"
            />
          </div>
          {stats && (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="flex flex-col gap-1">
                <span className="text-xs text-[var(--color-text-secondary)]">
                  {t('logs.totalTime')}
                </span>
                <span className="text-lg font-semibold text-[var(--color-text)] flex items-center gap-1.5">
                  <Clock size={16} className="text-[var(--color-accent)]" />
                  {formatDuration(stats.totalTimeMs)}
                </span>
              </div>
              <div className="flex flex-col gap-1">
                <span className="text-xs text-[var(--color-text-secondary)]">
                  {t('logs.totalDown')}
                </span>
                <span className="text-lg font-semibold text-[var(--color-text)]">
                  ↓ {formatBytes(stats.totalBytesDown)}
                </span>
              </div>
              <div className="flex flex-col gap-1">
                <span className="text-xs text-[var(--color-text-secondary)]">
                  {t('logs.totalUp')}
                </span>
                <span className="text-lg font-semibold text-[var(--color-text)]">
                  ↑ {formatBytes(stats.totalBytesUp)}
                </span>
              </div>
              <div className="flex flex-col gap-1">
                <span className="text-xs text-[var(--color-text-secondary)]">
                  {t('logs.connections')}
                </span>
                <span className="text-lg font-semibold text-[var(--color-text)]">
                  {stats.entryCount}
                </span>
              </div>
            </div>
          )}
        </MacCard>

        {/* Connection History Table */}
        <MacCard noPadding>
          <div className="px-5 pt-5 pb-3 flex items-center justify-between">
            <h3 className="text-sm font-semibold text-[var(--color-text)]">
              {t('logs.connectionHistory')}
            </h3>
            <span className="text-xs text-[var(--color-text-secondary)]">
              {sessionEntries.length} {t('logs.connections').toLowerCase()}
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full min-w-[760px] text-sm table-fixed">
              <colgroup>
                <col className="w-[20%]" />
                <col className="w-[8%]" />
                <col className="w-[15%]" />
                <col className="w-[15%]" />
                <col className="w-[11%]" />
                <col className="w-[13%]" />
                <col className="w-[18%]" />
              </colgroup>
              <thead>
                <tr className="border-b border-[var(--color-border)]">
                  <SortableHeader field="profileName" label={t('logs.profile')} onSort={handleSort} sortField={sortField} sortDirection={sortDirection} />
                  <SortableHeader field="mode" label={t('logs.mode')} onSort={handleSort} sortField={sortField} sortDirection={sortDirection} />
                  <SortableHeader field="startedAt" label={t('logs.startTime')} onSort={handleSort} sortField={sortField} sortDirection={sortDirection} />
                  <SortableHeader field="endedAt" label={t('logs.endTime')} onSort={handleSort} sortField={sortField} sortDirection={sortDirection} />
                  <SortableHeader field="duration" label={t('logs.duration')} onSort={handleSort} sortField={sortField} sortDirection={sortDirection} />
                  <SortableHeader field="traffic" label={t('logs.traffic')} onSort={handleSort} sortField={sortField} sortDirection={sortDirection} />
                  <SortableHeader field="disconnectReason" label={t('logs.reasonColumn')} onSort={handleSort} sortField={sortField} sortDirection={sortDirection} />
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr>
                    <td colSpan={7} className="text-center py-8 text-[var(--color-text-secondary)]">
                      {t('common.loading')}
                    </td>
                  </tr>
                ) : sessionEntries.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="text-center py-8 text-[var(--color-text-secondary)]">
                      {t('logs.noLogs')}
                    </td>
                  </tr>
                ) : (
                  sessionEntries.map((entry) => {
                    const { kind, headline, outcome } = outcomeFor(entry)
                    const expanded = expandedId === entry.id
                    return (
                      <Fragment key={entry.id}>
                        <tr
                          onClick={() => setExpandedId(expanded ? null : entry.id)}
                          className="border-b border-[var(--color-border)] last:border-0 hover:bg-[var(--color-border)]/30 transition-colors duration-[var(--transition-fast)] cursor-pointer"
                        >
                          <td className="px-4 py-2.5 font-medium text-[var(--color-text)] truncate" title={entry.profileName}>
                            {entry.profileName}
                          </td>
                          <td className="px-4 py-2.5 text-[var(--color-text-secondary)] truncate">
                            {entry.mode}
                          </td>
                          <td className="px-4 py-2.5 text-[var(--color-text-secondary)] truncate">
                            {formatDateTime(entry.startedAt)}
                          </td>
                          <td className="px-4 py-2.5 text-[var(--color-text-secondary)] truncate">
                            {entry.endedAt != null ? formatDateTime(entry.endedAt) : (
                              <span className="text-green-400 text-xs font-medium">{t('logs.active')}</span>
                            )}
                          </td>
                          <td className="px-4 py-2.5 text-[var(--color-text-secondary)] truncate">
                            {entry.endedAt != null ? formatDuration(entry.endedAt - entry.startedAt) : '—'}
                          </td>
                          <td className="px-4 py-2.5 text-[var(--color-text-secondary)] text-xs leading-tight tabular-nums">
                            <span className="block">↓ {formatBytes(entry.bytesDown)}</span>
                            <span className="block">↑ {formatBytes(entry.bytesUp)}</span>
                          </td>
                          <td className="px-3 py-2.5">
                            <div className="flex items-center gap-1.5 min-w-0">
                              <OutcomeChip kind={kind} label={t(`logs.outcome.${kind}`)} />
                              <ChevronRight
                                size={13}
                                className={`flex-shrink-0 text-[var(--color-text-muted)] transition-transform ${expanded ? 'rotate-90' : ''}`}
                              />
                            </div>
                          </td>
                        </tr>
                        {expanded && (
                          <tr className="bg-[var(--color-bg)]/60">
                            <td colSpan={7} className="px-5 py-3">
                              <OutcomeDetail
                                headline={headline}
                                outcome={outcome}
                                legacyMessage={outcome ? null : entry.errorMessage ?? null}
                                onCopy={() => copyDiagnostics(entry)}
                                copied={copiedId === entry.id}
                                t={t}
                              />
                            </td>
                          </tr>
                        )}
                      </Fragment>
                    )
                  })
                )}
              </tbody>
            </table>
          </div>
        </MacCard>

        {/* Start failures — attempts that never reached a working tunnel */}
        {startFailures.length > 0 && (
          <MacCard noPadding>
            <button
              onClick={() => setShowStartFailures((v) => !v)}
              className="w-full px-5 py-3.5 flex items-center justify-between text-left hover:bg-[var(--color-border)]/20 transition-colors"
            >
              <span className="text-sm font-semibold text-[var(--color-text)] flex items-center gap-2">
                <CircleSlash size={15} className="text-red-400" />
                {t('logs.startFailuresTitle')}
                <span className="text-xs font-normal text-[var(--color-text-secondary)]">
                  ({startFailures.length})
                </span>
              </span>
              <ChevronRight size={15} className={`text-[var(--color-text-muted)] transition-transform ${showStartFailures ? 'rotate-90' : ''}`} />
            </button>
            {showStartFailures && (
              <div className="px-5 pb-4">
                <p className="text-xs text-[var(--color-text-secondary)] mb-3">{t('logs.startFailuresHint')}</p>
                <div className="space-y-1.5">
                  {startFailures.map((entry) => (
                    <div key={entry.id} className="rounded-[var(--radius-sm)] bg-[var(--color-card)] border border-[var(--color-border)] px-3 py-2">
                      <div className="flex items-center justify-between gap-3">
                        <span className="text-xs font-medium text-[var(--color-text)] truncate">{entry.profileName}</span>
                        <span className="text-[10px] text-[var(--color-text-muted)] flex-shrink-0 tabular-nums">
                          {formatDateTime(entry.startedAt)}
                        </span>
                      </div>
                      <p className="text-[11px] text-red-400/90 mt-1 leading-snug">
                        {entry.outcome?.headline || entry.errorMessage}
                      </p>
                      {entry.outcome?.evidence?.outboundFault && (
                        <p className="text-[10px] text-[var(--color-text-secondary)] mt-0.5">
                          {t('logs.outcomeEvidence.outboundFault')}: {t(`logs.outboundFault.${entry.outcome.evidence.outboundFault}`)}
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </MacCard>
        )}
      </div>

      <div className="mt-5 xl:mt-0 space-y-5 xl:sticky xl:top-5">
        <MacCard>
          <div className="flex items-center justify-between gap-3">
            <div>
              <h3 className="text-sm font-semibold text-[var(--color-text)] flex items-center gap-2">
                <FileText size={16} />
                {t('logs.title')}
              </h3>
              <p className="text-xs text-[var(--color-text-secondary)] mt-1">
                Живой main и UI поток без отдельного открытия.
              </p>
            </div>
            <MacButton variant="ghost" size="sm" onClick={() => { void loadRawLogs() }} loading={rawLogsLoading}>
              <Activity size={12} className="mr-1" /> Обновить
            </MacButton>
          </div>
          {rawLogsError ? (
            <p className="mt-3 text-xs text-[var(--color-danger)]">{rawLogsError}</p>
          ) : (
            <div className="mt-3 space-y-4">
              <div>
                <div className="flex items-center justify-between gap-2 mb-2">
                  <p className="text-xs font-semibold text-[var(--color-text-secondary)] uppercase tracking-wider flex items-center gap-1.5">
                    <FileText size={12} className="text-[var(--color-accent)]" />
                    Main log
                  </p>
                  <span className="text-xs text-[var(--color-text-muted)]">{rawLogs.length} lines</span>
                </div>
                <div className="max-h-[28rem] overflow-y-auto rounded-[var(--radius-sm)] bg-[var(--color-bg)] p-3 font-mono text-xs space-y-0.5">
                  {rawLogsLoading && rawLogs.length === 0 ? (
                    <p className="text-[var(--color-text-muted)]">Загружаем main log…</p>
                  ) : mainLogs.length === 0 ? (
                    <p className="text-[var(--color-text-muted)]">Логов пока нет</p>
                  ) : (
                    mainLogs.map((entry, i) => (
                      <div key={i} className="flex gap-2 py-0.5">
                        {entry.ts && <span className="text-[var(--color-text-muted)] flex-shrink-0">{entry.ts}</span>}
                        <span className={`flex-shrink-0 font-semibold ${
                          entry.level === 'error' ? 'text-[var(--color-danger)]' :
                          entry.level === 'warn' ? 'text-[var(--color-warning)]' :
                          'text-[var(--color-text-secondary)]'
                        }`}>{entry.level}</span>
                        {entry.scope && <span className="text-[var(--color-accent)] flex-shrink-0">[{entry.scope}]</span>}
                        <span className="text-[var(--color-text)] break-all">{entry.msg}</span>
                      </div>
                    ))
                  )}
                </div>
              </div>

              <div className="pt-4 border-t border-[var(--color-card-elevated)]/40">
                <div className="flex items-center justify-between gap-2 mb-2">
                  <p className="text-xs font-semibold text-[var(--color-text-secondary)] uppercase tracking-wider flex items-center gap-1.5">
                    <Activity size={12} className="text-[var(--color-accent)]" />
                    UI logs
                  </p>
                  <span className="text-xs text-[var(--color-text-muted)]">{rendererLogs.length} lines</span>
                </div>
                <div className="max-h-48 overflow-y-auto rounded-[var(--radius-sm)] bg-[var(--color-bg)] p-3 font-mono text-xs space-y-0.5">
                  {uiLogs.length === 0 ? (
                    <p className="text-[var(--color-text-muted)]">UI логов пока нет</p>
                  ) : (
                    uiLogs.map((entry, i) => (
                      <div key={i} className="flex gap-2 py-0.5">
                        <span className="text-[var(--color-text-muted)] flex-shrink-0">
                          {new Date(entry.timestamp).toLocaleTimeString('ru-RU')}
                        </span>
                        <span className={`flex-shrink-0 font-semibold ${
                          entry.level === 'error' ? 'text-[var(--color-danger)]' :
                          entry.level === 'warn' ? 'text-[var(--color-warning)]' :
                          'text-[var(--color-text-secondary)]'
                        }`}>{entry.level}</span>
                        <span className="text-[var(--color-text)] break-all">{entry.message}</span>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          )}
        </MacCard>
      </div>
    </div>
  )
}

// ─── Sortable Table Header ───────────────────────────────────────────────────

function SortableHeader({
  field,
  label,
  onSort,
  sortField,
  sortDirection
}: {
  field: SortField
  label: string
  onSort: (field: SortField) => void
  sortField: SortField
  sortDirection: SortDirection
}) {
  const isActive = sortField === field

  return (
    <th
      className="px-4 py-3 text-left text-xs font-medium text-[var(--color-text-secondary)] uppercase tracking-wider cursor-pointer select-none hover:text-[var(--color-text)] transition-colors"
      onClick={() => onSort(field)}
    >
      <span className="flex items-center gap-1">
        {label}
        {isActive ? (
          sortDirection === 'asc'
            ? <ArrowUp size={12} className="text-[var(--color-accent)]" />
            : <ArrowDown size={12} className="text-[var(--color-accent)]" />
        ) : (
          <ArrowUpDown size={12} className="opacity-40" />
        )}
      </span>
    </th>
  )
}

// ─── Session outcome chip + detail ──────────────────────────────────────────

function OutcomeChip({ kind, label }: { kind: SessionOutcomeKind; label: string }) {
  const { tone, Icon } = OUTCOME_META[kind]
  return (
    <span
      className={`inline-flex min-w-0 items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-medium ${TONE_CLASS[tone]}`}
      title={label}
    >
      <Icon size={12} className="flex-shrink-0" />
      <span className="truncate">{label}</span>
    </span>
  )
}

function OutcomeDetail({
  headline,
  outcome,
  legacyMessage,
  onCopy,
  copied,
  t
}: {
  headline: string
  outcome: SessionOutcome | null
  legacyMessage: string | null
  onCopy: () => void
  copied: boolean
  t: (key: string, opts?: Record<string, unknown>) => string
}) {
  const ev = outcome?.evidence ?? {}
  const rows: Array<[string, string]> = []
  for (const [key, value] of Object.entries(ev)) {
    if (value === null || value === undefined || value === '') continue
    let display: string
    if (key === 'outboundFault') display = t(`logs.outboundFault.${value}`)
    else if (typeof value === 'boolean') display = value ? '✓' : '—'
    else display = String(value)
    rows.push([t(`logs.outcomeEvidence.${key}`), display])
  }

  return (
    <div className="space-y-2.5">
      <p className="text-sm text-[var(--color-text)] leading-snug">{headline}</p>
      {legacyMessage && legacyMessage !== headline && (
        <p className="text-xs text-[var(--color-text-secondary)]">{legacyMessage}</p>
      )}
      {rows.length > 0 && (
        <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-1 text-xs">
          {rows.map(([label, value]) => (
            <div key={label} className="flex justify-between gap-3 border-b border-[var(--color-border)]/40 py-0.5">
              <dt className="text-[var(--color-text-secondary)] flex-shrink-0">{label}</dt>
              <dd className="text-[var(--color-text)] text-right break-all font-mono">{value}</dd>
            </div>
          ))}
        </dl>
      )}
      <button
        onClick={(e) => { e.stopPropagation(); onCopy() }}
        className="inline-flex items-center gap-1.5 rounded-[var(--radius-sm)] border border-[var(--color-border)] px-2.5 py-1 text-[11px] text-[var(--color-text-secondary)] hover:text-[var(--color-text)] hover:border-[var(--color-accent)] transition-colors"
      >
        {copied ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
        {copied ? t('logs.copied') : t('logs.copyDiagnostics')}
      </button>
    </div>
  )
}
