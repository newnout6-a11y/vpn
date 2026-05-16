import { useEffect, useState, useMemo, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import {
  Search,
  Download,
  ArrowUpDown,
  ArrowUp,
  ArrowDown,
  Clock,
  Activity,
  FileText
} from 'lucide-react'
import { MacCard, MacInput, MacButton, MacSelect } from '../design-system'
import { PageTip } from '../components/PageTip'
import type { ConnectionLogEntry } from '../../shared/ipc-types'

// ─── Types ───────────────────────────────────────────────────────────────────

type DisconnectReason = ConnectionLogEntry['disconnectReason']
type SortField = 'startedAt' | 'endedAt' | 'profileName' | 'mode' | 'duration' | 'traffic' | 'disconnectReason'
type SortDirection = 'asc' | 'desc'

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

// ─── Component ───────────────────────────────────────────────────────────────

export function Logs() {
  const { t } = useTranslation()

  // ─── State ─────────────────────────────────────────────────────────────────
  const [entries, setEntries] = useState<ConnectionLogEntry[]>([])
  const [loading, setLoading] = useState(false)

  // Filters
  const [selectedReasons, setSelectedReasons] = useState<DisconnectReason[]>([])
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')
  const [searchText, setSearchText] = useState('')

  // Sorting
  const [sortField, setSortField] = useState<SortField>('startedAt')
  const [sortDirection, setSortDirection] = useState<SortDirection>('desc')

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
    } catch {
      // silently fail
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
    } catch {
      // silently fail
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
    return map[reason] || reason
  }

  const reasonColor = (reason: DisconnectReason): string => {
    switch (reason) {
      case 'user': return 'text-[var(--color-text-secondary)]'
      case 'error': return 'text-red-400'
      case 'crash': return 'text-red-500'
      case 'rotation': return 'text-blue-400'
      case 'schedule': return 'text-green-400'
      default: return 'text-[var(--color-text)]'
    }
  }

  // ─── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="space-y-5 max-w-6xl">
      {/* Onboarding tip */}
      <PageTip tipKey="logs">{t('tips.logs')}</PageTip>

      {/* Header */}
      <div className="flex items-center justify-between gap-3">
        <div>
          <h2 className="text-2xl font-semibold text-[var(--color-text)]">
            {t('logs.title')}
          </h2>
          <p className="text-sm text-[var(--color-text-secondary)] mt-1">
            {t('logs.description')}
          </p>
        </div>
        <div className="flex gap-2">
          <MacButton variant="secondary" size="sm" onClick={handleExportCsv}>
            <Download size={14} className="mr-1.5" />
            {t('logs.exportCsv')}
          </MacButton>
          <MacButton variant="secondary" size="sm" onClick={handleExportJson}>
            <FileText size={14} className="mr-1.5" />
            {t('logs.exportJson')}
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
            {sortedEntries.length} {t('logs.connections').toLowerCase()}
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[var(--color-border)]">
                <SortableHeader field="profileName" label={t('logs.profile')} onSort={handleSort} sortField={sortField} sortDirection={sortDirection} />
                <SortableHeader field="mode" label={t('logs.mode')} onSort={handleSort} sortField={sortField} sortDirection={sortDirection} />
                <SortableHeader field="startedAt" label={t('logs.startTime')} onSort={handleSort} sortField={sortField} sortDirection={sortDirection} />
                <SortableHeader field="endedAt" label={t('logs.endTime')} onSort={handleSort} sortField={sortField} sortDirection={sortDirection} />
                <SortableHeader field="duration" label={t('logs.duration')} onSort={handleSort} sortField={sortField} sortDirection={sortDirection} />
                <SortableHeader field="traffic" label={t('logs.traffic')} onSort={handleSort} sortField={sortField} sortDirection={sortDirection} />
                <SortableHeader field="disconnectReason" label={t('logs.reason')} onSort={handleSort} sortField={sortField} sortDirection={sortDirection} />
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={7} className="text-center py-8 text-[var(--color-text-secondary)]">
                    {t('common.loading')}
                  </td>
                </tr>
              ) : sortedEntries.length === 0 ? (
                <tr>
                  <td colSpan={7} className="text-center py-8 text-[var(--color-text-secondary)]">
                    {t('logs.noLogs')}
                  </td>
                </tr>
              ) : (
                sortedEntries.map((entry) => (
                  <tr
                    key={entry.id}
                    className="border-b border-[var(--color-border)] last:border-0 hover:bg-[var(--color-border)]/30 transition-colors duration-[var(--transition-fast)]"
                  >
                    <td className="px-4 py-2.5 font-medium text-[var(--color-text)]">
                      {entry.profileName}
                    </td>
                    <td className="px-4 py-2.5 text-[var(--color-text-secondary)]">
                      {entry.mode}
                    </td>
                    <td className="px-4 py-2.5 text-[var(--color-text-secondary)] whitespace-nowrap">
                      {formatDateTime(entry.startedAt)}
                    </td>
                    <td className="px-4 py-2.5 text-[var(--color-text-secondary)] whitespace-nowrap">
                      {entry.endedAt != null ? formatDateTime(entry.endedAt) : (
                        <span className="text-green-400 text-xs font-medium">{t('logs.active')}</span>
                      )}
                    </td>
                    <td className="px-4 py-2.5 text-[var(--color-text-secondary)] whitespace-nowrap">
                      {entry.endedAt != null
                        ? formatDuration(entry.endedAt - entry.startedAt)
                        : '—'}
                    </td>
                    <td className="px-4 py-2.5 text-[var(--color-text-secondary)] whitespace-nowrap">
                      <span className="text-xs">
                        ↓{formatBytes(entry.bytesDown)} / ↑{formatBytes(entry.bytesUp)}
                      </span>
                    </td>
                    <td className={`px-4 py-2.5 text-xs font-medium ${reasonColor(entry.disconnectReason)}`}>
                      {reasonLabel(entry.disconnectReason)}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </MacCard>
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
