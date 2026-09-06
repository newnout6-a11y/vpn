import { useState, useEffect, useCallback, useMemo, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { Globe, Search, Trash2, RefreshCw, Loader2, ExternalLink } from 'lucide-react'
import { MacCard, MacInput, MacButton, MacBadge } from '../design-system'
import { PageTip } from '../components/PageTip'
import { useAppStore } from '../store'

interface TrafficEntry {
  domain: string
  firstSeen: number
  lastSeen: number
  count: number
  vpnIp: string | null
  bytesUp?: number
  bytesDown?: number
  enrichment?: {
    status: 'pending' | 'ready' | 'unavailable'
    siteName: string | null
    title: string | null
    description: string | null
  }
}

const TRAFFIC_HISTORY_POLL_INTERVAL_MS = 15_000
const MAX_RENDERED_ENTRIES = 300

function formatDateTime(ts: number): string {
  return new Date(ts).toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  })
}

function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B'
  if (bytes < 1024) return `${Math.round(bytes)} B`
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(1)} MB`
  return `${(bytes / 1024 ** 3).toFixed(2)} GB`
}

export function TrafficHistory() {
  const { t } = useTranslation()
  const publicIp = useAppStore(s => s.publicIp)
  const tunRunning = useAppStore(s => s.tunRunning)
  const [entries, setEntries] = useState<TrafficEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [clearing, setClearing] = useState(false)
  const domainEnrichmentEnabled = useAppStore(s => s.settings.domainEnrichmentEnabled)
  const fetchInFlightRef = useRef(false)
  const enrichmentRefreshTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  const fetchHistory = useCallback(async (background = false) => {
    if (fetchInFlightRef.current) return
    fetchInFlightRef.current = true
    if (!background) setLoading(true)
    try {
      // Reading the journal is intentionally side-effect free. Enrichment is
      // queued by its own workflow, never on every mount or polling tick.
      const data = await window.electronAPI.trafficHistoryList(publicIp ?? undefined, false)
      setEntries(data || [])
    } catch (err) {
      console.error('Failed to fetch traffic history:', err)
      // Keep the last good list visible during a transient IPC/read failure.
      if (!background) setEntries([])
    } finally {
      fetchInFlightRef.current = false
      if (!background) setLoading(false)
    }
  }, [publicIp])

  useEffect(() => {
    void fetchHistory(false)
  }, [fetchHistory])

  useEffect(() => {
    if (!tunRunning) return

    void fetchHistory(true)
    const id = window.setInterval(() => {
      void fetchHistory(true)
    }, TRAFFIC_HISTORY_POLL_INTERVAL_MS)
    return () => window.clearInterval(id)
  }, [fetchHistory, tunRunning])

  useEffect(() => {
    if (!domainEnrichmentEnabled) return

    const unsubscribe = window.electronAPI.onTrafficHistoryUpdated(() => {
      // Metadata jobs can complete in a burst. Coalesce their notifications
      // into one background read instead of refreshing once per domain.
      if (enrichmentRefreshTimerRef.current) return
      enrichmentRefreshTimerRef.current = setTimeout(() => {
        enrichmentRefreshTimerRef.current = null
        void fetchHistory(true)
      }, 250)
    })

    return () => {
      unsubscribe()
      if (enrichmentRefreshTimerRef.current) {
        clearTimeout(enrichmentRefreshTimerRef.current)
        enrichmentRefreshTimerRef.current = null
      }
    }
  }, [domainEnrichmentEnabled, fetchHistory])

  const filtered = useMemo(() => {
    if (!search.trim()) return entries
    const q = search.toLowerCase()
    return entries.filter(e => e.domain.toLowerCase().includes(q))
  }, [entries, search])

  // Keep the page responsive even when the sing-box journal contains a large
  // number of unique domains. Search still runs against the complete result.
  const visibleEntries = useMemo(
    () => filtered.slice(0, MAX_RENDERED_ENTRIES),
    [filtered]
  )
  const hasMoreEntries = visibleEntries.length < filtered.length

  const totals = useMemo(() => {
    let up = 0
    let down = 0
    let withBytes = 0
    const ips = new Set<string>()
    for (const e of filtered) {
      up += e.bytesUp ?? 0
      down += e.bytesDown ?? 0
      if ((e.bytesUp ?? 0) + (e.bytesDown ?? 0) > 0) withBytes++
      if (e.vpnIp) ips.add(e.vpnIp)
    }
    return { up, down, hasBytes: withBytes > 0, ips: [...ips] }
  }, [filtered])

  const handleClear = async () => {
    setClearing(true)
    try {
      await window.electronAPI.trafficHistoryClear()
      setEntries([])
    } catch (err) {
      console.error('Failed to clear:', err)
    } finally {
      setClearing(false)
    }
  }

  // Group by date for nicer display
  const grouped = useMemo(() => {
    const groups: Record<string, TrafficEntry[]> = {}
    for (const entry of visibleEntries) {
      const day = new Date(entry.lastSeen).toLocaleDateString()
      if (!groups[day]) groups[day] = []
      groups[day].push(entry)
    }
    return groups
  }, [visibleEntries])

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      <PageTip tipKey="trafficHistory">
        {t('trafficHistory.tip')}
      </PageTip>

      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-[var(--color-text)]">
            {t('trafficHistory.title')}
          </h1>
          <p className="text-sm text-[var(--color-text-secondary)] mt-1">
            {t('trafficHistory.description')}
          </p>
        </div>
        <div className="flex gap-2">
          <MacButton variant="secondary" onClick={() => { void fetchHistory(false) }} loading={loading}>
            <RefreshCw className="w-4 h-4 mr-1.5" />
            {t('common.refresh', 'Обновить')}
          </MacButton>
          <MacButton variant="ghost" onClick={handleClear} loading={clearing} disabled={entries.length === 0}>
            <Trash2 className="w-4 h-4 mr-1.5" />
            {t('common.delete')}
          </MacButton>
        </div>
      </div>

      <MacCard>
        <MacInput
          placeholder={t('trafficHistory.searchPlaceholder')}
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          leftIcon={<Search className="w-4 h-4" />}
        />
      </MacCard>

      {loading ? (
        <div className="flex items-center justify-center py-12 text-[var(--color-text-secondary)]">
          <Loader2 className="w-5 h-5 animate-spin mr-2" />
          {t('common.loading')}
        </div>
      ) : entries.length === 0 ? (
        <MacCard>
          <div className="flex flex-col items-center justify-center py-12 text-center text-[var(--color-text-secondary)]">
            <Globe className="w-12 h-12 mb-3 opacity-40" />
            <p className="text-sm">{t('trafficHistory.empty')}</p>
            <p className="text-xs mt-1 max-w-sm">
              {tunRunning
                ? t('trafficHistory.emptyHintConnected', {
                    defaultValue: 'Откройте пару сайтов — домены появятся здесь в течение нескольких секунд.'
                  })
                : t('trafficHistory.emptyHint')}
            </p>
          </div>
        </MacCard>
      ) : filtered.length === 0 ? (
        <MacCard>
          <p className="text-sm text-[var(--color-text-secondary)] text-center py-8">
            {t('common.noResults')}
          </p>
        </MacCard>
      ) : (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-[var(--color-text-secondary)]">
            <p>{t('trafficHistory.total', { count: filtered.length })}</p>
            {totals.hasBytes && (
              <p className="font-mono">
                ↓ {formatBytes(totals.down)} · ↑ {formatBytes(totals.up)}
              </p>
            )}
            {totals.ips.length > 0 && (
              <p className="font-mono">
                {t('trafficHistory.viaIp', { defaultValue: 'через IP' })}: {totals.ips.join(', ')}
              </p>
            )}
            {hasMoreEntries && (
              <p>
                {t('trafficHistory.showingLatest', {
                  count: MAX_RENDERED_ENTRIES,
                  defaultValue: 'Показаны последние {{count}} записей. Уточните поиск, чтобы увидеть более ранние.'
                })}
              </p>
            )}
          </div>
          {Object.entries(grouped).map(([day, items]) => (
            <div key={day}>
              <h2 className="text-xs font-medium text-[var(--color-text-secondary)] uppercase tracking-wide mb-2">
                {day}
              </h2>
              <div className="space-y-1.5">
                {items.map((entry) => (
                  <div key={entry.domain}>
                    <MacCard className="!p-3">
                      <div className="flex items-center gap-3">
                        <Globe className="w-4 h-4 text-[var(--color-accent)] flex-shrink-0" />
                        <div className="flex-1 min-w-0">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="text-sm font-medium text-[var(--color-text)] truncate">
                              {entry.domain}
                            </span>
                            <MacBadge variant="neutral">×{entry.count}</MacBadge>
                            {entry.enrichment?.status === 'pending' && (
                              <Loader2
                                className="w-3.5 h-3.5 text-[var(--color-text-secondary)] animate-spin"
                                aria-label="Получаем метаданные сайта"
                              />
                            )}
                            {entry.enrichment?.status === 'ready' && entry.enrichment.siteName && (
                              <MacBadge variant="success">{entry.enrichment.siteName}</MacBadge>
                            )}
                            {entry.enrichment?.status === 'unavailable' && (
                              <MacBadge variant="neutral">
                                Нет метаданных
                              </MacBadge>
                            )}
                            {(entry.bytesDown ?? 0) + (entry.bytesUp ?? 0) > 0 && (
                              <span className="text-xs text-[var(--color-text-secondary)] font-mono ml-auto whitespace-nowrap">
                                ↓ {formatBytes(entry.bytesDown ?? 0)} · ↑ {formatBytes(entry.bytesUp ?? 0)}
                              </span>
                            )}
                          </div>
                          <p className="text-xs text-[var(--color-text-secondary)] mt-0.5">
                            {entry.enrichment?.status === 'ready' && entry.enrichment.title
                              ? entry.enrichment.title
                              : formatDateTime(entry.firstSeen)}
                            {entry.firstSeen !== entry.lastSeen && (
                              <>{entry.enrichment?.status === 'ready' && entry.enrichment.title ? ' · ' : ' – '}{formatDateTime(entry.lastSeen)}</>
                            )}
                          </p>
                        </div>
                        <a
                          href={`https://${entry.domain}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-[var(--color-text-secondary)] hover:text-[var(--color-accent)] transition-colors"
                          onClick={(e) => e.stopPropagation()}
                        >
                          <ExternalLink className="w-3.5 h-3.5" />
                        </a>
                      </div>
                    </MacCard>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
