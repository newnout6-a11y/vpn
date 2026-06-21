import { useState, useEffect, useCallback, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { motion } from 'framer-motion'
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
}

function formatDateTime(ts: number): string {
  return new Date(ts).toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  })
}

type BadgeVariant = 'neutral' | 'success' | 'warning' | 'danger' | 'accent'

function categorizeDomain(domain: string): { label: string, variant: BadgeVariant } | null {
  const d = domain.toLowerCase()
  if (/telemetry|metrics|analytics|events\.data|app-measurement|beacons|doubleclick\.net|track|crashlytics|flurry|appsflyer|appcenter/.test(d)) {
    return { label: 'Телеметрия / Трекинг', variant: 'danger' }
  }
  if (/adsystem|adservice|ads\.|ad\.|googlesyndication|criteo|taboola|outbrain|appnexus|pubmatic/.test(d)) {
    return { label: 'Реклама', variant: 'danger' }
  }
  if (/cloudflare|akamai|fastly|cloudfront|cdn|1e100\.net|gvt1|gvt2|googleapis|gstatic|edgecast|incapdns|akadns/.test(d)) {
    return { label: 'CDN / Инфраструктура', variant: 'neutral' }
  }
  if (/whatsapp|telegram|t\.me|viber|discord|slack|skype|teams/.test(d)) {
    return { label: 'Мессенджеры', variant: 'accent' }
  }
  if (/facebook|instagram|twitter|twimg|tiktok|vk\.com|linkedin|snapchat|pinterest/.test(d)) {
    return { label: 'Соцсети', variant: 'accent' }
  }
  if (/youtube|googlevideo|netflix|hulu|disney|primevideo|twitch|vimeo|spotify|apple\.music/.test(d)) {
    return { label: 'Медиа / Стриминг', variant: 'accent' }
  }
  if (/github|gitlab|bitbucket|npm|docker|huggingface|openai|anthropic|claude|api\./.test(d)) {
    return { label: 'Разработка / AI', variant: 'success' }
  }
  if (/mail|smtp|imap|pop|outlook|yandex|gmail/.test(d)) {
    return { label: 'Почта', variant: 'warning' }
  }
  if (/apple\.com|icloud|microsoft\.com|windowsupdate|mzstatic/.test(d)) {
    return { label: 'Системные сервисы', variant: 'neutral' }
  }
  return null
}

export function TrafficHistory() {
  const { t } = useTranslation()
  const publicIp = useAppStore(s => s.publicIp)
  const [entries, setEntries] = useState<TrafficEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [clearing, setClearing] = useState(false)

  const fetchHistory = useCallback(async () => {
    setLoading(true)
    try {
      const data = await window.electronAPI.trafficHistoryList(publicIp ?? undefined)
      setEntries(data || [])
    } catch (err) {
      console.error('Failed to fetch traffic history:', err)
      setEntries([])
    } finally {
      setLoading(false)
    }
  }, [publicIp])

  useEffect(() => {
    fetchHistory()
  }, [fetchHistory])

  const filtered = useMemo(() => {
    if (!search.trim()) return entries
    const q = search.toLowerCase()
    return entries.filter(e => e.domain.toLowerCase().includes(q))
  }, [entries, search])

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
    for (const entry of filtered) {
      const day = new Date(entry.lastSeen).toLocaleDateString()
      if (!groups[day]) groups[day] = []
      groups[day].push(entry)
    }
    return groups
  }, [filtered])

  return (
    <div className="space-y-6 max-w-4xl">
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
          <MacButton variant="secondary" onClick={fetchHistory} loading={loading}>
            <RefreshCw className="w-4 h-4 mr-1.5" />
            {t('common.search')}
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
          <div className="flex flex-col items-center justify-center py-12 text-[var(--color-text-secondary)]">
            <Globe className="w-12 h-12 mb-3 opacity-40" />
            <p className="text-sm">{t('trafficHistory.empty')}</p>
            <p className="text-xs mt-1">{t('trafficHistory.emptyHint')}</p>
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
          <p className="text-xs text-[var(--color-text-secondary)]">
            {t('trafficHistory.total', { count: filtered.length })}
          </p>
          {Object.entries(grouped).map(([day, items]) => (
            <div key={day}>
              <h2 className="text-xs font-medium text-[var(--color-text-secondary)] uppercase tracking-wide mb-2">
                {day}
              </h2>
              <div className="space-y-1.5">
                {items.map((entry, idx) => (
                  <motion.div
                    key={`${entry.domain}-${idx}`}
                    initial={{ opacity: 0, y: 4 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.15, delay: idx * 0.01 }}
                  >
                    <MacCard className="!p-3">
                      <div className="flex items-center gap-3">
                        <Globe className="w-4 h-4 text-[var(--color-accent)] flex-shrink-0" />
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="text-sm font-medium text-[var(--color-text)] truncate">
                              {entry.domain}
                            </span>
                            <MacBadge variant="neutral">×{entry.count}</MacBadge>
                            {(() => {
                              const cat = categorizeDomain(entry.domain)
                              return cat ? <MacBadge variant={cat.variant}>{cat.label}</MacBadge> : null
                            })()}
                            {entry.vpnIp && (
                              <span className="text-xs text-[var(--color-text-secondary)] font-mono ml-auto">
                                IP: {entry.vpnIp}
                              </span>
                            )}
                          </div>
                          <p className="text-xs text-[var(--color-text-secondary)] mt-0.5">
                            {formatDateTime(entry.firstSeen)}
                            {entry.firstSeen !== entry.lastSeen && (
                              <> – {formatDateTime(entry.lastSeen)}</>
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
                  </motion.div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
