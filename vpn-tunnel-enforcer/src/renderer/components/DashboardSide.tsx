/**
 * Right-hand companion column for the Dashboard.
 *
 * Only renders on `xl:` and above (≥1280px viewport). On narrower windows the
 * dashboard collapses to a single column and this component is hidden — see
 * the Tailwind classes on the parent grid in Dashboard.tsx.
 *
 * Three at-a-glance widgets, top to bottom:
 *   1. Quick server picker — every profile with country flag and live ping,
 *      one click to switch. Profiles are now grouped by their parent
 *      subscription/manual group with a tiny status pill (А/И/Н/?).
 *   2. Live traffic sparkline — download/upload over the last 60 seconds.
 *   3. Recent sites — top-5 domains seen by the tunnel.
 *
 * Each widget is a self-contained MacCard, so the column flexes naturally
 * with whatever vertical space is available.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { motion } from 'framer-motion'
import {
  Activity,
  Check,
  Download,
  Globe,
  Loader2,
  RefreshCw,
  Upload,
  Wifi
} from 'lucide-react'
import { MacCard } from '../design-system/MacCard'
import { cn } from '../design-system/utils'
import { useAppStore } from '../store'
import { detectCountry } from './countryGlyph'
import { SERVER_CHANGED_EVENT, emitServerChanged } from '../nav'
import type { ServerProfile } from '../../shared/ipc-types'

// Local mirror — see Servers.tsx / ProfileSelectorInline.tsx for rationale.
interface ServerGroup {
  id: string
  name: string
  source: 'subscription' | 'manual'
  status: 'active' | 'expired' | 'unreachable' | 'unknown'
}

// ─── Helpers ───────────────────────────────────────────────────────────────

function formatSpeedShort(bytesPerSecond: number): string {
  const bits = Math.max(0, bytesPerSecond * 8)
  if (bits < 1_000) return '0'
  if (bits < 1_000_000) return `${Math.round(bits / 1_000)} K`
  if (bits < 10_000_000) return `${(bits / 1_000_000).toFixed(1)} M`
  return `${Math.round(bits / 1_000_000)} M`
}

/** Map a latency in ms to one of the four colour buckets. */
function pingTone(ms: number | null | undefined): string {
  if (ms == null) return 'text-[var(--color-text-secondary)]'
  if (ms < 0) return 'text-[var(--color-danger)]'
  if (ms < 80) return 'text-[var(--color-success)]'
  if (ms < 200) return 'text-[var(--color-text)]'
  if (ms < 500) return 'text-[var(--color-warning)]'
  return 'text-[var(--color-danger)]'
}

function groupPillTone(status: ServerGroup['status']): string {
  switch (status) {
    case 'active':
      return 'bg-[var(--color-success)]/15 text-[var(--color-success)] border-[var(--color-success)]/30'
    case 'expired':
      return 'bg-[var(--color-warning)]/15 text-[var(--color-warning)] border-[var(--color-warning)]/30'
    case 'unreachable':
      return 'bg-[var(--color-danger)]/15 text-[var(--color-danger)] border-[var(--color-danger)]/30'
    default:
      return 'bg-[var(--color-border)] text-[var(--color-text-secondary)] border-[var(--color-border)]'
  }
}

// ─── Quick server picker ───────────────────────────────────────────────────

/**
 * Compact list of all available profiles. Same data as the Servers page,
 * always read from the unified server-picker store via IPC.
 */
function QuickServers() {
  const { t } = useTranslation()
  const addLog = useAppStore(s => s.addLog)
  const tunRunning = useAppStore(s => s.tunRunning)

  const [profiles, setProfiles] = useState<ServerProfile[]>([])
  const [groups, setGroups] = useState<ServerGroup[]>([])
  const [groupsAvailable, setGroupsAvailable] = useState<boolean>(false)
  const [activeId, setActiveId] = useState<string | null>(null)
  const [pings, setPings] = useState<Record<string, number | null | 'pinging'>>({})
  const [pingingAll, setPingingAll] = useState(false)

  const refresh = useCallback(async () => {
    try {
      const [list, active] = await Promise.all([
        window.electronAPI.serversList(),
        window.electronAPI.serversGetActive()
      ])
      setProfiles(list)
      setActiveId(active.activeId ?? active.profile?.id ?? null)
      const api = window.electronAPI as unknown as {
        groupsList?: () => Promise<ServerGroup[]>
      }
      if (typeof api.groupsList === 'function') {
        try {
          const gs = await api.groupsList()
          setGroups(Array.isArray(gs) ? gs : [])
          setGroupsAvailable(true)
        } catch {
          setGroupsAvailable(false)
          setGroups([])
        }
      } else {
        setGroupsAvailable(false)
        setGroups([])
      }
    } catch {
      // Silent — list will simply stay empty if IPC fails.
    }
  }, [])

  useEffect(() => {
    refresh()
    // Poll on a slow cadence so the dashboard reflects external changes
    // (a server added on the Servers page) without forcing the user to
    // navigate away and back.
    const id = setInterval(refresh, 5000)
    const handler = () => refresh()
    window.addEventListener(SERVER_CHANGED_EVENT, handler)
    return () => {
      clearInterval(id)
      window.removeEventListener(SERVER_CHANGED_EVENT, handler)
    }
  }, [refresh])

  // Drop cached per-row ping numbers whenever the tunnel state flips. Pings
  // measured while the tunnel was UP are tunnel-RTT (every row would show
  // the same number), and pings measured while DOWN are per-server. Mixing
  // them in the same map produces "выбранный криво, остальные норм" type
  // confusion — see pingServer dispatch in serverPicker.ts. Forcing a
  // clean slate on each transition guarantees the user is always looking at
  // numbers that mean what the column header claims.
  useEffect(() => {
    setPings({})
  }, [tunRunning])

  type Row = {
    key: string
    name: string
    protocol: string
    host: string | null
    port: number | null
    country: string | null
    selected: boolean
    onSelect: () => void
  }

  // Build clusters per group, falling back to a single ungrouped cluster
  // when IPC isn't available.
  const clusters = useMemo<Array<{ group: ServerGroup | null; rows: Row[] }>>(() => {
    const makeRow = (profile: ServerProfile): Row => ({
      key: profile.id,
      name: profile.name,
      protocol: profile.protocol,
      host: profile.server || null,
      port: profile.port || null,
      country: profile.country || null,
      selected: profile.id === activeId,
      onSelect: async () => {
        setActiveId(profile.id)
        try {
          await window.electronAPI.serversSelect(profile.id)
          addLog('info', `Сервер выбран: ${profile.name}`)
          emitServerChanged()
        } catch (err: unknown) {
          const message = err instanceof Error ? err.message : String(err)
          addLog('error', `Не удалось выбрать сервер: ${message}`)
          refresh()
        }
      }
    })

    if (!groupsAvailable) {
      return [{ group: null, rows: profiles.map(makeRow) }]
    }
    const buckets = new Map<string, Row[]>()
    const orphans: Row[] = []
    for (const g of groups) buckets.set(g.id, [])
    for (const p of profiles) {
      const gid = (p as ServerProfile & { groupId?: string }).groupId
      if (gid && buckets.has(gid)) buckets.get(gid)!.push(makeRow(p))
      else orphans.push(makeRow(p))
    }
    const sorted = [...groups].sort((a, b) => {
      if (a.source !== b.source) return a.source === 'subscription' ? -1 : 1
      return 0
    })
    const out: Array<{ group: ServerGroup | null; rows: Row[] }> = []
    for (const g of sorted) {
      const list = buckets.get(g.id) ?? []
      if (list.length > 0) out.push({ group: g, rows: list })
    }
    if (orphans.length > 0) out.push({ group: null, rows: orphans })
    return out
  }, [profiles, groups, groupsAvailable, activeId, addLog, refresh])

  const totalRows = useMemo(
    () => clusters.reduce((sum, c) => sum + c.rows.length, 0),
    [clusters]
  )

  // Ping a single endpoint and write the result into our local map.
  const pingOne = useCallback(async (key: string, host: string, port: number) => {
    setPings(prev => ({ ...prev, [key]: 'pinging' }))
    try {
      const ms = await window.electronAPI.serversPingOne(host, port)
      setPings(prev => ({ ...prev, [key]: ms }))
    } catch {
      setPings(prev => ({ ...prev, [key]: null }))
    }
  }, [])

  const handlePingAll = async () => {
    setPingingAll(true)
    try {
      const queue: Row[] = clusters.flatMap(c => c.rows.filter(r => r.host && r.port))
      const concurrency = 5
      let i = 0
      const worker = async () => {
        while (i < queue.length) {
          const idx = i++
          const r = queue[idx]
          if (r.host && r.port) await pingOne(r.key, r.host, r.port)
        }
      }
      await Promise.all(Array.from({ length: concurrency }, worker))
    } finally {
      setPingingAll(false)
    }
  }

  if (totalRows === 0) {
    return (
      <MacCard className="!p-3">
        <h3 className="text-xs font-semibold text-[var(--color-text-secondary)] uppercase tracking-wider mb-2 flex items-center gap-1.5">
          <Globe className="w-3.5 h-3.5" />
          {t('dashboardSide.servers', 'Серверы')}
        </h3>
        <p className="text-xs text-[var(--color-text-secondary)]">
          {t('dashboardSide.noServersV2', 'Нет профилей. Добавьте подписку в разделе «Серверы».')}
        </p>
      </MacCard>
    )
  }

  return (
    <MacCard className="!p-3 flex flex-col min-h-0">
      <div className="flex items-center justify-between mb-2 flex-shrink-0">
        <h3 className="text-xs font-semibold text-[var(--color-text-secondary)] uppercase tracking-wider flex items-center gap-1.5">
          <Globe className="w-3.5 h-3.5" />
          {t('dashboardSide.servers', 'Серверы')}
          <span className="text-[var(--color-text-muted)] font-normal lowercase">
            ·&nbsp;{totalRows}
          </span>
        </h3>
        <button
          type="button"
          onClick={handlePingAll}
          disabled={pingingAll}
          className={cn(
            'inline-flex items-center gap-1 px-2 py-1 rounded-[var(--radius-sm)] text-[11px] font-medium',
            'text-[var(--color-text-secondary)] hover:text-[var(--color-accent)]',
            'hover:bg-[var(--color-card-elevated)]',
            'transition-colors duration-[var(--transition-fast)]',
            'disabled:opacity-50 disabled:pointer-events-none',
            'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]'
          )}
          title={t('dashboardSide.pingAll', 'Пингануть все')}
          aria-label={t('dashboardSide.pingAll', 'Пингануть все')}
        >
          {pingingAll
            ? <Loader2 className="w-3 h-3 animate-spin" />
            : <RefreshCw className="w-3 h-3" />}
          {t('dashboardSide.pingShort', 'Пинг')}
        </button>
      </div>

      <div className="overflow-y-auto pr-1 -mr-1 max-h-[420px] space-y-3">
        {clusters.map((cluster, idx) => {
          const statusKey = cluster.group?.status ?? 'unknown'
          const statusShort =
            statusKey === 'active'
              ? t('dashboardSide.groupActive', 'А')
              : statusKey === 'expired'
                ? t('dashboardSide.groupExpired', 'И')
                : statusKey === 'unreachable'
                  ? t('dashboardSide.groupUnreachable', 'Н')
                  : t('dashboardSide.groupUnknown', '?')
          const statusTitle =
            statusKey === 'active'
              ? t('dashboardSide.groupStatusActiveTitle', 'Активна')
              : statusKey === 'expired'
                ? t('dashboardSide.groupStatusExpiredTitle', 'Истекла, ключи могут работать')
                : statusKey === 'unreachable'
                  ? t('dashboardSide.groupStatusUnreachableTitle', 'Не отвечает')
                  : t('dashboardSide.groupStatusUnknownTitle', 'Не проверена')
          return (
            <div key={cluster.group?.id ?? `orphan-${idx}`}>
              {cluster.group && (
                <div className="flex items-center gap-1.5 mb-1 px-1">
                  <span className="text-[10px]" aria-hidden="true">
                    {cluster.group.source === 'subscription' ? '📡' : '🔑'}
                  </span>
                  <span className="text-[10px] uppercase tracking-wider font-semibold text-[var(--color-text-secondary)] truncate flex-1">
                    {cluster.group.name}
                  </span>
                  <span
                    className={cn(
                      'inline-flex items-center justify-center w-4 h-4 rounded-full border text-[9px] font-bold leading-none',
                      groupPillTone(cluster.group.status)
                    )}
                    title={statusTitle}
                    aria-label={statusTitle}
                  >
                    {statusShort}
                  </span>
                </div>
              )}
              <ul className="space-y-1">
                {cluster.rows.map(row => {
                  const recognised = detectCountry(row.name)
                  const ping = pings[row.key]
                  const pingValue = ping === 'pinging' ? null : ping
                  return (
                    <li key={row.key}>
                      <button
                        type="button"
                        onClick={row.onSelect}
                        aria-pressed={row.selected}
                        className={cn(
                          'group w-full flex items-center gap-2 px-2 py-1.5 rounded-[var(--radius-sm)] text-left',
                          'transition-all duration-[var(--transition-fast)]',
                          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]',
                          row.selected
                            ? 'bg-[color-mix(in_srgb,var(--color-accent)_12%,transparent)] border border-[var(--color-accent)]/40'
                            : 'border border-transparent hover:bg-[var(--color-border)]/40'
                        )}
                      >
                        <span
                          className="text-base leading-none flex-shrink-0 select-none"
                          aria-hidden="true"
                        >
                          {recognised?.flag ?? '🌐'}
                        </span>
                        <span className="flex-1 min-w-0">
                          <span className="block text-xs font-medium text-[var(--color-text)] truncate">
                            {row.name}
                          </span>
                          <span className="block text-[10px] text-[var(--color-text-secondary)] truncate font-mono">
                            {row.country
                              ? `${row.country} · ${row.host ? `${row.host}${row.port ? `:${row.port}` : ''}` : row.protocol.toUpperCase()}`
                              : (row.host ? `${row.host}${row.port ? `:${row.port}` : ''}` : row.protocol.toUpperCase())}
                          </span>
                        </span>
                        <span
                          className={cn(
                            'text-[11px] tabular-nums font-medium flex-shrink-0 min-w-[34px] text-right',
                            pingTone(pingValue)
                          )}
                          aria-label={pingValue == null ? '' : `${pingValue} ms`}
                        >
                          {ping === 'pinging'
                            ? '…'
                            : pingValue == null
                              ? '—'
                              : `${pingValue}`}
                        </span>
                        {row.selected && (
                          <Check className="w-3.5 h-3.5 text-[var(--color-accent)] flex-shrink-0" />
                        )}
                        {!row.selected && (
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation()
                              if (row.host && row.port) pingOne(row.key, row.host, row.port)
                            }}
                            aria-label={t('dashboardSide.pingOne', 'Пингануть профиль')}
                            className={cn(
                              'opacity-0 group-hover:opacity-100',
                              'p-1 rounded-[4px] transition-opacity duration-[var(--transition-fast)]',
                              'text-[var(--color-text-secondary)] hover:text-[var(--color-accent)]',
                              'hover:bg-[var(--color-card-elevated)]'
                            )}
                          >
                            <Activity className={cn(
                              'w-3 h-3',
                              ping === 'pinging' && 'animate-pulse'
                            )} />
                          </button>
                        )}
                      </button>
                    </li>
                  )
                })}
              </ul>
            </div>
          )
        })}
      </div>
    </MacCard>
  )
}

// ─── Live traffic sparkline ────────────────────────────────────────────────

const SAMPLES_KEPT = 60 // 60 seconds at 1 sample/sec

/**
 * Twin sparkline of download / upload throughput. Reads the live traffic
 * stats from the store and stores up to 60 most recent samples in local
 * state. Drawing is a manual `<svg>` polyline — Recharts is overkill for a
 * 60-pixel-wide tracer.
 */
function LiveTraffic() {
  const { t } = useTranslation()
  const traffic = useAppStore(s => s.traffic)
  const tunRunning = useAppStore(s => s.tunRunning)
  const samplesRef = useRef<{ down: number[]; up: number[] }>({ down: [], up: [] })
  const [, forceTick] = useState(0)

  useEffect(() => {
    if (!tunRunning) {
      // Reset history when the tunnel goes down so the next session starts
      // with a clean baseline rather than a phantom spike at the join point.
      samplesRef.current = { down: [], up: [] }
      forceTick(t => t + 1)
      return
    }
    samplesRef.current.down = [
      ...samplesRef.current.down.slice(-(SAMPLES_KEPT - 1)),
      traffic.downloadBps
    ]
    samplesRef.current.up = [
      ...samplesRef.current.up.slice(-(SAMPLES_KEPT - 1)),
      traffic.uploadBps
    ]
    forceTick(t => t + 1)
  }, [traffic.ts, traffic.downloadBps, traffic.uploadBps, tunRunning])

  const downSamples = samplesRef.current.down
  const upSamples = samplesRef.current.up
  const max = Math.max(1, ...downSamples, ...upSamples)

  const buildPath = (samples: number[]): string => {
    if (samples.length === 0) return ''
    const w = 100 / Math.max(1, SAMPLES_KEPT - 1)
    return samples
      .map((value, idx) => {
        const x = idx * w
        const y = 100 - (value / max) * 100
        return `${idx === 0 ? 'M' : 'L'}${x.toFixed(2)},${y.toFixed(2)}`
      })
      .join(' ')
  }

  return (
    <MacCard className="!p-3">
      <h3 className="text-xs font-semibold text-[var(--color-text-secondary)] uppercase tracking-wider mb-2 flex items-center gap-1.5">
        <Activity className="w-3.5 h-3.5" />
        {t('dashboardSide.liveTraffic', 'Лайв-трафик')}
      </h3>

      <div className="grid grid-cols-2 gap-3 mb-2">
        <div>
          <div className="text-[10px] uppercase tracking-wider text-[var(--color-text-secondary)] flex items-center gap-1">
            <Download className="w-3 h-3 text-[var(--color-success)]" />
            {t('dashboardSide.down', 'Загрузка')}
          </div>
          <div className="text-sm font-semibold text-[var(--color-text)] tabular-nums">
            {formatSpeedShort(traffic.downloadBps)}
            <span className="text-[10px] font-normal text-[var(--color-text-secondary)] ml-1">bps</span>
          </div>
        </div>
        <div>
          <div className="text-[10px] uppercase tracking-wider text-[var(--color-text-secondary)] flex items-center gap-1">
            <Upload className="w-3 h-3 text-[var(--color-accent)]" />
            {t('dashboardSide.up', 'Отдача')}
          </div>
          <div className="text-sm font-semibold text-[var(--color-text)] tabular-nums">
            {formatSpeedShort(traffic.uploadBps)}
            <span className="text-[10px] font-normal text-[var(--color-text-secondary)] ml-1">bps</span>
          </div>
        </div>
      </div>

      <svg
        viewBox="0 0 100 100"
        preserveAspectRatio="none"
        className="w-full h-16"
        aria-hidden="true"
      >
        {/* Subtle baseline so the empty state still has visual weight */}
        <line x1="0" y1="100" x2="100" y2="100" stroke="var(--color-border)" strokeWidth="0.5" />
        {downSamples.length > 1 && (
          <path
            d={buildPath(downSamples)}
            fill="none"
            stroke="var(--color-success)"
            strokeWidth="1.2"
            vectorEffect="non-scaling-stroke"
          />
        )}
        {upSamples.length > 1 && (
          <path
            d={buildPath(upSamples)}
            fill="none"
            stroke="var(--color-accent)"
            strokeWidth="1.2"
            vectorEffect="non-scaling-stroke"
          />
        )}
      </svg>

      {!tunRunning && (
        <p className="text-[10px] text-[var(--color-text-secondary)] mt-1 text-center">
          {t('dashboardSide.idleHint', 'Включите защиту, чтобы увидеть график')}
        </p>
      )}
    </MacCard>
  )
}

// ─── Recent sites mini-panel ───────────────────────────────────────────────

interface RecentEntry {
  domain: string
  count: number
  lastSeen: number
}

/**
 * Top-5 domains seen by the tunnel, refreshed every 15 seconds while the
 * tunnel is up. Reuses the existing trafficHistoryList IPC.
 */
function RecentSites() {
  const { t } = useTranslation()
  const tunRunning = useAppStore(s => s.tunRunning)
  const [entries, setEntries] = useState<RecentEntry[]>([])
  const [loading, setLoading] = useState(false)

  const refresh = useCallback(async () => {
    setLoading(true)
    try {
      const list = await window.electronAPI.trafficHistoryList()
      const top: RecentEntry[] = (list || [])
        .map((e: { domain: string; count: number; lastSeen: number }) => ({
          domain: e.domain,
          count: e.count,
          lastSeen: e.lastSeen
        }))
        .sort((a, b) => b.lastSeen - a.lastSeen)
        .slice(0, 5)
      setEntries(top)
    } catch {
      setEntries([])
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    refresh()
    if (!tunRunning) return
    const id = setInterval(refresh, 15_000)
    return () => clearInterval(id)
  }, [refresh, tunRunning])

  return (
    <MacCard className="!p-3">
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-xs font-semibold text-[var(--color-text-secondary)] uppercase tracking-wider flex items-center gap-1.5">
          <Wifi className="w-3.5 h-3.5" />
          {t('dashboardSide.recentSites', 'Последние сайты')}
        </h3>
        <button
          type="button"
          onClick={refresh}
          disabled={loading}
          aria-label={t('dashboardSide.refresh', 'Обновить')}
          className={cn(
            'p-1 rounded-[4px] transition-colors duration-[var(--transition-fast)]',
            'text-[var(--color-text-secondary)] hover:text-[var(--color-accent)]',
            'hover:bg-[var(--color-card-elevated)]',
            'disabled:opacity-50'
          )}
        >
          {loading
            ? <Loader2 className="w-3 h-3 animate-spin" />
            : <RefreshCw className="w-3 h-3" />}
        </button>
      </div>

      {entries.length === 0 ? (
        <p className="text-[11px] text-[var(--color-text-secondary)]">
          {tunRunning
            ? t('dashboardSide.recentEmptyConnected', 'Пока нет данных. Откройте сайт, чтобы началась запись.')
            : t('dashboardSide.recentEmptyOffline', 'Включите защиту, чтобы увидеть историю.')}
        </p>
      ) : (
        <ul className="space-y-1">
          {entries.map((entry, idx) => (
            <motion.li
              key={entry.domain}
              initial={{ opacity: 0, x: -4 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.15, delay: idx * 0.02 }}
              className="flex items-center gap-2 text-[11px]"
            >
              <Globe className="w-3 h-3 text-[var(--color-text-secondary)] flex-shrink-0" />
              <span className="flex-1 min-w-0 truncate text-[var(--color-text)] font-mono">
                {entry.domain}
              </span>
              <span className="text-[var(--color-text-secondary)] tabular-nums">
                ×{entry.count}
              </span>
            </motion.li>
          ))}
        </ul>
      )}
    </MacCard>
  )
}

// ─── Aggregate ─────────────────────────────────────────────────────────────

export function DashboardSide() {
  return (
    <div className="flex flex-col gap-4 min-h-0">
      <QuickServers />
      <LiveTraffic />
      <RecentSites />
    </div>
  )
}
