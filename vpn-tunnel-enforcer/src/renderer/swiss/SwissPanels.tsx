import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { Loader2, RefreshCw } from 'lucide-react'
import { cn } from '../design-system/utils'
import { useAppStore } from '../store'
import { usePageActive } from '../hooks/usePageActive'
import { SERVER_CHANGED_EVENT, emitServerChanged } from '../nav'
import { isIpcRemoteErrorData } from '../../shared/ipc-result'
import { CountryFlagIcon } from '../components/CountryFlagIcon'
import type { ServerProfile } from '../../shared/ipc-types'
import { SwissJournal } from './SwissJournal'
import { SWISS_PING_EVENT, type SwissPingDetail } from './SwissIdentity'

const HISTORY = 48
const REFRESH_MS = 10000

const announcePing = (detail: SwissPingDetail) => {
  window.dispatchEvent(new CustomEvent<SwissPingDetail>(SWISS_PING_EVENT, { detail }))
}

/** «Пломба» panel row under the slab: traffic · servers · journal. */
export function SwissPanels() {
  return (
    <div className="swiss-panels">
      <SwissTraffic />
      <SwissServers />
      <SwissJournal />
    </div>
  )
}

function PanelHead({ title, perch, children }: { title: string; perch?: string; children?: ReactNode }) {
  return (
    <header className="swiss-panel-head" data-perch={perch} data-perch-y="bottom" data-perch-scale="0.32" data-perch-fit="gap">
      <span className="swiss-label swiss-label-ink">{title}</span>
      {children}
    </header>
  )
}

const toMbps = (bps: number) => (Math.max(0, bps) * 8) / 1000000

function SwissTraffic() {
  const { t } = useTranslation()
  const traffic = useAppStore(s => s.traffic)
  const running = traffic.running
  const down = toMbps(traffic.smoothedDownloadBps || traffic.downloadBps)
  const up = toMbps(traffic.smoothedUploadBps || traffic.uploadBps)
  const [history, setHistory] = useState<number[]>(() => Array(HISTORY).fill(0))
  const [hover, setHover] = useState<number | null>(null)

  // One bar per traffic sample (a new sample changes ts and the rate together)
  useEffect(() => {
    if (!running) return
    setHistory(h => h.slice(1).concat(down))
  }, [traffic.ts, running, down])

  const max = Math.max(10, ...history)
  const hovered = hover !== null ? history[hover] : undefined

  return (
    <section className="swiss-panel">
      <PanelHead title={t('swiss.traffic')} perch="traffic">
        <span className="swiss-label flex items-center gap-1.5">
          {hovered !== undefined ? (
            <span className="swiss-label-ink">{hovered.toFixed(1) + ' ' + t('swiss.mbps') + ' · ' + t('swiss.secondsAgo', { n: HISTORY - 1 - (hover ?? 0) })}</span>
          ) : running ? (
            <>
              <span className="blink h-1.5 w-1.5 bg-[var(--signal)]" />
              {t('swiss.live')}
            </>
          ) : (
            t('swiss.noData')
          )}
        </span>
      </PanelHead>
      <div className="swiss-traffic-figures">
        <div className="min-w-0">
          <div className="swiss-label">{t('swiss.download')}</div>
          <div className={cn('swiss-traffic-big', !running && 'is-dim')}>{down.toFixed(1)}</div>
        </div>
        <div className="swiss-traffic-small">
          <div><span className="swiss-label">{t('swiss.upload')}</span><span className="swiss-mono">{up.toFixed(1) + ' ' + t('swiss.mbps')}</span></div>
          <div><span className="swiss-label">{t('swiss.session')}</span><span className="swiss-mono">{(traffic.sessionDownloadBytes / 1073741824).toFixed(2) + ' ' + t('swiss.gb')}</span></div>
        </div>
      </div>
      <div className="swiss-bars" onMouseLeave={() => setHover(null)}>
        {history.map((v, i) => (
          <div key={i} className="swiss-bar-slot" onMouseEnter={() => setHover(i)}>
            <div
              className={cn('swiss-bar', !running && 'is-off', running && (i === hover || i === HISTORY - 1) && 'is-hot', running && hover !== null && i !== hover && 'is-faded')}
              style={{ height: Math.max(4, (v / max) * 100) + '%' }}
            />
          </div>
        ))}
      </div>
    </section>
  )
}

function minutesAgo(ts: number | undefined): number | null {
  return ts ? Math.max(0, Math.round((Date.now() - ts) / 60000)) : null
}

function SwissServers() {
  const { t } = useTranslation()
  const active = usePageActive()
  const addLog = useAppStore(s => s.addLog)
  const tunRunning = useAppStore(s => s.tunRunning)
  const connectionMode = useAppStore(s => s.settings.connectionMode)
  const setServerSwitchingName = useAppStore(s => s.setServerSwitchingName)
  const [profiles, setProfiles] = useState<ServerProfile[]>([])
  const [activeId, setActiveId] = useState<string | null>(null)
  const [pings, setPings] = useState<Record<string, number | null | 'pinging'>>({})
  const [pingingAll, setPingingAll] = useState(false)
  const seq = useRef(0)

  const refresh = useCallback(async () => {
    const mine = ++seq.current
    try {
      const [list, current] = await Promise.all([window.electronAPI.serversList(), window.electronAPI.serversGetActive()])
      if (mine !== seq.current) return
      setProfiles(list.filter(p => !p.removedFromSubscriptionAt))
      if (!useAppStore.getState().serverSwitchingName) setActiveId(current.activeId ?? current.profile?.id ?? null)
    } catch {
      // keep the last list if IPC fails
    }
  }, [])

  useEffect(() => {
    if (!active) return
    void refresh()
    const id = window.setInterval(refresh, REFRESH_MS)
    const onChange = () => void refresh()
    window.addEventListener(SERVER_CHANGED_EVENT, onChange)
    return () => {
      seq.current++
      window.clearInterval(id)
      window.removeEventListener(SERVER_CHANGED_EVENT, onChange)
    }
  }, [active, refresh])

  // Endpoint RTTs depend on the route; measure again after connect/disconnect
  useEffect(() => {
    setPings({})
  }, [tunRunning])

  const pingOf = (p: ServerProfile): number | null => {
    const local = pings[p.id]
    if (local === 'pinging') return null
    if (local !== undefined) return local
    return p.ping ?? p.healthLatencyMs ?? null
  }

  // Cheap enough to recompute each render: a handful of rows
  let best: string | null = null
  let bestMs = Infinity
  for (const p of profiles) {
    const ms = pingOf(p)
    if ((p.healthStatus ?? p.status) !== 'offline' && ms !== null && ms < bestMs) { bestMs = ms; best = p.id }
  }

  const pingOne = async (p: ServerProfile) => {
    if (!p.server || !p.port) return
    setPings(prev => ({ ...prev, [p.id]: 'pinging' }))
    try {
      const ms = await window.electronAPI.serversPingOne(p.server, p.port)
      setPings(prev => ({ ...prev, [p.id]: ms }))
      announcePing({ id: p.id, ms })
    } catch {
      setPings(prev => ({ ...prev, [p.id]: null }))
      announcePing({ id: p.id, ms: null })
    }
  }

  const pingAll = async () => {
    setPingingAll(true)
    try {
      const updated = await window.electronAPI.serversPingAll()
      setPings({})
      setProfiles(updated.filter(p => !p.removedFromSubscriptionAt))
      announcePing({})
    } catch (err: unknown) {
      addLog('error', t('swiss.pingFailed') + ': ' + (isIpcRemoteErrorData(err) || err instanceof Error ? err.message : String(err)))
    } finally {
      setPingingAll(false)
    }
  }

  const select = async (p: ServerProfile) => {
    if (p.id === activeId) return
    if (useAppStore.getState().serverSwitchingName || useAppStore.getState().connectionBusy) return
    const animate = tunRunning && connectionMode === 'directVpn'
    if (animate) setServerSwitchingName(p.name)
    seq.current++
    try {
      const result = await window.electronAPI.serversSelect(p.id)
      if (result?.cancelled) {
        addLog('info', t('dashboard.serverSwitchCancelled'))
        return
      }
      setActiveId(p.id)
      addLog('info', t('swiss.serverSelected', { name: p.name }))
    } catch (err: unknown) {
      addLog('error', t('swiss.serverSelectFailed') + ': ' + (isIpcRemoteErrorData(err) || err instanceof Error ? err.message : String(err)))
    } finally {
      if (animate) setServerSwitchingName(null)
      emitServerChanged()
    }
  }

  return (
    <section className="swiss-panel">
      <PanelHead title={t('swiss.servers')} perch="servers">
        <button type="button" className="swiss-fact-action" onClick={() => void pingAll()} disabled={pingingAll || profiles.length === 0}>
          {pingingAll && <Loader2 className="mr-1 inline h-3 w-3 animate-spin" />}
          {t('swiss.pingAll')}
        </button>
      </PanelHead>
      <div className="swiss-panel-body">
        {profiles.length === 0 ? (
          <p className="swiss-empty">{t('swiss.serversEmpty')}</p>
        ) : (
          profiles.map(p => {
            const sel = p.id === activeId
            const ms = pingOf(p)
            const health = p.healthStatus ?? p.status
            const ago = minutesAgo(p.healthCheckedAt ?? p.lastChecked)
            return (
              <div
                key={p.id}
                className={cn('swiss-server-row group', sel && 'is-selected', health === 'offline' && !sel && 'is-offline')}
                data-perch={'server-' + p.id}
                data-perch-y="bottom"
                data-perch-x="0.55"
                data-perch-scale="0.3"
                data-perch-fit="gap"
              >
                <span className="swiss-server-flag">{p.country ? <CountryFlagIcon country={p.country} size={14} /> : null}</span>
                <button type="button" className="swiss-server-name" onClick={() => void select(p)} title={p.name}>
                  <span className="truncate">{p.name}</span>
                  {p.id === best && !sel && <span className="swiss-best">{t('swiss.best')}</span>}
                </button>
                <span className="swiss-mono swiss-server-ping">
                  {pings[p.id] === 'pinging' ? <Loader2 className="ml-auto h-3 w-3 animate-spin" /> : ms ?? '—'}
                </span>
                <span className={cn('swiss-mono swiss-server-health', health === 'offline' && 'is-offline')}>
                  {health === 'offline' ? (
                    <><span className="swiss-health-dot is-offline" />{t('swiss.offline')}</>
                  ) : health === 'unknown' ? (
                    <><span className="swiss-health-dot is-unknown" />{t('swiss.unchecked')}</>
                  ) : (
                    <><span className="swiss-health-dot" />{ago === null ? t('swiss.online') : t('swiss.minAgo', { n: ago })}</>
                  )}
                </span>
                <button type="button" className="swiss-server-ping-btn" onClick={() => void pingOne(p)} title={t('swiss.pingOne')} aria-label={t('swiss.pingOne') + ': ' + p.name}>
                  <RefreshCw className="h-3 w-3" />
                </button>
              </div>
            )
          })
        )}
      </div>
    </section>
  )
}
