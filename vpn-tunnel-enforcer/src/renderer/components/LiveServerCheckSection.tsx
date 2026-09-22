import { useEffect, useState, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Activity,
  Play,
  Square,
  Shield,
  Lock,
  Globe,
  Network,
  Server as ServerIcon,
  AlertTriangle,
  AlertCircle,
  Info,
  History,
  Route as RouteIcon,
  Zap,
  Layers,
  Compass,
  Gauge,
  ArrowRightLeft
} from 'lucide-react'
import { MacButton, MacCard, MacBadge } from '../design-system'
import type {
  LiveCheckFinding,
  LiveCheckProgress,
  LiveCheckStage,
  LiveCheckStatus,
  LiveServerCheck
} from '../../shared/ipc-types'
import { sanitizeHopLine, formatInfrastructureError } from '../../shared/hopFormatting'

interface LiveServerCheckSectionProps {
  profileId?: string
  host?: string
  port?: number
}

const STAGE_LABELS: Record<LiveCheckStage, string> = {
  dns: 'DNS резолвинг и DoH',
  reachability: 'TCP доступность и задержка',
  tls: 'TLS сертификат и шифрование',
  http: 'HTTP/HTTPS зондирование',
  ports: 'Сканирование портов',
  route: 'Трассировка маршрута',
  infrastructure: 'ASN и сетевые диффы',
  handshake: 'Рукопожатие туннеля',
  egress: 'Свежий exit IP (рефлекторы)',
  mediaStream: 'Twitch HLS и медиапотоки',
  path: 'Маршрутизация Windows',
  pmtu: 'PMTU и DF зондирование'
}

export function LiveServerCheckSection({
  profileId,
  host,
  port
}: LiveServerCheckSectionProps) {
  const { t } = useTranslation()
  const [mode, setMode] = useState<'basic' | 'extended'>('basic')
  const [running, setRunning] = useState(false)
  const [progress, setProgress] = useState<LiveCheckProgress | null>(null)
  const [result, setResult] = useState<LiveServerCheck | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [history, setHistory] = useState<LiveServerCheck[]>([])
  const [historyRetry, setHistoryRetry] = useState(0)
  const [showHistory, setShowHistory] = useState(false)

  const currentRequestIdRef = useRef<string | null>(null)
  const generationRef = useRef<number>(0)
  const lastSequenceRef = useRef<number>(0)

  useEffect(() => {
    const unsub = window.electronAPI?.onLiveCheckProgress?.((p) => {
      if (currentRequestIdRef.current && p.requestId === currentRequestIdRef.current) {
        if (p.sequence > lastSequenceRef.current) {
          lastSequenceRef.current = p.sequence
          setProgress(p)
        }
      }
    })
    return () => {
      unsub?.()
    }
  }, [])

  // Target change or unmount cleanup
  useEffect(() => {
    // Cancel in-flight check if target changed
    if (currentRequestIdRef.current) {
      window.electronAPI?.serverLiveCheckCancel?.(currentRequestIdRef.current).catch(() => {})
      currentRequestIdRef.current = null
    }

    const currentGen = ++generationRef.current
    setRunning(false)
    setProgress(null)
    setHistory([])
    setShowHistory(false)
    setResult(null)
    setError(null)

    if (!profileId && !host) return

    window.electronAPI
      ?.serverLiveCheckHistory?.({ profileId, host })
      .then((items) => {
        if (generationRef.current !== currentGen) return
        if (Array.isArray(items)) {
          items = items.filter(item => port === undefined || item.port === port)
          setHistory(items)
          if (items.length > 0) {
            setResult(items[0])
          }
        }
      })
      .catch(() => {
        if (generationRef.current === currentGen) setError('Не удалось загрузить историю проверок')
      })

    return () => {
      ++generationRef.current
      if (currentRequestIdRef.current) {
        window.electronAPI?.serverLiveCheckCancel?.(currentRequestIdRef.current).catch(() => {})
        currentRequestIdRef.current = null
      }
    }
  }, [profileId, host, port, historyRetry])

  const handleStartCheck = async () => {
    if (running || (!host && !profileId)) return

    const requestId = `req-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`
    currentRequestIdRef.current = requestId
    const checkGen = ++generationRef.current
    lastSequenceRef.current = 0

    setRunning(true)
    setProgress(null)
    setError(null)

    try {
      const checkResult = await window.electronAPI.serverLiveCheck({
        requestId,
        profileId,
        host,
        port,
        mode
      })

      // Generation and requestId guard: ignore if stale or cancelled
      if (generationRef.current === checkGen && currentRequestIdRef.current === requestId) {
        setResult(checkResult)
        setHistory((prev) => [
          checkResult,
          ...prev.filter((c) => c.id !== checkResult.id)
        ].slice(0, 20))
      }
    } catch (err: any) {
      if (generationRef.current === checkGen) {
        const rawErr = err?.message || t('liveCheck.error', 'Ошибка при выполнении проверки')
        setError(formatInfrastructureError(rawErr))
      }
    } finally {
      if (generationRef.current === checkGen) {
        setRunning(false)
        currentRequestIdRef.current = null
      }
    }
  }

  const handleCancel = async () => {
    const reqToCancel = currentRequestIdRef.current
    generationRef.current++
    currentRequestIdRef.current = null
    setRunning(false)

    if (reqToCancel) {
      try {
        await window.electronAPI.serverLiveCheckCancel(reqToCancel)
      } catch {}
    }
  }

  if (!host && !profileId) return null

  return (
    <MacCard className="!p-3 border border-[var(--color-border)]">
      {result?.portsError && (
        <div
          role="alert"
          className="flex items-center gap-2 p-2.5 mb-3 rounded-[var(--radius-sm)] bg-amber-500/10 border border-amber-500/30 text-amber-400 text-xs"
        >
          <AlertTriangle size={14} className="shrink-0" />
          <span>{result.portsError}</span>
        </div>
      )}
      {result?.infrastructure?.error && (
        <div
          role="alert"
          className="flex items-center gap-2 p-2.5 mb-3 rounded-[var(--radius-sm)] bg-amber-500/10 border border-amber-500/30 text-amber-400 text-xs"
        >
          <AlertTriangle size={14} className="shrink-0" />
          <span>{formatInfrastructureError(result.infrastructure.error)}</span>
        </div>
      )}
      {error && error !== 'Не удалось загрузить историю проверок' && (
        <div
          role="alert"
          className="flex items-center gap-2 p-2.5 mb-3 rounded-[var(--radius-sm)] bg-amber-500/10 border border-amber-500/30 text-amber-400 text-xs"
        >
          <AlertCircle size={14} className="shrink-0" />
          <span>{error}</span>
        </div>
      )}
      {error === 'Не удалось загрузить историю проверок' && (
        <div
          role="alert"
          className="flex items-center justify-between p-2.5 mb-3 rounded-[var(--radius-sm)] bg-red-500/10 border border-red-500/30 text-red-400 text-xs"
        >
          <div className="flex items-center gap-2">
            <AlertCircle size={14} className="shrink-0" />
            <span>{error}</span>
          </div>
          <MacButton
            variant="secondary"
            size="sm"
            onClick={() => setHistoryRetry(n => n + 1)}
          >
            Повторить загрузку истории
          </MacButton>
        </div>
      )}
      <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
        <div className="flex items-center gap-2">
          <Activity size={14} className={running ? 'animate-pulse text-[var(--color-accent)]' : 'text-[var(--color-accent)]'} />
          <h4 className="text-xs font-semibold uppercase tracking-wider text-[var(--color-text)]">
            {t('liveCheck.title', 'Live-проверка и аудит endpoint')}
          </h4>
        </div>

        <div className="flex items-center gap-1.5">
          {/* Mode Selector */}
          <div className="inline-flex rounded-[var(--radius-sm)] bg-[var(--color-bg-tertiary)] p-0.5 border border-[var(--color-border)] text-[11px]">
            <button
              type="button"
              onClick={() => setMode('basic')}
              disabled={running}
              className={`px-2 py-0.5 rounded-[var(--radius-xs)] font-medium transition-colors ${
                mode === 'basic'
                  ? 'bg-[var(--color-accent)] text-white'
                  : 'text-[var(--color-text-secondary)] hover:text-[var(--color-text)]'
              }`}
            >
              {t('liveCheck.modeBasic', 'Базовая')}
            </button>
            <button
              type="button"
              onClick={() => setMode('extended')}
              disabled={running}
              className={`px-2 py-0.5 rounded-[var(--radius-xs)] font-medium transition-colors ${
                mode === 'extended'
                  ? 'bg-[var(--color-accent)] text-white'
                  : 'text-[var(--color-text-secondary)] hover:text-[var(--color-text)]'
              }`}
            >
              {t('liveCheck.modeExtended', 'Расширенная')}
            </button>
          </div>

          {/* Run / Cancel Action */}
          {running ? (
            <MacButton size="sm" variant="danger" onClick={handleCancel}>
              <Square size={12} className="mr-1.5" />
              {t('common.cancel', 'Отмена')}
            </MacButton>
          ) : (
            <MacButton size="sm" variant="primary" onClick={handleStartCheck}>
              <Play size={12} className="mr-1.5" />
              {t('liveCheck.run', 'Проверить')}
            </MacButton>
          )}

          {history.length > 0 && (
            <MacButton
              size="sm"
              variant="ghost"
              onClick={() => setShowHistory(!showHistory)}
              title={t('liveCheck.historyTitle', 'История проверок')}
            >
              <History size={12} className="mr-1" />
              {history.length}
            </MacButton>
          )}
        </div>
      </div>

      {running && progress && (() => {
        const currentStep = Math.min(
          progress.completedStages + (progress.status === 'running' ? 1 : 0),
          progress.totalStages
        )
        return (
          <div className="mb-3 p-2.5 rounded-[var(--radius-sm)] bg-[var(--color-bg-secondary)] border border-[var(--color-accent)]/40 text-xs shadow-sm">
            <div className="flex items-center justify-between mb-1.5">
              <div className="flex items-center gap-2">
                <span className="relative flex h-2 w-2">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[var(--color-accent)] opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-[var(--color-accent)]"></span>
                </span>
                <span className="font-medium text-[var(--color-text)]">
                  {STAGE_LABELS[progress.stage] || progress.stage}
                </span>
              </div>
              <div className="text-[11px] text-[var(--color-text-secondary)] font-mono">
                Этап {currentStep} из {progress.totalStages} • {(progress.elapsedMs / 1000).toFixed(1)}с
              </div>
            </div>
            <div className="w-full h-1.5 bg-[var(--color-bg-tertiary)] rounded-full overflow-hidden">
              <div
                className="h-full bg-[var(--color-accent)] transition-all duration-300 rounded-full"
                style={{
                  width: `${Math.min(100, Math.max(5, (currentStep / progress.totalStages) * 100))}%`
                }}
              />
            </div>
          </div>
        )
      })()}

      {mode === 'extended' && (
        <p className="text-[11px] text-[var(--color-warning)] mb-3 flex items-center gap-1.5">
          <AlertTriangle size={12} />
          {t(
            'liveCheck.extendedWarning',
            'Расширенная проверка выполняет зондирование портов (80..2096), CNAME-цепочки и трассировку маршрута.'
          )}
        </p>
      )}

      {error && (
        <div className="p-2 mb-3 rounded-[var(--radius-sm)] bg-[var(--color-danger)]/10 text-[var(--color-danger)] text-xs flex items-center gap-2">
          <AlertCircle size={14} />
          <span>{error}</span>
        </div>
      )}

      {/* History Drawer */}
      <AnimatePresence>
        {showHistory && history.length > 0 && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="mb-3 p-2.5 rounded-[var(--radius-sm)] bg-[var(--color-bg-secondary)] border border-[var(--color-border)] text-xs"
          >
            <div className="flex items-center justify-between mb-2">
              <span className="font-medium text-[var(--color-text-secondary)]">
                {t('liveCheck.recentChecks', 'Недавние проверки (до 20)')}
              </span>
              <span className="text-[11px] text-[var(--color-text-secondary)]">
                {history.length} записей
              </span>
            </div>
            <div className="space-y-1.5 max-h-40 overflow-y-auto pr-1">
              {history.map((h, i) => (
                <div
                  key={h.id || `${h.startedAt}-${i}`}
                  onClick={() => setResult(h)}
                  className={`p-1.5 rounded cursor-pointer transition-colors flex items-center justify-between text-[11px] ${
                    result?.id === h.id
                      ? 'bg-[var(--color-accent)]/15 border border-[var(--color-accent)]/30'
                      : 'hover:bg-[var(--color-bg-tertiary)]'
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <StatusDot status={h.reachability?.status || 'ok'} />
                    <span className="font-mono text-[10px]">
                      {new Date(h.startedAt).toLocaleTimeString()}
                    </span>
                    <MacBadge variant="neutral" className="text-[10px]">
                      {h.mode}
                    </MacBadge>
                    {h.dns?.a?.[0] && (
                      <span className="font-mono text-[10px] text-[var(--color-text-secondary)]">
                        {h.dns.a[0]}
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                    {h.latency && (
                      <span className="text-[var(--color-text)] font-semibold">
                        {h.latency.avg} ms
                      </span>
                    )}
                    {h.infrastructure?.changesFromPrevious &&
                      Object.values(h.infrastructure.changesFromPrevious).some(Boolean) && (
                        <span title="Сетевые диффы обнаружены">
                          <MacBadge variant="warning" className="text-[8px] py-0 px-1">
                            Diff
                          </MacBadge>
                        </span>
                      )}
                    {h.findings?.length > 0 && (
                      <MacBadge
                        variant={
                          h.findings.some((f) => f.severity === 'error')
                            ? 'danger'
                            : h.findings.some((f) => f.severity === 'warning')
                              ? 'warning'
                              : 'neutral'
                        }
                        className="text-[9px]"
                      >
                        {h.findings.length} findings
                      </MacBadge>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Main Result Display */}
      {result && (
        <div className="space-y-3">
          {/* Header Bar: Status, Duration, FinishedAt */}
          <div className="flex flex-wrap items-center justify-between text-xs py-1 px-2 rounded bg-[var(--color-bg-secondary)] text-[var(--color-text-secondary)]">
            <div className="flex items-center gap-2">
              <StatusDot status={result.reachability?.status || 'ok'} />
              <span>
                {result.reachability?.tcpReachable
                  ? t('liveCheck.reachable', 'Endpoint отвечает по TCP')
                  : t('liveCheck.unreachable', 'Endpoint недоступен')}
              </span>
              <MacBadge variant={result.mode === 'extended' ? 'info' : 'neutral'} className="text-[10px]">
                {result.mode}
              </MacBadge>
              {result.cancelled && (
                <MacBadge variant="warning" className="text-[10px]">
                  {t('liveCheck.cancelled', 'Отменено')}
                </MacBadge>
              )}
            </div>
            <div className="flex items-center gap-2 text-[11px]">
              <span title="Время проверки">
                {new Date(result.finishedAt).toLocaleTimeString()}
              </span>
              <span>•</span>
              <span>{result.durationMs} ms</span>
            </div>
          </div>

          {/* Findings List */}
          {result.findings && result.findings.length > 0 && (
            <div className="space-y-1.5">
              <h5 className="text-[11px] font-semibold text-[var(--color-text-secondary)] uppercase tracking-wider">
                {t('liveCheck.findings', 'Диагностические находки')} ({result.findings.length})
              </h5>
              <div className="space-y-1">
                {result.findings.map((f, i) => (
                  <FindingCard key={f.code + i} finding={f} />
                ))}
              </div>
            </div>
          )}

          {/* Detailed Diagnostic Sections */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
            {/* DNS Block */}
            <DiagnosticBox
              icon={<Network size={12} />}
              title="DNS"
              status={result.dns?.status}
              durationMs={result.dns?.durationMs}
            >
              <div className="space-y-1.5 text-[11px]">
                {result.dns?.a && result.dns.a.length > 0 && (
                  <div>
                    <div className="text-[var(--color-text-secondary)] text-[10px]">IPv4 (A):</div>
                    <div className="flex flex-wrap gap-1 mt-0.5">
                      {result.dns.a.map((ip) => (
                        <span key={ip} className="font-mono px-1 rounded bg-[var(--color-bg-tertiary)] border border-[var(--color-border)]">
                          {ip}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                {result.dns?.aaaa && result.dns.aaaa.length > 0 && (
                  <div>
                    <div className="text-[var(--color-text-secondary)] text-[10px]">IPv6 (AAAA):</div>
                    <div className="flex flex-wrap gap-1 mt-0.5">
                      {result.dns.aaaa.map((ip) => (
                        <span key={ip} className="font-mono text-[10px] px-1 rounded bg-[var(--color-bg-tertiary)] border border-[var(--color-border)]">
                          {ip}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                {result.dns?.cnameChain && result.dns.cnameChain.length > 0 && (
                  <div>
                    <div className="text-[var(--color-text-secondary)] text-[10px]">CNAME chain:</div>
                    <div className="font-mono text-[10px] text-[var(--color-text-secondary)] truncate">
                      {result.dns.cnameChain.join(' → ')}
                    </div>
                  </div>
                )}
                {result.dns?.ttl !== undefined && (
                  <div className="flex justify-between text-[11px]">
                    <span className="text-[var(--color-text-secondary)]">TTL:</span>
                    <span className="font-mono">{result.dns.ttl}s</span>
                  </div>
                )}
                {result.reverseDns && result.reverseDns.length > 0 && (
                  <div>
                    <div className="text-[var(--color-text-secondary)] text-[10px]">Reverse DNS:</div>
                    <div className="font-mono text-[10px] text-[var(--color-text)] truncate">
                      {result.reverseDns.join(', ')}
                    </div>
                  </div>
                )}
                {/* Multi-resolver Comparison Table */}
                {result.dns?.resolvers && result.dns.resolvers.length > 0 && (
                  <div className="pt-1 border-t border-[var(--color-border)]">
                    <div className="text-[10px] text-[var(--color-text-secondary)] mb-1">Сравнение резолверов:</div>
                    <div className="space-y-1 bg-[var(--color-bg-tertiary)] p-1.5 rounded">
                      {result.dns.resolvers.map((res, i) => {
                        const addresses = res.records.map((r) => r.value)
                        return (
                          <div key={i} className="flex items-center justify-between text-[10px]">
                            <div className="flex items-center gap-1">
                              <span className="font-mono font-medium text-[var(--color-text)]">
                                {res.resolverName || res.resolverId}
                              </span>
                              {res.authenticatedData && (
                                <span title="Флаг Authenticated Data ответа резолвера (DNSSEC)">
                                  <MacBadge
                                    variant="success"
                                    className="text-[8px] py-0 px-1"
                                  >
                                    AD (DNSSEC)
                                  </MacBadge>
                                </span>
                              )}
                              {res.status === 'partial' && (
                                <span title={res.error || 'Частичный ответ'}>
                                  <MacBadge variant="warning" className="text-[8px] py-0 px-1">
                                    Частично
                                  </MacBadge>
                                </span>
                              )}
                            </div>
                            <div className="flex items-center gap-1.5 font-mono text-[9px]">
                              {res.status === 'error' && res.error ? (
                                <span className="text-[var(--color-danger)]">{res.error}</span>
                              ) : (
                                <>
                                  <span className="text-[var(--color-text-secondary)]">{res.durationMs}ms</span>
                                  <span className="truncate max-w-[110px]" title={addresses.join(', ')}>
                                    {addresses.slice(0, 2).join(', ')}{addresses.length > 2 ? ` +${addresses.length - 2}` : ''}
                                  </span>
                                </>
                              )}
                            </div>
                          </div>
                        )
                      })}
                    </div>
                  </div>
                )}
                {/* Discrepancies */}
                {result.dns?.discrepancies && result.dns.discrepancies.length > 0 && (
                  <div className="space-y-0.5 pt-0.5">
                    {result.dns.discrepancies.map((d, i) => (
                      <div key={i} className="text-[10px] text-amber-400 flex items-center gap-1">
                        <AlertTriangle size={10} className="shrink-0" />
                        <span>{d}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </DiagnosticBox>

            {/* Latency & Stability Block */}
            <DiagnosticBox
              icon={<Activity size={12} />}
              title="Задержка и стабильность"
              status={result.reachability?.status}
              durationMs={result.reachability?.durationMs}
            >
              {result.latency ? (
                <div className="space-y-1.5 text-[11px]">
                  <div className="grid grid-cols-4 gap-1 text-center py-1 rounded bg-[var(--color-bg-tertiary)] font-mono">
                    <div>
                      <div className="text-[9px] text-[var(--color-text-secondary)]">MIN</div>
                      <div>{result.latency.min} ms</div>
                    </div>
                    <div>
                      <div className="text-[9px] text-[var(--color-text-secondary)]">AVG</div>
                      <div className="font-bold text-[var(--color-accent)]">{result.latency.avg} ms</div>
                    </div>
                    <div>
                      <div className="text-[9px] text-[var(--color-text-secondary)]">MEDIAN</div>
                      <div>{result.latency.median} ms</div>
                    </div>
                    <div>
                      <div className="text-[9px] text-[var(--color-text-secondary)]">MAX</div>
                      <div>{result.latency.max} ms</div>
                    </div>
                  </div>
                  <div className="flex justify-between text-[11px] pt-1">
                    <span className="text-[var(--color-text-secondary)]">Jitter:</span>
                    <span className="font-mono">{result.latency.jitter} ms</span>
                  </div>
                  <div className="flex justify-between text-[11px]">
                    <span className="text-[var(--color-text-secondary)]">Отказы TCP соединений:</span>
                    <span className={`font-mono ${result.latency.loss > 0 ? 'text-[var(--color-danger)]' : 'text-[var(--color-success)]'}`}>
                      {Math.round(result.latency.loss * 100)}% ({result.latency.samplesAttempted !== undefined ? `${result.latency.samplesAttempted - (result.latency.samplesSucceeded ?? result.latency.samples?.length ?? 0)}/${result.latency.samplesAttempted}` : ''})
                    </span>
                  </div>
                  <div className="flex justify-between text-[11px]">
                    <span className="text-[var(--color-text-secondary)]">Путь:</span>
                    <MacBadge variant="neutral" className="text-[10px]">
                      Маршрут выбран ОС (не измерен); TUN: {result.latency.tunRunning === undefined ? 'нет данных' : result.latency.tunRunning ? 'включён' : 'выключен'}
                    </MacBadge>
                  </div>
                </div>
              ) : (
                <div className="text-[11px] text-[var(--color-text-secondary)]">
                  {result.reachability?.error || 'Данные задержки недоступны'}
                </div>
              )}
            </DiagnosticBox>

            {/* TLS Certificate Block */}
            {result.tls && (
              <DiagnosticBox
                icon={<Lock size={12} />}
                title="TLS Сертификат"
                status={result.tls.status}
                durationMs={result.tls.durationMs}
              >
                <div className="space-y-1 text-[11px]">
                  {result.tls.subject && (
                    <div className="flex justify-between">
                      <span className="text-[var(--color-text-secondary)]">Subject:</span>
                      <span className="font-mono truncate max-w-[160px]" title={result.tls.subject}>
                        {result.tls.subject}
                      </span>
                    </div>
                  )}
                  {result.tls.issuer && (
                    <div className="flex justify-between">
                      <span className="text-[var(--color-text-secondary)]">Issuer:</span>
                      <span className="font-mono truncate max-w-[160px]" title={result.tls.issuer}>
                        {result.tls.issuer}
                      </span>
                    </div>
                  )}
                  {result.tls.daysRemaining !== undefined && (
                    <div className="flex justify-between items-center">
                      <span className="text-[var(--color-text-secondary)]">Срок действия:</span>
                      <MacBadge
                        variant={
                          result.tls.daysRemaining <= 7
                            ? 'danger'
                            : result.tls.daysRemaining <= 30
                              ? 'warning'
                              : 'success'
                        }
                        className="text-[10px]"
                      >
                        {result.tls.daysRemaining} дн. (до {result.tls.validTo?.split('T')?.[0] || result.tls.validTo})
                      </MacBadge>
                    </div>
                  )}
                  {result.tls.protocol && (
                    <div className="flex justify-between">
                      <span className="text-[var(--color-text-secondary)]">Протокол / Cipher:</span>
                      <span className="font-mono text-[10px] truncate max-w-[180px]">
                        {result.tls.protocol} {result.tls.cipher ? `(${result.tls.cipher})` : ''}
                      </span>
                    </div>
                  )}
                  {result.tls.alpn && (
                    <div className="flex justify-between">
                      <span className="text-[var(--color-text-secondary)]">ALPN:</span>
                      <span className="font-mono text-[10px]">{result.tls.alpn}</span>
                    </div>
                  )}
                  {result.tls.hostnameVerified !== undefined && (
                    <div className="flex justify-between items-center pt-0.5">
                      <span className="text-[var(--color-text-secondary)]">SAN совпадение:</span>
                      <span className={`text-[10px] font-medium ${result.tls.hostnameVerified ? 'text-[var(--color-success)]' : 'text-[var(--color-danger)]'}`}>
                        {result.tls.hostnameVerified ? 'Совпадает с SAN' : 'Не совпадает!'}
                      </span>
                    </div>
                  )}
                  {result.tls.authorized !== undefined && !result.tls.authorized && (
                    <div className="flex justify-between items-center pt-0.5">
                      <span className="text-[var(--color-text-secondary)]">Цепочка:</span>
                      <MacBadge variant="warning" className="text-[9px]">
                        {result.tls.authorizationError || 'Самоподписанный / не доверен'}
                      </MacBadge>
                    </div>
                  )}
                  {result.tls.fingerprint && (
                    <div className="pt-0.5">
                      <div className="text-[10px] text-[var(--color-text-secondary)]">SHA-256 Fingerprint:</div>
                      <div className="font-mono text-[9px] text-[var(--color-text)] break-all select-all">
                        {result.tls.fingerprint}
                      </div>
                    </div>
                  )}
                  <div className="text-[9px] text-[var(--color-text-secondary)] pt-1">
                    * Для Reality TLS-зонд видит маскировочный домен, а не внутренний VPN-бэкенд.
                  </div>
                </div>
              </DiagnosticBox>
            )}

            {/* HTTP Diagnostic Block */}
            {result.http && (
              <DiagnosticBox
                icon={<Globe size={12} />}
                title="HTTP Диагностика"
                status={result.http.status}
                durationMs={result.http.durationMs}
              >
                <div className="space-y-1 text-[11px]">
                  <div className="flex justify-between items-center">
                    <span className="text-[var(--color-text-secondary)]">Статус ответа:</span>
                    <MacBadge
                      variant={
                        result.http.statusCode && result.http.statusCode < 400
                          ? 'success'
                          : result.http.statusCode && result.http.statusCode < 500
                            ? 'warning'
                            : 'neutral'
                      }
                      className="font-mono text-[10px]"
                    >
                      {result.http.statusCode ? `HTTP ${result.http.statusCode}` : 'Нет ответа'}
                    </MacBadge>
                  </div>
                  {result.http.targetPort && (
                    <div className="flex justify-between">
                      <span className="text-[var(--color-text-secondary)]">Проверенный порт:</span>
                      <span className="font-mono">{result.http.targetPort} ({result.http.isTls ? 'HTTPS' : 'HTTP'})</span>
                    </div>
                  )}
                  {result.http.serverHeader && (
                    <div className="flex justify-between">
                      <span className="text-[var(--color-text-secondary)]">Server:</span>
                      <span className="font-mono truncate max-w-[160px]">{result.http.serverHeader}</span>
                    </div>
                  )}
                  {result.http.viaHeader && (
                    <div className="flex justify-between">
                      <span className="text-[var(--color-text-secondary)]">Via:</span>
                      <span className="font-mono truncate max-w-[160px]">{result.http.viaHeader}</span>
                    </div>
                  )}
                  {result.http.locationHeader && (
                    <div className="flex justify-between">
                      <span className="text-[var(--color-text-secondary)]">Location:</span>
                      <span className="font-mono truncate max-w-[160px]" title={result.http.locationHeader}>
                        {result.http.locationHeader}
                      </span>
                    </div>
                  )}
                  <div className="text-[9px] text-[var(--color-text-secondary)] pt-1">
                    * Диагностический признак, не является доказательством безопасности сервиса.
                  </div>
                </div>
              </DiagnosticBox>
            )}

            {/* Ports Scan Block */}
            {result.openPorts && result.openPorts.length > 0 && (
              <DiagnosticBox
                icon={<ServerIcon size={12} />}
                title="Проверенные порты"
                status="ok"
              >
                <div className="space-y-1.5 text-[11px]">
                  <div className="flex flex-wrap gap-1">
                    {result.openPorts.map((p) => (
                      <MacBadge
                        key={p.port}
                        variant={p.open ? 'success' : 'neutral'}
                        className="font-mono text-[10px]"
                      >
                        {p.port} {p.service ? `(${p.service})` : ''}: {p.state}
                      </MacBadge>
                    ))}
                  </div>
                  <div className="text-[9px] text-[var(--color-text-secondary)]">
                    * Открытый порт не означает активный VPN-протокол.
                  </div>
                </div>
              </DiagnosticBox>
            )}

            {/* Route Diagnostics Block */}
            {result.route && (
              <DiagnosticBox
                icon={<RouteIcon size={12} />}
                title="Маршрут до endpoint"
                status={result.route.status}
                durationMs={result.route.durationMs}
              >
                <div className="space-y-1 text-[11px]">
                  <div className="flex justify-between items-center">
                    <span className="text-[var(--color-text-secondary)]">Число хопов:</span>
                    <span className="font-mono font-bold">
                      {result.route.hops !== undefined ? result.route.hops : '—'}
                    </span>
                  </div>
                  {result.route.reachedTarget !== undefined && (
                    <div className="flex justify-between items-center">
                      <span className="text-[var(--color-text-secondary)]">Достижение цели:</span>
                      <MacBadge variant={result.route.reachedTarget ? 'success' : 'warning'} className="text-[10px]">
                        {result.route.reachedTarget ? 'Достигнут' : 'Не завершено'}
                      </MacBadge>
                    </div>
                  )}
                  {result.route.hopDetails && result.route.hopDetails.length > 0 && (
                    <div className="pt-1">
                      <div className="text-[10px] text-[var(--color-text-secondary)] mb-0.5">Хопы трассировки:</div>
                      <div className="bg-[var(--color-bg-tertiary)] p-1 rounded font-mono text-[9px] max-h-20 overflow-y-auto space-y-0.5">
                        {result.route.hopDetails.map((h, i) => (
                          <div key={i} className="truncate">
                            {sanitizeHopLine(typeof h === 'string' ? h : String(h))}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {result.route.error && (
                    <div className="text-[10px] text-[var(--color-warning)] pt-0.5">
                      {result.route.error}
                    </div>
                  )}
                </div>
              </DiagnosticBox>
            )}

            {/* Infrastructure & Diffs Block */}
            <DiagnosticBox
              icon={<Shield size={12} />}
              title="Инфраструктура и диффы"
              status="ok"
            >
              <div className="space-y-1 text-[11px]">
                {result.asn && (
                  <div className="flex justify-between">
                    <span className="text-[var(--color-text-secondary)]">ASN / Org:</span>
                    <span className="font-mono text-[10px] truncate max-w-[160px]" title={`${result.asn.asn} ${result.asn.org}`}>
                      {result.asn.asn} {result.asn.org}
                    </span>
                  </div>
                )}
                {result.infrastructure?.endpointCountry && (
                  <div className="flex justify-between">
                    <span className="text-[var(--color-text-secondary)]">Страна endpoint:</span>
                    <span>{result.infrastructure.endpointCountry}</span>
                  </div>
                )}
                {result.infrastructure?.activeTunnelMatchesProfile && result.infrastructure?.egressCountry && (
                  <div className="flex justify-between">
                    <span className="text-[var(--color-text-secondary)]">Страна egress (активный VPN):</span>
                    <span>{result.infrastructure.egressCountry} (из профиля; время измерения неизвестно)</span>
                  </div>
                )}
                {result.infrastructure?.sharedCidrWithProfiles && (
                  <div className="text-[10px] text-[var(--color-accent)] pt-1">
                    Общая /24 подсеть с {result.infrastructure.sharedCidrWithProfiles.length} серверами
                  </div>
                )}
                {result.infrastructure?.changesFromPrevious && (
                  <div className="pt-1 flex flex-wrap gap-1">
                    {result.infrastructure.changesFromPrevious.ipChanged && (
                      <MacBadge variant="warning" className="text-[9px]">IP изменился</MacBadge>
                    )}
                    {result.infrastructure.changesFromPrevious.tlsCertChanged && (
                      <MacBadge variant="warning" className="text-[9px]">TLS отпечаток изменился</MacBadge>
                    )}
                    {result.infrastructure.changesFromPrevious.asnChanged && (
                      <MacBadge variant="warning" className="text-[9px]">ASN изменился</MacBadge>
                    )}
                    {result.infrastructure.changesFromPrevious.countryChanged && (
                      <MacBadge variant="warning" className="text-[9px]">Страна изменилась</MacBadge>
                    )}
                    {result.infrastructure.changesFromPrevious.latencySpike && (
                      <MacBadge variant="danger" className="text-[9px]">Всплеск задержки</MacBadge>
                    )}
                    {result.infrastructure.changesFromPrevious.portsChanged && (
                      <MacBadge variant="neutral" className="text-[9px]">Порты изменились</MacBadge>
                    )}
                    {result.infrastructure.changesFromPrevious.handshakeChanged && (
                      <MacBadge variant="warning" className="text-[9px]">Handshake изменился</MacBadge>
                    )}
                    {result.infrastructure.changesFromPrevious.egressChanged && (
                      <MacBadge variant="warning" className="text-[9px]">Egress IP изменился</MacBadge>
                    )}
                    {result.infrastructure.changesFromPrevious.pmtuChanged && (
                      <MacBadge variant="info" className="text-[9px]">PMTU изменился</MacBadge>
                    )}
                  </div>
                )}
              </div>
            </DiagnosticBox>

            {/* Tunnel Handshake Block */}
            {result.handshake && (
              <DiagnosticBox
                icon={<Zap size={12} />}
                title="Рукопожатие туннеля (Handshake)"
                status={result.handshake.status}
                durationMs={result.handshake.durationMs}
              >
                <div className="space-y-1.5 text-[11px]">
                  <div className="flex justify-between items-center">
                    <span className="text-[var(--color-text-secondary)]">Протокол:</span>
                    <MacBadge variant="info" className="font-mono text-[10px] uppercase">
                      {result.handshake.protocol || '—'}
                    </MacBadge>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-[var(--color-text-secondary)]">Статус проверки:</span>
                    <MacBadge
                      variant={
                        result.handshake.status === 'ok'
                          ? 'success'
                          : result.handshake.status === 'auth_failed'
                            ? 'danger'
                            : 'warning'
                      }
                      className="text-[10px]"
                    >
                      {result.handshake.status === 'ok'
                        ? 'Успешно (handshake ok)'
                        : result.handshake.status === 'auth_failed'
                          ? 'Ошибка аутентификации'
                          : result.handshake.status === 'transport_failed'
                            ? 'Сбой транспорта'
                            : result.handshake.status === 'timeout'
                              ? 'Таймаут соединения'
                              : result.handshake.status}
                    </MacBadge>
                  </div>
                  {result.handshake.durationMs !== undefined && (
                    <div className="flex justify-between">
                      <span className="text-[var(--color-text-secondary)]">Время установления:</span>
                      <span className="font-mono">{result.handshake.durationMs} ms</span>
                    </div>
                  )}
                  {result.handshake.evidence && (
                    <div className="pt-0.5">
                      <div className="text-[10px] text-[var(--color-text-secondary)]">Свидетельство:</div>
                      <div className="font-mono text-[9px] text-[var(--color-text-secondary)] bg-[var(--color-bg-tertiary)] p-1 rounded max-h-16 overflow-y-auto break-all">
                        {result.handshake.evidence.detail ||
                          result.handshake.evidence.transport ||
                          JSON.stringify(result.handshake.evidence)}
                      </div>
                    </div>
                  )}
                  {result.handshake.error && (
                    <div className="text-[10px] text-[var(--color-danger)] pt-0.5">
                      {result.handshake.error}
                    </div>
                  )}
                </div>
              </DiagnosticBox>
            )}

            {/* Fresh Egress Verification Block */}
            {result.egress && (
              <DiagnosticBox
                icon={<ArrowRightLeft size={12} />}
                title="Свежий Egress (Выходной IP)"
                status={result.egress.status}
                durationMs={result.egress.durationMs}
              >
                <div className="space-y-1.5 text-[11px]">
                  <div className="flex justify-between items-center">
                    <span className="text-[var(--color-text-secondary)]">Egress IPv4:</span>
                    <span className="font-mono font-bold text-[var(--color-accent)]">
                      {result.egress.exitIpv4 || 'Не определён'}
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-[var(--color-text-secondary)]">Egress IPv6:</span>
                    <span className="font-mono text-[var(--color-text)]">
                      {result.egress.exitIpv6 || (result.egress.ipv6Status === 'unsupported' ? 'Не поддерживается туннелем' : 'Не определён')}
                    </span>
                  </div>
                  {result.egress.country && (
                    <div className="flex justify-between">
                      <span className="text-[var(--color-text-secondary)]">Страна выхода:</span>
                      <span>{result.egress.country}</span>
                    </div>
                  )}
                  <div className="flex justify-between items-center pt-0.5">
                    <span className="text-[var(--color-text-secondary)]">Сравнение с Endpoint:</span>
                    <MacBadge
                      variant={result.egress.matchesEndpoint ? 'success' : 'neutral'}
                      className="text-[10px]"
                    >
                      {result.egress.matchesEndpoint ? 'Совпадает с Endpoint' : 'Отличается (Dual-hop/NAT)'}
                    </MacBadge>
                  </div>
                  {result.egress.underlayPath && result.egress.underlayPath !== 'unknown' && (
                    <div className="flex justify-between items-center pt-0.5">
                      <span className="text-[var(--color-text-secondary)]">Путь транспорта:</span>
                      <MacBadge variant="neutral" className="text-[10px]">
                        {result.egress.underlayPath === 'route-selected' ? 'По таблице ОС' : result.egress.underlayPath}
                      </MacBadge>
                    </div>
                  )}
                  {result.egress.reflectors && result.egress.reflectors.length > 0 && (
                    <div className="pt-1">
                      <div className="text-[10px] text-[var(--color-text-secondary)] mb-0.5">Независимые рефлекторы:</div>
                      <div className="space-y-0.5 bg-[var(--color-bg-tertiary)] p-1 rounded font-mono text-[9px]">
                        {result.egress.reflectors.map((r, i) => (
                          <div key={i} className="flex justify-between">
                            <span className="text-[var(--color-text-secondary)]">{r.source}:</span>
                            <span>{r.ip || r.error || 'нет данных'} {r.country ? `(${r.country})` : ''}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {result.egress.error && (
                    <div className="text-[10px] text-[var(--color-danger)] pt-0.5">
                      {result.egress.error}
                    </div>
                  )}
                </div>
              </DiagnosticBox>
            )}

            {/* Windows Path Routing Block */}
            {result.pathDiagnostics && (
              <DiagnosticBox
                icon={<Compass size={12} />}
                title="Маршрутизация Windows"
                status={result.pathDiagnostics.status}
                durationMs={result.pathDiagnostics.durationMs}
              >
                <div className="space-y-1.5 text-[11px]">
                  <div className="flex justify-between items-center">
                    <span className="text-[var(--color-text-secondary)]">Интерфейс:</span>
                    <span className="font-mono font-medium truncate max-w-[160px]" title={result.pathDiagnostics.activeInterfaceAlias}>
                      {result.pathDiagnostics.activeInterfaceAlias || `Index ${result.pathDiagnostics.activeInterfaceIndex ?? '—'}`}
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-[var(--color-text-secondary)]">Тип маршрута:</span>
                    <MacBadge
                      variant={result.pathDiagnostics.status === 'ok' ? (result.pathDiagnostics.isTunInterface ? 'info' : 'neutral') : 'warning'}
                      className="text-[10px]"
                    >
                      {result.pathDiagnostics.status !== 'ok'
                        ? 'Маршрут не определён'
                        : result.pathDiagnostics.isTunInterface
                          ? 'TUN интерфейс (по таблице ОС)'
                          : 'Физический адаптер (по таблице ОС)'}
                    </MacBadge>
                  </div>
                  {result.pathDiagnostics.nextHop && (
                    <div className="flex justify-between">
                      <span className="text-[var(--color-text-secondary)]">Шлюз (NextHop):</span>
                      <span className="font-mono text-[10px]">{result.pathDiagnostics.nextHop}</span>
                    </div>
                  )}
                  {result.pathDiagnostics.activeLocalIp && (
                    <div className="flex justify-between">
                      <span className="text-[var(--color-text-secondary)]">Локальный IP:</span>
                      <span className="font-mono text-[10px]">{result.pathDiagnostics.activeLocalIp}</span>
                    </div>
                  )}
                  {result.pathDiagnostics.error && (
                    <div className="text-[10px] text-[var(--color-warning)] pt-0.5">
                      {result.pathDiagnostics.error}
                    </div>
                  )}
                </div>
              </DiagnosticBox>
            )}

            {/* PMTU Discovery Block */}
            {result.pmtu && (
              <DiagnosticBox
                icon={<Gauge size={12} />}
                title="PMTU и фрагментация"
                status={result.pmtu.status}
                durationMs={result.pmtu.durationMs}
              >
                <div className="space-y-1.5 text-[11px]">
                  <div className="flex justify-between items-center">
                    <span className="text-[var(--color-text-secondary)]">Определённый MTU:</span>
                    <span className="font-mono font-bold text-[var(--color-accent)] text-xs">
                      {result.pmtu.pmtu ? `${result.pmtu.pmtu} B` : 'Не определён'}
                    </span>
                  </div>
                  {result.pmtu.minTested !== undefined && result.pmtu.maxTested !== undefined && (
                    <div className="flex justify-between items-center">
                      <span className="text-[var(--color-text-secondary)]">Интервал:</span>
                      <span className="font-mono text-[10px]">[{result.pmtu.minTested} .. {result.pmtu.maxTested}] B</span>
                    </div>
                  )}
                  <div className="flex justify-between items-center">
                    <span className="text-[var(--color-text-secondary)]">Метод:</span>
                    <MacBadge variant="neutral" className="text-[10px]">
                      {result.pmtu.method === 'icmp-df'
                        ? 'ICMP DF ladder (пинг)'
                        : result.pmtu.method === 'interface-nlmtu'
                          ? 'MTU интерфейса'
                          : result.pmtu.method}
                    </MacBadge>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-[var(--color-text-secondary)]">Статус PMTU:</span>
                    <MacBadge
                      variant={
                        result.pmtu.status === 'ok'
                          ? 'success'
                          : result.pmtu.status === 'lower_bound'
                            ? (result.pmtu.pmtu && result.pmtu.pmtu >= 1420 ? 'success' : 'warning')
                            : 'danger'
                      }
                      className="text-[10px]"
                    >
                      {result.pmtu.status === 'ok'
                        ? 'Стабильно'
                        : result.pmtu.status === 'lower_bound'
                          ? (result.pmtu.pmtu && result.pmtu.pmtu >= 1420 ? `Не менее ${result.pmtu.pmtu} B` : `Пониженный MTU (≥${result.pmtu.pmtu} B)`)
                          : result.pmtu.status === 'blackhole_suspected'
                            ? 'Подозрение на Blackhole'
                            : result.pmtu.status === 'icmp_blocked'
                              ? 'ICMP заблокирован'
                              : 'Ошибка зондирования'}
                    </MacBadge>
                  </div>
                  {result.pmtu.detail && (
                    <div className="text-[10px] text-[var(--color-text-secondary)] pt-0.5">
                      {result.pmtu.detail}
                    </div>
                  )}
                  {result.pmtu.error && (
                    <div className="text-[10px] text-[var(--color-danger)] pt-0.5">
                      {result.pmtu.error}
                    </div>
                  )}
                </div>
              </DiagnosticBox>
            )}

            {/* Twitch & HLS Media Stream Diagnostics Block */}
            {result.mediaStream && (
              <DiagnosticBox
                icon={<Activity size={12} />}
                title="Twitch HLS и медиапотоки"
                status={result.mediaStream.status}
                durationMs={result.mediaStream.durationMs}
              >
                <div className="space-y-1.5 text-[11px]">
                  <div className="flex justify-between items-center">
                    <span className="text-[var(--color-text-secondary)]">Twitch HLS CDN:</span>
                    <MacBadge
                      variant={result.mediaStream.twitchHlsReachable ? 'success' : 'danger'}
                      className="text-[10px]"
                    >
                      {result.mediaStream.twitchHlsReachable ? 'Доступен (TCP/TLS)' : 'Недоступен'}
                    </MacBadge>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-[var(--color-text-secondary)]">Защита от QUIC Blackhole:</span>
                    <MacBadge
                      variant={result.mediaStream.quicFallbackGuarded ? 'success' : 'warning'}
                      className="text-[10px]"
                    >
                      {result.mediaStream.quicFallbackGuarded ? 'Активна (UDP/443 guard)' : 'Не активна'}
                    </MacBadge>
                  </div>
                  {result.mediaStream.error2000Risk && (
                    <div className="flex justify-between items-center pt-0.5">
                      <span className="text-[var(--color-text-secondary)]">Риск ошибки #2000:</span>
                      <MacBadge variant="danger" className="text-[10px]">
                        Высокий (QUIC stall)
                      </MacBadge>
                    </div>
                  )}
                  {result.mediaStream.testedEndpoints && result.mediaStream.testedEndpoints.length > 0 && (
                    <div className="pt-1">
                      <div className="text-[10px] text-[var(--color-text-secondary)] mb-0.5">Проверенные CDN:</div>
                      <div className="space-y-0.5 bg-[var(--color-bg-tertiary)] p-1 rounded font-mono text-[9px]">
                        {result.mediaStream.testedEndpoints.map((ep, i) => (
                          <div key={i} className="flex justify-between">
                            <span className="text-[var(--color-text-secondary)]">{ep.endpoint}:</span>
                            <span>{ep.reachable ? `${ep.latencyMs ?? '—'} ms (OK)` : (ep.error || 'Сбой')}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {result.mediaStream.detail && (
                    <div className="text-[10px] text-[var(--color-text-secondary)] pt-0.5">
                      {result.mediaStream.detail}
                    </div>
                  )}
                  {result.mediaStream.error && (
                    <div className="text-[10px] text-[var(--color-danger)] pt-0.5">
                      {result.mediaStream.error}
                    </div>
                  )}
                </div>
              </DiagnosticBox>
            )}
          </div>
        </div>
      )}
    </MacCard>
  )
}

function DiagnosticBox({
  icon,
  title,
  status,
  durationMs,
  children
}: {
  icon: React.ReactNode
  title: string
  status?: string
  durationMs?: number
  children: React.ReactNode
}) {
  return (
    <div className="p-2 rounded bg-[var(--color-bg-secondary)] border border-[var(--color-border)]">
      <div className="flex items-center justify-between gap-1 mb-1.5 pb-1 border-b border-[var(--color-border)]">
        <div className="flex items-center gap-1.5 text-xs font-semibold text-[var(--color-text)]">
          {icon}
          <span>{title}</span>
        </div>
        <div className="flex items-center gap-1.5 text-[10px] text-[var(--color-text-secondary)]">
          {durationMs !== undefined && <span>{durationMs}ms</span>}
          {status && <StatusDot status={status} />}
        </div>
      </div>
      {children}
    </div>
  )
}

function FindingCard({ finding }: { finding: LiveCheckFinding }) {
  const isError = finding.severity === 'error'
  const isWarning = finding.severity === 'warning'

  const borderClass = isError
    ? 'border-[var(--color-danger)]/40 bg-[var(--color-danger)]/10 text-[var(--color-danger)]'
    : isWarning
      ? 'border-[var(--color-warning)]/40 bg-[var(--color-warning)]/10 text-[var(--color-warning)]'
      : 'border-[var(--color-accent)]/30 bg-[var(--color-accent)]/10 text-[var(--color-text)]'

  return (
    <div className={`p-2 rounded-[var(--radius-sm)] border text-xs ${borderClass}`}>
      <div className="flex items-center gap-1.5 font-medium mb-0.5">
        {isError ? (
          <AlertCircle size={13} className="shrink-0 text-[var(--color-danger)]" />
        ) : isWarning ? (
          <AlertTriangle size={13} className="shrink-0 text-[var(--color-warning)]" />
        ) : (
          <Info size={13} className="shrink-0 text-[var(--color-accent)]" />
        )}
        <span className="font-semibold">{finding.title}</span>
        <MacBadge
          variant={isError ? 'danger' : isWarning ? 'warning' : 'neutral'}
          className="ml-auto text-[9px] font-mono uppercase"
        >
          {finding.code}
        </MacBadge>
      </div>
      <p className="text-[11px] text-[var(--color-text)] opacity-90 pl-5">
        {finding.detail}
      </p>
    </div>
  )
}

function StatusDot({ status }: { status: string }) {
  const colorClass =
    status === 'ok'
      ? 'bg-[var(--color-success)]'
      : status === 'error' || status === 'auth_failed' || status === 'blackhole_suspected'
        ? 'bg-[var(--color-danger)]'
        : status === 'skipped' || status === 'unsupported'
          ? 'bg-[var(--color-text-secondary)]'
          : 'bg-[var(--color-warning)]'

  return <span className={`inline-block w-2 h-2 rounded-full ${colorClass}`} title={status} />
}
