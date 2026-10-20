import { useDiagnosticsExport } from '../hooks/useDiagnosticsExport'
import { useEffect, useRef, useState } from 'react'
import { isIpcRemoteErrorData } from '../../shared/ipc-result'
import { adapterLeakVerdict, leakSelfTestMessage, leakSelfTestVerdict } from '../../shared/leak-self-test'
import { useTranslation } from 'react-i18next'
import { useAppStore, type LeakSelfTestResultClient } from '../store'
import { AlertTriangle, CheckCircle2, FileArchive, FolderOpen, Loader2, Radar, RefreshCw, Send, ShieldAlert } from 'lucide-react'
import { MacCard, MacButton } from '../design-system'

const FORENSICS_RUNNING_POLL_INTERVAL_MS = 10_000
const FORENSICS_IDLE_POLL_INTERVAL_MS = 30_000
const UNKNOWN_CAPTURE_STATUS = { cleanupPending: true, statusUnavailable: true }

/**
 * The "everything you need to debug a not-working app" surface.
 *
 * Three primary actions:
 *   1. Active leak test: checks whether the physical adapter can still reach
 *      the internet outside the tunnel.
 *   2. Open snapshots folder: shows the raw captured artifacts.
 *   3. Export diagnostics: bundles logs and artifacts into a ZIP for support.
 */
export function DiagnosticsCard() {
  const { t } = useTranslation()
  const leakResult = useAppStore((s) => s.leakSelfTestResult)
  const setLeakResult = useAppStore((s) => s.setLeakSelfTestResult)
  const lastErr = useAppStore((s) => s.lastMainError)
  const addLog = useAppStore((s) => s.addLog)

  const [testing, setTesting] = useState(false)
  const selfTestScope = useRef<{ active: boolean; token?: string } | null>(null)
  useEffect(() => {
    const current = { active: true } as { active: boolean; token?: string }
    selfTestScope.current = current
    return () => {
      current.active = false
      if (current.token) void window.electronAPI.operationsCancelRequest(current.token).catch(() => {})
      if (selfTestScope.current === current) selfTestScope.current = null
    }
  }, [])
  const [restartingForensics, setRestartingForensics] = useState(false)
  const [exportPath, setExportPath] = useState<string | null>(null)
  const { exporting, exportDiagnostics: handleExport } = useDiagnosticsExport(setExportPath)
  const [forensicsStatus, setForensicsStatus] = useState<any>(null)

  const checkForensicsStatus = async () => {
    try {
      const status = await window.electronAPI.getTrafficForensicsStatus()
      setForensicsStatus(status)
    } catch {
      setForensicsStatus(UNKNOWN_CAPTURE_STATUS)
    }
  }

  useEffect(() => {
    let cancelled = false
    let timeout: number | null = null

    const scheduleNext = (running: boolean) => {
      timeout = window.setTimeout(
        checkStatus,
        running ? FORENSICS_RUNNING_POLL_INTERVAL_MS : FORENSICS_IDLE_POLL_INTERVAL_MS
      )
    }

    const checkStatus = async () => {
      try {
        const status = await window.electronAPI.getTrafficForensicsStatus()
        if (cancelled) return
        setForensicsStatus(status)
        scheduleNext(Boolean(status?.running))
      } catch {
        if (!cancelled) {
          setForensicsStatus(UNKNOWN_CAPTURE_STATUS)
          scheduleNext(false)
        }
      }
    }

    void checkStatus()
    return () => {
      cancelled = true
      if (timeout) window.clearTimeout(timeout)
    }
  }, [])

  const handleSelfTest = async () => {
    const current = selfTestScope.current
    if (!current?.active || current.token) return
    const token = crypto.randomUUID()
    current.token = token
    const owns = () => current.active && selfTestScope.current === current && current.token === token
    setTesting(true)
    addLog('info', 'Активная проверка утечки: пробую достучаться до интернета через физический адаптер…')
    try {
      const result = await window.electronAPI.runLeakSelfTest(token)
      if (!owns()) return
      setLeakResult(result)
      const verdict = leakSelfTestVerdict(result)
      const level = verdict === 'leak' ? 'error' : verdict === 'ok' || result.cancelled ? 'info' : 'warn'
      addLog(level, `Результат проверки: ${leakSelfTestMessage(result)}`)
    } catch (err: any) {
      if (owns() && !(isIpcRemoteErrorData(err) && err.category === 'cancelled')) {
        addLog('error', `Не удалось запустить проверку утечки: ${err.message ?? err}`)
      }
    } finally {
      if (owns()) setTesting(false)
      if (current.token === token) current.token = undefined
    }
  }

  const handleRestartForensics = async () => {
    setRestartingForensics(true)
    addLog('info', 'Перезапускаю сбор пакетов и ETW-логи…')
    try {
      const status = await window.electronAPI.restartTrafficForensics()
      setForensicsStatus(status)
      if (status?.running) {
        addLog('info', 'Сбор пакетов перезапущен.')
      } else {
        addLog('warn', `Сбор пакетов не запустился: ${status?.lastError ?? 'нет активного VPN-контекста'}`)
      }
    } catch (err: any) {
      addLog('error', `Не удалось перезапустить сбор пакетов: ${err.message ?? err}`)
    } finally {
      setRestartingForensics(false)
      await checkForensicsStatus()
    }
  }

  const handleOpenSnapshots = async () => {
    try {
      await window.electronAPI.openSnapshotsFolder()
    } catch (err: any) {
      addLog('error', `Не удалось открыть папку снимков: ${err.message ?? err}`)
    }
  }

  const isForensicsRunning = forensicsStatus?.running
  const isForensicsFailed = !isForensicsRunning && forensicsStatus?.stopReason === 'start-failed'
  const forensicsHealth = forensicsStatus?.health
  const formatBytes = (bytes?: number) => {
    if (!bytes) return '0 KB'
    if (bytes >= 1024 * 1024) return `${Math.round(bytes / 1024 / 1024)} MB`
    return `${Math.round(bytes / 1024)} KB`
  }
  const liveSnapshotText = forensicsHealth?.liveSnapshotAt
    ? new Date(forensicsHealth.liveSnapshotAt).toLocaleTimeString('ru-RU')
    : 'none'

  const sidecarEngine: string | null = forensicsHealth?.sidecarEngine ?? null
  const engineLabel =
    sidecarEngine === 'ferrisetw-realtime'
      ? 'ETW real-time'
      : sidecarEngine === 'powershell-poller'
        ? 'poller (fallback)'
        : sidecarEngine ?? '—'
  const categoryCounts: Record<string, number> = forensicsHealth?.sidecarCategoryCounts ?? {}
  const categoryOrder = ['tcp', 'dns', 'wfp', 'afd', 'webio', 'udp']
  const categoryEntries = Object.entries(categoryCounts).sort((a, b) => {
    const ai = categoryOrder.indexOf(a[0])
    const bi = categoryOrder.indexOf(b[0])
    if (ai !== -1 && bi !== -1) return ai - bi
    if (ai !== -1) return -1
    if (bi !== -1) return 1
    return b[1] - a[1]
  })
  const topDomains: Array<{ name: string; count: number }> = forensicsHealth?.sidecarTopDomains ?? []
  const topRemotes: Array<{ address: string; count: number }> = forensicsHealth?.sidecarTopRemotes ?? []
  const wfpBlocks: number = forensicsHealth?.sidecarWfpBlocks ?? 0
  const dataEvents: number = forensicsHealth?.sidecarDataEvents ?? 0
  const lastEventText = forensicsHealth?.sidecarLastEventAt
    ? new Date(forensicsHealth.sidecarLastEventAt).toLocaleTimeString('ru-RU')
    : '—'
  const showSidecarDetails = Boolean(forensicsStatus?.sidecar?.running || dataEvents > 0)

  const cleanupWarning = forensicsStatus?.statusUnavailable
    ? t('diagnosticsCapture.statusUnavailable')
    : forensicsStatus?.lastError?.startsWith('LegacyCaptureCleanupRequired:')
      ? t('diagnosticsCapture.legacyCleanupRequired')
      : forensicsStatus?.lastError || t('diagnosticsCapture.stopUnconfirmed')
  let forensicsDotColor = 'bg-[var(--color-text-muted)]'
  let forensicsText = t('diagnosticsCapture.stoppedLabel')
  let forensicsTooltip = t('diagnosticsCapture.stopped')

  if (forensicsStatus?.cleanupPending) {
    forensicsDotColor = 'bg-[var(--color-warning)]'
    forensicsText = t('diagnosticsCapture.pendingLabel')
    forensicsTooltip = cleanupWarning
  } else if (isForensicsRunning) {
    forensicsDotColor = 'bg-[var(--color-success)] animate-pulse'
    forensicsText = t('diagnosticsCapture.runningLabel')
    forensicsTooltip = t('diagnosticsCapture.running')
  } else if (isForensicsFailed) {
    forensicsDotColor = 'bg-[var(--color-danger)]'
    forensicsText = t('diagnosticsCapture.failedLabel')
    forensicsTooltip = forensicsStatus?.lastError || t('diagnosticsCapture.startFailed')
  }

  return (
    <MacCard className="space-y-4">
      <div>
        <div className="flex items-center gap-2">
          <h3 className="text-sm font-semibold text-[var(--color-text)] uppercase tracking-wider">Диагностика</h3>
          {forensicsStatus && (
            <div className="flex items-center gap-1.5 bg-[var(--color-bg)]/50 px-2 py-0.5 rounded-full border border-[var(--color-card-elevated)]/20" title={forensicsTooltip}>
              <div className={`w-2 h-2 rounded-full ${forensicsDotColor}`} />
              <span className="text-[10px] text-[var(--color-text-secondary)] font-medium tracking-wide">
                {forensicsText}
              </span>
            </div>
          )}
        </div>
        {forensicsStatus && (
          <div className="mt-2 grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px]">
            <div className="rounded border border-[var(--color-card-elevated)]/20 bg-[var(--color-bg)]/40 px-2 py-1">
              <p className="text-[var(--color-text-secondary)]">pktmon</p>
              <p className="text-[var(--color-text)] font-mono">{forensicsStatus.engine ?? 'off'} · {formatBytes(forensicsHealth?.etlBytes)}</p>
            </div>
            <div className="rounded border border-[var(--color-card-elevated)]/20 bg-[var(--color-bg)]/40 px-2 py-1">
              <p className="text-[var(--color-text-secondary)]">live</p>
              <p className="text-[var(--color-text)] font-mono">{liveSnapshotText}</p>
            </div>
            <div className={`rounded border px-2 py-1 ${forensicsHealth?.sidecarOnlyLifecycle ? 'border-[var(--color-warning)]/40 bg-[var(--color-warning)]/10' : 'border-[var(--color-card-elevated)]/20 bg-[var(--color-bg)]/40'}`}>
              <p className="text-[var(--color-text-secondary)]">sidecar · {engineLabel}</p>
              <p className="text-[var(--color-text)] font-mono">
                {forensicsHealth?.sidecarWarmingUp ? 'warming up' : forensicsStatus.sidecar?.running ? 'running' : 'off'} · {dataEvents} data
              </p>
            </div>
            <div className="rounded border border-[var(--color-card-elevated)]/20 bg-[var(--color-bg)]/40 px-2 py-1">
              <p className="text-[var(--color-text-secondary)]">artifacts</p>
              <p className="text-[var(--color-text)] font-mono">{forensicsHealth?.artifactCount ?? 0} files</p>
            </div>
          </div>
        )}
        {forensicsStatus && showSidecarDetails && (
          <div className="mt-2 rounded border border-[var(--color-card-elevated)]/20 bg-[var(--color-bg)]/30 px-2.5 py-2 space-y-2 text-[11px]">
            <div className="flex items-center justify-between gap-2">
              <span className="text-[var(--color-text-secondary)] font-medium">Что видит ETW-сборщик</span>
              <span className="text-[var(--color-text-secondary)] font-mono">посл. событие: {lastEventText}</span>
            </div>
            {categoryEntries.length > 0 ? (
              <div className="flex flex-wrap gap-1.5">
                {categoryEntries.map(([cat, count]) => (
                  <span
                    key={cat}
                    className="inline-flex items-center gap-1 rounded bg-[var(--color-bg)]/60 border border-[var(--color-card-elevated)]/20 px-1.5 py-0.5 font-mono text-[var(--color-text)]"
                  >
                    <span className="uppercase text-[var(--color-text-secondary)]">{cat}</span>
                    {count}
                  </span>
                ))}
                {wfpBlocks > 0 && (
                  <span className="inline-flex items-center gap-1 rounded bg-[var(--color-danger)]/10 border border-[var(--color-danger)]/30 px-1.5 py-0.5 font-mono text-[var(--color-danger)]">
                    <span className="uppercase">wfp-block</span>
                    {wfpBlocks}
                  </span>
                )}
              </div>
            ) : (
              <p className="text-[var(--color-text-secondary)]">
                {forensicsHealth?.sidecarWarmingUp ? 'прогрев — события вот-вот пойдут…' : 'пока нет data-событий'}
              </p>
            )}
            {(topDomains.length > 0 || topRemotes.length > 0) && (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 pt-1">
                {topDomains.length > 0 && (
                  <div>
                    <p className="text-[var(--color-text-secondary)] mb-0.5">Топ доменов (DNS)</p>
                    <ul className="space-y-0.5">
                      {topDomains.map((d) => (
                        <li key={d.name} className="flex justify-between gap-2 font-mono text-[var(--color-text)]">
                          <span className="truncate">{d.name}</span>
                          <span className="text-[var(--color-text-secondary)]">{d.count}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                {topRemotes.length > 0 && (
                  <div>
                    <p className="text-[var(--color-text-secondary)] mb-0.5">Топ эндпоинтов</p>
                    <ul className="space-y-0.5">
                      {topRemotes.map((r) => (
                        <li key={r.address} className="flex justify-between gap-2 font-mono text-[var(--color-text)]">
                          <span className="truncate">{r.address}</span>
                          <span className="text-[var(--color-text-secondary)]">{r.count}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}
          </div>
        )}
        {forensicsStatus?.cleanupPending && (
          <p role="alert" className="text-[11px] text-[var(--color-warning)] mt-1">
            {cleanupWarning}
          </p>
        )}
        {!forensicsStatus?.cleanupPending && forensicsHealth?.warnings?.length > 0 && (
          <p className="text-[11px] text-[var(--color-warning)] mt-1">
            {forensicsHealth.warnings[0]}
          </p>
        )}
        <p className="text-xs text-[var(--color-text-secondary)] mt-1">
          Если что-то не так — нажмите «Отправить логи разработчику» и пришлите ZIP. Внутри уже есть все
          снимки сетевого состояния, конфиги и логи за последние сессии.
        </p>
      </div>

      {/*
        All four are secondary on purpose. Exporting a support bundle used to be
        the only `primary` here, which made it the loudest button on the whole
        dashboard — the page's actual primary action is the connect toggle above,
        and nothing in a diagnostics card should outrank it.
      */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-2">
        <MacButton
          variant="secondary"
          onClick={handleRestartForensics}
          disabled={restartingForensics}
          className="flex items-center justify-center gap-2 text-sm"
        >
          {restartingForensics ? <Loader2 className="w-4 h-4 animate-spin" /> : <RefreshCw className="w-4 h-4" />}
          Перезапустить сбор
        </MacButton>
        <MacButton
          variant="secondary"
          onClick={handleSelfTest}
          disabled={testing}
          className="flex items-center justify-center gap-2 text-sm"
        >
          {testing ? <Loader2 className="w-4 h-4 animate-spin" /> : <Radar className="w-4 h-4" />}
          Активная проверка утечки
        </MacButton>
        <MacButton
          variant="secondary"
          onClick={handleOpenSnapshots}
          className="flex items-center justify-center gap-2 text-sm"
        >
          <FolderOpen className="w-4 h-4" />
          Папка со снимками
        </MacButton>
        <MacButton
          variant="secondary"
          onClick={handleExport}
          disabled={exporting}
          className="flex items-center justify-center gap-2 text-sm"
        >
          {exporting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
          Отправить логи разработчику
        </MacButton>
      </div>

      {exportPath && (
        <div className="bg-[var(--color-accent)]/10 border border-[var(--color-accent)]/30 rounded-lg p-3 flex items-start gap-2">
          <FileArchive className="w-4 h-4 text-[var(--color-accent)] flex-shrink-0 mt-0.5" />
          <div className="text-xs flex-1">
            <p className="font-semibold mb-1 text-[var(--color-accent)]">Архив готов:</p>
            <p className="font-mono break-all text-[var(--color-text)]">{exportPath}</p>
            <p className="text-[var(--color-text-secondary)] mt-1">Перетащите его в чат разработчику — внутри всё нужное.</p>
          </div>
        </div>
      )}

      {leakResult && <LeakResultPanel result={leakResult} />}

      {lastErr && (
        <div className="bg-[var(--color-warning)]/10 border border-[var(--color-warning)]/30 rounded-lg p-3 flex items-start gap-2">
          <AlertTriangle className="w-4 h-4 text-[var(--color-warning)] flex-shrink-0 mt-0.5" />
          <div className="text-xs flex-1">
            <p className="font-semibold text-[var(--color-warning)] mb-0.5">Поймана ошибка main-процесса (приложение не упало)</p>
            <p className="text-[var(--color-text-secondary)] font-mono break-all">{lastErr.code}: {lastErr.message}</p>
            <p className="text-[var(--color-text-secondary)] mt-1">{new Date(lastErr.ts).toLocaleString('ru-RU')}</p>
          </div>
        </div>
      )}
    </MacCard>
  )
}

function LeakResultPanel({ result }: { result: LeakSelfTestResultClient }) {
  const verdict = leakSelfTestVerdict(result)
  const isLeak = verdict === 'leak', isOk = verdict === 'ok'
  const Icon = isLeak ? ShieldAlert : isOk ? CheckCircle2 : AlertTriangle
  // Tailwind cannot resolve dynamic class names like `bg-${color}/10` because
  // it purges unused classes at build time, so each variant is explicit.
  const containerClass = isLeak
    ? 'bg-[var(--color-danger)]/10 border border-[var(--color-danger)]/30 rounded-lg p-3 space-y-2'
    : isOk ? 'bg-[var(--color-success)]/10 border border-[var(--color-success)]/30 rounded-lg p-3 space-y-2'
      : 'bg-[var(--color-warning)]/10 border border-[var(--color-warning)]/30 rounded-lg p-3 space-y-2'
  const iconClass = isLeak
    ? 'w-5 h-5 flex-shrink-0 mt-0.5 text-[var(--color-danger)]'
    : isOk ? 'w-5 h-5 flex-shrink-0 mt-0.5 text-[var(--color-success)]'
      : 'w-5 h-5 flex-shrink-0 mt-0.5 text-[var(--color-warning)]'
  const summaryClass = isLeak
    ? 'text-sm font-semibold text-[var(--color-danger)]'
    : isOk ? 'text-sm font-semibold text-[var(--color-success)]'
      : 'text-sm font-semibold text-[var(--color-warning)]'

  return (
    <div className={containerClass} role="status" aria-label="Результат проверки утечек" data-verdict={verdict}>
      <div className="flex items-start gap-2">
        <Icon className={iconClass} />
        <div className="flex-1">
          <p className={summaryClass}>{leakSelfTestMessage(result)}</p>
          <p className="text-xs text-[var(--color-text-secondary)] mt-0.5">
            Проверено: {new Date(result.ts).toLocaleTimeString('ru-RU')}
          </p>
        </div>
      </div>
      <div className="text-xs space-y-1.5 pl-7">
        <div className="flex justify-between gap-3">
          <span className="text-[var(--color-text-secondary)]">Публичный IP через TUN:</span>
          <span className="font-mono text-[var(--color-text)]">{result.defaultRoutePublicIp ?? '—'}</span>
        </div>
        {result.perAdapter.map((a) => (
          <div key={a.alias} className="border-t border-[var(--color-card-elevated)]/30 pt-1.5">
            <div className="flex justify-between gap-3">
              <span className="text-[var(--color-text-secondary)]">{a.alias} ({a.ipv4 ?? 'no IP'})</span>
              <span className={`font-mono ${adapterLeakVerdict(a) === 'reached' ? 'text-[var(--color-danger)]' : 'text-[var(--color-text-secondary)]'}`}>
                {adapterLeakVerdict(a) === 'reached'
                  ? `видно как ${a.publicIpViaThisAdapter}`
                  : adapterLeakVerdict(a) === 'not-reached'
                    ? `внешний IP не получен (curl exit ${a.curlExitCode})`
                    : `результат неизвестен (curl exit ${a.curlExitCode ?? '?'})`}
              </span>
            </div>
            {a.curlStderrTail && (
              <p className="text-[var(--color-text-muted)] font-mono break-all mt-0.5 text-[10px]">{a.curlStderrTail}</p>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
