import { useEffect, useState } from 'react'
import { useAppStore, type LeakSelfTestResultClient } from '../store'
import { AlertTriangle, CheckCircle2, FileArchive, FolderOpen, Loader2, Radar, Send, ShieldAlert } from 'lucide-react'

/**
 * The "everything you need to debug a not-working app" surface.
 *
 * Three buttons:
 *   1. Активная проверка утечки  — runs the curl-bound-to-physical-adapter
 *      probe and tells the user RIGHT NOW if the kill-switch is sealing
 *      the physical interface.
 *   2. Открыть папку снимков — opens File Explorer at the snapshots dir so
 *      the user can see what's being captured.
 *   3. Отправить логи разработчику — bundles app log, sing-box log,
 *      manifests, all snapshots, system info into one ZIP and opens
 *      Explorer at the file. The user just drags the ZIP into the chat.
 *
 * Plus: rolling display of the most recent leak self-test result and the
 * most recent uncaught error caught by main process (so the user can see
 * "the app didn't crash but something happened").
 */
export function DiagnosticsCard() {
  const leakResult = useAppStore((s) => s.leakSelfTestResult)
  const setLeakResult = useAppStore((s) => s.setLeakSelfTestResult)
  const lastErr = useAppStore((s) => s.lastMainError)
  const addLog = useAppStore((s) => s.addLog)

  const [testing, setTesting] = useState(false)
  const [exporting, setExporting] = useState(false)
  const [exportPath, setExportPath] = useState<string | null>(null)
  const [forensicsStatus, setForensicsStatus] = useState<any>(null)

  useEffect(() => {
    let mounted = true
    const checkStatus = async () => {
      try {
        const status = await window.electronAPI.getTrafficForensicsStatus()
        if (mounted) setForensicsStatus(status)
      } catch (err) {
        // Status is best-effort UI telemetry; the export button remains usable.
      }
    }
    checkStatus()
    const interval = setInterval(checkStatus, 3000)
    return () => {
      mounted = false
      clearInterval(interval)
    }
  }, [])

  const handleSelfTest = async () => {
    setTesting(true)
    addLog('info', 'Активная проверка утечки: пробую достучаться до интернета через физический адаптер…')
    try {
      const result = await window.electronAPI.runLeakSelfTest()
      setLeakResult(result)
      const level = result.physicalAdapterReached || result.publicIpMismatch || result.dnsLeakDetected ? 'error' : 'info'
      addLog(level, `Результат проверки: ${result.summary}`)
    } catch (err: any) {
      addLog('error', `Не удалось запустить проверку утечки: ${err.message ?? err}`)
    } finally {
      setTesting(false)
    }
  }

  const handleExport = async () => {
    setExporting(true)
    addLog('info', 'Собираю диагностический архив (снимки, логи, настройки)…')
    try {
      const result = await window.electronAPI.exportDiagnostics()
      if (result.cancelled) {
        addLog('warn', 'Экспорт отменён пользователем.')
      } else if (result.success && result.path) {
        setExportPath(result.path)
        addLog('info', `Архив создан: ${result.path}`)
      } else {
        addLog('error', `Не удалось создать архив: ${result.error ?? 'неизвестная ошибка'}`)
      }
    } catch (err: any) {
      addLog('error', `Ошибка при экспорте: ${err.message ?? err}`)
    } finally {
      setExporting(false)
    }
  }

  const handleOpenSnapshots = async () => {
    try {
      const r = await window.electronAPI.openSnapshotsFolder()
      if (!r.success) addLog('warn', `Не удалось открыть папку: ${r.error}`)
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

  let forensicsDotColor = 'bg-gray-500'
  let forensicsText = 'СБОР ОСТАНОВЛЕН'
  let forensicsTooltip = 'Сбор пакетов остановлен'

  if (isForensicsRunning) {
    forensicsDotColor = 'bg-success animate-pulse'
    forensicsText = 'СБОР ПАКЕТОВ'
    forensicsTooltip = 'Идёт сбор пакетов'
  } else if (isForensicsFailed) {
    forensicsDotColor = 'bg-danger'
    forensicsText = 'ОШИБКА СБОРА'
    forensicsTooltip = forensicsStatus?.lastError || 'Не удалось запустить сбор пакетов'
  }

  return (
    <div className="card space-y-4">
      <div>
        <div className="flex items-center gap-2">
          <h3 className="text-sm font-semibold text-gray-300 uppercase tracking-wider">Диагностика</h3>
          {forensicsStatus && (
            <div className="flex items-center gap-1.5 bg-surface/50 px-2 py-0.5 rounded-full border border-surface-lighter/20" title={forensicsTooltip}>
              <div className={`w-2 h-2 rounded-full ${forensicsDotColor}`} />
              <span className="text-[10px] text-gray-400 font-medium tracking-wide">
                {forensicsText}
              </span>
            </div>
          )}
        </div>
        {forensicsStatus && (
          <div className="mt-2 grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px]">
            <div className="rounded border border-surface-lighter/20 bg-surface/40 px-2 py-1">
              <p className="text-gray-500">pktmon</p>
              <p className="text-gray-300 font-mono">{forensicsStatus.engine ?? 'off'} · {formatBytes(forensicsHealth?.etlBytes)}</p>
            </div>
            <div className="rounded border border-surface-lighter/20 bg-surface/40 px-2 py-1">
              <p className="text-gray-500">live</p>
              <p className="text-gray-300 font-mono">{liveSnapshotText}</p>
            </div>
            <div className={`rounded border px-2 py-1 ${forensicsHealth?.sidecarOnlyLifecycle ? 'border-warning/40 bg-warning/10' : 'border-surface-lighter/20 bg-surface/40'}`}>
              <p className="text-gray-500">sidecar</p>
              <p className="text-gray-300 font-mono">
                {forensicsHealth?.sidecarWarmingUp ? 'warming up' : forensicsStatus.sidecar?.running ? 'running' : 'off'} · {forensicsHealth?.sidecarEvents ?? 0} events
              </p>
            </div>
            <div className="rounded border border-surface-lighter/20 bg-surface/40 px-2 py-1">
              <p className="text-gray-500">artifacts</p>
              <p className="text-gray-300 font-mono">{forensicsHealth?.artifactCount ?? 0} files</p>
            </div>
          </div>
        )}
        {forensicsHealth?.warnings?.length > 0 && (
          <p className="text-[11px] text-warning mt-1">
            {forensicsHealth.warnings[0]}
          </p>
        )}
        <p className="text-xs text-gray-500 mt-1">
          Если что-то не так — нажмите «Отправить логи разработчику» и пришлите ZIP. Внутри уже есть все
          снимки сетевого состояния, конфиги и логи за последние сессии.
        </p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
        <button
          onClick={handleSelfTest}
          disabled={testing}
          className="btn-secondary flex items-center justify-center gap-2 text-sm disabled:opacity-50"
        >
          {testing ? <Loader2 className="w-4 h-4 animate-spin" /> : <Radar className="w-4 h-4" />}
          Активная проверка утечки
        </button>
        <button
          onClick={handleOpenSnapshots}
          className="btn-secondary flex items-center justify-center gap-2 text-sm"
        >
          <FolderOpen className="w-4 h-4" />
          Папка со снимками
        </button>
        <button
          onClick={handleExport}
          disabled={exporting}
          className="btn-primary flex items-center justify-center gap-2 text-sm disabled:opacity-50"
        >
          {exporting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
          Отправить логи разработчику
        </button>
      </div>

      {exportPath && (
        <div className="bg-accent/10 border border-accent/30 rounded-lg p-3 flex items-start gap-2">
          <FileArchive className="w-4 h-4 text-accent flex-shrink-0 mt-0.5" />
          <div className="text-xs flex-1">
            <p className="font-semibold mb-1 text-accent">Архив готов:</p>
            <p className="font-mono break-all text-gray-300">{exportPath}</p>
            <p className="text-gray-500 mt-1">Перетащите его в чат разработчику — внутри всё нужное.</p>
          </div>
        </div>
      )}

      {leakResult && <LeakResultPanel result={leakResult} />}

      {lastErr && (
        <div className="bg-warning/10 border border-warning/30 rounded-lg p-3 flex items-start gap-2">
          <AlertTriangle className="w-4 h-4 text-warning flex-shrink-0 mt-0.5" />
          <div className="text-xs flex-1">
            <p className="font-semibold text-warning mb-0.5">Поймана ошибка main-процесса (приложение не упало)</p>
            <p className="text-gray-400 font-mono break-all">{lastErr.code}: {lastErr.message}</p>
            <p className="text-gray-500 mt-1">{new Date(lastErr.ts).toLocaleString('ru-RU')}</p>
          </div>
        </div>
      )}
    </div>
  )
}

function LeakResultPanel({ result }: { result: LeakSelfTestResultClient }) {
  const isLeak = result.physicalAdapterReached || result.publicIpMismatch || result.dnsLeakDetected
  const Icon = isLeak ? ShieldAlert : CheckCircle2
  // Tailwind cannot resolve dynamic class names like `bg-${color}/10` because
  // it purges unused classes at build time, so we hard-code the two variants.
  const containerClass = isLeak
    ? 'bg-danger/10 border border-danger/30 rounded-lg p-3 space-y-2'
    : 'bg-success/10 border border-success/30 rounded-lg p-3 space-y-2'
  const iconClass = isLeak
    ? 'w-5 h-5 flex-shrink-0 mt-0.5 text-danger'
    : 'w-5 h-5 flex-shrink-0 mt-0.5 text-success'
  const summaryClass = isLeak
    ? 'text-sm font-semibold text-danger'
    : 'text-sm font-semibold text-success'

  return (
    <div className={containerClass}>
      <div className="flex items-start gap-2">
        <Icon className={iconClass} />
        <div className="flex-1">
          <p className={summaryClass}>{result.summary}</p>
          <p className="text-xs text-gray-500 mt-0.5">
            Проверено: {new Date(result.ts).toLocaleTimeString('ru-RU')}
          </p>
        </div>
      </div>
      <div className="text-xs space-y-1.5 pl-7">
        <div className="flex justify-between gap-3">
          <span className="text-gray-400">Публичный IP через TUN:</span>
          <span className="font-mono text-gray-200">{result.defaultRoutePublicIp ?? '—'}</span>
        </div>
        {result.perAdapter.map((a) => (
          <div key={a.alias} className="border-t border-surface-lighter/30 pt-1.5">
            <div className="flex justify-between gap-3">
              <span className="text-gray-400">{a.alias} ({a.ipv4 ?? 'no IP'})</span>
              <span className={`font-mono ${a.publicIpViaThisAdapter ? 'text-danger' : 'text-success'}`}>
                {a.publicIpViaThisAdapter
                  ? `видно как ${a.publicIpViaThisAdapter}`
                  : `заблокирован (curl exit ${a.curlExitCode ?? '?'})`}
              </span>
            </div>
            {a.curlStderrTail && (
              <p className="text-gray-600 font-mono break-all mt-0.5 text-[10px]">{a.curlStderrTail}</p>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
