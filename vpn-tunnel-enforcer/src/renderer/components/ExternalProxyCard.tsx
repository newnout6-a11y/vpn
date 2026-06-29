import { useCallback, useEffect, useState } from 'react'
import { Globe2, Loader2, Power, RefreshCw, Square } from 'lucide-react'
import { MacCard } from '../design-system/MacCard'
import { MacButton } from '../design-system/MacButton'
import { useAppStore } from '../store'
import type { ExternalProxyStatus } from '../../shared/ipc-types'

const CONTROL_PORT = 17873

const STOPPED: ExternalProxyStatus = {
  running: false,
  host: '127.0.0.1',
  port: null,
  proxyUrl: null,
  profileId: null,
  profileName: null,
  country: null,
  pid: null,
  startedAt: null
}

export function ExternalProxyCard() {
  const addLog = useAppStore(s => s.addLog)
  const addGlobalToast = useAppStore(s => s.addGlobalToast)

  const [status, setStatus] = useState<ExternalProxyStatus>(STOPPED)
  const [busy, setBusy] = useState<'start' | 'stop' | 'rotate' | null>(null)
  const [error, setError] = useState<string | null>(null)

  const refreshStatus = useCallback(async () => {
    try {
      const next = await window.electronAPI.externalProxyStatus()
      setStatus(next ?? STOPPED)
    } catch {
      // Silent — status poll failures are non-fatal.
    }
  }, [])

  // Initial status read.
  useEffect(() => {
    refreshStatus()
  }, [refreshStatus])

  // Poll every 5s while running so we catch an externally-killed process
  // (control API, OS, crash) without the user clicking anything.
  useEffect(() => {
    if (!status.running) return
    const id = setInterval(refreshStatus, 5000)
    return () => clearInterval(id)
  }, [status.running, refreshStatus])

  const handleStart = async () => {
    setBusy('start')
    setError(null)
    addLog('info', 'Внешний прокси: запускаем sing-box…')
    try {
      const next = await window.electronAPI.externalProxyStart()
      setStatus(next)
      if (next.running) {
        addGlobalToast('success', 'Внешний прокси запущен', next.proxyUrl ?? undefined)
        addLog('info', `Внешний прокси запущен: ${next.proxyUrl} (${next.profileName ?? '—'})`)
      }
    } catch (err: any) {
      const msg = err?.message || String(err)
      setError(msg)
      addGlobalToast('error', 'Не удалось запустить внешний прокси', msg)
      addLog('error', `Внешний прокси: ошибка запуска — ${msg}`)
    } finally {
      setBusy(null)
    }
  }

  const handleStop = async () => {
    setBusy('stop')
    setError(null)
    addLog('info', 'Внешний прокси: останавливаем…')
    try {
      const next = await window.electronAPI.externalProxyStop()
      setStatus(next ?? STOPPED)
      addGlobalToast('info', 'Внешний прокси остановлен')
      addLog('info', 'Внешний прокси остановлен')
    } catch (err: any) {
      const msg = err?.message || String(err)
      setError(msg)
      addGlobalToast('error', 'Не удалось остановить внешний прокси', msg)
      addLog('error', `Внешний прокси: ошибка остановки — ${msg}`)
    } finally {
      setBusy(null)
    }
  }

  const handleRotate = async () => {
    setBusy('rotate')
    setError(null)
    addLog('info', 'Внешний прокси: меняем профиль…')
    try {
      const next = await window.electronAPI.externalProxyRotate()
      setStatus(next)
      if (next.running) {
        addGlobalToast('success', 'Профель сменён', next.profileName ?? undefined)
        addLog('info', `Внешний прокси: новый профиль — ${next.profileName ?? '—'}`)
      }
    } catch (err: any) {
      const msg = err?.message || String(err)
      setError(msg)
      addGlobalToast('error', 'Не удалось сменить профиль', msg)
      addLog('error', `Внешний прокси: ошибка ротации — ${msg}`)
    } finally {
      setBusy(null)
    }
  }

  const running = status.running
  const isBusy = busy !== null

  return (
    <MacCard>
      <div className="flex items-center justify-between gap-3">
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-[var(--color-text-secondary)] uppercase tracking-wider flex items-center gap-2">
            <Globe2 className="w-4 h-4 text-[var(--color-accent)]" />
            Внешний прокси
          </h3>
          <p className={`text-sm mt-1 ${running ? 'text-[var(--color-success)]' : 'text-[var(--color-text-secondary)]'}`}>
            {running ? 'Запущен' : 'Остановлен'}
            {running && status.profileName ? ` — ${status.profileName}` : ''}
          </p>
        </div>
        <span
          className={`flex-shrink-0 inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium ${
            running
              ? 'bg-[var(--color-success)]/10 text-[var(--color-success)]'
              : 'bg-[var(--color-bg)] text-[var(--color-text-secondary)]'
          }`}
        >
          <span className={`w-1.5 h-1.5 rounded-full ${running ? 'bg-[var(--color-success)]' : 'bg-[var(--color-text-tertiary)]'}`} />
          {running ? 'on' : 'off'}
        </span>
      </div>

      {running && (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 mt-3">
          <div className="bg-[var(--color-bg)] border border-[var(--color-border)] rounded-[var(--radius-sm)] px-3 py-2">
            <div className="flex items-center justify-between gap-2">
              <span className="text-xs text-[var(--color-text-secondary)]">Proxy URL</span>
              <span className="text-xs font-mono text-[var(--color-text)]">{status.proxyUrl ?? '—'}</span>
            </div>
          </div>
          <div className="bg-[var(--color-bg)] border border-[var(--color-border)] rounded-[var(--radius-sm)] px-3 py-2">
            <div className="flex items-center justify-between gap-2">
              <span className="text-xs text-[var(--color-text-secondary)]">Control API</span>
              <span className="text-xs font-mono text-[var(--color-text)]">127.0.0.1:{CONTROL_PORT}</span>
            </div>
          </div>
        </div>
      )}

      {error && (
        <p className="text-xs text-[var(--color-danger)] mt-3 break-words">{error}</p>
      )}

      <div className="flex flex-wrap gap-2 mt-3">
        {!running ? (
          <MacButton variant="primary" size="sm" onClick={handleStart} disabled={isBusy}>
            {busy === 'start' ? <Loader2 className="w-4 h-4 animate-spin" /> : <Power className="w-4 h-4" />}
            Запустить
          </MacButton>
        ) : (
          <MacButton variant="danger" size="sm" onClick={handleStop} disabled={isBusy}>
            {busy === 'stop' ? <Loader2 className="w-4 h-4 animate-spin" /> : <Square className="w-4 h-4" />}
            Остановить
          </MacButton>
        )}
        <MacButton
          variant="secondary"
          size="sm"
          onClick={handleRotate}
          disabled={isBusy || !running}
        >
          {busy === 'rotate' ? <Loader2 className="w-4 h-4 animate-spin" /> : <RefreshCw className="w-4 h-4" />}
          Сменить профиль
        </MacButton>
      </div>
    </MacCard>
  )
}
