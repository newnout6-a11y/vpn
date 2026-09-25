import { useEffect, useMemo, useState } from 'react'
import { AlertTriangle, Check, Gauge, Play, Square } from 'lucide-react'
import { MacBadge, MacButton, MacInput, MacModal } from '../design-system'
import type {
  LiveServerBatchCheckProgress,
  LiveServerBatchCheckResult,
  LiveServerCheck,
  LiveThroughputDiagnostics,
  ServerProfile
} from '../../shared/ipc-types'

interface LiveServerBatchComparisonProps {
  open: boolean
  profiles: ServerProfile[]
  onClose: () => void
}

const MAX_SELECTED = 12

function formatMbps(value: number | undefined): string {
  return value === undefined || !Number.isFinite(value) ? '—' : `${value.toFixed(2)} Mbps`
}

function resultLabel(result: LiveServerCheck): string {
  return result.throughput?.status === 'error'
    ? 'Ошибка проб'
    : result.throughput?.status === 'warning'
      ? 'Нестабильно'
      : result.throughput?.status === 'ok'
        ? 'Стабильно'
        : result.handshake?.status === 'ok' ? 'Доступен' : 'Ошибка'
}

function routeLabel(route: LiveThroughputDiagnostics['route']): string {
  if (route === 'physical-direct') return 'Wi-Fi'
  if (route === 'active-profile-self') return 'активный профиль'
  if (route === 'active-tunnel-direct-detour') return 'через активный туннель'
  return '—'
}

export function LiveServerBatchComparison({ open, profiles, onClose }: LiveServerBatchComparisonProps) {
  const [query, setQuery] = useState('')
  const [selected, setSelected] = useState<string[]>([])
  const [running, setRunning] = useState(false)
  const [progress, setProgress] = useState<LiveServerBatchCheckProgress | null>(null)
  const [result, setResult] = useState<LiveServerBatchCheckResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!open) return
    setQuery('')
    setSelected(profiles.slice(0, MAX_SELECTED).map(profile => profile.id))
    setProgress(null)
    setResult(null)
    setError(null)
    setRunning(false)
  }, [open])

  useEffect(() => {
    if (!open) return
    const unsubscribe = window.electronAPI?.onLiveBatchCheckProgress?.(setProgress)
    return () => unsubscribe?.()
  }, [open])

  const visibleProfiles = useMemo(() => {
    const needle = query.trim().toLowerCase()
    if (!needle) return profiles
    return profiles.filter(profile =>
      profile.name.toLowerCase().includes(needle) ||
      profile.server.toLowerCase().includes(needle) ||
      String(profile.port).includes(needle)
    )
  }, [profiles, query])

  const toggleProfile = (id: string) => {
    setSelected(current => current.includes(id)
      ? current.filter(value => value !== id)
      : current.length >= MAX_SELECTED ? current : [...current, id])
  }

  const handleStart = async () => {
    if (running || selected.length === 0) return
    setRunning(true)
    setError(null)
    setResult(null)
    try {
      const batch = await window.electronAPI.serverLiveCheckBatch({
        profileIds: selected,
        mode: 'extended'
      })
      setResult(batch)
    } catch (err: any) {
      setError(err?.message || 'Не удалось запустить сравнение серверов')
    } finally {
      setRunning(false)
    }
  }

  const handleCancel = async () => {
    if (!progress?.requestId) return
    try {
      await window.electronAPI.serverLiveCheckCancel(progress.requestId)
    } catch {}
  }

  const handleClose = () => {
    if (running) return
    onClose()
  }

  const rows = result?.results ?? []
  const byProfileId = new Map(rows.map(row => [row.profileId, row]))
  const profileById = new Map(profiles.map(profile => [profile.id, profile]))
  const routeKinds = new Set(rows.map(row => row.throughput?.route).filter(Boolean))
  const routeSummary = routeKinds.size > 1
    ? ' · пути смешаны'
    : routeKinds.size === 1
      ? ` · путь: ${routeLabel(rows[0]?.throughput?.route)}`
      : ''

  return (
    <MacModal open={open} onClose={handleClose} title="Сравнение серверов" size="lg">
      <div className="space-y-3">
        <div className="flex items-start justify-between gap-3">
          <p className="text-xs text-[var(--color-text-secondary)]">
            Последовательные расширенные пробы одинакового размера. Выберите до {MAX_SELECTED} включённых профилей, чтобы сравнение не искажалось параллельной нагрузкой.
            <span className="block mt-1 text-[var(--color-text)]">Доступно включённых серверов: <span className="font-mono font-semibold">{profiles.length}</span></span>
          </p>
          <MacBadge variant="neutral">{selected.length}/{MAX_SELECTED}</MacBadge>
        </div>

        {!running && !result && (
          <>
            <MacInput value={query} onChange={event => setQuery(event.target.value)} placeholder="Поиск по имени или адресу" />
            <div className="max-h-64 overflow-y-auto space-y-1 pr-1">
              {visibleProfiles.map(profile => {
                const checked = selected.includes(profile.id)
                return (
                  <button
                    key={profile.id}
                    type="button"
                    onClick={() => toggleProfile(profile.id)}
                    className={`w-full flex items-center gap-2 rounded-[var(--radius-sm)] border px-2.5 py-2 text-left transition-colors ${checked ? 'border-[var(--color-accent)]/60 bg-[var(--color-accent)]/10' : 'border-[var(--color-border)] hover:border-[var(--color-accent)]/40'}`}
                  >
                    <span className={`flex h-4 w-4 shrink-0 items-center justify-center rounded border ${checked ? 'border-[var(--color-accent)] bg-[var(--color-accent)] text-white' : 'border-[var(--color-border)]'}`}>
                      {checked && <Check size={12} />}
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-xs font-medium">{profile.name}</span>
                      <span className="block truncate font-mono text-[10px] text-[var(--color-text-muted)]">{profile.server}:{profile.port}</span>
                    </span>
                  </button>
                )
              })}
            </div>
          </>
        )}

        {running && progress && (
          <div className="rounded-[var(--radius-sm)] border border-[var(--color-accent)]/35 bg-[var(--color-accent)]/8 p-3 text-xs">
            <div className="flex items-center justify-between gap-2">
              <span className="font-medium">Профиль {progress.index + 1} из {progress.total}: {profileById.get(progress.profileId)?.name || progress.profileId}</span>
              <span className="font-mono text-[var(--color-text-secondary)]">{progress.stage || progress.status}</span>
            </div>
            <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-[var(--color-bg-tertiary)]">
              <div className="h-full bg-[var(--color-accent)] transition-all" style={{ width: `${Math.max(4, ((progress.index + (progress.status === 'completed' ? 1 : 0)) / Math.max(1, progress.total)) * 100)}%` }} />
            </div>
            <div className="mt-2 flex justify-end">
              <MacButton size="sm" variant="danger" onClick={handleCancel}><Square size={12} className="mr-1.5" />Отмена</MacButton>
            </div>
          </div>
        )}

        {error && <div role="alert" className="flex items-center gap-2 rounded-[var(--radius-sm)] border border-[var(--color-danger)]/30 bg-[var(--color-danger)]/10 p-2 text-xs text-[var(--color-danger)]"><AlertTriangle size={14} />{error}</div>}

        {result && (
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs text-[var(--color-text-secondary)]">
              <span>Проверено: {rows.length} из {selected.length}</span>
              <span>{result.cancelled ? 'Остановлено' : 'Готово'}{routeSummary}</span>
            </div>
            <div className="overflow-x-auto rounded-[var(--radius-sm)] border border-[var(--color-border)]">
              <table className="w-full text-xs">
                <thead className="bg-[var(--color-bg-secondary)] text-[var(--color-text-secondary)]">
                  <tr><th className="px-2 py-1.5 text-left">Сервер</th><th className="px-2 py-1.5 text-right">Медиана</th><th className="px-2 py-1.5 text-right">Разброс</th><th className="px-2 py-1.5 text-right">Stalls</th><th className="px-2 py-1.5 text-right">Путь</th><th className="px-2 py-1.5 text-right">Статус</th></tr>
                </thead>
                <tbody>
                  {[...selected].map(id => {
                    const profile = profileById.get(id)
                    const check = byProfileId.get(id)
                    const throughput = check?.throughput
                    return <tr key={id} className="border-t border-[var(--color-border)]"><td className="max-w-[240px] truncate px-2 py-1.5"><span className="font-medium">{profile?.name || id}</span><span className="ml-2 font-mono text-[10px] text-[var(--color-text-muted)]">{profile?.server}</span></td><td className="px-2 py-1.5 text-right font-mono">{formatMbps(throughput?.medianMbps)}</td><td className="px-2 py-1.5 text-right font-mono">{throughput?.variabilityPct === undefined ? '—' : `${throughput.variabilityPct}%`}</td><td className="px-2 py-1.5 text-right font-mono">{throughput?.stallCount ?? '—'}</td><td className="px-2 py-1.5 text-right text-[10px] text-[var(--color-text-secondary)]">{routeLabel(throughput?.route)}</td><td className="px-2 py-1.5 text-right"><MacBadge variant={throughput?.status === 'ok' ? 'success' : throughput?.status === 'warning' ? 'warning' : 'danger'}>{check ? resultLabel(check) : 'Нет данных'}</MacBadge></td></tr>
                  })}
                </tbody>
              </table>
            </div>
            {result.errors.length > 0 && <p className="text-[11px] text-[var(--color-warning)]">Не удалось проверить профилей: {result.errors.length}. Причины доступны в логах и истории конкретного профиля.</p>}
            <MacButton variant="secondary" onClick={() => setResult(null)}><Gauge size={14} className="mr-1.5" />Новое сравнение</MacButton>
          </div>
        )}

        {!running && !result && <div className="flex justify-end gap-2"><MacButton variant="ghost" onClick={onClose}>Закрыть</MacButton><MacButton variant="primary" disabled={selected.length === 0} onClick={handleStart}><Play size={14} className="mr-1.5" />Запустить сравнение</MacButton></div>}
      </div>
    </MacModal>
  )
}
