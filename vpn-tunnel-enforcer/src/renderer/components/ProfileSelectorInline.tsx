import { useCallback, useEffect, useState } from 'react'
import type { MouseEventHandler } from 'react'
import { useTranslation } from 'react-i18next'
import { motion, AnimatePresence } from 'framer-motion'
import { Check, ChevronDown, Globe, Activity } from 'lucide-react'
import { MacCard } from '../design-system/MacCard'
import { MacButton } from '../design-system/MacButton'
import { cn } from '../design-system/utils'
import { countryFlag } from './countryGlyph'
import { useAppStore } from '../store'
import { navigateTo, SERVER_CHANGED_EVENT, emitServerChanged } from '../nav'
import type { ServerProfile } from '../../shared/ipc-types'

/**
 * Map a profile name to a country flag emoji.
 */
function countryGlyph(name: string): string {
  return countryFlag(name)
}

/**
 * Inline profile selector card for the Dashboard.
 *
 * Always backed by the server-picker store (servers:list / servers:get-active /
 * servers:select). Used to be split between localProxy and directVpn modes
 * with separate caches; in V2 there is one source of truth.
 */
export function ProfileSelectorInline() {
  const { t } = useTranslation()
  const addLog = useAppStore(s => s.addLog)

  const [open, setOpen] = useState(false)
  const [profiles, setProfiles] = useState<ServerProfile[]>([])
  const [activeId, setActiveId] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  /** null = never measured, 'pinging' = inflight, number = ms, -1 = failed */
  const [pingMs, setPingMs] = useState<number | null | 'pinging' | -1>(null)

  const refresh = useCallback(async () => {
    setLoading(true)
    try {
      const [list, active] = await Promise.all([
        window.electronAPI.serversList(),
        window.electronAPI.serversGetActive()
      ])
      setProfiles(list)
      setActiveId(active.activeId ?? active.profile?.id ?? null)
    } catch (err) {
      console.warn('[ProfileSelectorInline] refresh failed:', err)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    refresh()
  }, [refresh])

  // Re-fetch when another component announces a server change (e.g. the
  // Servers page click, the right-hand quick picker), so the dashboard
  // updates instantly without waiting for a route change.
  useEffect(() => {
    const handler = () => refresh()
    window.addEventListener(SERVER_CHANGED_EVENT, handler)
    return () => window.removeEventListener(SERVER_CHANGED_EVENT, handler)
  }, [refresh])

  // Re-fetch when the dropdown opens — covers the case where the user added
  // servers on the Servers page and switches back to Dashboard without a
  // route change. Cheap because the IPC is local.
  useEffect(() => {
    if (open) refresh()
  }, [open, refresh])

  const current = profiles.find(p => p.id === activeId) ?? profiles[0] ?? null
  const currentName = current?.name ?? null
  const currentProtocol = current?.protocol ?? null
  const hasProfiles = profiles.length > 0

  const handleSelect = async (id: string) => {
    setOpen(false)
    if (id === current?.id) return
    setActiveId(id)
    setPingMs(null)
    try {
      await window.electronAPI.serversSelect(id)
      const profile = profiles.find(p => p.id === id)
      addLog('info', `Сервер выбран: ${profile?.name ?? id}`)
      emitServerChanged()
    } catch (err: any) {
      addLog('error', `Не удалось выбрать сервер: ${err.message}`)
      // Roll back optimistic state
      refresh()
    }
  }

  const handlePingSelected: MouseEventHandler<HTMLButtonElement> = async (e) => {
    e.stopPropagation()
    if (!current?.server || !current.port) {
      addLog('warn', 'Не удалось пингануть: профиль не выбран или некорректен.')
      return
    }
    setPingMs('pinging')
    try {
      const ms = await window.electronAPI.serversPingOne(current.server, current.port)
      if (ms == null) {
        setPingMs(-1)
        addLog('warn', `Пинг ${current.server}:${current.port} не прошёл.`)
      } else {
        setPingMs(ms)
        addLog('info', `Пинг ${current.server}:${current.port}: ${ms} мс`)
      }
    } catch (err: any) {
      setPingMs(-1)
      addLog('error', `Ошибка пинга: ${err.message ?? err}`)
    }
  }

  const pingClass = (() => {
    if (pingMs === 'pinging') return 'text-[var(--color-text-secondary)]'
    if (pingMs === -1) return 'text-[var(--color-danger)]'
    if (typeof pingMs !== 'number') return 'text-[var(--color-text-secondary)]'
    if (pingMs < 80) return 'text-[var(--color-success)]'
    if (pingMs < 200) return 'text-[var(--color-text)]'
    if (pingMs < 500) return 'text-[var(--color-warning)]'
    return 'text-[var(--color-danger)]'
  })()

  const pingLabel = (() => {
    if (pingMs === 'pinging') return '…'
    if (pingMs === -1) return t('profileSelector.pingFailed', '—')
    if (typeof pingMs === 'number') return `${pingMs} ${t('profileSelector.ms', 'ms')}`
    return null
  })()

  // ─── Empty state ──────────────────────────────────────────────────────────

  if (!hasProfiles) {
    return (
      <MacCard className="!p-3">
        <div className="flex items-center gap-3 text-sm text-[var(--color-text-secondary)]">
          <Globe className="w-4 h-4 flex-shrink-0" />
          <span className="flex-1">
            {t('profileSelector.empty', 'Нет доступных профилей.')}{' '}
            <button
              type="button"
              onClick={() => navigateTo('servers')}
              className="text-[var(--color-accent)] hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--color-bg)] rounded"
            >
              {t('profileSelector.addInServers', 'Добавить профиль в раздел «Серверы»')}
            </button>
          </span>
        </div>
      </MacCard>
    )
  }

  // ─── Main render ──────────────────────────────────────────────────────────

  return (
    <MacCard className="!p-2">
      <div
        role="button"
        tabIndex={0}
        onClick={() => setOpen(o => !o)}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault()
            setOpen(o => !o)
          }
        }}
        aria-expanded={open}
        aria-haspopup="listbox"
        className="w-full flex items-center gap-3 px-3 py-2 rounded-[var(--radius-sm)] hover:bg-[var(--color-border)]/40 transition-colors duration-[var(--transition-fast)] cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--color-bg)]"
      >
        <span className="grid h-9 w-9 place-items-center rounded-full bg-[var(--color-bg)] border border-[var(--color-border)] text-lg flex-shrink-0">
          {currentName ? countryGlyph(currentName) : '🌐'}
        </span>
        <div className="flex-1 min-w-0 text-left">
          <p className="text-xs uppercase tracking-wider text-[var(--color-text-secondary)]">
            {t('profileSelector.current', 'Текущий профиль')}
          </p>
          <p className="text-sm font-medium text-[var(--color-text)] truncate">
            {currentName ?? t('profileSelector.none', 'Профиль не выбран')}
            {currentProtocol && (
              <span className="ml-2 text-xs uppercase tracking-wider text-[var(--color-text-secondary)]">
                {currentProtocol}
              </span>
            )}
          </p>
        </div>
        <button
          type="button"
          onClick={handlePingSelected}
          disabled={pingMs === 'pinging' || !currentName}
          aria-label={t('profileSelector.pingSelected', 'Пингануть выбранный')}
          title={t('profileSelector.pingSelected', 'Пингануть выбранный')}
          className={cn(
            'inline-flex items-center gap-1.5 px-2.5 py-1.5 mr-1 rounded-[var(--radius-sm)] text-xs font-medium tabular-nums',
            'border border-[var(--color-border)] bg-[var(--color-bg)]/60',
            'transition-all duration-[var(--transition-fast)]',
            'hover:border-[var(--color-accent)]/50 hover:bg-[var(--color-card-elevated)]',
            'disabled:opacity-50 disabled:pointer-events-none',
            'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--color-bg)]',
            pingClass
          )}
        >
          <Activity
            className={cn(
              'w-3.5 h-3.5 flex-shrink-0',
              pingMs === 'pinging' && 'animate-pulse'
            )}
          />
          {pingLabel ?? t('profileSelector.ping', 'Пинг')}
        </button>
        <motion.div
          animate={{ rotate: open ? 180 : 0 }}
          transition={{ duration: 0.2 }}
          className="text-[var(--color-text-secondary)]"
        >
          <ChevronDown className="w-4 h-4" />
        </motion.div>
      </div>

      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            key="profile-list"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2, ease: 'easeOut' }}
            className="overflow-hidden"
          >
            <div className="mt-2 max-h-72 overflow-y-auto pr-1 space-y-1">
              {profiles.map(profile => {
                const selected = profile.id === current?.id
                return (
                  <button
                    key={profile.id}
                    type="button"
                    onClick={() => handleSelect(profile.id)}
                    className={`w-full flex items-center gap-3 px-3 py-2 rounded-[var(--radius-sm)] text-left transition-all duration-[var(--transition-fast)] ${
                      selected
                        ? 'bg-[var(--color-accent)]/10 border border-[var(--color-accent)]/40'
                        : 'border border-transparent hover:bg-[var(--color-border)]/40'
                    }`}
                  >
                    <span className="text-lg flex-shrink-0">{countryGlyph(profile.name)}</span>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-[var(--color-text)] truncate">
                        {profile.name}
                      </p>
                      <p className="text-[11px] uppercase tracking-wider text-[var(--color-text-secondary)]">
                        {profile.protocol}
                        {profile.country ? ` · ${profile.country}` : ''}
                        {profile.ping != null ? ` · ${profile.ping} ms` : ''}
                      </p>
                    </div>
                    {selected && (
                      <Check className="w-4 h-4 text-[var(--color-accent)] flex-shrink-0" />
                    )}
                  </button>
                )
              })}
              {loading && (
                <p className="text-xs text-[var(--color-text-secondary)] px-3 py-2">
                  {t('common.loading')}
                </p>
              )}
            </div>
            <div className="flex justify-end mt-2 px-1">
              <MacButton variant="ghost" size="sm" onClick={() => setOpen(false)}>
                {t('common.close')}
              </MacButton>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </MacCard>
  )
}
