import { useState, useEffect, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { Server, Wifi, WifiOff, Plus, Trash2, Check, RefreshCw, Loader2, Copy } from 'lucide-react'
import { MacCard, MacBadge, MacButton, MacInput } from '../design-system'
import { PageTip } from '../components/PageTip'
import { ServerDetailModal } from '../components/ServerDetailModal'
import { detectCountry } from '../components/countryGlyph'
import { emitServerChanged } from '../nav'
import type { ServerProfile } from '../../shared/ipc-types'

/**
 * Per-row ping result keyed by row id (profile.id or `cached-${idx}`).
 */
interface PerRowPing {
  ping: number | null
  country: string | null
  loading: boolean
}

/**
 * Groups profiles by their protocol field (client-side).
 */
function groupByProtocol(profiles: ServerProfile[]): Record<string, ServerProfile[]> {
  const groups: Record<string, ServerProfile[]> = {}
  for (const profile of profiles) {
    const key = profile.protocol || 'unknown'
    if (!groups[key]) {
      groups[key] = []
    }
    groups[key].push(profile)
  }
  return groups
}

/**
 * Returns the badge variant for a server status.
 */
function statusVariant(status: ServerProfile['status']) {
  switch (status) {
    case 'online':
      return 'success'
    case 'offline':
      return 'danger'
    default:
      return 'neutral'
  }
}

/**
 * Extracts a probe result into a compact ping/country shape.
 */
function probeToPing(probe: any): { ping: number | null; country: string | null } {
  return {
    ping: probe?.latency?.avg != null ? Math.round(probe.latency.avg) : null,
    country: probe?.asn?.country || null
  }
}

/**
 * Servers page — displays server/profile list grouped by protocol.
 * Supports ping all, add from subscription, select, and remove actions.
 */
export function Servers() {
  const { t } = useTranslation()
  const [profiles, setProfiles] = useState<ServerProfile[]>([])
  const [activeId, setActiveId] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [pinging, setPinging] = useState(false)
  const [addInput, setAddInput] = useState('')
  const [adding, setAdding] = useState(false)
  const [addError, setAddError] = useState('')
  const [perRowPings, setPerRowPings] = useState<Record<string, PerRowPing>>({})
  const [detailProfile, setDetailProfile] = useState<ServerProfile | null>(null)
  // Per-row "Скопировано/Ошибка" badge state for the export-key button.
  // Cleared automatically after a few seconds; multiple rows can be in
  // flight simultaneously without stomping each other.
  const [exportFlash, setExportFlash] = useState<Record<string, 'copied' | 'failed'>>({})

  const fetchProfiles = useCallback(async () => {
    try {
      const [list, active] = await Promise.all([
        window.electronAPI.serversList(),
        window.electronAPI.serversGetActive()
      ])
      setProfiles(list)
      setActiveId(active.activeId)
    } catch (err) {
      console.error('Failed to fetch server profiles:', err)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchProfiles()
  }, [fetchProfiles])

  /**
   * Probe a single profile and update its row state.
   */
  const probeRow = useCallback(
    async (rowKey: string, host: string, port: number | undefined) => {
      setPerRowPings((prev) => ({
        ...prev,
        [rowKey]: { ping: prev[rowKey]?.ping ?? null, country: prev[rowKey]?.country ?? null, loading: true }
      }))
      try {
        const probe = await window.electronAPI.serverProbe(host, port)
        const { ping, country } = probeToPing(probe)
        setPerRowPings((prev) => ({
          ...prev,
          [rowKey]: { ping, country, loading: false }
        }))
      } catch (err) {
        console.error('Per-row probe failed:', err)
        setPerRowPings((prev) => ({
          ...prev,
          [rowKey]: { ping: prev[rowKey]?.ping ?? null, country: prev[rowKey]?.country ?? null, loading: false }
        }))
      }
    },
    []
  )

  const handlePingOne = (profile: ServerProfile) => {
    if (!profile.server) return
    probeRow(profile.id, profile.server, profile.port)
  }

  const handlePingAll = async () => {
    setPinging(true)
    try {
      if (profiles.length > 0) {
        const updated = await window.electronAPI.serversPingAll()
        setProfiles(updated)
        setPerRowPings((prev) => {
          const next = { ...prev }
          for (const p of updated) {
            next[p.id] = {
              ping: p.ping ?? null,
              country: prev[p.id]?.country ?? p.country ?? null,
              loading: false
            }
          }
          return next
        })
      }
    } catch (err) {
      console.error('Ping all failed:', err)
    } finally {
      setPinging(false)
    }
  }

  const handleAdd = async () => {
    const trimmed = addInput.trim()
    if (!trimmed) return

    setAdding(true)
    setAddError('')
    try {
      await window.electronAPI.serversAdd(trimmed)
      setAddInput('')
      await fetchProfiles()
    } catch (err: any) {
      setAddError(err?.message || String(err))
    } finally {
      setAdding(false)
    }
  }

  const handleSelect = async (id: string) => {
    try {
      await window.electronAPI.serversSelect(id)
      setActiveId(id)
      emitServerChanged()
    } catch (err) {
      console.error('Select failed:', err)
    }
  }

  const handleRemove = async (id: string) => {
    try {
      await window.electronAPI.serversRemove(id)
      setProfiles((prev) => prev.filter((p) => p.id !== id))
      if (activeId === id) setActiveId(null)
    } catch (err) {
      console.error('Remove failed:', err)
    }
  }

  const handleExport = async (id: string) => {
    try {
      const result = await window.electronAPI.serversExportKey(id)
      if (!result.ok) {
        setExportFlash(prev => ({ ...prev, [id]: 'failed' }))
        setTimeout(() => setExportFlash(prev => { const next = { ...prev }; delete next[id]; return next }), 2200)
        return
      }
      await navigator.clipboard.writeText(result.uri)
      setExportFlash(prev => ({ ...prev, [id]: 'copied' }))
      setTimeout(() => setExportFlash(prev => { const next = { ...prev }; delete next[id]; return next }), 2200)
    } catch {
      setExportFlash(prev => ({ ...prev, [id]: 'failed' }))
      setTimeout(() => setExportFlash(prev => { const next = { ...prev }; delete next[id]; return next }), 2200)
    }
  }

  const grouped = groupByProtocol(profiles)
  const protocolKeys = Object.keys(grouped).sort()

  return (
    <div className="space-y-6">
      {/* Onboarding tip */}
      <PageTip tipKey="servers">{t('tips.servers')}</PageTip>

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-[var(--color-text)]">
            {t('servers.title')}
          </h1>
          <p className="text-sm text-[var(--color-text-secondary)] mt-1">
            {t('servers.description')}
          </p>
        </div>
        <MacButton
          variant="secondary"
          onClick={handlePingAll}
          loading={pinging}
          disabled={profiles.length === 0}
        >
          <RefreshCw className="w-4 h-4 mr-2" />
          {pinging ? t('servers.checking') : t('servers.pingAll')}
        </MacButton>
      </div>

      {/* Add server input */}
      <MacCard>
        <div className="flex items-end gap-3">
          <div className="flex-1">
            <MacInput
              placeholder={t('servers.addPlaceholder')}
              value={addInput}
              onChange={(e) => {
                setAddInput(e.target.value)
                if (addError) setAddError('')
              }}
              error={addError}
              onKeyDown={(e) => {
                if (e.key === 'Enter') handleAdd()
              }}
            />
          </div>
          <MacButton onClick={handleAdd} loading={adding} disabled={!addInput.trim()}>
            <Plus className="w-4 h-4 mr-1" />
            {t('servers.addServer')}
          </MacButton>
        </div>
      </MacCard>

      {/* Server list */}
      {loading ? (
        <div className="flex items-center justify-center py-16 text-[var(--color-text-secondary)]">
          <p className="text-sm">{t('common.loading')}</p>
        </div>
      ) : profiles.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-16 text-[var(--color-text-secondary)]">
          <Server className="w-12 h-12 mb-4 opacity-40" />
          <p className="text-sm">{t('servers.noServers')}</p>
        </div>
      ) : (
        <div className="space-y-6">
          {protocolKeys.map((protocol) => (
            <div key={protocol}>
              <h2 className="text-sm font-medium text-[var(--color-text-secondary)] uppercase tracking-wide mb-3">
                {protocol}
              </h2>
              <div className="space-y-2">
                {grouped[protocol].map((profile) => (
                  <ServerProfileCard
                    key={profile.id}
                    profile={profile}
                    isActive={profile.id === activeId}
                    perRowPing={perRowPings[profile.id]}
                    exportFlash={exportFlash[profile.id]}
                    onSelect={handleSelect}
                    onRemove={handleRemove}
                    onPing={handlePingOne}
                    onExport={handleExport}
                    onOpenDetail={setDetailProfile}
                    t={t}
                  />
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Detail modal */}
      <ServerDetailModal
        open={!!detailProfile}
        profile={detailProfile}
        onClose={() => setDetailProfile(null)}
      />
    </div>
  )
}

interface ServerProfileCardProps {
  profile: ServerProfile
  isActive: boolean
  perRowPing?: PerRowPing
  exportFlash?: 'copied' | 'failed'
  onSelect: (id: string) => void
  onRemove: (id: string) => void
  onPing: (profile: ServerProfile) => void
  onExport: (id: string) => void
  onOpenDetail: (profile: ServerProfile) => void
  t: (key: string, fallback?: string) => string
}

function ServerProfileCard({
  profile,
  isActive,
  perRowPing,
  exportFlash,
  onSelect,
  onRemove,
  onPing,
  onExport,
  onOpenDetail,
  t
}: ServerProfileCardProps) {
  // Country comes from the picker's geolocation (filled via ipapi by IP) or,
  // when an ad-hoc probe runs on this row, from the live ASN lookup. Name
  // recognition is only used as a last-resort source for the flag emoji
  // when neither geolocation nor the live probe has produced a country yet.
  const country = perRowPing?.country || profile.country || null
  const recognised = detectCountry(profile.name)
  const flag = recognised?.flag || '🌐'
  const ping = perRowPing?.ping ?? profile.ping
  return (
    <MacCard
      hoverable
      className={
        '!p-3 cursor-pointer ' +
        (isActive ? '!border-[var(--color-accent)] ring-1 ring-[var(--color-accent)]/30' : '')
      }
      onClick={() => onOpenDetail(profile)}
    >
      <div className="flex items-center gap-3">
        <MacBadge variant={statusVariant(profile.status)} dot pulse={profile.status === 'online'} />
        <span
          className="text-lg leading-none flex-shrink-0 select-none"
          aria-hidden="true"
          title={country ?? undefined}
        >
          {flag}
        </span>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium text-[var(--color-text)] truncate">
              {profile.name}
            </span>
            <MacBadge variant="info">{profile.protocol}</MacBadge>
            {isActive && <MacBadge variant="success">{t('servers.active', 'Активный')}</MacBadge>}
            {country && (
              <span className="text-xs text-[var(--color-text-secondary)]">
                {country}
              </span>
            )}
          </div>
          <div className="flex items-center gap-3 mt-0.5">
            <span className="text-xs text-[var(--color-text-secondary)]">
              {profile.server}:{profile.port}
            </span>
          </div>
        </div>

        <div className="flex items-center gap-1 min-w-[60px] justify-end">
          {profile.status === 'online' ? (
            <Wifi className="w-3.5 h-3.5 text-[var(--color-success)]" />
          ) : profile.status === 'offline' ? (
            <WifiOff className="w-3.5 h-3.5 text-[var(--color-danger)]" />
          ) : null}
          <span className="text-xs text-[var(--color-text-secondary)] tabular-nums">
            {ping != null ? `${ping} ms` : '—'}
          </span>
        </div>

        <div className="flex items-center gap-1.5">
          <MacButton
            size="sm"
            variant="ghost"
            disabled={!profile.server || perRowPing?.loading}
            onClick={(e) => {
              e.stopPropagation()
              onPing(profile)
            }}
            aria-label={t('servers.pingOne', 'Ping')}
          >
            {perRowPing?.loading ? (
              <Loader2 size={12} className="animate-spin" />
            ) : (
              <Wifi size={12} />
            )}
          </MacButton>
          <MacButton
            size="sm"
            variant="ghost"
            onClick={(e) => {
              e.stopPropagation()
              onExport(profile.id)
            }}
            aria-label={t('servers.exportKey', 'Скопировать ключ')}
            title={
              exportFlash === 'copied'
                ? t('servers.keyCopied', 'Ключ скопирован')
                : exportFlash === 'failed'
                  ? t('servers.exportFailed', 'Не удалось экспортировать')
                  : t('servers.exportKey', 'Скопировать ключ')
            }
          >
            {exportFlash === 'copied'
              ? <Check className="w-3.5 h-3.5 text-[var(--color-success)]" />
              : <Copy className="w-3.5 h-3.5" />}
          </MacButton>
          <MacButton
            size="sm"
            variant={isActive ? 'secondary' : 'primary'}
            disabled={isActive}
            onClick={(e) => {
              e.stopPropagation()
              if (!isActive) onSelect(profile.id)
            }}
          >
            <Check className="w-3.5 h-3.5 mr-1" />
            {isActive ? t('servers.selected', 'Выбран') : t('servers.select')}
          </MacButton>
          <MacButton
            size="sm"
            variant="ghost"
            onClick={(e) => {
              e.stopPropagation()
              onRemove(profile.id)
            }}
          >
            <Trash2 className="w-3.5 h-3.5 text-[var(--color-danger)]" />
          </MacButton>
        </div>
      </div>
    </MacCard>
  )
}
