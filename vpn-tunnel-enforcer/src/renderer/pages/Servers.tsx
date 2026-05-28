import { useState, useEffect, useCallback, useMemo, useRef, type KeyboardEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Server,
  Wifi,
  WifiOff,
  Plus,
  Trash2,
  Check,
  RefreshCw,
  Loader2,
  Copy,
  Download,
  ChevronRight,
  ChevronDown,
  HeartPulse,
  ExternalLink,
  AlertCircle
} from 'lucide-react'
import {
  MacCard,
  MacBadge,
  MacButton,
  MacInput,
  MacSelect,
  MacModal,
  MacProgress,
  MacToast,
  type ToastData,
  type SelectOption,
  type BadgeVariant
} from '../design-system'
import { PageTip } from '../components/PageTip'
import { ServerDetailModal } from '../components/ServerDetailModal'
import { detectCountry } from '../components/countryGlyph'
import { emitServerChanged } from '../nav'
import { useAppStore } from '../store'
import type { ServerProfile } from '../../shared/ipc-types'

// ─── Types ─────────────────────────────────────────────────────────────────

/**
 * Mirrors the future shared `ServerGroup` shape from ipc-types. Defined
 * locally so this file compiles before Agent A merges the type addition;
 * once that lands, this can be deleted in favour of the import.
 */
interface ServerGroup {
  id: string
  name: string
  source: 'subscription' | 'manual'
  sourceUrl?: string
  importedAt: number
  lastFetchedAt?: number
  lastFetchAttemptAt?: number
  lastFetchError?: string
  status: 'active' | 'expired' | 'unreachable' | 'unknown'
  trafficUsedBytes?: number
  trafficUploadBytes?: number
  trafficDownloadBytes?: number
  trafficTotalBytes?: number
  expiresAt?: number
  refreshIntervalSeconds?: number
  webPageUrl?: string
  lastRefreshProfilesCount?: number
}

interface PerRowPing {
  ping: number | null
  country: string | null
  loading: boolean
}

interface HealthRow {
  online: boolean
  latencyMs: number | null
  reason?: string
}

const VIRTUAL_ALL_GROUP_ID = '__virtual_all__'
const EXPANDED_STORAGE_KEY = 'vpnte:expanded-groups'
const NEW_GROUP_OPTION = '__new__'

// ─── Helpers ───────────────────────────────────────────────────────────────

/** Keep ServerProfileCards visually consistent with the previous protocol-grouped layout. */
function groupByProtocol(profiles: ServerProfile[]): Record<string, ServerProfile[]> {
  const groups: Record<string, ServerProfile[]> = {}
  for (const profile of profiles) {
    const key = profile.protocol || 'unknown'
    if (!groups[key]) groups[key] = []
    groups[key].push(profile)
  }
  return groups
}

function statusVariant(status: ServerProfile['status']): BadgeVariant {
  switch (status) {
    case 'online':
      return 'success'
    case 'offline':
      return 'danger'
    default:
      return 'neutral'
  }
}

function groupStatusVariant(status: ServerGroup['status']): BadgeVariant {
  switch (status) {
    case 'active':
      return 'success'
    case 'expired':
      return 'warning'
    case 'unreachable':
      return 'danger'
    default:
      return 'neutral'
  }
}

function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let value = bytes
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024
    unit++
  }
  const decimals = value >= 100 ? 0 : value >= 10 ? 1 : 2
  return `${value.toFixed(decimals)} ${units[unit]}`
}

/**
 * Locale-aware "5 minutes ago" / "in 3 days" formatting. Falls back to a
 * plain ISO date when Intl.RelativeTimeFormat isn't available.
 */
function formatRelative(ts: number, locale: string): string {
  if (!ts) return ''
  try {
    const rtf = new Intl.RelativeTimeFormat(locale.startsWith('ru') ? 'ru' : locale, {
      numeric: 'auto'
    })
    const diffMs = ts - Date.now()
    const abs = Math.abs(diffMs)
    const minute = 60_000
    const hour = 60 * minute
    const day = 24 * hour
    if (abs < minute) return rtf.format(Math.round(diffMs / 1000), 'second')
    if (abs < hour) return rtf.format(Math.round(diffMs / minute), 'minute')
    if (abs < day) return rtf.format(Math.round(diffMs / hour), 'hour')
    return rtf.format(Math.round(diffMs / day), 'day')
  } catch {
    return new Date(ts).toLocaleString()
  }
}

let __toastSeq = 0
function nextToastId(): string {
  __toastSeq += 1
  return `srv-toast-${__toastSeq}-${Date.now()}`
}

/** Sort groups: subscriptions first by importedAt desc, manual last. */
function sortGroups(groups: ServerGroup[]): ServerGroup[] {
  return [...groups].sort((a, b) => {
    if (a.source !== b.source) return a.source === 'subscription' ? -1 : 1
    return (b.importedAt ?? 0) - (a.importedAt ?? 0)
  })
}

/** Read persisted expanded ids from localStorage. Tolerates parse errors. */
function readExpandedIds(): Set<string> {
  try {
    const raw = localStorage.getItem(EXPANDED_STORAGE_KEY)
    if (!raw) return new Set()
    const parsed = JSON.parse(raw) as unknown
    if (Array.isArray(parsed)) return new Set(parsed.filter((x): x is string => typeof x === 'string'))
  } catch {}
  return new Set()
}

function writeExpandedIds(ids: Set<string>) {
  try {
    localStorage.setItem(EXPANDED_STORAGE_KEY, JSON.stringify(Array.from(ids)))
  } catch {}
}

// ─── Page ──────────────────────────────────────────────────────────────────

export function Servers() {
  const { t, i18n } = useTranslation()
  const addLog = useAppStore((s) => s.addLog)
  const [profiles, setProfiles] = useState<ServerProfile[]>([])
  const [groups, setGroups] = useState<ServerGroup[]>([])
  const [groupsAvailable, setGroupsAvailable] = useState<boolean | null>(null)
  const [activeId, setActiveId] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [pinging, setPinging] = useState(false)
  const [addInput, setAddInput] = useState('')
  const [addGroupId, setAddGroupId] = useState<string>(NEW_GROUP_OPTION)
  const [adding, setAdding] = useState(false)
  const [addError, setAddError] = useState('')
  const [perRowPings, setPerRowPings] = useState<Record<string, PerRowPing>>({})
  const [detailProfile, setDetailProfile] = useState<ServerProfile | null>(null)
  const [exportFlash, setExportFlash] = useState<Record<string, 'copied' | 'saved' | 'failed'>>({})
  const [exportingAll, setExportingAll] = useState(false)
  const [expandedIds, setExpandedIds] = useState<Set<string>>(() => readExpandedIds())

  // Per-group-runtime UI state.
  const [refreshingGroups, setRefreshingGroups] = useState<Record<string, boolean>>({})
  const [healthCheckingGroups, setHealthCheckingGroups] = useState<Record<string, boolean>>({})
  // Health-check results live only in-page (intentionally not persisted).
  // Keyed by profileId.
  const [healthByProfile, setHealthByProfile] = useState<Record<string, HealthRow>>({})

  // Inline rename: holds the id of the group being renamed and the draft.
  const [renamingId, setRenamingId] = useState<string | null>(null)
  const [renameDraft, setRenameDraft] = useState('')
  const renameInputRef = useRef<HTMLInputElement>(null)

  // Two-button delete confirmation.
  const [deleteTarget, setDeleteTarget] = useState<ServerGroup | null>(null)
  const [deletingGroup, setDeletingGroup] = useState(false)

  // Toast stack (group refresh outcomes, etc.)
  const [toasts, setToasts] = useState<ToastData[]>([])

  const showToast = useCallback(
    (variant: ToastData['variant'], title: string, description?: string) => {
      const id = nextToastId()
      setToasts((prev) => [...prev, { id, variant, title, description }])
      window.setTimeout(() => {
        setToasts((prev) => prev.filter((tt) => tt.id !== id))
      }, 6000)
    },
    []
  )
  const dismissToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((tt) => tt.id !== id))
  }, [])

  // ─── Data fetch ─────────────────────────────────────────────────────────

  const fetchProfiles = useCallback(async () => {
    try {
      const [list, active] = await Promise.all([
        window.electronAPI.serversList(),
        window.electronAPI.serversGetActive()
      ])
      setProfiles(list)
      setActiveId(active.activeId ?? active.profile?.id ?? null)
    } catch (err) {
      console.error('Failed to fetch server profiles:', err)
    }
  }, [])

  const fetchGroups = useCallback(async () => {
    const api = window.electronAPI as unknown as {
      groupsList?: () => Promise<ServerGroup[]>
    }
    if (typeof api.groupsList !== 'function') {
      // IPC not wired yet — fall back to a synthetic "All servers" group.
      setGroupsAvailable(false)
      setGroups([])
      return
    }
    try {
      const list = await api.groupsList()
      setGroupsAvailable(true)
      setGroups(Array.isArray(list) ? list : [])
    } catch (err) {
      // If the IPC exists but blows up, fall back rather than wedging the page.
      console.warn('[Servers] groupsList failed, falling back to flat list:', err)
      setGroupsAvailable(false)
      setGroups([])
    }
  }, [])

  const refreshAll = useCallback(async () => {
    await Promise.all([fetchProfiles(), fetchGroups()])
  }, [fetchProfiles, fetchGroups])

  useEffect(() => {
    let mounted = true
    ;(async () => {
      try {
        await refreshAll()
      } finally {
        if (mounted) setLoading(false)
      }
    })()
    return () => {
      mounted = false
    }
  }, [refreshAll])

  // Auto-expand when there is exactly one effective group, and remember the
  // user's choices via localStorage on every change.
  useEffect(() => {
    writeExpandedIds(expandedIds)
  }, [expandedIds])

  const effectiveGroups = useMemo<ServerGroup[]>(() => {
    if (!groupsAvailable) {
      // Single virtual group containing every profile.
      return [
        {
          id: VIRTUAL_ALL_GROUP_ID,
          name: t('servers.groups.all', 'Все серверы'),
          source: 'manual',
          importedAt: 0,
          status: 'unknown'
        }
      ]
    }
    return sortGroups(groups)
  }, [groups, groupsAvailable, t])

  // When there's exactly one group, treat it as expanded by default.
  useEffect(() => {
    if (effectiveGroups.length === 1) {
      const onlyId = effectiveGroups[0].id
      setExpandedIds((prev) => (prev.has(onlyId) ? prev : new Set([...prev, onlyId])))
    }
  }, [effectiveGroups])

  // Map profiles to their group (or virtual). If a profile has a groupId we
  // don't know about (race during refresh), it floats up as its own bucket.
  const profilesByGroup = useMemo<Record<string, ServerProfile[]>>(() => {
    const map: Record<string, ServerProfile[]> = {}
    if (!groupsAvailable) {
      map[VIRTUAL_ALL_GROUP_ID] = profiles
      return map
    }
    for (const g of groups) map[g.id] = []
    for (const p of profiles) {
      const gid = (p as ServerProfile & { groupId?: string }).groupId
      const target = gid && map[gid] ? gid : null
      if (target) {
        map[target].push(p)
      } else if (gid) {
        // Orphan — keep them in a synthetic bucket keyed by their groupId so
        // they're at least visible. Won't normally render unless the group
        // header is also synthesised.
        if (!map[gid]) map[gid] = []
        map[gid].push(p)
      } else {
        // Profile with no groupId at all — bucket under the first manual
        // group, or first group, or virtual all.
        const fallbackId =
          groups.find((g) => g.source === 'manual')?.id ?? groups[0]?.id ?? VIRTUAL_ALL_GROUP_ID
        if (!map[fallbackId]) map[fallbackId] = []
        map[fallbackId].push(p)
      }
    }
    return map
  }, [profiles, groups, groupsAvailable])

  // ─── Per-row probe (kept verbatim from the previous version) ─────────────

  const probeRow = useCallback(
    async (rowKey: string, host: string, port: number | undefined) => {
      setPerRowPings((prev) => ({
        ...prev,
        [rowKey]: {
          ping: prev[rowKey]?.ping ?? null,
          country: prev[rowKey]?.country ?? null,
          loading: true
        }
      }))
      try {
        const probe = await window.electronAPI.serverProbe(host, port)
        const ping = probe?.latency?.avg != null ? Math.round(probe.latency.avg) : null
        const country = probe?.asn?.country || null
        setPerRowPings((prev) => ({ ...prev, [rowKey]: { ping, country, loading: false } }))
      } catch (err) {
        console.error('Per-row probe failed:', err)
        setPerRowPings((prev) => ({
          ...prev,
          [rowKey]: {
            ping: prev[rowKey]?.ping ?? null,
            country: prev[rowKey]?.country ?? null,
            loading: false
          }
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

  // ─── Add ────────────────────────────────────────────────────────────────

  const handleAdd = async () => {
    const trimmed = addInput.trim()
    if (!trimmed) return

    setAdding(true)
    setAddError('')
    try {
      const api = window.electronAPI as unknown as {
        serversAddToGroup?: (input: string, groupId: string | null) => Promise<ServerProfile[]>
      }
      if (addGroupId !== NEW_GROUP_OPTION && groupsAvailable && api.serversAddToGroup) {
        await api.serversAddToGroup(trimmed, addGroupId)
      } else {
        await window.electronAPI.serversAdd(trimmed)
      }
      setAddInput('')
      // Reset selection to "create new" so the user's next paste also creates
      // a fresh group unless they pick otherwise. Keeps focus on the input
      // for serial pastes.
      setAddGroupId(NEW_GROUP_OPTION)
      await refreshAll()
    } catch (err: any) {
      setAddError(err?.message || String(err))
    } finally {
      setAdding(false)
    }
  }

  // ─── Select / Remove / Export ───────────────────────────────────────────

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
        setExportFlash((prev) => ({ ...prev, [id]: 'failed' }))
        window.setTimeout(
          () =>
            setExportFlash((prev) => {
              const next = { ...prev }
              delete next[id]
              return next
            }),
          2200
        )
        return
      }
      await navigator.clipboard.writeText(result.uri)
      setExportFlash((prev) => ({ ...prev, [id]: 'copied' }))
      window.setTimeout(
        () =>
          setExportFlash((prev) => {
            const next = { ...prev }
            delete next[id]
            return next
          }),
        2200
      )
    } catch {
      setExportFlash((prev) => ({ ...prev, [id]: 'failed' }))
      window.setTimeout(
        () =>
          setExportFlash((prev) => {
            const next = { ...prev }
            delete next[id]
            return next
          }),
        2200
      )
    }
  }

  const handleExportToFile = async (id: string) => {
    try {
      const result = await window.electronAPI.serversExportKeyToFile(id)
      if (result.ok) {
        setExportFlash((prev) => ({ ...prev, [id]: 'saved' }))
        window.setTimeout(
          () =>
            setExportFlash((prev) => {
              const next = { ...prev }
              delete next[id]
              return next
            }),
          2500
        )
        return
      }
      if ((result as any).cancelled) return
      setExportFlash((prev) => ({ ...prev, [id]: 'failed' }))
      window.setTimeout(
        () =>
          setExportFlash((prev) => {
            const next = { ...prev }
            delete next[id]
            return next
          }),
        2200
      )
    } catch {
      setExportFlash((prev) => ({ ...prev, [id]: 'failed' }))
      window.setTimeout(
        () =>
          setExportFlash((prev) => {
            const next = { ...prev }
            delete next[id]
            return next
          }),
        2200
      )
    }
  }

  const handleExportAll = async () => {
    setExportingAll(true)
    try {
      const result = await window.electronAPI.serversExportAllKeysToFile()
      if (result.ok) {
        addLog(
          'info',
          `Сохранено ${result.exported} ключей в ${result.path}` +
            (result.skipped > 0 ? ` (пропущено: ${result.skipped})` : '')
        )
        return
      }
      if ((result as any).cancelled) return
      const reason = (result as { reason?: string }).reason || 'неизвестная ошибка'
      addLog('error', `Не удалось сохранить ключи: ${reason}`)
    } catch (err: any) {
      addLog('error', `Не удалось сохранить ключи: ${err?.message ?? err}`)
    } finally {
      setExportingAll(false)
    }
  }

  // ─── Group expand/collapse ──────────────────────────────────────────────

  const toggleGroupExpanded = (id: string) => {
    setExpandedIds((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  // ─── Group rename ───────────────────────────────────────────────────────

  const startRename = (group: ServerGroup) => {
    if (group.id === VIRTUAL_ALL_GROUP_ID || !groupsAvailable) return
    setRenamingId(group.id)
    setRenameDraft(group.name)
    // Defer focus until the input is mounted.
    window.setTimeout(() => renameInputRef.current?.focus(), 0)
  }

  const commitRename = async () => {
    if (!renamingId) return
    const target = groups.find((g) => g.id === renamingId)
    if (!target) {
      setRenamingId(null)
      return
    }
    const next = renameDraft.trim()
    if (!next || next === target.name) {
      setRenamingId(null)
      return
    }
    try {
      const api = window.electronAPI as unknown as {
        groupsRename?: (id: string, name: string) => Promise<ServerGroup | null>
      }
      if (api.groupsRename) {
        const updated = await api.groupsRename(renamingId, next)
        if (updated) {
          setGroups((prev) => prev.map((g) => (g.id === updated.id ? updated : g)))
        } else {
          await fetchGroups()
        }
      }
    } catch (err) {
      console.error('Rename failed:', err)
    } finally {
      setRenamingId(null)
    }
  }

  const cancelRename = () => {
    setRenamingId(null)
    setRenameDraft('')
  }

  const handleRenameKey = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      e.preventDefault()
      commitRename()
    } else if (e.key === 'Escape') {
      e.preventDefault()
      cancelRename()
    }
  }

  // ─── Group refresh / health-check / delete ──────────────────────────────

  const handleGroupRefresh = async (group: ServerGroup) => {
    if (group.id === VIRTUAL_ALL_GROUP_ID) return
    const api = window.electronAPI as unknown as {
      groupsRefresh?: (id: string) => Promise<
        | { ok: true; group: ServerGroup; addedCount: number; updatedCount: number; removedCount: number }
        | { ok: false; error: string }
      >
    }
    if (!api.groupsRefresh) {
      showToast('warning', t('servers.groups.fallbackHint', 'Группы по подпискам станут доступны после следующего обновления.'))
      return
    }
    setRefreshingGroups((prev) => ({ ...prev, [group.id]: true }))
    try {
      const result = await api.groupsRefresh(group.id)
      if (result.ok) {
        setGroups((prev) => prev.map((g) => (g.id === result.group.id ? result.group : g)))
        await fetchProfiles()
        addLog(
          'info',
          t('servers.groups.refreshOk', {
            added: result.addedCount,
            updated: result.updatedCount,
            removed: result.removedCount
          })
        )
        showToast(
          'success',
          group.name,
          t('servers.groups.refreshOk', {
            added: result.addedCount,
            updated: result.updatedCount,
            removed: result.removedCount
          })
        )
        if (result.group.status === 'expired') {
          showToast(
            'warning',
            group.name,
            t('servers.groups.expiredBannerToast')
          )
        }
      } else {
        const message = t('servers.groups.refreshFailedDetail', {
          error: result.error,
          when: formatRelative(Date.now(), i18n.language)
        })
        addLog('warn', `${group.name}: ${result.error}`)
        showToast('error', t('servers.groups.refreshFailed'), message)
        // Re-fetch so the lastFetchAttemptAt / lastFetchError fields update.
        await fetchGroups()
      }
    } catch (err: any) {
      const message = err?.message ?? String(err)
      addLog('error', `${group.name}: ${message}`)
      showToast('error', t('servers.groups.refreshFailed'), message)
    } finally {
      setRefreshingGroups((prev) => {
        const next = { ...prev }
        delete next[group.id]
        return next
      })
    }
  }

  const handleGroupHealth = async (group: ServerGroup) => {
    if (group.id === VIRTUAL_ALL_GROUP_ID) return
    const api = window.electronAPI as unknown as {
      groupsCheckHealth?: (id: string) => Promise<
        | {
            ok: true
            results: Array<{ profileId: string; online: boolean; latencyMs: number | null; reason?: string }>
          }
        | { ok: false; error: string }
      >
    }
    if (!api.groupsCheckHealth) {
      showToast('warning', t('servers.groups.fallbackHint', 'Группы по подпискам станут доступны после следующего обновления.'))
      return
    }
    setHealthCheckingGroups((prev) => ({ ...prev, [group.id]: true }))
    try {
      const result = await api.groupsCheckHealth(group.id)
      if (result.ok) {
        setHealthByProfile((prev) => {
          const next = { ...prev }
          for (const r of result.results) {
            next[r.profileId] = {
              online: r.online,
              latencyMs: r.latencyMs ?? null,
              reason: r.reason
            }
          }
          return next
        })
        const alive = result.results.filter((r) => r.online).length
        showToast(
          'info',
          group.name,
          t('servers.health.aliveCount', { count: alive, total: result.results.length })
        )
      } else {
        showToast('error', group.name, result.error)
      }
    } catch (err: any) {
      showToast('error', group.name, err?.message ?? String(err))
    } finally {
      setHealthCheckingGroups((prev) => {
        const next = { ...prev }
        delete next[group.id]
        return next
      })
    }
  }

  const confirmDeleteGroup = async (deleteServers: boolean) => {
    if (!deleteTarget) return
    const target = deleteTarget
    setDeletingGroup(true)
    try {
      const api = window.electronAPI as unknown as {
        groupsDelete?: (id: string, deleteServers: boolean) => Promise<{ ok: boolean }>
      }
      if (!api.groupsDelete) {
        showToast('warning', t('servers.groups.fallbackHint', 'Группы по подпискам станут доступны после следующего обновления.'))
        return
      }
      await api.groupsDelete(target.id, deleteServers)
      await refreshAll()
      addLog(
        'info',
        `${target.name}: ${deleteServers ? 'удалена с серверами' : 'удалена (серверы оставлены)'}`
      )
    } catch (err: any) {
      addLog('error', `${target.name}: ${err?.message ?? err}`)
    } finally {
      setDeletingGroup(false)
      setDeleteTarget(null)
    }
  }

  // ─── Render helpers ─────────────────────────────────────────────────────

  const groupOptions = useMemo<SelectOption[]>(() => {
    const opts: SelectOption[] = [
      {
        value: NEW_GROUP_OPTION,
        label: t('servers.add.newGroupOption', 'Создать новую группу')
      }
    ]
    if (groupsAvailable) {
      for (const g of sortGroups(groups)) {
        const tag =
          g.source === 'subscription'
            ? t('servers.add.groupSubscriptionTag', 'подписка')
            : t('servers.add.groupManualTag', 'ключи')
        const icon = g.source === 'subscription' ? '📡' : '🔑'
        opts.push({ value: g.id, label: `${icon} ${g.name}  ·  ${tag}` })
      }
    }
    return opts
  }, [groups, groupsAvailable, t])

  // ─── JSX ────────────────────────────────────────────────────────────────

  const totalProfiles = profiles.length

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
        <div className="flex items-center gap-2">
          <MacButton
            variant="secondary"
            onClick={handleExportAll}
            loading={exportingAll}
            disabled={totalProfiles === 0 || exportingAll}
          >
            <Download className="w-4 h-4 mr-2" />
            {t('servers.exportAllKeys')}
          </MacButton>
          <MacButton
            variant="secondary"
            onClick={handlePingAll}
            loading={pinging}
            disabled={totalProfiles === 0}
          >
            <RefreshCw className="w-4 h-4 mr-2" />
            {pinging ? t('servers.checking') : t('servers.pingAll')}
          </MacButton>
        </div>
      </div>

      {/* Add card */}
      <MacCard>
        <div className="flex flex-col md:flex-row md:items-end gap-3">
          <div className="flex-1 min-w-0">
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
          <div className="md:w-72">
            <MacSelect
              label={t('servers.add.selectGroup')}
              options={groupOptions}
              value={addGroupId}
              onChange={(v) => setAddGroupId(v)}
              disabled={!groupsAvailable && groupOptions.length === 1}
            />
          </div>
          <MacButton onClick={handleAdd} loading={adding} disabled={!addInput.trim()}>
            <Plus className="w-4 h-4 mr-1" />
            {t('servers.addServer')}
          </MacButton>
        </div>
        {!groupsAvailable && groupsAvailable !== null && (
          <p className="text-[11px] text-[var(--color-text-secondary)] mt-2">
            {t('servers.groups.fallbackHint')}
          </p>
        )}
      </MacCard>

      {/* Body */}
      {loading ? (
        <div className="flex items-center justify-center py-16 text-[var(--color-text-secondary)]">
          <p className="text-sm">{t('common.loading')}</p>
        </div>
      ) : totalProfiles === 0 && (groupsAvailable === false || groups.length === 0) ? (
        <EmptyState />
      ) : (
        <div className="space-y-4">
          {effectiveGroups.map((group) => {
            const groupProfiles = profilesByGroup[group.id] ?? []
            const isExpanded = expandedIds.has(group.id) || effectiveGroups.length === 1
            return (
              <GroupCard
                key={group.id}
                group={group}
                profiles={groupProfiles}
                expanded={isExpanded}
                onToggle={() => toggleGroupExpanded(group.id)}
                renamingId={renamingId}
                renameDraft={renameDraft}
                renameInputRef={renameInputRef}
                onRenameStart={startRename}
                onRenameDraftChange={setRenameDraft}
                onRenameCommit={commitRename}
                onRenameCancel={cancelRename}
                onRenameKey={handleRenameKey}
                onRefresh={() => handleGroupRefresh(group)}
                onCheckHealth={() => handleGroupHealth(group)}
                onDelete={() => setDeleteTarget(group)}
                isRefreshing={!!refreshingGroups[group.id]}
                isCheckingHealth={!!healthCheckingGroups[group.id]}
                healthByProfile={healthByProfile}
                activeId={activeId}
                perRowPings={perRowPings}
                exportFlash={exportFlash}
                onSelectProfile={handleSelect}
                onRemoveProfile={handleRemove}
                onPingProfile={handlePingOne}
                onExportProfile={handleExport}
                onExportProfileToFile={handleExportToFile}
                onOpenDetail={setDetailProfile}
                groupsAvailable={!!groupsAvailable}
                locale={i18n.language}
              />
            )
          })}
        </div>
      )}

      {/* Detail modal */}
      <ServerDetailModal
        open={!!detailProfile}
        profile={detailProfile}
        onClose={() => setDetailProfile(null)}
      />

      {/* Delete group confirmation */}
      <MacModal
        open={!!deleteTarget}
        onClose={() => (deletingGroup ? undefined : setDeleteTarget(null))}
        title={t('servers.groups.deletePromptTitle')}
        size="md"
      >
        <div className="space-y-4">
          <p className="text-sm text-[var(--color-text)]">
            {t('servers.groups.deletePromptBody')}
          </p>
          {deleteTarget && (
            <p className="text-xs text-[var(--color-text-secondary)]">
              <span className="font-medium text-[var(--color-text)]">{deleteTarget.name}</span>
              {' · '}
              {t('servers.groups.serverCount', {
                count: profilesByGroup[deleteTarget.id]?.length ?? 0
              })}
            </p>
          )}
          <div className="flex flex-col sm:flex-row sm:justify-end gap-2 pt-2">
            <MacButton variant="ghost" onClick={() => setDeleteTarget(null)} disabled={deletingGroup}>
              {t('servers.groups.deleteCancel')}
            </MacButton>
            <MacButton
              variant="secondary"
              onClick={() => confirmDeleteGroup(false)}
              loading={deletingGroup}
              disabled={deletingGroup}
            >
              {t('servers.groups.deleteOnlyGroup')}
            </MacButton>
            <MacButton
              variant="danger"
              onClick={() => confirmDeleteGroup(true)}
              loading={deletingGroup}
              disabled={deletingGroup}
            >
              <Trash2 className="w-3.5 h-3.5 mr-1.5" />
              {t('servers.groups.deleteWithServers')}
            </MacButton>
          </div>
        </div>
      </MacModal>

      {/* Toasts */}
      <MacToast toasts={toasts} onDismiss={dismissToast} position="top-right" />
    </div>
  )
}

// ─── EmptyState ────────────────────────────────────────────────────────────

function EmptyState() {
  const { t } = useTranslation()
  return (
    <div className="flex flex-col items-center justify-center py-16 text-[var(--color-text-secondary)]">
      <Server className="w-12 h-12 mb-4 opacity-40" />
      <p className="text-base font-medium text-[var(--color-text)]">{t('servers.emptyTitle')}</p>
      <p className="text-sm mt-1 max-w-md text-center">{t('servers.emptyHint')}</p>
    </div>
  )
}

// ─── GroupCard ─────────────────────────────────────────────────────────────

interface GroupCardProps {
  group: ServerGroup
  profiles: ServerProfile[]
  expanded: boolean
  onToggle: () => void
  renamingId: string | null
  renameDraft: string
  renameInputRef: React.RefObject<HTMLInputElement>
  onRenameStart: (g: ServerGroup) => void
  onRenameDraftChange: (v: string) => void
  onRenameCommit: () => void
  onRenameCancel: () => void
  onRenameKey: (e: KeyboardEvent<HTMLInputElement>) => void
  onRefresh: () => void
  onCheckHealth: () => void
  onDelete: () => void
  isRefreshing: boolean
  isCheckingHealth: boolean
  healthByProfile: Record<string, HealthRow>
  activeId: string | null
  perRowPings: Record<string, PerRowPing>
  exportFlash: Record<string, 'copied' | 'saved' | 'failed'>
  onSelectProfile: (id: string) => void
  onRemoveProfile: (id: string) => void
  onPingProfile: (p: ServerProfile) => void
  onExportProfile: (id: string) => void
  onExportProfileToFile: (id: string) => void
  onOpenDetail: (p: ServerProfile) => void
  groupsAvailable: boolean
  locale: string
}

function GroupCard(props: GroupCardProps) {
  const {
    group,
    profiles,
    expanded,
    onToggle,
    renamingId,
    renameDraft,
    renameInputRef,
    onRenameStart,
    onRenameDraftChange,
    onRenameCommit,
    onRenameCancel,
    onRenameKey,
    onRefresh,
    onCheckHealth,
    onDelete,
    isRefreshing,
    isCheckingHealth,
    healthByProfile,
    activeId,
    perRowPings,
    exportFlash,
    onSelectProfile,
    onRemoveProfile,
    onPingProfile,
    onExportProfile,
    onExportProfileToFile,
    onOpenDetail,
    groupsAvailable,
    locale
  } = props
  const { t } = useTranslation()

  const isVirtual = group.id === VIRTUAL_ALL_GROUP_ID
  const isSubscription = group.source === 'subscription'
  const headerIcon = isSubscription ? '📡' : '🔑'

  const statusLabel =
    group.status === 'active'
      ? t('servers.groups.statusActive')
      : group.status === 'expired'
        ? t('servers.groups.statusExpired')
        : group.status === 'unreachable'
          ? t('servers.groups.statusUnreachable')
          : t('servers.groups.statusUnknown')

  const isRenamingHere = renamingId === group.id
  const grouped = groupByProtocol(profiles)
  const protocolKeys = Object.keys(grouped).sort()

  return (
    <MacCard className="!p-0 overflow-hidden">
      {/* Header (clickable) */}
      <div
        role="button"
        tabIndex={0}
        aria-expanded={expanded}
        aria-label={expanded ? t('servers.groups.collapse') : t('servers.groups.expand')}
        onClick={(e) => {
          // Avoid toggling when clicking inside header inputs / buttons.
          const target = e.target as HTMLElement
          if (target.closest('button, input, a, [data-no-toggle]')) return
          onToggle()
        }}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault()
            onToggle()
          }
        }}
        className="flex items-center gap-3 px-4 py-3 cursor-pointer focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] hover:bg-[var(--color-border)]/30 transition-colors"
      >
        <motion.span
          animate={{ rotate: expanded ? 90 : 0 }}
          transition={{ duration: 0.18 }}
          className="text-[var(--color-text-secondary)] flex-shrink-0"
        >
          <ChevronRight className="w-4 h-4" />
        </motion.span>
        <span className="text-base leading-none flex-shrink-0 select-none" aria-hidden="true">
          {headerIcon}
        </span>
        <div className="flex-1 min-w-0">
          {isRenamingHere ? (
            <div data-no-toggle>
              <MacInput
                ref={renameInputRef}
                value={renameDraft}
                onChange={(e) => onRenameDraftChange(e.target.value)}
                onKeyDown={onRenameKey}
                onBlur={onRenameCommit}
                placeholder={t('servers.groups.renamePlaceholder')}
              />
            </div>
          ) : (
            <div
              className="flex items-center gap-2 flex-wrap"
              onDoubleClick={(e) => {
                if (isVirtual || !groupsAvailable) return
                e.stopPropagation()
                onRenameStart(group)
              }}
              title={
                isVirtual || !groupsAvailable
                  ? undefined
                  : t('servers.groups.rename')
              }
            >
              <span className="text-sm font-medium text-[var(--color-text)] truncate">
                {group.name}
              </span>
              {!isVirtual && (
                <MacBadge variant={groupStatusVariant(group.status)}>{statusLabel}</MacBadge>
              )}
              <span className="text-xs text-[var(--color-text-secondary)]">
                {t('servers.groups.serverCount', { count: profiles.length })}
              </span>
            </div>
          )}
        </div>

        {!isVirtual && groupsAvailable && (
          <div className="flex items-center gap-1.5 flex-shrink-0" data-no-toggle>
            {isSubscription && (
              <MacButton
                size="sm"
                variant="ghost"
                onClick={(e) => {
                  e.stopPropagation()
                  onRefresh()
                }}
                loading={isRefreshing}
                disabled={isRefreshing}
                title={t('servers.groups.refresh')}
              >
                <RefreshCw className="w-3.5 h-3.5 mr-1" />
                {isRefreshing ? t('servers.groups.refreshing') : t('servers.groups.refresh')}
              </MacButton>
            )}
            <MacButton
              size="sm"
              variant="ghost"
              onClick={(e) => {
                e.stopPropagation()
                onCheckHealth()
              }}
              loading={isCheckingHealth}
              disabled={isCheckingHealth || profiles.length === 0}
              title={t('servers.groups.checkHealth')}
            >
              <HeartPulse className="w-3.5 h-3.5 mr-1" />
              {isCheckingHealth ? t('servers.groups.checking') : t('servers.groups.checkHealth')}
            </MacButton>
            <MacButton
              size="sm"
              variant="ghost"
              onClick={(e) => {
                e.stopPropagation()
                onDelete()
              }}
              title={t('servers.groups.delete')}
            >
              <Trash2 className="w-3.5 h-3.5 text-[var(--color-danger)]" />
            </MacButton>
          </div>
        )}
      </div>

      {/* Body */}
      <AnimatePresence initial={false}>
        {expanded && (
          <motion.div
            key={`body-${group.id}`}
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.22, ease: 'easeOut' }}
            className="overflow-hidden"
          >
            <div className="px-4 pb-4 pt-1 border-t border-[var(--color-border)]/60 space-y-3">
              {/* Metadata banner */}
              {!isVirtual && groupsAvailable && (
                <GroupMetadataBanner group={group} locale={locale} />
              )}

              {/* Profiles */}
              {profiles.length === 0 ? (
                <p className="text-xs text-[var(--color-text-secondary)] py-3">
                  {t('servers.noServers')}
                </p>
              ) : (
                <div className="space-y-4">
                  {protocolKeys.map((protocol) => (
                    <div key={protocol}>
                      <h2 className="text-[11px] font-medium text-[var(--color-text-secondary)] uppercase tracking-wide mb-2">
                        {protocol}
                      </h2>
                      <div className="space-y-2">
                        {grouped[protocol].map((profile) => (
                          <ServerProfileCard
                            key={profile.id}
                            profile={profile}
                            group={isVirtual ? null : group}
                            isActive={profile.id === activeId}
                            perRowPing={perRowPings[profile.id]}
                            health={healthByProfile[profile.id]}
                            exportFlash={exportFlash[profile.id]}
                            onSelect={onSelectProfile}
                            onRemove={onRemoveProfile}
                            onPing={onPingProfile}
                            onExport={onExportProfile}
                            onExportToFile={onExportProfileToFile}
                            onOpenDetail={onOpenDetail}
                          />
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </MacCard>
  )
}

// ─── GroupMetadataBanner ───────────────────────────────────────────────────

function GroupMetadataBanner({ group, locale }: { group: ServerGroup; locale: string }) {
  const { t } = useTranslation()
  const items: React.ReactNode[] = []

  if (group.lastFetchError) {
    const when = group.lastFetchAttemptAt ? formatRelative(group.lastFetchAttemptAt, locale) : ''
    items.push(
      <div
        key="error"
        className="flex items-start gap-2 text-xs px-3 py-2 rounded-[var(--radius-sm)] bg-[var(--color-danger)]/10 border border-[var(--color-danger)]/30 text-[var(--color-danger)]"
      >
        <AlertCircle className="w-3.5 h-3.5 mt-0.5 flex-shrink-0" />
        <span>
          {t('servers.groups.refreshFailedDetail', { error: group.lastFetchError, when })}
        </span>
      </div>
    )
  }

  if (group.status === 'expired') {
    items.push(
      <div
        key="expired"
        className="text-xs px-3 py-2 rounded-[var(--radius-sm)] bg-[var(--color-warning)]/10 border border-[var(--color-warning)]/30 text-[var(--color-text)] leading-relaxed"
      >
        {t('servers.groups.expiredBanner')}
      </div>
    )
  }

  if (group.expiresAt) {
    const isPast = group.expiresAt < Date.now()
    const when = formatRelative(group.expiresAt, locale)
    items.push(
      <p key="expiresAt" className="text-xs text-[var(--color-text-secondary)]">
        {isPast
          ? t('servers.groups.expiredAt', { when })
          : t('servers.groups.expiresAt', { when })}
      </p>
    )
  }

  if (group.trafficTotalBytes && group.trafficTotalBytes > 0) {
    const used = group.trafficUsedBytes ?? 0
    const total = group.trafficTotalBytes
    const pct = Math.min(100, Math.round((used / total) * 100))
    const overLimit = used > total
    items.push(
      <div key="traffic" className="space-y-1">
        <div className="flex items-center justify-between text-xs">
          <span className="text-[var(--color-text-secondary)]">
            {t('servers.groups.trafficUsage')}
          </span>
          <span
            className={
              overLimit
                ? 'text-[var(--color-danger)] tabular-nums'
                : 'text-[var(--color-text)] tabular-nums'
            }
          >
            {t('servers.groups.trafficUsed', {
              used: formatBytes(used),
              total: formatBytes(total)
            })}
          </span>
        </div>
        <MacProgress
          value={pct}
          variant={overLimit ? 'danger' : pct > 80 ? 'warning' : 'accent'}
          size="sm"
        />
      </div>
    )
  }

  if (group.webPageUrl) {
    items.push(
      <p key="webPage" className="text-xs">
        <span className="text-[var(--color-text-secondary)] mr-1">
          {t('servers.groups.providerPanel')}:
        </span>
        <a
          href={group.webPageUrl}
          target="_blank"
          rel="noreferrer"
          className="text-[var(--color-accent)] hover:underline inline-flex items-center gap-1"
        >
          {group.webPageUrl}
          <ExternalLink className="w-3 h-3" />
        </a>
      </p>
    )
  }

  if (group.lastFetchedAt) {
    items.push(
      <p key="lastUpdated" className="text-[11px] text-[var(--color-text-secondary)]">
        {t('servers.groups.lastUpdatedAt', { when: formatRelative(group.lastFetchedAt, locale) })}
      </p>
    )
  }

  if (items.length === 0) return null
  return <div className="space-y-2">{items}</div>
}

// ─── ServerProfileCard ────────────────────────────────────────────────────

interface ServerProfileCardProps {
  profile: ServerProfile
  group: ServerGroup | null
  isActive: boolean
  perRowPing?: PerRowPing
  health?: HealthRow
  exportFlash?: 'copied' | 'saved' | 'failed'
  onSelect: (id: string) => void
  onRemove: (id: string) => void
  onPing: (profile: ServerProfile) => void
  onExport: (id: string) => void
  onExportToFile: (id: string) => void
  onOpenDetail: (profile: ServerProfile) => void
}

function ServerProfileCard({
  profile,
  group,
  isActive,
  perRowPing,
  health,
  exportFlash,
  onSelect,
  onRemove,
  onPing,
  onExport,
  onExportToFile,
  onOpenDetail
}: ServerProfileCardProps) {
  const { t } = useTranslation()

  const country = perRowPing?.country || profile.country || null
  const recognised = detectCountry(profile.name)
  const flag = recognised?.flag || '🌐'
  const ping = perRowPing?.ping ?? profile.ping

  // Stale-from-subscription marker: lastSeenInSubscriptionAt is older than
  // group.lastFetchedAt by at least one minute. The fields are optional —
  // bail out of the comparison whenever we lack the data.
  const lastSeen =
    (profile as ServerProfile & { lastSeenInSubscriptionAt?: number }).lastSeenInSubscriptionAt ??
    null
  const staleFromSub =
    !!group &&
    group.source === 'subscription' &&
    !!group.lastFetchedAt &&
    lastSeen != null &&
    group.lastFetchedAt - lastSeen >= 60_000

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
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-medium text-[var(--color-text)] truncate">
              {profile.name}
            </span>
            <MacBadge variant="info">{profile.protocol}</MacBadge>
            {staleFromSub && (
              <MacBadge variant="warning" className="!text-[10px]">
                {t('servers.groups.removedFromSub')}
              </MacBadge>
            )}
            {isActive && (
              <MacBadge variant="success">{t('servers.active')}</MacBadge>
            )}
            {country && (
              <span className="text-xs text-[var(--color-text-secondary)]">{country}</span>
            )}
          </div>
          <div className="flex items-center gap-3 mt-0.5">
            <span className="text-xs text-[var(--color-text-secondary)]">
              {profile.server}:{profile.port}
            </span>
          </div>
        </div>

        {/* Status / ping cluster.
            When a fresh health-check result exists we replace the legacy
            online/offline icon + ping ms with a coloured dot + latency. */}
        <div className="flex items-center gap-1 min-w-[64px] justify-end">
          {health ? (
            health.online ? (
              <span className="inline-flex items-center gap-1 text-xs tabular-nums text-[var(--color-success)]">
                <Check className="w-3.5 h-3.5" />
                {health.latencyMs != null ? `${health.latencyMs} ms` : ''}
              </span>
            ) : (
              <span
                className="inline-flex items-center gap-1 text-xs text-[var(--color-danger)]"
                title={health.reason}
              >
                <AlertCircle className="w-3.5 h-3.5" />
                {t('servers.health.dead')}
              </span>
            )
          ) : (
            <>
              {profile.status === 'online' ? (
                <Wifi className="w-3.5 h-3.5 text-[var(--color-success)]" />
              ) : profile.status === 'offline' ? (
                <WifiOff className="w-3.5 h-3.5 text-[var(--color-danger)]" />
              ) : null}
              <span className="text-xs text-[var(--color-text-secondary)] tabular-nums">
                {ping != null ? `${ping} ms` : '—'}
              </span>
            </>
          )}
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
            aria-label={t('servers.pingOne')}
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
            aria-label={t('servers.exportKey')}
            title={
              exportFlash === 'copied'
                ? t('servers.keyCopied')
                : exportFlash === 'failed'
                  ? t('servers.exportFailed')
                  : t('servers.exportKey')
            }
          >
            {exportFlash === 'copied' ? (
              <Check className="w-3.5 h-3.5 text-[var(--color-success)]" />
            ) : (
              <Copy className="w-3.5 h-3.5" />
            )}
          </MacButton>
          <MacButton
            size="sm"
            variant="ghost"
            onClick={(e) => {
              e.stopPropagation()
              onExportToFile(profile.id)
            }}
            aria-label={t('servers.saveKey')}
            title={
              exportFlash === 'saved'
                ? t('servers.keySaved')
                : exportFlash === 'failed'
                  ? t('servers.exportFailed')
                  : t('servers.saveKey')
            }
          >
            {exportFlash === 'saved' ? (
              <Check className="w-3.5 h-3.5 text-[var(--color-success)]" />
            ) : (
              <Download className="w-3.5 h-3.5" />
            )}
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
            {isActive ? t('servers.selected') : t('servers.select')}
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

// Quiet TS about the imported but currently-unused ChevronDown — keeping it
// available so future variants of the chevron animation can swap in without
// touching imports. eslint-disable-next-line @typescript-eslint/no-unused-vars
void ChevronDown
