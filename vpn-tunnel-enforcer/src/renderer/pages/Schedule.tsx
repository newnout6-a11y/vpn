import { useState, useEffect, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { Calendar, Plus, Trash2, Edit2, Clock, Play, Square } from 'lucide-react'
import {
  MacCard,
  MacInput,
  MacSelect,
  MacSwitch,
  MacButton,
  MacSegmentedControl
} from '../design-system'
import { PageTip } from '../components/PageTip'
import type { ScheduleEntry, ServerProfile } from '../../shared/ipc-types'

/** Days of week mapping: 0=Sun, 1=Mon, ..., 6=Sat */
const DAY_INDICES = [1, 2, 3, 4, 5, 6, 0] // Mon-Sun display order

const DAY_KEYS = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']

interface NextEvent {
  type: 'start' | 'stop'
  at: number
  schedule: ScheduleEntry
}

type FormData = {
  name: string
  enabled: boolean
  days: number[]
  startTime: string
  endTime: string
  profileId: string
  mode: 'hard' | 'soft' | 'direct'
}

const EMPTY_FORM: FormData = {
  name: '',
  enabled: true,
  days: [],
  startTime: '09:00',
  endTime: '18:00',
  profileId: '',
  mode: 'hard'
}

function formatTimeUntil(timestamp: number): string {
  const diff = Math.max(0, timestamp - Date.now())
  const hours = Math.floor(diff / 3_600_000)
  const minutes = Math.floor((diff % 3_600_000) / 60_000)
  if (hours > 24) return `${Math.floor(hours / 24)}d ${hours % 24}h`
  if (hours > 0) return `${hours}h ${minutes}m`
  return `${minutes}m`
}

function getDayAbbreviations(days: number[], t: (key: string) => string): string {
  const dayKeyMap: Record<number, string> = {
    0: 'schedule.sunday',
    1: 'schedule.monday',
    2: 'schedule.tuesday',
    3: 'schedule.wednesday',
    4: 'schedule.thursday',
    5: 'schedule.friday',
    6: 'schedule.saturday'
  }
  return days
    .sort((a, b) => a - b)
    .map((d) => t(dayKeyMap[d]))
    .join(', ')
}

/**
 * Schedule page — displays schedule list with creation/edit form
 * for scheduled VPN connections.
 */
export function Schedule() {
  const { t } = useTranslation()
  const [schedules, setSchedules] = useState<ScheduleEntry[]>([])
  const [nextEvent, setNextEvent] = useState<NextEvent | null>(null)
  const [profiles, setProfiles] = useState<ServerProfile[]>([])
  const [loading, setLoading] = useState(true)
  const [showForm, setShowForm] = useState(false)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [form, setForm] = useState<FormData>(EMPTY_FORM)

  const fetchSchedules = useCallback(async () => {
    try {
      const api = (window as any).electronAPI
      if (api?.schedulerList) {
        const list = await api.schedulerList()
        setSchedules(list)
      }
    } catch (err) {
      console.error('Failed to fetch schedules:', err)
    } finally {
      setLoading(false)
    }
  }, [])

  const fetchNextEvent = useCallback(async () => {
    try {
      const api = (window as any).electronAPI
      if (api?.schedulerNextEvent) {
        const event = await api.schedulerNextEvent()
        setNextEvent(event)
      }
    } catch {
      // IPC not yet wired
    }
  }, [])

  const fetchProfiles = useCallback(async () => {
    try {
      const list = await window.electronAPI.serversList()
      setProfiles(list)
    } catch {
      // Profiles not available
    }
  }, [])

  useEffect(() => {
    fetchSchedules()
    fetchNextEvent()
    fetchProfiles()
    const interval = setInterval(fetchNextEvent, 30_000)
    return () => clearInterval(interval)
  }, [fetchSchedules, fetchNextEvent, fetchProfiles])

  const handleCreate = async () => {
    try {
      const api = (window as any).electronAPI
      if (api?.schedulerCreate) {
        await api.schedulerCreate({
          name: form.name,
          enabled: form.enabled,
          days: form.days,
          startTime: form.startTime,
          endTime: form.endTime,
          profileId: form.profileId,
          mode: form.mode
        })
        setShowForm(false)
        setForm(EMPTY_FORM)
        await fetchSchedules()
        await fetchNextEvent()
      }
    } catch (err) {
      console.error('Failed to create schedule:', err)
    }
  }

  const handleUpdate = async () => {
    if (!editingId) return
    try {
      const api = (window as any).electronAPI
      if (api?.schedulerUpdate) {
        await api.schedulerUpdate(editingId, {
          name: form.name,
          enabled: form.enabled,
          days: form.days,
          startTime: form.startTime,
          endTime: form.endTime,
          profileId: form.profileId,
          mode: form.mode
        })
        setShowForm(false)
        setEditingId(null)
        setForm(EMPTY_FORM)
        await fetchSchedules()
        await fetchNextEvent()
      }
    } catch (err) {
      console.error('Failed to update schedule:', err)
    }
  }

  const handleDelete = async (id: string) => {
    try {
      const api = (window as any).electronAPI
      if (api?.schedulerDelete) {
        await api.schedulerDelete(id)
        setSchedules((prev) => prev.filter((s) => s.id !== id))
        await fetchNextEvent()
      }
    } catch (err) {
      console.error('Failed to delete schedule:', err)
    }
  }

  const handleToggleEnabled = async (id: string, enabled: boolean) => {
    try {
      const api = (window as any).electronAPI
      if (api?.schedulerUpdate) {
        await api.schedulerUpdate(id, { enabled })
        setSchedules((prev) =>
          prev.map((s) => (s.id === id ? { ...s, enabled } : s))
        )
        await fetchNextEvent()
      }
    } catch (err) {
      console.error('Failed to toggle schedule:', err)
    }
  }

  const handleEdit = (schedule: ScheduleEntry) => {
    setEditingId(schedule.id)
    setForm({
      name: schedule.name,
      enabled: schedule.enabled,
      days: [...schedule.days],
      startTime: schedule.startTime,
      endTime: schedule.endTime,
      profileId: schedule.profileId,
      mode: schedule.mode
    })
    setShowForm(true)
  }

  const handleOpenCreate = () => {
    setEditingId(null)
    setForm(EMPTY_FORM)
    setShowForm(true)
  }

  const handleCancel = () => {
    setShowForm(false)
    setEditingId(null)
    setForm(EMPTY_FORM)
  }

  const toggleDay = (day: number) => {
    setForm((prev) => ({
      ...prev,
      days: prev.days.includes(day)
        ? prev.days.filter((d) => d !== day)
        : [...prev.days, day]
    }))
  }

  const profileOptions = profiles.map((p) => ({
    value: p.id,
    label: `${p.name} (${p.protocol})`
  }))

  const modeOptions = [
    { value: 'hard', label: t('modes.hard') },
    { value: 'soft', label: t('modes.soft') },
    { value: 'direct', label: t('modes.direct') }
  ]

  const isFormValid = form.name.trim() && form.days.length > 0 && form.startTime && form.endTime

  return (
    <div className="space-y-6">
      {/* Onboarding tip */}
      <PageTip tipKey="schedule">{t('tips.schedule')}</PageTip>

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-[var(--color-text)]">
            {t('schedule.title')}
          </h1>
          <p className="text-sm text-[var(--color-text-secondary)] mt-1">
            {t('schedule.description')}
          </p>
        </div>
        <MacButton onClick={handleOpenCreate}>
          <Plus className="w-4 h-4 mr-2" />
          {t('schedule.create')}
        </MacButton>
      </div>

      {/* Next event banner */}
      {nextEvent && (
        <MacCard className="!p-4 border-l-4 border-l-[var(--color-accent)]">
          <div className="flex items-center gap-3">
            {nextEvent.type === 'start' ? (
              <Play size={16} className="text-green-500 shrink-0" />
            ) : (
              <Square size={16} className="text-red-500 shrink-0" />
            )}
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-[var(--color-text)]">
                {t('schedule.nextEvent')}: {nextEvent.schedule.name}
              </p>
              <p className="text-xs text-[var(--color-text-secondary)]">
                {nextEvent.type === 'start' ? 'Connect' : 'Disconnect'} at{' '}
                {new Date(nextEvent.at).toLocaleTimeString([], {
                  hour: '2-digit',
                  minute: '2-digit'
                })}{' '}
                ({formatTimeUntil(nextEvent.at)})
              </p>
            </div>
            <Clock size={16} className="text-[var(--color-text-secondary)] shrink-0" />
          </div>
        </MacCard>
      )}

      {/* Create/Edit form */}
      {showForm && (
        <MacCard>
          <div className="space-y-4">
            <h2 className="text-lg font-medium text-[var(--color-text)]">
              {editingId ? t('schedule.edit') : t('schedule.create')}
            </h2>

            {/* Name */}
            <MacInput
              label={t('schedule.name')}
              placeholder={t('schedule.name')}
              value={form.name}
              onChange={(e) => setForm((prev) => ({ ...prev, name: e.target.value }))}
            />

            {/* Day selector */}
            <div className="space-y-1.5">
              <label className="text-sm font-medium text-[var(--color-text)]">
                {t('schedule.days')}
              </label>
              <div className="flex gap-2">
                {DAY_INDICES.map((dayIndex, i) => (
                  <button
                    key={dayIndex}
                    type="button"
                    onClick={() => toggleDay(dayIndex)}
                    className={`
                      w-10 h-10 rounded-[var(--radius-sm)] text-xs font-medium
                      transition-all duration-[var(--transition-fast)]
                      focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]
                      ${
                        form.days.includes(dayIndex)
                          ? 'bg-[var(--color-accent)] text-white'
                          : 'bg-[var(--color-bg)] text-[var(--color-text-secondary)] border border-[var(--color-border)] hover:bg-[var(--color-border)]/50'
                      }
                    `}
                  >
                    {t(`schedule.${DAY_KEYS[i]}`)}
                  </button>
                ))}
              </div>
            </div>

            {/* Time inputs */}
            <div className="grid grid-cols-2 gap-4">
              <MacInput
                label={t('schedule.startTime')}
                type="time"
                value={form.startTime}
                onChange={(e) =>
                  setForm((prev) => ({ ...prev, startTime: e.target.value }))
                }
              />
              <MacInput
                label={t('schedule.endTime')}
                type="time"
                value={form.endTime}
                onChange={(e) =>
                  setForm((prev) => ({ ...prev, endTime: e.target.value }))
                }
              />
            </div>

            {/* Profile selector */}
            <MacSelect
              label={t('schedule.profile')}
              options={profileOptions}
              value={form.profileId}
              onChange={(value) => setForm((prev) => ({ ...prev, profileId: value }))}
              placeholder={t('schedule.profile')}
            />

            {/* Mode selector */}
            <div className="space-y-1.5">
              <label className="text-sm font-medium text-[var(--color-text)]">
                {t('schedule.mode')}
              </label>
              <MacSegmentedControl
                options={modeOptions}
                value={form.mode}
                onChange={(value) =>
                  setForm((prev) => ({
                    ...prev,
                    mode: value as 'hard' | 'soft' | 'direct'
                  }))
                }
              />
            </div>

            {/* Enabled toggle */}
            <MacSwitch
              checked={form.enabled}
              onChange={(checked) => setForm((prev) => ({ ...prev, enabled: checked }))}
              label={t('schedule.enabled')}
            />

            {/* Actions */}
            <div className="flex items-center gap-3 pt-2">
              <MacButton
                onClick={editingId ? handleUpdate : handleCreate}
                disabled={!isFormValid}
              >
                {t('schedule.save')}
              </MacButton>
              <MacButton variant="ghost" onClick={handleCancel}>
                {t('common.cancel')}
              </MacButton>
            </div>
          </div>
        </MacCard>
      )}

      {/* Schedule list */}
      {loading ? (
        <div className="flex items-center justify-center py-16 text-[var(--color-text-secondary)]">
          <p className="text-sm">{t('common.loading')}</p>
        </div>
      ) : schedules.length === 0 && !showForm ? (
        <div className="flex flex-col items-center justify-center py-16 text-[var(--color-text-secondary)]">
          <Calendar className="w-12 h-12 mb-4 opacity-40" />
          <p className="text-sm">{t('schedule.noSchedules')}</p>
        </div>
      ) : (
        <div className="space-y-2">
          {schedules.map((schedule) => (
            <ScheduleCard
              key={schedule.id}
              schedule={schedule}
              onEdit={handleEdit}
              onDelete={handleDelete}
              onToggleEnabled={handleToggleEnabled}
              t={t}
            />
          ))}
        </div>
      )}
    </div>
  )
}

interface ScheduleCardProps {
  schedule: ScheduleEntry
  onEdit: (schedule: ScheduleEntry) => void
  onDelete: (id: string) => void
  onToggleEnabled: (id: string, enabled: boolean) => void
  t: (key: string) => string
}

function ScheduleCard({
  schedule,
  onEdit,
  onDelete,
  onToggleEnabled,
  t
}: ScheduleCardProps) {
  const modeLabel =
    schedule.mode === 'hard'
      ? t('modes.hard')
      : schedule.mode === 'soft'
        ? t('modes.soft')
        : t('modes.direct')

  return (
    <MacCard hoverable className="!p-4">
      <div className="flex items-center gap-4">
        {/* Enabled toggle */}
        <MacSwitch
          checked={schedule.enabled}
          onChange={(checked) => onToggleEnabled(schedule.id, checked)}
        />

        {/* Schedule info */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span
              className={`text-sm font-medium truncate ${
                schedule.enabled
                  ? 'text-[var(--color-text)]'
                  : 'text-[var(--color-text-secondary)]'
              }`}
            >
              {schedule.name}
            </span>
          </div>
          <div className="flex items-center gap-3 mt-1 text-xs text-[var(--color-text-secondary)]">
            <span>{getDayAbbreviations(schedule.days, t)}</span>
            <span className="tabular-nums">
              {schedule.startTime} – {schedule.endTime}
            </span>
            <span className="px-1.5 py-0.5 rounded bg-[var(--color-bg)] border border-[var(--color-border)]">
              {modeLabel}
            </span>
          </div>
        </div>

        {/* Actions */}
        <div className="flex items-center gap-1.5 shrink-0">
          <MacButton size="sm" variant="ghost" onClick={() => onEdit(schedule)}>
            <Edit2 className="w-3.5 h-3.5" />
          </MacButton>
          <MacButton size="sm" variant="ghost" onClick={() => onDelete(schedule.id)}>
            <Trash2 className="w-3.5 h-3.5 text-[var(--color-danger)]" />
          </MacButton>
        </div>
      </div>
    </MacCard>
  )
}
