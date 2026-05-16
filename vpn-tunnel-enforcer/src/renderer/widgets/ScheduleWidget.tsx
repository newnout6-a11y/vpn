/**
 * ScheduleWidget — Shows next scheduled event (time, profile, action)
 * or "No schedules" placeholder. Will read from IPC later.
 */

import React, { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Calendar, Play, Square } from 'lucide-react'

export interface ScheduleWidgetProps {
  size: 'compact' | 'expanded'
}

interface NextEvent {
  type: 'start' | 'stop'
  at: number
  schedule: {
    name: string
    profileId: string
    mode: string
  }
}

function formatTimeUntil(timestamp: number): string {
  const diff = Math.max(0, timestamp - Date.now())
  const hours = Math.floor(diff / 3_600_000)
  const minutes = Math.floor((diff % 3_600_000) / 60_000)
  if (hours > 24) return `${Math.floor(hours / 24)}d ${hours % 24}h`
  if (hours > 0) return `${hours}h ${minutes}m`
  return `${minutes}m`
}

export const ScheduleWidget: React.FC<ScheduleWidgetProps> = ({ size }) => {
  const { t } = useTranslation()
  const [nextEvent, setNextEvent] = useState<NextEvent | null>(null)

  // Attempt to fetch next scheduled event from IPC
  useEffect(() => {
    const fetchNext = async () => {
      try {
        const api = (window as any).electronAPI
        if (api?.getNextScheduleEvent) {
          const event = await api.getNextScheduleEvent()
          setNextEvent(event)
        }
      } catch {
        // IPC not yet wired — show placeholder
      }
    }
    fetchNext()
    const interval = setInterval(fetchNext, 30_000)
    return () => clearInterval(interval)
  }, [])

  if (!nextEvent) {
    if (size === 'compact') {
      return (
        <div className="flex items-center gap-3">
          <Calendar size={18} className="text-[var(--color-text-secondary)]" />
          <p className="text-sm text-[var(--color-text-secondary)]">
            {t('schedule.noSchedules')}
          </p>
        </div>
      )
    }
    return (
      <div className="flex flex-col items-center justify-center py-4 text-[var(--color-text-secondary)]">
        <Calendar size={24} className="mb-2 opacity-50" />
        <p className="text-sm">{t('schedule.noSchedules')}</p>
      </div>
    )
  }

  const eventIcon =
    nextEvent.type === 'start' ? (
      <Play size={14} className="text-green-500" />
    ) : (
      <Square size={14} className="text-red-500" />
    )

  const eventLabel = nextEvent.type === 'start' ? 'Connect' : 'Disconnect'
  const timeStr = new Date(nextEvent.at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })

  if (size === 'compact') {
    return (
      <div className="flex items-center gap-3">
        <Calendar size={18} className="text-[var(--color-accent)]" />
        <div className="min-w-0 flex-1">
          <p className="text-sm text-[var(--color-text)] truncate">
            {nextEvent.schedule.name}
          </p>
          <p className="text-xs text-[var(--color-text-secondary)]">
            {eventLabel} at {timeStr} ({formatTimeUntil(nextEvent.at)})
          </p>
        </div>
        {eventIcon}
      </div>
    )
  }

  // Expanded view
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <Calendar size={20} className="text-[var(--color-accent)]" />
        <span className="text-sm font-medium text-[var(--color-text)]">
          {t('dashboard.nextSchedule')}
        </span>
      </div>
      <div className="rounded-[var(--radius-sm)] bg-[var(--color-bg)] p-3 border border-[var(--color-border)]">
        <div className="flex items-center justify-between mb-2">
          <span className="text-sm font-medium text-[var(--color-text)]">
            {nextEvent.schedule.name}
          </span>
          {eventIcon}
        </div>
        <div className="grid grid-cols-2 gap-2 text-xs text-[var(--color-text-secondary)]">
          <div>
            <p className="opacity-70">Action</p>
            <p className="text-[var(--color-text)]">{eventLabel}</p>
          </div>
          <div>
            <p className="opacity-70">Time</p>
            <p className="text-[var(--color-text)] tabular-nums">{timeStr}</p>
          </div>
          <div>
            <p className="opacity-70">In</p>
            <p className="text-[var(--color-text)] tabular-nums">{formatTimeUntil(nextEvent.at)}</p>
          </div>
          <div>
            <p className="opacity-70">Mode</p>
            <p className="text-[var(--color-text)]">{nextEvent.schedule.mode}</p>
          </div>
        </div>
      </div>
    </div>
  )
}
