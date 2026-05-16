/**
 * KillSwitchWidget — Shows current kill-switch level (off/standard/strict)
 * and whether it's actively blocking traffic.
 * Reads firewallKillSwitchActive and settings from Zustand store.
 */

import React from 'react'
import { useTranslation } from 'react-i18next'
import { Shield, ShieldOff, ShieldAlert } from 'lucide-react'
import { useAppStore } from '../store'

export interface KillSwitchWidgetProps {
  size: 'compact' | 'expanded'
}

export const KillSwitchWidget: React.FC<KillSwitchWidgetProps> = ({ size }) => {
  const { t } = useTranslation()
  const firewallKillSwitchActive = useAppStore((s) => s.firewallKillSwitchActive)
  const settings = useAppStore((s) => s.settings)

  // Determine kill-switch level from settings
  // The existing store has a boolean `firewallKillSwitch`. We map it to levels:
  // If strictAdapterLockdown is on → strict, if firewallKillSwitch is on → standard, else off
  const level: 'off' | 'standard' | 'strict' = !settings.firewallKillSwitch
    ? 'off'
    : settings.strictAdapterLockdown
      ? 'strict'
      : 'standard'

  const levelLabel = t(`settings.killSwitch${level.charAt(0).toUpperCase() + level.slice(1)}`)

  const icon =
    level === 'off' ? (
      <ShieldOff size={size === 'compact' ? 18 : 22} className="text-[var(--color-text-secondary)]" />
    ) : firewallKillSwitchActive ? (
      <ShieldAlert size={size === 'compact' ? 18 : 22} className="text-red-500" />
    ) : (
      <Shield size={size === 'compact' ? 18 : 22} className="text-green-500" />
    )

  const statusText = firewallKillSwitchActive ? 'Blocking' : level === 'off' ? 'Disabled' : 'Standby'
  const statusColor = firewallKillSwitchActive
    ? 'text-red-500'
    : level === 'off'
      ? 'text-[var(--color-text-secondary)]'
      : 'text-green-500'

  if (size === 'compact') {
    return (
      <div className="flex items-center gap-3">
        {icon}
        <div className="min-w-0 flex-1">
          <p className="text-sm font-medium text-[var(--color-text)]">
            {t('dashboard.killSwitchStatus')}
          </p>
          <p className={`text-xs ${statusColor}`}>
            {levelLabel} • {statusText}
          </p>
        </div>
      </div>
    )
  }

  // Expanded view
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        {icon}
        <span className="text-sm font-medium text-[var(--color-text)]">
          {t('dashboard.killSwitchStatus')}
        </span>
      </div>
      <div className="grid grid-cols-2 gap-2">
        <div className="rounded-[var(--radius-sm)] bg-[var(--color-bg)] p-2.5 border border-[var(--color-border)]">
          <p className="text-xs text-[var(--color-text-secondary)] mb-0.5">Level</p>
          <p className="text-sm font-medium text-[var(--color-text)]">{levelLabel}</p>
        </div>
        <div className="rounded-[var(--radius-sm)] bg-[var(--color-bg)] p-2.5 border border-[var(--color-border)]">
          <p className="text-xs text-[var(--color-text-secondary)] mb-0.5">Status</p>
          <p className={`text-sm font-medium ${statusColor}`}>{statusText}</p>
        </div>
      </div>
      {firewallKillSwitchActive && (
        <div className="rounded-[var(--radius-sm)] bg-red-500/10 border border-red-500/20 p-2 text-xs text-red-600">
          Traffic is being blocked by kill-switch rules
        </div>
      )}
    </div>
  )
}
