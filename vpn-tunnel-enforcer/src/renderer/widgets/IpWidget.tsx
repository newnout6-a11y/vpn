/**
 * IpWidget — Shows current public IP address and leak status.
 * Green check if no leak, red warning if leak detected.
 * Reads publicIp and isLeak from Zustand store.
 */

import React from 'react'
import { useTranslation } from 'react-i18next'
import { ShieldCheck, ShieldAlert, Globe } from 'lucide-react'
import { useAppStore } from '../store'

export interface IpWidgetProps {
  size: 'compact' | 'expanded'
}

export const IpWidget: React.FC<IpWidgetProps> = ({ size }) => {
  const { t } = useTranslation()
  const publicIp = useAppStore((s) => s.publicIp)
  const isLeak = useAppStore((s) => s.isLeak)
  const vpnIp = useAppStore((s) => s.vpnIp)

  const leakIcon = isLeak ? (
    <ShieldAlert size={size === 'compact' ? 18 : 22} className="text-red-500" />
  ) : (
    <ShieldCheck size={size === 'compact' ? 18 : 22} className="text-green-500" />
  )

  const leakLabel = isLeak ? 'Leak detected' : 'No leak'
  const leakColor = isLeak ? 'text-red-500' : 'text-green-500'

  if (size === 'compact') {
    return (
      <div className="flex items-center gap-3">
        {leakIcon}
        <div className="min-w-0 flex-1">
          <p className="text-sm font-medium text-[var(--color-text)] truncate">
            {publicIp || '—'}
          </p>
          <p className={`text-xs ${leakColor}`}>{leakLabel}</p>
        </div>
      </div>
    )
  }

  // Expanded view
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-3">
        <Globe size={20} className="text-[var(--color-text-secondary)]" />
        <span className="text-sm font-medium text-[var(--color-text)]">
          {t('dashboard.publicIp')}
        </span>
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div className="rounded-[var(--radius-sm)] bg-[var(--color-bg)] p-2.5 border border-[var(--color-border)]">
          <p className="text-xs text-[var(--color-text-secondary)] mb-0.5">Public IP</p>
          <p className="text-sm font-medium text-[var(--color-text)] tabular-nums">
            {publicIp || '—'}
          </p>
        </div>
        <div className="rounded-[var(--radius-sm)] bg-[var(--color-bg)] p-2.5 border border-[var(--color-border)]">
          <p className="text-xs text-[var(--color-text-secondary)] mb-0.5">VPN IP</p>
          <p className="text-sm font-medium text-[var(--color-text)] tabular-nums">
            {vpnIp || '—'}
          </p>
        </div>
      </div>
      <div className="flex items-center gap-2">
        {leakIcon}
        <span className={`text-sm font-medium ${leakColor}`}>{leakLabel}</span>
      </div>
    </div>
  )
}
