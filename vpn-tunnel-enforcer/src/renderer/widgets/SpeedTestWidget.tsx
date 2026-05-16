/**
 * SpeedTestWidget — Shows last speed test result (download Mbps, upload Mbps, latency ms)
 * or "No tests yet" placeholder. Will read from IPC later.
 */

import React, { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Zap, ArrowDown, ArrowUp, Clock } from 'lucide-react'

export interface SpeedTestWidgetProps {
  size: 'compact' | 'expanded'
}

interface SpeedTestResult {
  downloadMbps: number
  uploadMbps: number
  latencyMs: number
  timestamp: number
}

export const SpeedTestWidget: React.FC<SpeedTestWidgetProps> = ({ size }) => {
  const { t } = useTranslation()
  const [lastResult, setLastResult] = useState<SpeedTestResult | null>(null)

  // Attempt to fetch last speed test result from IPC
  useEffect(() => {
    const fetchResult = async () => {
      try {
        const api = (window as any).electronAPI
        if (api?.speedTestHistory) {
          const history = await api.speedTestHistory()
          if (history && history.length > 0) {
            const last = history[0]
            setLastResult({
              downloadMbps: last.downloadMbps,
              uploadMbps: last.uploadMbps,
              latencyMs: last.latencyMs,
              timestamp: last.timestamp
            })
          }
        }
      } catch {
        // IPC not yet wired — show placeholder
      }
    }
    fetchResult()
  }, [])

  if (!lastResult) {
    if (size === 'compact') {
      return (
        <div className="flex items-center gap-3">
          <Zap size={18} className="text-[var(--color-text-secondary)]" />
          <p className="text-sm text-[var(--color-text-secondary)]">
            {t('dashboard.speedTestLast')}: —
          </p>
        </div>
      )
    }
    return (
      <div className="flex flex-col items-center justify-center py-4 text-[var(--color-text-secondary)]">
        <Zap size={24} className="mb-2 opacity-50" />
        <p className="text-sm">No tests yet</p>
      </div>
    )
  }

  if (size === 'compact') {
    return (
      <div className="flex items-center gap-3">
        <Zap size={18} className="text-yellow-500" />
        <div className="flex items-center gap-3 text-xs">
          <span className="flex items-center gap-1">
            <ArrowDown size={12} className="text-blue-500" />
            {lastResult.downloadMbps.toFixed(1)} Mbps
          </span>
          <span className="flex items-center gap-1">
            <ArrowUp size={12} className="text-emerald-500" />
            {lastResult.uploadMbps.toFixed(1)} Mbps
          </span>
          <span className="flex items-center gap-1">
            <Clock size={12} className="text-[var(--color-text-secondary)]" />
            {lastResult.latencyMs} ms
          </span>
        </div>
      </div>
    )
  }

  // Expanded view
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <Zap size={20} className="text-yellow-500" />
        <span className="text-sm font-medium text-[var(--color-text)]">
          {t('dashboard.speedTestLast')}
        </span>
      </div>
      <div className="grid grid-cols-3 gap-2">
        <div className="rounded-[var(--radius-sm)] bg-[var(--color-bg)] p-2.5 border border-[var(--color-border)] text-center">
          <ArrowDown size={16} className="mx-auto text-blue-500 mb-1" />
          <p className="text-lg font-semibold text-[var(--color-text)] tabular-nums">
            {lastResult.downloadMbps.toFixed(1)}
          </p>
          <p className="text-xs text-[var(--color-text-secondary)]">Mbps ↓</p>
        </div>
        <div className="rounded-[var(--radius-sm)] bg-[var(--color-bg)] p-2.5 border border-[var(--color-border)] text-center">
          <ArrowUp size={16} className="mx-auto text-emerald-500 mb-1" />
          <p className="text-lg font-semibold text-[var(--color-text)] tabular-nums">
            {lastResult.uploadMbps.toFixed(1)}
          </p>
          <p className="text-xs text-[var(--color-text-secondary)]">Mbps ↑</p>
        </div>
        <div className="rounded-[var(--radius-sm)] bg-[var(--color-bg)] p-2.5 border border-[var(--color-border)] text-center">
          <Clock size={16} className="mx-auto text-[var(--color-text-secondary)] mb-1" />
          <p className="text-lg font-semibold text-[var(--color-text)] tabular-nums">
            {lastResult.latencyMs}
          </p>
          <p className="text-xs text-[var(--color-text-secondary)]">ms</p>
        </div>
      </div>
      <p className="text-xs text-[var(--color-text-secondary)] text-right">
        {new Date(lastResult.timestamp).toLocaleString()}
      </p>
    </div>
  )
}
