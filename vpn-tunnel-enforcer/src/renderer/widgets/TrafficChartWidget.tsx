/**
 * TrafficChartWidget — Real-time line chart of download/upload speed
 * over the last 60 seconds using Recharts.
 * Reads traffic data from Zustand store.
 */

import React, { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'
import { useAppStore } from '../store'

export interface TrafficChartWidgetProps {
  size: 'compact' | 'expanded'
}

interface TrafficPoint {
  time: number
  download: number
  upload: number
}

function formatSpeed(bps: number): string {
  if (bps >= 1_000_000) return `${(bps / 1_000_000).toFixed(1)} MB/s`
  if (bps >= 1_000) return `${(bps / 1_000).toFixed(0)} KB/s`
  return `${bps} B/s`
}

const MAX_POINTS = 60

export const TrafficChartWidget: React.FC<TrafficChartWidgetProps> = ({ size }) => {
  const { t } = useTranslation()
  const traffic = useAppStore((s) => s.traffic)
  const [history, setHistory] = useState<TrafficPoint[]>([])
  const lastTs = useRef(0)

  // Accumulate traffic data points (one per second)
  useEffect(() => {
    if (traffic.ts === lastTs.current) return
    lastTs.current = traffic.ts

    setHistory((prev) => {
      const point: TrafficPoint = {
        time: Date.now(),
        download: traffic.downloadBps,
        upload: traffic.uploadBps
      }
      const next = [...prev, point]
      return next.length > MAX_POINTS ? next.slice(-MAX_POINTS) : next
    })
  }, [traffic.ts, traffic.downloadBps, traffic.uploadBps])

  const chartHeight = size === 'compact' ? 60 : 140

  if (size === 'compact') {
    return (
      <div>
        <div className="flex items-center justify-between mb-1">
          <div className="flex items-center gap-2 text-xs text-[var(--color-text-secondary)]">
            <span className="inline-block w-2 h-2 rounded-full bg-blue-500" />
            {t('dashboard.trafficDown')}: {formatSpeed(traffic.downloadBps)}
          </div>
          <div className="flex items-center gap-2 text-xs text-[var(--color-text-secondary)]">
            <span className="inline-block w-2 h-2 rounded-full bg-emerald-500" />
            {t('dashboard.trafficUp')}: {formatSpeed(traffic.uploadBps)}
          </div>
        </div>
        <ResponsiveContainer width="100%" height={chartHeight}>
          <LineChart data={history} margin={{ top: 2, right: 0, left: 0, bottom: 0 }}>
            <Line
              type="monotone"
              dataKey="download"
              stroke="#3b82f6"
              strokeWidth={1.5}
              dot={false}
              isAnimationActive={false}
            />
            <Line
              type="monotone"
              dataKey="upload"
              stroke="#10b981"
              strokeWidth={1.5}
              dot={false}
              isAnimationActive={false}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    )
  }

  // Expanded view
  return (
    <div>
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-3 text-sm">
          <span className="flex items-center gap-1.5">
            <span className="inline-block w-2.5 h-2.5 rounded-full bg-blue-500" />
            <span className="text-[var(--color-text-secondary)]">{t('dashboard.trafficDown')}:</span>
            <span className="text-[var(--color-text)] font-medium">{formatSpeed(traffic.downloadBps)}</span>
          </span>
          <span className="flex items-center gap-1.5">
            <span className="inline-block w-2.5 h-2.5 rounded-full bg-emerald-500" />
            <span className="text-[var(--color-text-secondary)]">{t('dashboard.trafficUp')}:</span>
            <span className="text-[var(--color-text)] font-medium">{formatSpeed(traffic.uploadBps)}</span>
          </span>
        </div>
      </div>
      <ResponsiveContainer width="100%" height={chartHeight}>
        <LineChart data={history} margin={{ top: 4, right: 8, left: 0, bottom: 4 }}>
          <XAxis dataKey="time" hide />
          <YAxis hide />
          <Tooltip
            contentStyle={{
              background: 'var(--color-card)',
              border: '1px solid var(--color-border)',
              borderRadius: 'var(--radius-sm)',
              fontSize: '12px'
            }}
            labelFormatter={() => ''}
            formatter={(value, name) => [
              formatSpeed(Number(value)),
              name === 'download' ? t('dashboard.trafficDown') : t('dashboard.trafficUp')
            ]}
          />
          <Line
            type="monotone"
            dataKey="download"
            stroke="#3b82f6"
            strokeWidth={2}
            dot={false}
            isAnimationActive={false}
          />
          <Line
            type="monotone"
            dataKey="upload"
            stroke="#10b981"
            strokeWidth={2}
            dot={false}
            isAnimationActive={false}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  )
}
