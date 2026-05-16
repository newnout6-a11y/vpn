import { useState, useEffect, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { Zap, AlertTriangle, Download, Upload, Clock, Server } from 'lucide-react'
import { MacCard, MacButton, MacProgress } from '../design-system'
import { PageTip } from '../components/PageTip'
import { useAppStore } from '../store'
import type { SpeedTestResult } from '../../shared/ipc-types'

/**
 * SpeedTest page — run speed tests through VPN and view history.
 *
 * Features:
 * - "Run Test" button that calls speed-test:run IPC
 * - Animated progress bar showing test progress
 * - Display results: download Mbps, upload Mbps, latency ms
 * - Warning banner if VPN is not connected
 * - History section showing past test results with timestamps
 */
export function SpeedTest() {
  const { t } = useTranslation()
  const tunRunning = useAppStore((s) => s.tunRunning)

  const [running, setRunning] = useState(false)
  const [progress, setProgress] = useState(0)
  const [phase, setPhase] = useState('')
  const [result, setResult] = useState<SpeedTestResult | null>(null)
  const [error, setError] = useState('')
  const [history, setHistory] = useState<SpeedTestResult[]>([])
  const [loadingHistory, setLoadingHistory] = useState(true)

  // Load history on mount
  const fetchHistory = useCallback(async () => {
    try {
      const data = await window.electronAPI.speedTestHistory()
      setHistory(data)
    } catch (err) {
      console.error('Failed to fetch speed test history:', err)
    } finally {
      setLoadingHistory(false)
    }
  }, [])

  useEffect(() => {
    fetchHistory()
  }, [fetchHistory])

  // Listen to progress events
  useEffect(() => {
    const unsub = window.electronAPI.onSpeedTestProgress(({ percent, phase: p }) => {
      setProgress(percent)
      setPhase(p)
    })
    return unsub
  }, [])

  const handleRunTest = async () => {
    setRunning(true)
    setError('')
    setResult(null)
    setProgress(0)
    setPhase('latency')

    try {
      const testResult = await window.electronAPI.speedTestRun()
      setResult(testResult)
      // Refresh history after successful test
      await fetchHistory()
    } catch (err: any) {
      setError(err?.message || String(err))
    } finally {
      setRunning(false)
      setProgress(0)
      setPhase('')
    }
  }

  const phaseLabel = (p: string): string => {
    switch (p) {
      case 'latency':
        return t('speedTest.phaseLatency')
      case 'download':
        return t('speedTest.phaseDownload')
      case 'upload':
        return t('speedTest.phaseUpload')
      case 'complete':
        return t('speedTest.phaseComplete')
      default:
        return ''
    }
  }

  return (
    <div className="space-y-6">
      {/* Onboarding tip */}
      <PageTip tipKey="speedTest">{t('tips.speedTest')}</PageTip>

      {/* Header */}
      <div>
        <h1 className="text-2xl font-semibold text-[var(--color-text)]">
          {t('speedTest.title')}
        </h1>
        <p className="text-sm text-[var(--color-text-secondary)] mt-1">
          {t('speedTest.description')}
        </p>
      </div>

      {/* VPN not connected warning */}
      {!tunRunning && (
        <MacCard className="!border-[var(--color-warning)] !bg-[var(--color-warning)]/5">
          <div className="flex items-center gap-3">
            <AlertTriangle className="w-5 h-5 text-[var(--color-warning)] shrink-0" />
            <p className="text-sm text-[var(--color-text)]">
              {t('speedTest.vpnNotConnected')}
            </p>
          </div>
        </MacCard>
      )}

      {/* Run test card */}
      <MacCard>
        <div className="flex flex-col items-center gap-4 py-4">
          <MacButton
            variant="primary"
            size="lg"
            onClick={handleRunTest}
            loading={running}
            disabled={!tunRunning || running}
          >
            <Zap className="w-5 h-5 mr-2" />
            {running ? t('speedTest.running') : t('speedTest.runTest')}
          </MacButton>

          {/* Progress bar */}
          {running && (
            <div className="w-full max-w-md space-y-2">
              <MacProgress value={progress} size="md" variant="accent" showLabel />
              <p className="text-xs text-center text-[var(--color-text-secondary)]">
                {phaseLabel(phase)}
              </p>
            </div>
          )}

          {/* Error display */}
          {error && (
            <p className="text-sm text-[var(--color-danger)]">{error}</p>
          )}
        </div>
      </MacCard>

      {/* Results card */}
      {result && (
        <MacCard>
          <h2 className="text-lg font-medium text-[var(--color-text)] mb-4">
            {t('speedTest.results')}
          </h2>
          <div className="grid grid-cols-3 gap-4">
            <ResultMetric
              icon={<Download className="w-5 h-5 text-[var(--color-accent)]" />}
              label={t('speedTest.download')}
              value={`${result.downloadMbps}`}
              unit={t('speedTest.mbps')}
            />
            <ResultMetric
              icon={<Upload className="w-5 h-5 text-[var(--color-success)]" />}
              label={t('speedTest.upload')}
              value={`${result.uploadMbps}`}
              unit={t('speedTest.mbps')}
            />
            <ResultMetric
              icon={<Clock className="w-5 h-5 text-[var(--color-warning)]" />}
              label={t('speedTest.latency')}
              value={`${result.latencyMs}`}
              unit={t('speedTest.ms')}
            />
          </div>
          <div className="flex items-center gap-2 mt-4 pt-3 border-t border-[var(--color-border)]">
            <Server className="w-4 h-4 text-[var(--color-text-secondary)]" />
            <span className="text-xs text-[var(--color-text-secondary)]">
              {result.serverName} • {result.profileUsed} • {formatTimestamp(result.timestamp)}
            </span>
          </div>
        </MacCard>
      )}

      {/* History section */}
      <div>
        <h2 className="text-lg font-medium text-[var(--color-text)] mb-3">
          {t('speedTest.history')}
        </h2>
        {loadingHistory ? (
          <div className="flex items-center justify-center py-8 text-[var(--color-text-secondary)]">
            <p className="text-sm">{t('common.loading')}</p>
          </div>
        ) : history.length === 0 ? (
          <MacCard>
            <div className="flex flex-col items-center justify-center py-8 text-[var(--color-text-secondary)]">
              <Zap className="w-10 h-10 mb-3 opacity-40" />
              <p className="text-sm">{t('speedTest.noHistory')}</p>
            </div>
          </MacCard>
        ) : (
          <div className="space-y-2">
            {history.map((entry) => (
              <HistoryEntry key={entry.id} entry={entry} t={t} />
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

// ─── Sub-components ──────────────────────────────────────────────────────────

interface ResultMetricProps {
  icon: React.ReactNode
  label: string
  value: string
  unit: string
}

function ResultMetric({ icon, label, value, unit }: ResultMetricProps) {
  return (
    <div className="flex flex-col items-center gap-1 p-3 rounded-[var(--radius-sm)] bg-[var(--color-bg)]">
      {icon}
      <span className="text-2xl font-semibold text-[var(--color-text)] tabular-nums">
        {value}
      </span>
      <span className="text-xs text-[var(--color-text-secondary)]">
        {unit}
      </span>
      <span className="text-xs text-[var(--color-text-secondary)]">
        {label}
      </span>
    </div>
  )
}

interface HistoryEntryProps {
  entry: SpeedTestResult
  t: (key: string) => string
}

function HistoryEntry({ entry, t }: HistoryEntryProps) {
  return (
    <MacCard className="!p-3">
      <div className="flex items-center gap-4">
        {/* Timestamp */}
        <div className="min-w-[120px]">
          <span className="text-xs text-[var(--color-text-secondary)]">
            {formatTimestamp(entry.timestamp)}
          </span>
        </div>

        {/* Metrics */}
        <div className="flex items-center gap-4 flex-1">
          <div className="flex items-center gap-1.5">
            <Download className="w-3.5 h-3.5 text-[var(--color-accent)]" />
            <span className="text-sm font-medium text-[var(--color-text)] tabular-nums">
              {entry.downloadMbps} {t('speedTest.mbps')}
            </span>
          </div>
          <div className="flex items-center gap-1.5">
            <Upload className="w-3.5 h-3.5 text-[var(--color-success)]" />
            <span className="text-sm font-medium text-[var(--color-text)] tabular-nums">
              {entry.uploadMbps} {t('speedTest.mbps')}
            </span>
          </div>
          <div className="flex items-center gap-1.5">
            <Clock className="w-3.5 h-3.5 text-[var(--color-warning)]" />
            <span className="text-sm font-medium text-[var(--color-text)] tabular-nums">
              {entry.latencyMs} {t('speedTest.ms')}
            </span>
          </div>
        </div>

        {/* Server info */}
        <div className="text-right">
          <span className="text-xs text-[var(--color-text-secondary)]">
            {entry.serverName} • {entry.profileUsed}
          </span>
        </div>
      </div>
    </MacCard>
  )
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function formatTimestamp(ts: number): string {
  const date = new Date(ts)
  return date.toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  })
}
