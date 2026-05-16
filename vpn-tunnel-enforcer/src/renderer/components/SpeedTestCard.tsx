/**
 * SpeedTestCard — Full speed test UI component with:
 * - "Run Speed Test" button that calls 'speed-test:run' IPC
 * - Animated progress bar (MacProgress) during test with phase labels
 * - Listens for 'speed-test:progress' IPC events
 * - Displays results: download Mbps, upload Mbps, latency ms
 * - Warning if VPN is not connected
 * - History of past tests with timestamps
 *
 * Validates: Requirements 7.1, 7.2, 7.3, 7.4, 7.5
 */

import React, { useEffect, useState, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { Zap, ArrowDown, ArrowUp, Clock, AlertTriangle, History } from 'lucide-react'
import { MacCard } from '../design-system/MacCard'
import { MacButton } from '../design-system/MacButton'
import { MacProgress } from '../design-system/MacProgress'
import { useAppStore } from '../store'

interface SpeedTestResult {
  id: string
  timestamp: number
  downloadMbps: number
  uploadMbps: number
  latencyMs: number
  serverName: string
  profileUsed: string
}

type TestPhase = 'idle' | 'latency' | 'download' | 'upload' | 'complete' | 'error'

const phaseLabels: Record<TestPhase, string> = {
  idle: '',
  latency: 'Измерение задержки...',
  download: 'Тест загрузки...',
  upload: 'Тест отдачи...',
  complete: 'Завершено',
  error: 'Ошибка'
}

export const SpeedTestCard: React.FC = () => {
  const { t } = useTranslation()
  const tunRunning = useAppStore((s) => s.tunRunning)

  const [running, setRunning] = useState(false)
  const [phase, setPhase] = useState<TestPhase>('idle')
  const [progress, setProgress] = useState(0)
  const [lastResult, setLastResult] = useState<SpeedTestResult | null>(null)
  const [history, setHistory] = useState<SpeedTestResult[]>([])
  const [error, setError] = useState<string | null>(null)
  const [showHistory, setShowHistory] = useState(false)

  // Fetch history on mount
  useEffect(() => {
    const fetchHistory = async () => {
      try {
        const api = (window as any).electronAPI
        if (api?.speedTestHistory) {
          const results = await api.speedTestHistory()
          setHistory(results || [])
          if (results && results.length > 0) {
            setLastResult(results[0])
          }
        }
      } catch {
        // IPC not yet wired
      }
    }
    fetchHistory()
  }, [])

  // Listen for progress events
  useEffect(() => {
    const api = (window as any).electronAPI
    if (!api?.onSpeedTestProgress) return

    const unsubscribe = api.onSpeedTestProgress(
      (data: { percent: number; phase: string }) => {
        setProgress(data.percent)
        if (data.phase === 'latency') setPhase('latency')
        else if (data.phase === 'download') setPhase('download')
        else if (data.phase === 'upload') setPhase('upload')
        else if (data.phase === 'complete') setPhase('complete')
        else if (data.phase === 'error') setPhase('error')
      }
    )

    return () => {
      if (typeof unsubscribe === 'function') unsubscribe()
    }
  }, [])

  const handleRunTest = useCallback(async () => {
    if (running) return
    if (!tunRunning) return

    setRunning(true)
    setError(null)
    setPhase('latency')
    setProgress(0)

    try {
      const api = (window as any).electronAPI
      if (!api?.speedTestRun) {
        throw new Error('Speed test API not available')
      }

      const result: SpeedTestResult = await api.speedTestRun()
      setLastResult(result)
      setPhase('complete')
      setProgress(100)

      // Refresh history
      if (api?.speedTestHistory) {
        const results = await api.speedTestHistory()
        setHistory(results || [])
      }
    } catch (err: any) {
      setError(err.message || 'Ошибка теста скорости')
      setPhase('error')
    } finally {
      setRunning(false)
    }
  }, [running, tunRunning])

  const formatTimestamp = (ts: number): string => {
    return new Date(ts).toLocaleString()
  }

  return (
    <MacCard className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Zap size={20} className="text-yellow-500" />
          <h3 className="text-base font-semibold text-[var(--color-text)]">
            {t('speedTest.title', 'Тест скорости')}
          </h3>
        </div>
        <MacButton
          variant="primary"
          size="sm"
          onClick={handleRunTest}
          disabled={!tunRunning || running}
          loading={running}
        >
          {running
            ? t('speedTest.running', 'Тестирование...')
            : t('speedTest.run', 'Запустить тест')}
        </MacButton>
      </div>

      {/* VPN not connected warning */}
      {!tunRunning && (
        <div className="flex items-center gap-2 rounded-[var(--radius-sm)] bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 px-3 py-2">
          <AlertTriangle size={16} className="text-yellow-600 dark:text-yellow-400 shrink-0" />
          <p className="text-xs text-yellow-700 dark:text-yellow-300">
            {t('speedTest.vpnRequired', 'VPN не подключён. Подключите VPN для запуска теста скорости.')}
          </p>
        </div>
      )}

      {/* Progress bar during test */}
      {running && (
        <div className="space-y-2">
          <MacProgress
            value={progress}
            size="md"
            variant={phase === 'error' ? 'danger' : 'accent'}
            showLabel
          />
          <p className="text-xs text-[var(--color-text-secondary)] text-center">
            {phaseLabels[phase]}
          </p>
        </div>
      )}

      {/* Error message */}
      {error && !running && (
        <div className="flex items-center gap-2 rounded-[var(--radius-sm)] bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 px-3 py-2">
          <AlertTriangle size={16} className="text-red-600 dark:text-red-400 shrink-0" />
          <p className="text-xs text-red-700 dark:text-red-300">{error}</p>
        </div>
      )}

      {/* Results display */}
      {lastResult && !running && phase !== 'error' && (
        <div className="space-y-3">
          <div className="grid grid-cols-3 gap-3">
            {/* Download */}
            <div className="rounded-[var(--radius-sm)] bg-[var(--color-bg)] p-3 border border-[var(--color-border)] text-center">
              <ArrowDown size={16} className="mx-auto text-blue-500 mb-1" />
              <p className="text-lg font-semibold text-[var(--color-text)] tabular-nums">
                {lastResult.downloadMbps.toFixed(1)}
              </p>
              <p className="text-xs text-[var(--color-text-secondary)]">
                {t('speedTest.download', 'Загрузка')} Mbps
              </p>
            </div>
            {/* Upload */}
            <div className="rounded-[var(--radius-sm)] bg-[var(--color-bg)] p-3 border border-[var(--color-border)] text-center">
              <ArrowUp size={16} className="mx-auto text-emerald-500 mb-1" />
              <p className="text-lg font-semibold text-[var(--color-text)] tabular-nums">
                {lastResult.uploadMbps.toFixed(1)}
              </p>
              <p className="text-xs text-[var(--color-text-secondary)]">
                {t('speedTest.upload', 'Отдача')} Mbps
              </p>
            </div>
            {/* Latency */}
            <div className="rounded-[var(--radius-sm)] bg-[var(--color-bg)] p-3 border border-[var(--color-border)] text-center">
              <Clock size={16} className="mx-auto text-[var(--color-text-secondary)] mb-1" />
              <p className="text-lg font-semibold text-[var(--color-text)] tabular-nums">
                {lastResult.latencyMs}
              </p>
              <p className="text-xs text-[var(--color-text-secondary)]">
                {t('speedTest.latency', 'Задержка')} ms
              </p>
            </div>
          </div>
          <p className="text-xs text-[var(--color-text-secondary)] text-right">
            {formatTimestamp(lastResult.timestamp)}
          </p>
        </div>
      )}

      {/* History toggle */}
      {history.length > 0 && (
        <div className="border-t border-[var(--color-border)] pt-3">
          <button
            onClick={() => setShowHistory(!showHistory)}
            className="flex items-center gap-1.5 text-xs text-[var(--color-accent)] hover:underline transition-colors"
          >
            <History size={14} />
            {showHistory
              ? t('speedTest.hideHistory', 'Скрыть историю')
              : t('speedTest.showHistory', `Показать историю (${history.length})`)}
          </button>

          {/* History list */}
          {showHistory && (
            <div className="mt-3 space-y-2 max-h-48 overflow-y-auto">
              {history.map((item) => (
                <div
                  key={item.id}
                  className="flex items-center justify-between rounded-[var(--radius-sm)] bg-[var(--color-bg)] px-3 py-2 border border-[var(--color-border)]"
                >
                  <div className="flex items-center gap-3 text-xs">
                    <span className="flex items-center gap-1 text-blue-500">
                      <ArrowDown size={12} />
                      {item.downloadMbps.toFixed(1)}
                    </span>
                    <span className="flex items-center gap-1 text-emerald-500">
                      <ArrowUp size={12} />
                      {item.uploadMbps.toFixed(1)}
                    </span>
                    <span className="flex items-center gap-1 text-[var(--color-text-secondary)]">
                      <Clock size={12} />
                      {item.latencyMs} ms
                    </span>
                  </div>
                  <span className="text-xs text-[var(--color-text-secondary)]">
                    {formatTimestamp(item.timestamp)}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </MacCard>
  )
}
