import { readFileSync } from 'fs'
import { join } from 'path'
import { describe, expect, it } from 'vitest'

const logsSource = () => readFileSync(join(process.cwd(), 'src', 'renderer', 'pages', 'Logs.tsx'), 'utf8')

describe('Logs source regressions', () => {
  it('clears every persistent log/history/artifact store from the Logs clear action', () => {
    const source = logsSource()
    const handlerStart = source.indexOf('const handleClearLogs = async () =>')
    const handlerEnd = source.indexOf('const loadRawLogs = useCallback(async () =>', handlerStart)
    const handler = source.slice(handlerStart, handlerEnd)

    expect(handlerStart).toBeGreaterThanOrEqual(0)
    expect(handler).toContain('window.electronAPI.clearAppLog()')
    expect(handler).toContain('window.electronAPI.connectionHistoryClear()')
    expect(handler).toContain('window.electronAPI.trafficHistoryClear()')
    expect(handler).toContain('window.electronAPI.clearDiagnosticArtifacts()')
    expect(handler).toContain('setEntries([])')
    expect(handler).toContain('setRawLogs([])')
    expect(handler).toContain('setStats(null)')
  })

  it('stops raw-log polling when the app window is hidden and prevents overlapping reads', () => {
    const source = logsSource()

    expect(source).toContain('RAW_LOG_POLL_INTERVAL_MS = 10_000')
    expect(source).toContain('rawLogsFetchInFlightRef')
    expect(source).toContain("document.visibilityState !== 'visible'")
    expect(source).toContain("document.addEventListener('visibilitychange', onVisibilityChange)")
    expect(source).toContain('void loadRawLogs(true)')
  })

  it('keeps the raw logs panel visible in a right-hand desktop column without a toggle', () => {
    const source = logsSource()

    expect(source).toContain("xl:grid-cols-[minmax(0,1fr)_420px]")
    expect(source).toContain('xl:sticky xl:top-5')
    expect(source).toContain('const mainLogs = useMemo(() => [...rawLogs].reverse(), [rawLogs])')
    expect(source).toContain('const uiLogs = useMemo(() => [...rendererLogs].slice(-100).reverse(), [rendererLogs])')
    expect(source).toContain('<FileText size={12} className="text-[var(--color-accent)]" />')
    expect(source).toContain('<Activity size={12} className="text-[var(--color-accent)]" />')
    expect(source).not.toContain('showRawLogs')
    expect(source).not.toContain('Показать логи')
    expect(source).not.toContain('Скрыть логи')
  })
})
