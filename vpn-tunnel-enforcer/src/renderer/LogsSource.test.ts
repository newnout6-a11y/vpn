import { readFileSync } from 'fs'
import { join } from 'path'
import { describe, expect, it } from 'vitest'

const logsSource = () => readFileSync(join(process.cwd(), 'src', 'renderer', 'pages', 'Logs.tsx'), 'utf8')

describe('Logs source regressions', () => {
  it('clears every persistent log/history/artifact store from the Logs clear action', () => {
    const source = logsSource()
    const handlerStart = source.indexOf('const handleClearLogs = async () =>')
    const handlerEnd = source.indexOf('const loadRawLogs = async () =>', handlerStart)
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
})
