import { useEffect, useRef } from 'react'
import { isIpcRemoteErrorData } from '../../shared/ipc-result'
import { useAppStore } from '../store'

// All entrypoints share one busy owner. An old reply cannot clear a new export.
let busyOwner: string | null = null
export function useDiagnosticsExport(onExported?: (path: string) => void, onError?: (message: string) => void) {
  const exporting = useAppStore(s => s.exportingDiagnostics)
  const setExporting = useAppStore(s => s.setExportingDiagnostics)
  const addLog = useAppStore(s => s.addLog)
  const scope = useRef<{ active: boolean; token?: string } | null>(null)
  useEffect(() => {
    const current = { active: true } as { active: boolean; token?: string }
    scope.current = current
    return () => {
      current.active = false
      if (current.token) {
        void window.electronAPI.operationsCancelRequest(current.token).catch(() => {})
        if (busyOwner === current.token) { busyOwner = null; setExporting(false) }
      }
      if (scope.current === current) scope.current = null
    }
  }, [setExporting])
  const exportDiagnostics = async () => {
    const current = scope.current
    if (!current?.active || current.token || busyOwner) return
    const token = crypto.randomUUID()
    current.token = token; busyOwner = token; setExporting(true)
    const owns = () => current.active && scope.current === current && current.token === token && busyOwner === token
    addLog('info', 'Собираю диагностический архив (снимки, логи, настройки)…')
    try {
      const result = await window.electronAPI.exportDiagnostics(token)
      if (!owns()) return
      if (result.cancelled) { addLog('info', 'Экспорт диагностики отменён пользователем.'); return }
      if (result.success && result.path) {
        onExported?.(result.path)
        addLog('info', `Архив создан: ${result.path}`)
      } else {
        const message = `Не удалось создать архив: ${result.error ?? 'неизвестная ошибка'}`
        addLog('error', message); onError?.(message)
      }
      if (result.warning === 'cleanup-failed') {
        const message = 'Не удалось удалить временные файлы диагностики.'
        addLog('warn', message)
        useAppStore.getState().addGlobalToast('warning', 'Очистка диагностики не завершена', message)
      }
    } catch (error) {
      if (owns() && !(isIpcRemoteErrorData(error) && error.category === 'cancelled')) {
        const message = `Ошибка при экспорте: ${error instanceof Error || isIpcRemoteErrorData(error) ? error.message : String(error)}`
        addLog('error', message); onError?.(message)
      }
    } finally {
      if (owns()) { busyOwner = null; setExporting(false) }
      if (current.token === token) current.token = undefined
    }
  }
  return { exporting, exportDiagnostics }
}
