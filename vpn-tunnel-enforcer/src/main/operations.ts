import { OperationRegistry } from './operationRegistry'
import { logEvent } from './appLogger'
import { ipcMain } from 'electron'
import { requireString, IpcValidationError } from './ipcValidation'
import { withCorrelation } from './actionCorrelation'
import { operationLogDetails } from '../shared/operation'

export const operations = new OperationRegistry(operation => {
  logEvent(operation.status === 'running' ? 'debug' : 'info', 'lifecycle', 'feature operation', operationLogDetails(operation))
}, (operation, category) => {
  withCorrelation(operation.correlationId, () => logEvent('error', 'lifecycle', 'feature post-commit failure', {
    operationKey: 'op_' + operation.operationId.replaceAll('-', ''), category
  }), { source: operation.source, owner: operation.owner })
})

export function registerOperationHandlers(): void {
  ipcMain.handle('operations:list', () => operations.list())
  ipcMain.handle('operations:cancel', (_event, operationId: string) => {
    const id = requireString(operationId, 'operationId', { maxLength: 36 })
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id)) throw new IpcValidationError('Invalid operationId')
    return operations.cancel(id)
  })
}
