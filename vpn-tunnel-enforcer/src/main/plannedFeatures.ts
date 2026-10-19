import { ipcMain } from 'electron'
import { PLANNED_FEATURE_IDS, plannedFeatureStatus, type PlannedFeatureId } from '../shared/planned-features'
import { IpcFault, IpcValidationError } from '../shared/ipc-result'
import { logEvent } from './appLogger'

export function registerPlannedFeatureHandlers(): void {
  ipcMain.handle('planned-features:status', () => plannedFeatureStatus())
  ipcMain.handle('planned-features:activate', (_event, featureId: PlannedFeatureId): boolean => {
    if (!PLANNED_FEATURE_IDS.includes(featureId)) throw new IpcValidationError('Unknown planned feature')
    logEvent('warn', 'features', 'feature.activation-denied', {
      featureId, reason: 'laboratory-evidence-missing',
      requiredTests: plannedFeatureStatus().find(feature => feature.id === featureId)!.requiredTests
    })
    throw new IpcFault('permission')
  })
}
