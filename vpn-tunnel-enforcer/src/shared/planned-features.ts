/** AT-00-009/AT-12-002: admission is a release decision, never a user setting. */
export const PLANNED_FEATURE_IDS = Object.freeze(['mihomo', 'amneziawg', 'process-monitor', 'browser-boxes'] as const)
export type PlannedFeatureId = typeof PLANNED_FEATURE_IDS[number]

const requiredTests: Record<PlannedFeatureId, readonly string[]> = {
  mihomo: ['AT-12-001', 'AT-12-002', 'AT-12-004', 'AT-12-007'],
  amneziawg: ['AT-12-002', 'AT-12-003', 'AT-12-007', 'AT-12-008'],
  'process-monitor': ['AT-12-002', 'AT-12-005', 'AT-12-007'],
  'browser-boxes': ['AT-12-002', 'AT-12-006', 'AT-12-007']
}

export interface PlannedFeatureStatus {
  id: PlannedFeatureId
  enabled: false
  laboratoryAdmission: null
  requiredTests: string[]
}

/** Fresh snapshots cannot turn a renderer edit into release admission. No WP-12
 * feature has laboratory evidence or implementation in this release. */
export function plannedFeatureStatus(): PlannedFeatureStatus[] {
  return PLANNED_FEATURE_IDS.map(id => ({ id, enabled: false, laboratoryAdmission: null,
    requiredTests: [...requiredTests[id]] }))
}
