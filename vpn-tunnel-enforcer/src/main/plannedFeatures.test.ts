// AT-00-001/009, AT-12-002: production policy through the actual IPC boundary.
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { PLANNED_FEATURE_IDS, plannedFeatureStatus } from '../shared/planned-features'
import { IPC_REQUESTS } from '../shared/ipc-contract'

const state = vi.hoisted(() => ({ handlers: new Map<string, (...args: any[]) => any>(), handle: vi.fn(), log: vi.fn(), auditIds: [] as (string | undefined)[] }))
vi.mock('electron', () => ({ ipcMain: { handle: state.handle }, app: { isPackaged: false } }))
vi.mock('./appLogger', () => ({ logEvent: state.log }))

beforeEach(async () => {
  vi.resetModules()
  vi.clearAllMocks()
  state.handlers.clear()
  state.auditIds.length = 0
  state.handle.mockImplementation((channel, handler) => state.handlers.set(channel, handler))
  const { ipcMain } = await import('electron')
  ipcMain.handle = state.handle
  delete (ipcMain as any)[Symbol.for('vpnte.ipc.trusted-boundary.installed')]
  ;(await import('./ipcSecurity')).installTrustedIpcBoundary()
  const { currentCorrelationId } = await import('./actionCorrelation')
  state.log.mockImplementation((_level, _scope, message) => {
    if (message === 'feature.activation-denied') state.auditIds.push(currentCorrelationId())
  })
  ;(await import('./plannedFeatures')).registerPlannedFeatureHandlers()
})

describe('planned feature release admission', () => {
  it('lists all four features disabled and without lab admission; caller mutation cannot enable them', async () => {
    const snapshot = await state.handlers.get('planned-features:status')!({})
    expect(snapshot).toMatchObject({ ok: true, result: PLANNED_FEATURE_IDS.map(id => ({ id, enabled: false, laboratoryAdmission: null })) })
    snapshot.result[0].enabled = true
    snapshot.result[0].laboratoryAdmission = { passed: true }
    snapshot.result[0].requiredTests.length = 0
    expect((await state.handlers.get('planned-features:status')!({})).result).toEqual(plannedFeatureStatus())
    expect(plannedFeatureStatus().every(feature => feature.requiredTests.includes('AT-12-002'))).toBe(true)
    for (const id of PLANNED_FEATURE_IDS) expect(Object.keys(IPC_REQUESTS).some(channel => channel.startsWith(id + ':'))).toBe(false)
  })

  it.each(PLANNED_FEATURE_IDS)('denies %s without lab evidence and audits the same action correlation', async featureId => {
    const result = await state.handlers.get('planned-features:activate')!({}, featureId)
    expect(result).toMatchObject({ ok: false, error: { code: 'IPC_PERMISSION_DENIED', category: 'permission' } })
    expect(state.log).toHaveBeenCalledWith('warn', 'features', 'feature.activation-denied', {
      featureId, reason: 'laboratory-evidence-missing', requiredTests: expect.arrayContaining(['AT-12-002'])
    })
    expect(state.auditIds).toEqual([result.correlationId])
    const { currentCorrelationId } = await import('./actionCorrelation')
    expect(currentCorrelationId()).toBeUndefined()
    expect(plannedFeatureStatus().every(feature => !feature.enabled && feature.laboratoryAdmission === null)).toBe(true)
  })

  it.each([[], ['unknown'], [null], ['mihomo', { passed: true, requiredTests: ['AT-12-004'] }]].map(args => ({ args })))('rejects malformed/forged admission $args before the handler', async ({ args }) => {
    expect(await state.handlers.get('planned-features:activate')!({}, ...args)).toMatchObject({ ok: false, error: { category: 'validation' } })
    expect(state.log.mock.calls.filter(call => call[2] === 'feature.activation-denied')).toEqual([])
  })
})
