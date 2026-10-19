// AT-00-005: real logger, credential redactor and on-disk JSONL backend.
import { afterEach, expect, it, vi } from 'vitest'
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { resolve, join } from 'node:path'
import { ConnectionLifecycle } from './connectionLifecycle'
import { operationLogDetails } from '../shared/operation'

const fixture = vi.hoisted(() => ({ directory: '' }))
vi.mock('electron', () => ({ app: { getPath: () => fixture.directory }, shell: { openPath: vi.fn() } }))

afterEach(() => {
  vi.restoreAllMocks()
  if (fixture.directory) rmSync(fixture.directory, { recursive: true, force: true })
})

it('keeps operation events distinguishable after real secret redaction (AT-00-005)', async () => {
  mkdirSync(resolve('.tmp'), { recursive: true })
  fixture.directory = mkdtempSync(join(resolve('.tmp'), 'operation-logs-'))
  vi.spyOn(console, 'log').mockImplementation(() => {})
  const { logEvent, getAppLogPath } = await import('./appLogger')
  const credential = '8093a2ec-f028-4e3c-96a7-b301efaf23dd'
  const lane = new ConnectionLifecycle(() => {}, undefined, operation =>
    logEvent('info', 'lifecycle', 'connection operation', { ...operationLogDetails(operation), credential, opaqueNote: credential, password: 'private-test-password' }))
  await lane.stop(async () => ({ success: true }))
  const first = lane.operation!
  await lane.stop(async () => ({ success: true }))
  const second = lane.operation!
  let raw = ''
  await vi.waitFor(() => {
    raw = readFileSync(getAppLogPath(), 'utf8')
    expect(raw.trim().split('\n')).toHaveLength(4)
  })
  const events = raw.trim().split('\n').map(line => JSON.parse(line).details)
  expect(events.map(event => event.operationId)).toEqual([
    first.operationId, first.operationId, second.operationId, second.operationId
  ])
  expect(events.map(event => event.correlationId)).toEqual([
    first.operationId, first.operationId, second.operationId, second.operationId
  ])
  expect(first.operationId).not.toBe(second.operationId)
  expect(events.every(event => event.operationKey === event.operationId)).toBe(true)
  const readBack = (await (await import('./appLogger')).getFullLogs()).find(file => file.path === getAppLogPath())!
  expect(readBack.content.trim().split('\n').map(line => JSON.parse(line).details)).toEqual(events)
  expect(raw).toContain(first.operationId)
  expect(raw).not.toContain(credential)
  expect(raw).not.toContain('private-test-password')
  expect(raw).toContain('<redacted-uuid>')
})
