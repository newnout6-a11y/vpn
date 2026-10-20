// AT-00-005, F-143: execute the actual main callbacks with controlled effects.
import { readFileSync } from 'node:fs'
import { randomUUID } from 'node:crypto'
import { resolve } from 'node:path'
import ts from 'typescript'
import { describe, expect, it, vi } from 'vitest'
import { currentActionMetadata, currentCorrelationId, withCorrelation } from './actionCorrelation'
import { ConnectionLifecycle } from './connectionLifecycle'
import { runScheduledConnection } from './scheduledConnection'
import type { ScheduleEntry } from '../shared/ipc-types'

const source = ts.createSourceFile('index.ts', readFileSync(resolve('src/main/index.ts'), 'utf8'), ts.ScriptTarget.Latest, true)
function compile<T>(text: string, result: string, bindings: Record<string, unknown>): T {
  const js = ts.transpileModule(text, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText
  return new Function(...Object.keys(bindings), js + '\nreturn ' + result)(...Object.values(bindings)) as T
}
function schedulerArgument(): string {
  let argument = ''
  const visit = (node: ts.Node) => {
    if (ts.isCallExpression(node) && node.expression.getText(source) === 'schedulerService.init') argument = node.arguments[0].getText(source)
    ts.forEachChild(node, visit)
  }
  visit(source)
  if (!argument) throw new Error('Production scheduler callbacks not found')
  return argument
}
function declarations(...names: string[]): string {
  return source.statements.filter(node => ts.isFunctionDeclaration(node) && names.includes(node.name?.text ?? '')).map(node => node.getText(source)).join('\n')
}
function held() {
  let release!: () => void
  const promise = new Promise<void>(yes => { release = yes })
  return { promise, release }
}
function recorder() {
  const events: { name: string; id: string | undefined; metadata: ReturnType<typeof currentActionMetadata> }[] = []
  return { events, record: (name: string) => { events.push({ name, id: currentCorrelationId(), metadata: currentActionMetadata() }) } }
}
const schedule: ScheduleEntry = { id: 'schedule1', name: 'night', enabled: true, days: [1], startTime: '10:00', endTime: '11:00', mode: 'hard', profileId: '' }
function schedulerFixture(fail = false) {
  const gate = held(), stopGate = held(), notificationGate = held(), { events, record } = recorder()
  const lane = new ConnectionLifecycle(() => {}, undefined, operation => record('operation:' + operation.status))
  const start = async () => { record('native:start'); return { success: true as const } }
  const callbacks = compile<{
    onConnect(schedule: ScheduleEntry): Promise<unknown>
    onDisconnect(schedule: ScheduleEntry): void | Promise<void>
  }>('const callbacks = ' + schedulerArgument(), 'callbacks', {
    withCorrelation, randomUUID, runScheduledConnection, connectionLifecycle: lane,
    logEvent: (_level: string, _module: string, message: string) => record(message),
    resolveProxyForTrayStart: async () => { record('proxy:before'); await gate.promise; record('proxy:after'); if (fail) throw new Error('Injected failure'); return { proxyAddr: '127.0.0.1:1080', proxyType: 'socks5' } },
    serverPicker: { selectProfile: () => {}, getActiveProfile: () => null },
    startDirectVpnProtectionEffects: start, startSoftProtectionEffects: start, startProtectionEffects: start,
    stopProtection: () => lane.stop(async () => { record('stop:before'); await stopGate.promise; record('stop:after'); return { success: true } }, { owner: 'schedule' }),
    notify: async () => { record('notify'); await notificationGate.promise; record('notify:after') }
  })
  return { callbacks, events, gate, stopGate, notificationGate }
}
function assertScope(events: ReturnType<typeof recorder>['events'], owner: 'schedule' | 'recovery') {
  expect(events.length).toBeGreaterThan(1)
  const id = events[0].id
  expect(id).toMatch(/^op_[0-9a-f]{32}$/)
  for (const event of events) expect(event).toMatchObject({ id, metadata: { source: 'lifecycle', owner } })
  expect(currentCorrelationId()).toBeUndefined()
  return id
}

describe('background action correlation', () => {
  it('correlates the schedule trigger, preflight, native work, terminal operation and notification', async () => {
    const f = schedulerFixture(), pending = f.callbacks.onConnect(schedule)
    f.gate.release(); f.notificationGate.release(); await pending
    expect(f.events.map(e => e.name)).toContain('notify')
    assertScope(f.events, 'schedule')
  })
  it('keeps asynchronous schedule stop and its terminal notification in the trigger scope', async () => {
    const f = schedulerFixture(), pending = f.callbacks.onDisconnect(schedule)
    f.stopGate.release(); f.notificationGate.release(); await pending
    // A void callback used to finish before the native stop completed.
    expect(f.events.map(e => e.name)).toContain('stop:after')
    expect(f.events.map(e => e.name)).toContain('notify')
    assertScope(f.events, 'schedule')
  })
  it('isolates overlapping schedule actions and includes the failure path', async () => {
    const a = schedulerFixture(), b = schedulerFixture(true)
    const first = a.callbacks.onConnect(schedule), second = b.callbacks.onConnect(schedule)
    b.gate.release(); await second; a.gate.release(); a.notificationGate.release(); await first
    expect(b.events.some(e => e.name.includes('did not complete') || e.name.includes('failed'))).toBe(true)
    expect(assertScope(a.events, 'schedule')).not.toBe(assertScope(b.events, 'schedule'))
  })
  it('retains the action scope through a delayed success notification', async () => {
    const f = schedulerFixture()
    let settled = false
    const pending = f.callbacks.onConnect(schedule).then(() => { settled = true })
    f.gate.release()
    for (let turn = 0; turn < 20; turn++) await Promise.resolve()
    expect(f.events.map(e => e.name)).toContain('notify')
    expect(settled).toBe(false)
    f.notificationGate.release(); await pending
    expect(f.events.map(e => e.name)).toContain('notify:after')
    assertScope(f.events, 'schedule')
  })
  it.each([false, true])('correlates startup recovery phases and failure handling (failure=%s)', async failure => {
    const { events, record } = recorder(), gate = held()
    const recover = compile<() => Promise<void>>(declarations('performCrashRecovery', 'performCrashRecoveryEffects'), 'performCrashRecovery', {
      withCorrelation, currentCorrelationId, randomUUID, process: { platform: 'win32' },
      timePhase: async (phase: string, effect: () => Promise<unknown>) => { record(phase); return effect() },
      isOwnedTunRuntimeRunning: async () => false,
      recoverStaleBaseline: async () => { record('baseline:before'); await gate.promise; record('baseline:after'); if (failure) throw new Error('Injected recovery failure') },
      recoverStaleKillSwitch: async () => { record('killswitch') }, isPhysicalAdapterLockdownApplied: async () => false,
      repairOrphanedPhysicalAdapterDns: async () => { record('dns') }, autoconfig: { isApplied: async () => false },
      logEvent: (_level: string, _module: string, message: string) => record(message),
      tunnelState: { fault: () => { record('fault') } }, dialog: { showMessageBox: async () => { record('warning') } },
      require: () => ({ tunController: { getStatus: () => ({ running: false }) } })
    })
    const pending = recover(); gate.release(); await pending
    expect(events.map(e => e.name)).toContain(failure ? 'warning' : 'dns')
    assertScope(events, 'recovery')
  })
  it.each([false, true])('correlates retained Soft recovery preflight, reconciliation and failure (failure=%s)', async failure => {
    const { events, record } = recorder(), gate = held()
    const lane = new ConnectionLifecycle(() => {}, undefined, operation => record('operation:' + operation.status))
    const adopt = compile<() => Promise<void>>(declarations('adoptRetainedSoftProtection', 'adoptRetainedSoftProtectionEffects'), 'adoptRetainedSoftProtection', {
      withCorrelation, randomUUID, connectionLifecycle: lane,
      settingsStore: { get: () => ({ routingMode: 'soft' }) },
      autoconfig: { isApplied: async () => { record('trust:before'); await gate.promise; record('trust:after'); return true } },
      tunnelState: { snapshot: { state: 'disconnected' }, fault: () => { record('fault') } },
      resolveProxyForTrayStart: async () => { record('proxy'); if (failure) throw new Error('Injected reconciliation failure'); return { proxyAddr: '127.0.0.1:1080', proxyType: 'socks5' } },
      startSoftProtectionEffects: async () => { record('soft:reconciled'); return { success: true } },
      logEvent: (_level: string, _module: string, message: string) => record(message)
    })
    const pending = adopt(); gate.release(); await pending
    expect(events.map(e => e.name)).toContain(failure ? 'fault' : 'soft:reconciled')
    assertScope(events, 'recovery')
  })
  it('correlates a delayed warning-dialog failure without blocking startup on the dialog', async () => {
    const { events, record } = recorder()
    let rejectDialog!: (error: Error) => void
    const dialogResult = new Promise<never>((_yes, no) => { rejectDialog = no })
    const recover = compile<() => Promise<void>>(declarations('performCrashRecovery', 'performCrashRecoveryEffects'), 'performCrashRecovery', {
      withCorrelation, currentCorrelationId, randomUUID, process: { platform: 'win32' },
      timePhase: async (_phase: string, effect: () => Promise<unknown>) => effect(),
      isOwnedTunRuntimeRunning: async () => { throw new Error('Injected recovery failure') },
      tunnelState: { fault: () => { record('fault') } },
      dialog: { showMessageBox: () => { record('warning'); return dialogResult } },
      logEvent: (_level: string, _module: string, message: string) => record(message)
    })
    await recover()
    expect(currentCorrelationId()).toBeUndefined()
    rejectDialog(new Error('Injected dialog failure'))
    await vi.waitFor(() => expect(events.some(e => e.name === 'crash-recovery warning dialog failed')).toBe(true))
    assertScope(events, 'recovery')
  })
})
