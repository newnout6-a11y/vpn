// AT-00-005: real scheduler re-arming must not retain the schedule-edit action.
import { expect, it, vi } from 'vitest'
import type { ScheduleEntry } from '../shared/ipc-types'
import { currentCorrelationId, withCorrelation } from './actionCorrelation'
import { ConnectionLifecycle } from './connectionLifecycle'
import { schedulerService } from './scheduler'

vi.mock('electron', () => ({ ipcMain: { handle: vi.fn() } }))
vi.mock('electron-store', () => ({ default: class {
  private schedules: ScheduleEntry[] = []
  get() { return this.schedules }
  set(_key: string, schedules: ScheduleEntry[]) { this.schedules = schedules }
} }))

it('assigns fresh operation IDs to recurring scheduled starts/stops after a UI edit settles', async () => {
  const editId = 'ipc_00000000000040008000000000000001'
  let now = new Date(2024, 0, 10, 8, 59).getTime()
  const nativeTimeout = globalThis.setTimeout
  // Compress only scheduler boundaries. Native timers still create real async
  // resources; fake timers alone do not reproduce AsyncLocalStorage inheritance.
  vi.spyOn(Date, 'now').mockImplementation(() => now)
  vi.spyOn(globalThis, 'setTimeout').mockImplementation(((callback: () => void, delay: number) => {
    if ([60_000, 8 * 60 * 60_000, 16 * 60 * 60_000].includes(delay)) {
      return nativeTimeout(() => { now += delay; callback() }, 5)
    }
    return nativeTimeout(callback, delay)
  }) as typeof setTimeout)
  const events: string[] = [], entryContexts: Array<string | undefined> = []
  const lane = new ConnectionLifecycle(() => {}, undefined, operation => {
    if (operation.status === 'running') events.push(operation.correlationId)
  })
  let finish!: () => void
  const finished = new Promise<void>(done => { finish = done })
  const tasks: Promise<unknown>[] = []
  try {
    schedulerService.init({
      onConnect: () => {
        entryContexts.push(currentCorrelationId())
        const task = lane.start(async () => ({ success: true }), { owner: 'schedule' })
        tasks.push(task)
        if (entryContexts.length === 3) finish()
      },
      onDisconnect: () => {
        entryContexts.push(currentCorrelationId())
        tasks.push(lane.stop(async () => ({ success: true }), { owner: 'schedule' }))
      }
    })
    await withCorrelation(editId, async () => {
      const schedule = schedulerService.createSchedule({ name: 'Daily', enabled: true,
        days: [1, 2, 3, 4, 5], startTime: '09:00', endTime: '17:00', profileId: 'profile', mode: 'direct' })
      schedulerService.updateSchedule(schedule.id, { name: 'Edited' })
    })
    await finished
    schedulerService.stop()
    await Promise.all(tasks)
    expect(entryContexts).toEqual([undefined, undefined, undefined])
    expect(events).toHaveLength(3)
    expect(new Set(events).size).toBe(3)
    expect(events.every(id => /^op_[0-9a-f]{32}$/.test(id))).toBe(true)
  } finally {
    schedulerService.stop()
    vi.restoreAllMocks()
    await Promise.allSettled(tasks)
  }
})
