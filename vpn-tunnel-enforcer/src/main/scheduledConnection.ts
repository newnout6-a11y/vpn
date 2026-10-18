import type { ScheduleEntry } from '../shared/ipc-types'
import type { ConnectionStartResult } from '../shared/operation'
import { ConnectionLifecycle, type ConnectionStartupOwner } from './connectionLifecycle'

type Proxy = { proxyAddr: string; proxyType: 'socks5' | 'http' }
type ScheduledConnectionResult = ConnectionStartResult | { success: false; code: 'SCHEDULE_PROFILE_UNAVAILABLE'; error: string }
interface ScheduledConnectionActions {
  resolveProxy(): Promise<Proxy | null>
  selectProfile(id: string): boolean
  startDirect(owner: ConnectionStartupOwner): Promise<ConnectionStartResult>
  startProxy(owner: ConnectionStartupOwner, proxy: Proxy, mode: 'soft' | 'hard'): Promise<ConnectionStartResult>
}

/** Admission precedes detection and selection: a delayed schedule cannot revive
 * protection or overwrite the user's selected profile after a manual stop. */
export function runScheduledConnection(
  lifecycle: ConnectionLifecycle,
  schedule: Pick<ScheduleEntry, 'mode' | 'profileId'>,
  actions: ScheduledConnectionActions
): Promise<ScheduledConnectionResult> {
  return lifecycle.start<ScheduledConnectionResult>(async owner => {
    const proxy = schedule.mode === 'direct' ? null : await owner.wait(actions.resolveProxy())
    owner.assertActive()
    if (schedule.mode !== 'direct' && !proxy) return { success: false, error: 'Не найден локальный прокси' }
    if (schedule.profileId && !actions.selectProfile(schedule.profileId)) return { success: false, code: 'SCHEDULE_PROFILE_UNAVAILABLE', error: 'Профиль расписания недоступен' }
    return schedule.mode === 'direct'
      ? owner.wait(actions.startDirect(owner))
      : owner.wait(actions.startProxy(owner, proxy!, schedule.mode))
  }, { owner: 'schedule' })
}
