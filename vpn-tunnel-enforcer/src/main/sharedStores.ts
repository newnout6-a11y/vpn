import Store from 'electron-store'
import type { ServerProfile, ServerGroup, KillSwitchLevel, KillSwitchException } from '../shared/ipc-types'

export interface ServerPickerStoreShape {
  profiles: ServerProfile[]
  activeProfileId: string | null
}

export interface ServerGroupsStoreShape {
  groups: ServerGroup[]
}

export interface GranularKillSwitchStoreShape {
  killSwitchLevel: KillSwitchLevel
  killSwitchExceptions: KillSwitchException[]
}

export const serverPickerStore = new Store<ServerPickerStoreShape>({
  name: 'server-picker',
  defaults: { profiles: [], activeProfileId: null }
})

export const serverGroupsStore = new Store<ServerGroupsStoreShape>({
  name: 'server-groups',
  defaults: { groups: [] }
})

export const granularKillSwitchStore = new Store<GranularKillSwitchStoreShape>({
  name: 'granular-kill-switch',
  defaults: { killSwitchLevel: 'off', killSwitchExceptions: [] }
})
