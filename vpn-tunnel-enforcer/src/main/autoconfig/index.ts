import { androidStudio } from './androidStudio'
import { gradle } from './gradle'
import { env } from './env'
import { git } from './git'

export interface AutoconfigTarget {
  id: string
  name: string
  applied: boolean
  scope?: 'user-global' | 'app-global' | 'project-local'
  warning?: string
  managedPath?: string
  backupPath?: string
}

const targets: Record<string, {
  name: string
  scope?: 'user-global' | 'app-global' | 'project-local'
  warning?: string
  managedPath?: () => string | null
  backupPath?: () => string | null
  apply: (proxyAddr: string, proxyType: 'socks5' | 'http') => Promise<boolean>
  rollback: () => Promise<boolean>
  isApplied: () => Promise<boolean>
}> = {
  'android-studio': androidStudio,
  'gradle': gradle,
  'env': env,
  'git': git
}

export const autoconfig = {
  async apply(
    targetIds: string[],
    proxyAddr: string,
    proxyType: 'socks5' | 'http' = 'socks5'
  ): Promise<Record<string, boolean>> {
    const results: Record<string, boolean> = {}
    for (const id of targetIds) {
      const target = targets[id]
      if (target) {
        try {
          results[id] = await target.apply(proxyAddr, proxyType)
        } catch {
          results[id] = false
        }
      }
    }
    return results
  },

  async rollback(targetIds: string[]): Promise<Record<string, boolean>> {
    const results: Record<string, boolean> = {}
    for (const id of targetIds) {
      const target = targets[id]
      if (target) {
        try {
          results[id] = await target.rollback()
        } catch {
          results[id] = false
        }
      }
    }
    return results
  },

  async getStatus(): Promise<AutoconfigTarget[]> {
    const result: AutoconfigTarget[] = []
    for (const [id, target] of Object.entries(targets)) {
      let applied = false
      try {
        applied = await target.isApplied()
      } catch { /* */ }
      result.push({
        id,
        name: target.name,
        applied,
        scope: target.scope,
        warning: target.warning,
        managedPath: target.managedPath?.() ?? undefined,
        backupPath: target.backupPath?.() ?? undefined
      })
    }
    return result
  }
}
