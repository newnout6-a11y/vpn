import type { AutoconfigTarget } from '../../shared/network'
export type { AutoconfigTarget } from '../../shared/network'
import { androidStudio } from './androidStudio'
import { gradle } from './gradle'
import { env } from './env'
import { git } from './git'

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
  isEnvProxyConfigured(proxyAddr: string, proxyType: 'socks5' | 'http'): Promise<boolean> {
    return env.matchesProxy(proxyAddr, proxyType)
  },

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
            if (!results[id]) {
              for (const appliedId of Object.keys(results).filter((key) => results[key])) {
                results[appliedId] = await (targets[appliedId]?.rollback() ?? Promise.resolve(false))
              }
              break
            }
          } catch {
            results[id] = false
            for (const appliedId of Object.keys(results).filter((key) => results[key])) {
              results[appliedId] = await (targets[appliedId]?.rollback() ?? Promise.resolve(false))
            }
            break
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

  // Unlike the UI status list, shutdown must not treat read failures as unapplied.
  async isApplied(targetId: string): Promise<boolean> {
    if (!Object.prototype.hasOwnProperty.call(targets, targetId)) {
      throw new Error(`Unknown autoconfig target: ${targetId}`)
    }
    return targets[targetId].isApplied()
  },

  /** Lifecycle cleanup must distinguish an absent target from failed inspection
   * or a rollback that left its durable recovery evidence pending. */
  async rollbackApplied(targetId: string): Promise<boolean> {
    if (!await this.isApplied(targetId)) return false
    const result = await this.rollback([targetId])
    if (result[targetId] !== true) throw new Error('Autoconfig rollback unconfirmed')
    return true
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
