import { execFile } from 'child_process'
import { isIP } from 'net'
import { executeRecoveryOperation } from './recoveryPsWorker'
import { ADAPTIVE_NETWORK_IDENTITY_SCRIPT } from './adaptiveNetworkIdentityScript'
export { ADAPTIVE_NETWORK_IDENTITY_SCRIPT } from './adaptiveNetworkIdentityScript'

export interface AdaptiveNetworkIdentity {
  alias: string
  guid: string
  profiles: string[]
  gateways: string[]
}

export async function readAdaptiveNetworkIdentity(): Promise<AdaptiveNetworkIdentity[] | null> {
  if (process.platform !== 'win32') return null
  try {
    let stdout: string
    try { stdout = await executeRecoveryOperation({ op: 'inspect-network-identity' }, 4000) }
    catch (error: unknown) {
      // Fallback is allowed only before dispatch, never after uncertain work.
      if ((error as { code?: unknown })?.code !== 'unavailable') throw error
      stdout = await new Promise<string>((resolve, reject) => {
        execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand',
          Buffer.from(ADAPTIVE_NETWORK_IDENTITY_SCRIPT, 'utf16le').toString('base64')],
        { windowsHide: true, timeout: 4000, maxBuffer: 256 * 1024, encoding: 'utf8' },
        (error, stdout) => error ? reject(error) : resolve(stdout))
      })
    }
    if (Buffer.byteLength(stdout, 'utf8') > 256 * 1024) return null
    const parsed = JSON.parse(stdout.trim())
    const rows = Array.isArray(parsed) ? parsed : parsed && typeof parsed === 'object' ? [parsed] : []
    if (!rows.length || rows.some(row => typeof row.alias !== 'string' || typeof row.guid !== 'string'
      || !Array.isArray(row.profiles) || !Array.isArray(row.gateways)
      || ![...row.profiles, ...row.gateways].every(value => typeof value === 'string')
      || !row.profiles.length && !row.gateways.length)) return null
    return rows.map(row => {
      const gateways = row.gateways.filter((value: string) => isIP(value) === 4)
      return { alias: row.alias, guid: row.guid, profiles: [...new Set<string>(row.profiles)].sort(),
        gateways: [...new Set<string>(gateways.length ? gateways : row.gateways)].sort() }
    })
  } catch {
    // Unknown identity must not reuse or learn a decision for another network.
    return null
  }
}
