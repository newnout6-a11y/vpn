// AT-01-009, F-002/F-104: privileged execution must not live below user-writable AppData.
import { app } from 'electron'
import { createHash } from 'crypto'
import { join, win32 } from 'path'

export type PrivilegedRuntimeName = 'tun-runtime' | 'external-proxy-runtime' | 'traffic-forensics'

/** This is a location, not authorization. The ACL helper checks the Windows
 * known folder and the entire namespace before creating/staging any artifact. */
export function getPrivilegedRuntimeDir(name: PrivilegedRuntimeName): string {
  if (!['tun-runtime', 'external-proxy-runtime', 'traffic-forensics'].includes(name)) {
    throw new Error('Invalid privileged runtime name')
  }
  if (process.platform !== 'win32') return join(app.getPath('userData'), name)
  const programData = process.env.ProgramData || 'C:\\ProgramData'
  if (!win32.isAbsolute(programData) || programData.startsWith('\\\\') || /[\x00-\x1f]/.test(programData)) {
    throw new Error('Invalid ProgramData runtime location')
  }
  // Separate users and development/installed instances without embedding their
  // profile paths in a shared directory name. Do not reuse legacy runtime data.
  const instance = createHash('sha256').update(win32.resolve(app.getPath('userData')).toLowerCase()).digest('hex').slice(0, 32)
  return win32.join(programData, 'VPNTE', 'runtime', instance, name)
}
