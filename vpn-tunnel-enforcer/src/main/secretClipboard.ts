import { clipboard } from 'electron'
import { createHash } from 'crypto'
import { logEvent } from './appLogger'

export const SECRET_CLIPBOARD_TTL_MS = 60_000
const RETRY_DELAY_MS = 5_000
interface OwnedClipboard { digest: string; formats: string }
let owned: OwnedClipboard | null = null
let timer: ReturnType<typeof setTimeout> | undefined

function digest(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex')
}
function formats(): string { return JSON.stringify(clipboard.availableFormats().sort()) }
function arm(delay: number): void {
  if (timer) clearTimeout(timer)
  timer = setTimeout(clearOwnedSecretClipboard, delay)
  timer.unref?.()
}

/** Main-owned timer survives renderer navigation, reload and destruction.
 * Retain only a fingerprint, not another plaintext copy of the VPN key.
 * Clipboard history/cloud synchronization is outside this cleanup's scope.
 */
export function copySecretToClipboard(secret: string): { clearAfterMs: number } {
  const fingerprint = digest(secret)
  clipboard.writeText(secret) // If this fails, keep the previous cleanup armed.
  if (timer) clearTimeout(timer)
  owned = { digest: fingerprint, formats: '' }
  try { owned.formats = formats() } catch {
    // Never erase unknown clipboard formats if native format discovery fails.
    logEvent('warn', 'secret-clipboard', 'clipboard format ownership could not be verified')
  }
  arm(SECRET_CLIPBOARD_TTL_MS)
  return { clearAfterMs: SECRET_CLIPBOARD_TTL_MS }
}

/** Also called before main-process shutdown. Native failures are visible and
 * retried while main is alive; unknown/new clipboard data is never erased.
 */
export function clearOwnedSecretClipboard(): void {
  if (timer) clearTimeout(timer)
  timer = undefined
  if (!owned) return
  try {
    if (digest(clipboard.readText()) === owned.digest && formats() === owned.formats) {
      clipboard.clear()
    }
    owned = null
  } catch {
    logEvent('warn', 'secret-clipboard', 'secret clipboard cleanup failed; retry scheduled')
    arm(RETRY_DELAY_MS)
  }
}
