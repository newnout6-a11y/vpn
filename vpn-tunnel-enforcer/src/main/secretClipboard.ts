import { clipboard } from 'electron'
import { createHash } from 'crypto'
import { logEvent } from './appLogger'

export const SECRET_CLIPBOARD_TTL_MS = 60_000
const RETRY_DELAY_MS = 5_000
interface OwnedClipboard { digest: string; formats: string }
let owned: OwnedClipboard | null = null
let timer: ReturnType<typeof setTimeout> | undefined
// Native clipboard reads/writes yield in Electron 44. Serialize our operations
// so an old timeout cannot discard ownership of a newly copied key.
let pending: Promise<unknown> = Promise.resolve()
function serialize<T>(operation: () => Promise<T>): Promise<T> {
  const result = pending.then(operation)
  pending = result.catch(() => undefined)
  return result
}

function digest(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex')
}
async function formats(): Promise<string> {
  const items = await clipboard.read()
  return JSON.stringify(items.map(item => [...item.types].sort()).sort())
}
function arm(delay: number): void {
  if (timer) clearTimeout(timer)
  const expectedOwner = owned
  timer = setTimeout(() => { void clearClipboard(expectedOwner) }, delay)
  timer.unref?.()
}

/** Main-owned timer survives renderer navigation, reload and destruction.
 * Retain only a fingerprint, not another plaintext copy of the VPN key.
 * Clipboard history/cloud synchronization is outside this cleanup's scope.
 */
export function copySecretToClipboard(secret: string): Promise<{ clearAfterMs: number }> {
  const fingerprint = digest(secret)
  return serialize(async () => {
    await clipboard.writeText(secret) // If this fails, keep the previous cleanup armed.
    if (timer) clearTimeout(timer)
    owned = { digest: fingerprint, formats: '' }
    arm(SECRET_CLIPBOARD_TTL_MS)
    try { owned.formats = await formats() } catch {
      // Never erase unknown clipboard formats if native format discovery fails.
      logEvent('warn', 'secret-clipboard', 'clipboard format ownership could not be verified')
    }
    return { clearAfterMs: SECRET_CLIPBOARD_TTL_MS }
  })
}

/** Also called before main-process shutdown. Native failures are visible and
 * retried while main is alive; unknown/new clipboard data is never erased.
 */
export function clearOwnedSecretClipboard(): Promise<void> {
  return clearClipboard()
}

function clearClipboard(expectedOwner?: OwnedClipboard | null): Promise<void> {
  return serialize(async () => {
    // A timeout may fire during an asynchronous replacement write and queue
    // behind it. That stale timeout must leave the replacement's TTL intact.
    if (expectedOwner !== undefined && owned !== expectedOwner) return
    if (timer) clearTimeout(timer)
    timer = undefined
    if (!owned) return
    try {
      if (digest(await clipboard.readText()) === owned.digest && await formats() === owned.formats
        // Recheck after async format discovery: a user may have copied new text.
        && digest(await clipboard.readText()) === owned.digest) {
        clipboard.clear()
      }
      owned = null
    } catch {
      logEvent('warn', 'secret-clipboard', 'secret clipboard cleanup failed; retry scheduled')
      arm(RETRY_DELAY_MS)
    }
  })
}
