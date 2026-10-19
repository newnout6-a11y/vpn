import type { WebContents } from 'electron'
import { IpcFault } from '../shared/ipc-result'

/** Main-only ownership of a requesting document. Full navigation/crash can
 * replace that document while keeping its WebContents alive. SPA unmount
 * requires a separate request/cancel contract in the renderer. */
export function requestDocumentLifetime(sender?: WebContents, signal?: AbortSignal): {
  signal: AbortSignal
  dispose(): void
} {
  if (sender?.isDestroyed?.() || signal?.aborted) throw new IpcFault('cancelled')
  const controller = new AbortController(), abort = () => controller.abort()
  sender?.once?.('destroyed', abort)
  sender?.once?.('render-process-gone', abort)
  // did-navigate is main-frame only, excludes in-page navigation and fires
  // after the security guard can prevent navigation. An attempt alone must
  // not revoke a document that remains in place.
  sender?.on?.('did-navigate', abort)
  return {
    signal: signal ? AbortSignal.any([signal, controller.signal]) : controller.signal,
    dispose() {
      sender?.removeListener?.('destroyed', abort)
      sender?.removeListener?.('render-process-gone', abort)
      sender?.removeListener?.('did-navigate', abort)
    }
  }
}
