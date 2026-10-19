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
  const navigating = (details: { isMainFrame: boolean; isSameDocument: boolean }) => {
    if (details.isMainFrame && !details.isSameDocument) abort()
  }
  sender?.once?.('destroyed', abort)
  sender?.once?.('render-process-gone', abort)
  sender?.on?.('did-start-navigation', navigating)
  return {
    signal: signal ? AbortSignal.any([signal, controller.signal]) : controller.signal,
    dispose() {
      sender?.removeListener?.('destroyed', abort)
      sender?.removeListener?.('render-process-gone', abort)
      sender?.removeListener?.('did-start-navigation', navigating)
    }
  }
}
