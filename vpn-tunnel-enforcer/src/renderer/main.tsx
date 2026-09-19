import React from 'react'
import ReactDOM from 'react-dom/client'
import { MotionConfig } from 'framer-motion'
import './i18n' // Initialize i18n before rendering
import App from './App'
import { RootErrorBoundary } from './components/RootErrorBoundary'
import './styles/globals.css'

// Report uncaught window-level errors to main-process logger
if (typeof window !== 'undefined') {
  window.addEventListener('error', (event) => {
    try {
      const msg = event.error?.stack || `${event.message} at ${event.filename}:${event.lineno}:${event.colno}`
      window.electronAPI?.logRenderer?.('error', `[window.onerror] ${msg}`)
    } catch {
      /* ignore */
    }
  })

  window.addEventListener('unhandledrejection', (event) => {
    try {
      const reason = event.reason instanceof Error ? event.reason.stack || event.reason.message : String(event.reason)
      window.electronAPI?.logRenderer?.('error', `[window.unhandledrejection] ${reason}`)
    } catch {
      /* ignore */
    }
  })
}

/**
 * `reducedMotion="user"` is an accessibility fix, not a nicety.
 *
 * globals.css already honours `@media (prefers-reduced-motion: reduce)`, but a
 * media query cannot reach the inline styles framer-motion writes straight onto
 * the element — so with the OS setting on, CSS transitions stopped while every
 * `motion.*` component in the app kept animating. MotionConfig is the one place
 * that closes that gap, and it covers all 17 files that use motion at once.
 *
 * Mounted here rather than inside App so it also wraps anything App renders
 * outside its own tree in future (portals, modals mounted at the root).
 */
ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <RootErrorBoundary>
      <MotionConfig reducedMotion="user">
        <App />
      </MotionConfig>
    </RootErrorBoundary>
  </React.StrictMode>
)
