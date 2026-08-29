import React from 'react'
import ReactDOM from 'react-dom/client'
import { MotionConfig } from 'framer-motion'
import './i18n' // Initialize i18n before rendering
import App from './App'
import './styles/globals.css'

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
    <MotionConfig reducedMotion="user">
      <App />
    </MotionConfig>
  </React.StrictMode>
)
