import React, { useEffect, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { cn } from './utils'
import { X } from 'lucide-react'
import { MASCOT_EVENT, type MascotEvent } from '../swiss/useMascot'
import '../styles/swiss.css'
import { usePageActive } from '../hooks/usePageActive'

export type ToastVariant = 'success' | 'error' | 'warning' | 'info'

export interface ToastData {
  id: string
  variant: ToastVariant
  title: string
  description?: string
}

export interface MacToastProps {
  toast: ToastData
  onDismiss: (id: string) => void
}

// The mascot reacts to fresh toasts; info toasts are too frequent to comment on
const MASCOT_REACTION: Partial<Record<ToastVariant, MascotEvent>> = {
  error: 'notice-error',
  warning: 'notice-warn',
  success: 'notice-ok',
}

/**
 * Single toast notification component.
 */
/**
 * Single toast notification in the «Пломба» style: a square paper card with a
 * state bar (orange = error/warning, ink = success, grey = info).
 */
const MacToastItem: React.FC<MacToastProps> = ({ toast, onDismiss }) => {
  return (
    <motion.div
      layout
      initial={{ opacity: 0, x: 24 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 24 }}
      transition={{ duration: 0.2, ease: 'easeOut' }}
      className={cn('swiss-toast', 'is-' + toast.variant)}
    >
      <div className="flex-1 min-w-0">
        <p className="swiss-toast-title">{toast.title}</p>
        {toast.description && <p className="swiss-toast-desc">{toast.description}</p>}
      </div>
      <button onClick={() => onDismiss(toast.id)} className="swiss-toast-close" aria-label="Dismiss">
        <X size={14} />
      </button>
    </motion.div>
  )
}

export interface MacToastContainerProps {
  toasts: ToastData[]
  onDismiss: (id: string) => void
  position?: 'top-right' | 'top-center' | 'bottom-right'
}

const positionClasses = {
  // top-[52px]: below the 36px title bar and the native caption buttons
  'top-right': 'top-[52px] right-4',
  'top-center': 'top-[52px] left-1/2 -translate-x-1/2',
  'bottom-right': 'bottom-4 right-4',
}

/**
 * Toast container that renders a stack of toast notifications.
 */
export const MacToast: React.FC<MacToastContainerProps> = ({
  toasts,
  onDismiss,
  position = 'top-right',
}) => {
  // Toasts already showing on mount are old news; only new ones get a reaction
  const seen = useRef<Set<string>>(new Set(toasts.map(t => t.id)))
  // A hidden page's toasts stay silent (and must not use up the mascot's throttle)
  const pageActive = usePageActive()
  useEffect(() => {
    for (const toast of toasts) {
      if (seen.current.has(toast.id)) continue
      seen.current.add(toast.id)
      const reaction = MASCOT_REACTION[toast.variant]
      if (reaction && pageActive) window.dispatchEvent(new CustomEvent(MASCOT_EVENT, { detail: reaction }))
    }
    const live = new Set(toasts.map(t => t.id))
    for (const id of seen.current) if (!live.has(id)) seen.current.delete(id)
  }, [toasts, pageActive])

  return (
    <div className={cn('c-swiss fixed z-[100] flex flex-col gap-2', positionClasses[position])}>
      <AnimatePresence mode="popLayout">
        {toasts.map((toast) => (
          <MacToastItem key={toast.id} toast={toast} onDismiss={onDismiss} />
        ))}
      </AnimatePresence>
    </div>
  )
}
