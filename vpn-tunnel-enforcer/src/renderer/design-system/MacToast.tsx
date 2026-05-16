import React from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { cn } from './utils'
import { CheckCircle, AlertCircle, Info, X } from 'lucide-react'

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

const variantConfig: Record<ToastVariant, { icon: React.ReactNode; color: string }> = {
  success: {
    icon: <CheckCircle size={18} />,
    color: 'text-[var(--color-success)]',
  },
  error: {
    icon: <AlertCircle size={18} />,
    color: 'text-[var(--color-danger)]',
  },
  warning: {
    icon: <AlertCircle size={18} />,
    color: 'text-[var(--color-warning)]',
  },
  info: {
    icon: <Info size={18} />,
    color: 'text-[var(--color-accent)]',
  },
}

/**
 * Single toast notification component.
 */
const MacToastItem: React.FC<MacToastProps> = ({ toast, onDismiss }) => {
  const config = variantConfig[toast.variant]

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: -10, scale: 0.95 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      exit={{ opacity: 0, y: -10, scale: 0.95 }}
      transition={{ duration: 0.2, ease: 'easeOut' }}
      className={cn(
        'flex items-start gap-3 w-[360px] p-4',
        'bg-[var(--color-card)] rounded-[var(--radius-md)]',
        'shadow-[var(--shadow-toast)]',
        'border border-[var(--color-border)]'
      )}
    >
      <span className={cn('shrink-0 mt-0.5', config.color)}>{config.icon}</span>
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium text-[var(--color-text)]">{toast.title}</p>
        {toast.description && (
          <p className="text-xs text-[var(--color-text-secondary)] mt-0.5">
            {toast.description}
          </p>
        )}
      </div>
      <button
        onClick={() => onDismiss(toast.id)}
        className={cn(
          'shrink-0 p-1 rounded-full',
          'text-[var(--color-text-secondary)] hover:text-[var(--color-text)]',
          'hover:bg-[var(--color-border)]/50',
          'transition-colors duration-[var(--transition-fast)]'
        )}
        aria-label="Dismiss"
      >
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
  'top-right': 'top-4 right-4',
  'top-center': 'top-4 left-1/2 -translate-x-1/2',
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
  return (
    <div className={cn('fixed z-[100] flex flex-col gap-2', positionClasses[position])}>
      <AnimatePresence mode="popLayout">
        {toasts.map((toast) => (
          <MacToastItem key={toast.id} toast={toast} onDismiss={onDismiss} />
        ))}
      </AnimatePresence>
    </div>
  )
}
