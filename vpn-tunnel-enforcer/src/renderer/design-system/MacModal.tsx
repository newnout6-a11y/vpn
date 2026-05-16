import React, { useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { cn } from './utils'
import { X } from 'lucide-react'

export interface MacModalProps {
  open: boolean
  onClose: () => void
  title?: string
  description?: string
  children: React.ReactNode
  className?: string
  /** Width of the modal content */
  size?: 'sm' | 'md' | 'lg'
  /** Show close button in header */
  showClose?: boolean
  /** Footer content (e.g., action buttons) */
  footer?: React.ReactNode
}

const sizeClasses = {
  sm: 'max-w-sm',
  md: 'max-w-md',
  lg: 'max-w-lg',
}

/**
 * macOS-style modal dialog with backdrop blur and smooth enter/exit animations.
 */
export const MacModal: React.FC<MacModalProps> = ({
  open,
  onClose,
  title,
  description,
  children,
  className,
  size = 'md',
  showClose = true,
  footer,
}) => {
  // Close on Escape key
  useEffect(() => {
    if (!open) return
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', handler)
    return () => document.removeEventListener('keydown', handler)
  }, [open, onClose])

  return (
    <AnimatePresence>
      {open && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          {/* Backdrop */}
          <motion.div
            className="absolute inset-0 bg-black/40 backdrop-blur-sm"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.15 }}
            onClick={onClose}
          />

          {/* Modal content */}
          <motion.div
            className={cn(
              'relative w-full mx-4 flex flex-col max-h-[90vh]',
              sizeClasses[size],
              'bg-[var(--color-card)] rounded-[var(--radius-lg)]',
              'shadow-[var(--shadow-modal)]',
              'border border-[var(--color-border)]',
              className
            )}
            initial={{ opacity: 0, scale: 0.96, y: 12 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.96, y: 12 }}
            transition={{ type: 'spring', stiffness: 380, damping: 32, mass: 0.6 }}
            role="dialog"
            aria-modal="true"
            aria-labelledby={title ? 'mac-modal-title' : undefined}
          >
            {/* Header (fixed) */}
            {(title || showClose) && (
              <div className="flex items-center justify-between px-5 pt-5 pb-2 flex-shrink-0">
                <div>
                  {title && (
                    <h2
                      id="mac-modal-title"
                      className="text-base font-semibold text-[var(--color-text)]"
                    >
                      {title}
                    </h2>
                  )}
                  {description && (
                    <p className="text-sm text-[var(--color-text-secondary)] mt-0.5">
                      {description}
                    </p>
                  )}
                </div>
                {showClose && (
                  <button
                    onClick={onClose}
                    className={cn(
                      'p-1.5 rounded-full',
                      'text-[var(--color-text-secondary)] hover:text-[var(--color-text)]',
                      'hover:bg-[var(--color-border)]/50',
                      'transition-colors duration-[var(--transition-fast)]'
                    )}
                    aria-label="Close"
                  >
                    <X size={16} />
                  </button>
                )}
              </div>
            )}

            {/* Body (scrolls when content overflows) */}
            <div className="px-5 py-3 overflow-y-auto flex-1 min-h-0">{children}</div>

            {/* Footer (fixed) */}
            {footer && (
              <div className="flex items-center justify-end gap-2 px-5 pb-5 pt-2 flex-shrink-0 border-t border-[var(--color-border)]/50">
                {footer}
              </div>
            )}
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  )
}
