import React, { useState, useRef, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { cn } from './utils'
import { ChevronDown } from 'lucide-react'

export interface SelectOption {
  value: string
  label: string
  disabled?: boolean
}

export interface MacSelectProps {
  options: SelectOption[]
  value: string
  onChange: (value: string) => void
  placeholder?: string
  label?: string
  error?: string
  disabled?: boolean
  className?: string
}

/**
 * macOS-style dropdown select with animated open/close.
 */
export const MacSelect: React.FC<MacSelectProps> = ({
  options,
  value,
  onChange,
  placeholder = 'Выберите...',
  label,
  error,
  disabled,
  className,
}) => {
  const [open, setOpen] = useState(false)
  const containerRef = useRef<HTMLDivElement>(null)

  const selectedOption = options.find((o) => o.value === value)

  // Close on outside click
  useEffect(() => {
    if (!open) return
    const handler = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setOpen(false)
      }
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [open])

  // Close on Escape
  useEffect(() => {
    if (!open) return
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false)
    }
    document.addEventListener('keydown', handler)
    return () => document.removeEventListener('keydown', handler)
  }, [open])

  return (
    <div className={cn('flex flex-col gap-1.5', className)} ref={containerRef}>
      {label && (
        <label className="text-sm font-medium text-[var(--color-text)]">{label}</label>
      )}
      <div className="relative">
        <button
          type="button"
          onClick={() => !disabled && setOpen(!open)}
          disabled={disabled}
          className={cn(
            'w-full flex items-center justify-between px-3 py-2 text-sm',
            'bg-[var(--color-card)] rounded-[var(--radius-sm)]',
            'border transition-all duration-[var(--transition-fast)]',
            'focus:outline-none focus:ring-2 focus:ring-[var(--color-accent)] focus:border-transparent',
            'disabled:opacity-50 disabled:cursor-not-allowed',
            error
              ? 'border-[var(--color-danger)]'
              : 'border-[var(--color-border)]',
            open && 'ring-2 ring-[var(--color-accent)] border-transparent'
          )}
          aria-expanded={open}
          aria-haspopup="listbox"
        >
          <span
            className={cn(
              selectedOption
                ? 'text-[var(--color-text)]'
                : 'text-[var(--color-text-secondary)]'
            )}
          >
            {selectedOption?.label || placeholder}
          </span>
          <ChevronDown
            size={16}
            className={cn(
              'text-[var(--color-text-secondary)] transition-transform duration-[var(--transition-fast)]',
              open && 'rotate-180'
            )}
          />
        </button>

        <AnimatePresence>
          {open && (
            <motion.ul
              initial={{ opacity: 0, y: -4 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -4 }}
              transition={{ duration: 0.15 }}
              className={cn(
                'absolute z-50 w-full mt-1 py-1',
                'bg-[var(--color-card)] rounded-[var(--radius-sm)]',
                'border border-[var(--color-border)]',
                'shadow-[var(--shadow-modal)]',
                'max-h-[200px] overflow-y-auto'
              )}
              role="listbox"
            >
              {options.map((option) => (
                <li
                  key={option.value}
                  role="option"
                  aria-selected={option.value === value}
                  className={cn(
                    'px-3 py-1.5 text-sm cursor-pointer',
                    'transition-colors duration-[var(--transition-fast)]',
                    option.value === value
                      ? 'bg-[var(--color-accent)]/10 text-[var(--color-accent)]'
                      : 'text-[var(--color-text)] hover:bg-[var(--color-border)]/50',
                    option.disabled && 'opacity-50 cursor-not-allowed'
                  )}
                  onClick={() => {
                    if (!option.disabled) {
                      onChange(option.value)
                      setOpen(false)
                    }
                  }}
                >
                  {option.label}
                </li>
              ))}
            </motion.ul>
          )}
        </AnimatePresence>
      </div>
      {error && (
        <p className="text-xs text-[var(--color-danger)]">{error}</p>
      )}
    </div>
  )
}
