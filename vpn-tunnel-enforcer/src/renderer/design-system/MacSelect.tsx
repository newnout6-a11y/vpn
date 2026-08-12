import React, { useState, useRef, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { cn } from './utils'
import { ChevronDown } from 'lucide-react'

export interface SelectOption {
  value: string
  label: string
  disabled?: boolean
  /** Optional compact visual state shown before the label. */
  indicator?: 'success' | 'danger' | 'muted' | 'accent'
  /** Accessible description for the visual indicator. */
  indicatorLabel?: string
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

function indicatorClass(indicator: NonNullable<SelectOption['indicator']>): string {
  if (indicator === 'success') return 'bg-[var(--color-success)] shadow-[0_0_0_3px_color-mix(in_srgb,var(--color-success)_16%,transparent)]'
  if (indicator === 'danger') return 'bg-[var(--color-danger)] shadow-[0_0_0_3px_color-mix(in_srgb,var(--color-danger)_14%,transparent)]'
  if (indicator === 'accent') return 'bg-[var(--color-accent)] shadow-[0_0_0_3px_color-mix(in_srgb,var(--color-accent)_14%,transparent)]'
  return 'bg-[var(--color-text-muted)]'
}

function OptionLabel({ option }: { option: SelectOption }) {
  return (
    <span className="flex min-w-0 items-center gap-2">
      {option.indicator && (
        <span
          className={cn('h-2 w-2 flex-shrink-0 rounded-full', indicatorClass(option.indicator))}
          role="img"
          aria-label={option.indicatorLabel}
          title={option.indicatorLabel}
        />
      )}
      <span className="truncate">{option.label}</span>
    </span>
  )
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
    <div className={cn('relative flex flex-col gap-1.5', open && 'z-[120]', className)} ref={containerRef}>
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
              'min-w-0',
              selectedOption
                ? 'text-[var(--color-text)]'
                : 'text-[var(--color-text-secondary)]'
            )}
          >
            {selectedOption ? <OptionLabel option={selectedOption} /> : placeholder}
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
              initial={{ opacity: 0, y: -3 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -3 }}
              transition={{ duration: 0.12, ease: 'easeOut' }}
              className={cn(
                'absolute z-[130] w-full mt-1 py-1',
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
                  <OptionLabel option={option} />
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
