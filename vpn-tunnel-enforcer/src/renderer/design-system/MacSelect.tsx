import React, { useState, useRef, useEffect, useId } from 'react'
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
  ariaLabel?: string
  size?: 'sm' | 'md'
  onOpenChange?: (open: boolean) => void
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
  ariaLabel,
  size = 'md',
  onOpenChange,
  className,
}) => {
  const [open, setOpen] = useState(false)
  const [activeIndex, setActiveIndex] = useState(0)
  const containerRef = useRef<HTMLDivElement>(null)
  const selectId = useId()
  const listboxId = `${selectId}-listbox`
  const labelId = `${selectId}-label`

  const selectedOption = options.find((o) => o.value === value)
  const enabledIndexes = options.flatMap((option, index) => option.disabled ? [] : [index])

  const setDropdownOpen = (nextOpen: boolean) => {
    if (nextOpen) {
      const selectedIndex = options.findIndex((option) => option.value === value && !option.disabled)
      setActiveIndex(selectedIndex >= 0 ? selectedIndex : enabledIndexes[0] ?? 0)
    }
    setOpen(nextOpen)
    onOpenChange?.(nextOpen)
  }

  const moveActiveOption = (direction: -1 | 1) => {
    if (enabledIndexes.length === 0) return
    const currentPosition = enabledIndexes.indexOf(activeIndex)
    const nextPosition = currentPosition < 0
      ? 0
      : (currentPosition + direction + enabledIndexes.length) % enabledIndexes.length
    setActiveIndex(enabledIndexes[nextPosition])
  }

  const selectActiveOption = () => {
    const option = options[activeIndex]
    if (!option || option.disabled) return
    onChange(option.value)
    setDropdownOpen(false)
  }

  // Close on outside click
  useEffect(() => {
    if (!open) return
    const handler = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setDropdownOpen(false)
      }
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [open, onOpenChange])

  // Close on Escape
  useEffect(() => {
    if (!open) return
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setDropdownOpen(false)
    }
    document.addEventListener('keydown', handler)
    return () => document.removeEventListener('keydown', handler)
  }, [open, onOpenChange])

  return (
    <div className={cn('relative flex flex-col gap-1.5', open && 'z-[120]', className)} ref={containerRef}>
      {label && (
        <label id={labelId} htmlFor={`${selectId}-trigger`} className="text-sm font-medium text-[var(--color-text)]">{label}</label>
      )}
      <div className="relative">
        <button
          id={`${selectId}-trigger`}
          type="button"
          onClick={() => !disabled && setDropdownOpen(!open)}
          onKeyDown={(event) => {
            if (disabled) return
            if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
              event.preventDefault()
              if (!open) {
                setDropdownOpen(true)
              } else {
                moveActiveOption(event.key === 'ArrowDown' ? 1 : -1)
              }
            } else if (event.key === 'Home' || event.key === 'End') {
              event.preventDefault()
              if (!open) setDropdownOpen(true)
              const index = event.key === 'Home'
                ? enabledIndexes[0]
                : enabledIndexes[enabledIndexes.length - 1]
              if (index !== undefined) setActiveIndex(index)
            } else if (open && (event.key === 'Enter' || event.key === ' ')) {
              event.preventDefault()
              selectActiveOption()
            } else if (open && event.key === 'Escape') {
              event.preventDefault()
              setDropdownOpen(false)
            }
          }}
          disabled={disabled}
          className={cn(
            'w-full flex items-center justify-between',
            size === 'sm' ? 'h-8 px-2 text-xs' : 'px-3 py-2 text-sm',
            'bg-[var(--color-card)] rounded-[var(--radius-sm)]',
            'border transition-all duration-[var(--transition-fast)]',
            'focus:outline-none focus:ring-2 focus:ring-[var(--color-accent)] focus:border-transparent',
            'disabled:opacity-50 disabled:cursor-not-allowed',
            error
              ? 'border-[var(--color-danger)]'
              : 'border-[var(--color-border)]',
            open && 'ring-2 ring-[var(--color-accent)] border-transparent'
          )}
          role="combobox"
          aria-label={!label ? ariaLabel : undefined}
          aria-labelledby={label ? labelId : undefined}
          aria-expanded={open}
          aria-haspopup="listbox"
          aria-controls={listboxId}
          aria-activedescendant={open ? `${listboxId}-option-${activeIndex}` : undefined}
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
            size={size === 'sm' ? 14 : 16}
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
              id={listboxId}
              aria-label={ariaLabel || label}
            >
              {options.map((option, optionIndex) => (
                <li
                  key={option.value}
                  id={`${listboxId}-option-${optionIndex}`}
                  role="option"
                  aria-selected={option.value === value}
                  className={cn(
                    size === 'sm' ? 'px-2 py-1 text-xs' : 'px-3 py-1.5 text-sm',
                    'cursor-pointer',
                    'transition-colors duration-[var(--transition-fast)]',
                    option.value === value
                      ? 'bg-[var(--color-accent)]/10 text-[var(--color-accent)]'
                      : 'text-[var(--color-text)] hover:bg-[var(--color-border)]/50',
                    activeIndex === optionIndex && 'bg-[var(--color-border)]/50',
                    option.disabled && 'opacity-50 cursor-not-allowed'
                  )}
                  onMouseEnter={() => !option.disabled && setActiveIndex(optionIndex)}
                  onClick={() => {
                    if (!option.disabled) {
                      onChange(option.value)
                      setDropdownOpen(false)
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
