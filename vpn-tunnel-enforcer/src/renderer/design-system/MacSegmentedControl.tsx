import React from 'react'
import { motion } from 'framer-motion'
import { cn } from './utils'

export interface SegmentOption {
  value: string
  label: string
  disabled?: boolean
}

export interface MacSegmentedControlProps {
  options: SegmentOption[]
  value: string
  onChange: (value: string) => void
  className?: string
}

/**
 * macOS-style segmented control with animated selection indicator.
 * Animates the background pill to the selected segment over 200ms.
 */
export const MacSegmentedControl: React.FC<MacSegmentedControlProps> = ({
  options,
  value,
  onChange,
  className,
}) => {
  const selectedIndex = options.findIndex((o) => o.value === value)

  return (
    <div
      className={cn(
        'relative inline-flex items-center',
        'bg-[var(--color-border)]/50 rounded-[var(--radius-sm)] p-1',
        className
      )}
      role="radiogroup"
    >
      {/* Animated background indicator */}
      {selectedIndex >= 0 && (
        <motion.div
          className="absolute top-1 bottom-1 rounded-[6px] bg-[var(--color-card)] shadow-sm"
          layoutId="segment-indicator"
          style={{
            width: `calc(${100 / options.length}% - 4px)`,
          }}
          animate={{
            left: `calc(${(selectedIndex / options.length) * 100}% + 2px)`,
          }}
          transition={{ type: 'spring', stiffness: 400, damping: 30, duration: 0.2 }}
        />
      )}

      {options.map((option) => (
        <button
          key={option.value}
          role="radio"
          aria-checked={option.value === value}
          disabled={option.disabled}
          onClick={() => !option.disabled && onChange(option.value)}
          className={cn(
            'relative z-10 flex-1 px-4 py-1.5 text-sm font-medium text-center',
            'rounded-[6px] transition-colors duration-[var(--transition-fast)]',
            'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]',
            option.value === value
              ? 'text-[var(--color-text)]'
              : 'text-[var(--color-text-secondary)]',
            option.disabled && 'opacity-50 cursor-not-allowed'
          )}
        >
          {option.label}
        </button>
      ))}
    </div>
  )
}
