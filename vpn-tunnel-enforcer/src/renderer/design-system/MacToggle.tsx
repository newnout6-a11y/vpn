import React from 'react'
import { motion } from 'framer-motion'
import { cn } from './utils'

export interface MacToggleProps {
  checked: boolean
  onChange: (checked: boolean) => void
  disabled?: boolean
  loading?: boolean
  className?: string
  /** Label text displayed next to the toggle */
  label?: string
}

/**
 * Large iOS-style toggle switch (≥80px wide, ≥40px tall).
 * Used as the main VPN on/off control on the dashboard.
 */
export const MacToggle: React.FC<MacToggleProps> = ({
  checked,
  onChange,
  disabled,
  loading,
  className,
  label,
}) => {
  const isDisabled = disabled || loading

  return (
    <label
      className={cn(
        'inline-flex items-center gap-3 cursor-pointer select-none',
        isDisabled && 'opacity-50 cursor-not-allowed',
        className
      )}
    >
      <button
        role="switch"
        aria-checked={checked}
        aria-label={label}
        disabled={isDisabled}
        onClick={() => !isDisabled && onChange(!checked)}
        className={cn(
          'relative w-[80px] h-[40px] rounded-full',
          'transition-colors duration-[var(--transition-normal)]',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-2',
          checked ? 'bg-[var(--color-success)]' : 'bg-[var(--color-border)]'
        )}
      >
        <motion.div
          className={cn(
            'absolute top-[3px] w-[34px] h-[34px] rounded-full bg-white shadow-md',
            'flex items-center justify-center'
          )}
          animate={{ left: checked ? '43px' : '3px' }}
          transition={{ type: 'spring', stiffness: 500, damping: 30 }}
        >
          {loading && (
            <svg
              className="animate-spin h-4 w-4 text-[var(--color-text-secondary)]"
              xmlns="http://www.w3.org/2000/svg"
              fill="none"
              viewBox="0 0 24 24"
            >
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
            </svg>
          )}
        </motion.div>
      </button>
      {label && (
        <span className="text-sm font-medium text-[var(--color-text)]">{label}</span>
      )}
    </label>
  )
}
