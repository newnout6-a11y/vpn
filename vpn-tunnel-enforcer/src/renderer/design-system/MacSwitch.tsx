import React from 'react'
import { motion } from 'framer-motion'
import { cn } from './utils'

export interface MacSwitchProps {
  checked: boolean
  onChange: (checked: boolean) => void
  disabled?: boolean
  label?: string
  description?: string
  className?: string
}

/**
 * Small on/off switch (standard size, unlike the large MacToggle).
 * Used for settings toggles throughout the app.
 */
export const MacSwitch: React.FC<MacSwitchProps> = ({
  checked,
  onChange,
  disabled,
  label,
  description,
  className,
}) => {
  return (
    <label
      className={cn(
        'inline-flex items-center gap-3 cursor-pointer select-none',
        disabled && 'opacity-50 cursor-not-allowed',
        className
      )}
    >
      <button
        role="switch"
        aria-checked={checked}
        aria-label={label}
        disabled={disabled}
        onClick={() => !disabled && onChange(!checked)}
        className={cn(
          'group relative w-[44px] h-[24px] rounded-full shrink-0',
          'transition-colors duration-[var(--transition-normal)]',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--color-bg)]',
          'shadow-[inset_0_1px_2px_rgba(0,0,0,0.12)]',
          checked ? 'bg-[var(--color-accent)]' : 'bg-[var(--color-border)]'
        )}
      >
        <motion.div
          className={cn(
            'absolute top-[2px] w-[20px] h-[20px] rounded-full bg-white',
            'shadow-[0_2px_4px_rgba(0,0,0,0.15),0_0_0_0.5px_rgba(0,0,0,0.04)]',
            'group-active:w-[24px]'
          )}
          animate={{ left: checked ? '22px' : '2px' }}
          transition={{ type: 'spring', stiffness: 500, damping: 30 }}
        />
      </button>
      {(label || description) && (
        <div className="flex flex-col">
          {label && (
            <span className="text-sm font-medium text-[var(--color-text)]">{label}</span>
          )}
          {description && (
            <span className="text-xs text-[var(--color-text-secondary)]">{description}</span>
          )}
        </div>
      )}
    </label>
  )
}
