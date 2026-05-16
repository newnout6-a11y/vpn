import React from 'react'
import { motion } from 'framer-motion'
import { cn } from './utils'

export interface MacProgressProps {
  /** Progress value from 0 to 100 */
  value: number
  /** Show indeterminate animation (ignores value) */
  indeterminate?: boolean
  /** Height of the progress bar */
  size?: 'sm' | 'md' | 'lg'
  /** Color variant */
  variant?: 'accent' | 'success' | 'warning' | 'danger'
  /** Show percentage label */
  showLabel?: boolean
  className?: string
}

const sizeClasses = {
  sm: 'h-1.5',
  md: 'h-2.5',
  lg: 'h-4',
}

const variantColors = {
  accent: 'bg-[var(--color-accent)]',
  success: 'bg-[var(--color-success)]',
  warning: 'bg-[var(--color-warning)]',
  danger: 'bg-[var(--color-danger)]',
}

/**
 * macOS-style progress bar with smooth animated fill.
 */
export const MacProgress: React.FC<MacProgressProps> = ({
  value,
  indeterminate,
  size = 'md',
  variant = 'accent',
  showLabel,
  className,
}) => {
  const clampedValue = Math.max(0, Math.min(100, value))

  return (
    <div className={cn('flex items-center gap-2', className)}>
      <div
        className={cn(
          'flex-1 rounded-full overflow-hidden',
          'bg-[var(--color-border)]',
          sizeClasses[size]
        )}
        role="progressbar"
        aria-valuenow={indeterminate ? undefined : clampedValue}
        aria-valuemin={0}
        aria-valuemax={100}
      >
        {indeterminate ? (
          <motion.div
            className={cn('h-full w-1/3 rounded-full', variantColors[variant])}
            animate={{ x: ['-100%', '400%'] }}
            transition={{ repeat: Infinity, duration: 1.5, ease: 'easeInOut' }}
          />
        ) : (
          <motion.div
            className={cn('h-full rounded-full', variantColors[variant])}
            initial={{ width: 0 }}
            animate={{ width: `${clampedValue}%` }}
            transition={{ duration: 0.3, ease: 'easeOut' }}
          />
        )}
      </div>
      {showLabel && !indeterminate && (
        <span className="text-xs font-medium text-[var(--color-text-secondary)] min-w-[3ch] text-right">
          {Math.round(clampedValue)}%
        </span>
      )}
    </div>
  )
}
