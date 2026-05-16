import React from 'react'
import { cn } from './utils'

export type BadgeVariant = 'success' | 'warning' | 'danger' | 'info' | 'neutral'

export interface MacBadgeProps {
  variant?: BadgeVariant
  /** Show as a small dot only (no text) */
  dot?: boolean
  /** Badge text content */
  children?: React.ReactNode
  /** Pulse animation for active states */
  pulse?: boolean
  className?: string
}

const variantClasses: Record<BadgeVariant, string> = {
  success: 'bg-[var(--color-success)]/15 text-[var(--color-success)] border-[var(--color-success)]/30',
  warning: 'bg-[var(--color-warning)]/15 text-[var(--color-warning)] border-[var(--color-warning)]/30',
  danger: 'bg-[var(--color-danger)]/15 text-[var(--color-danger)] border-[var(--color-danger)]/30',
  info: 'bg-[var(--color-accent)]/15 text-[var(--color-accent)] border-[var(--color-accent)]/30',
  neutral: 'bg-[var(--color-border)] text-[var(--color-text-secondary)] border-[var(--color-border)]',
}

const dotColors: Record<BadgeVariant, string> = {
  success: 'bg-[var(--color-success)]',
  warning: 'bg-[var(--color-warning)]',
  danger: 'bg-[var(--color-danger)]',
  info: 'bg-[var(--color-accent)]',
  neutral: 'bg-[var(--color-text-secondary)]',
}

/**
 * Status badge/dot component.
 * Can be used as a colored dot indicator or as a labeled badge.
 */
export const MacBadge: React.FC<MacBadgeProps> = ({
  variant = 'neutral',
  dot,
  children,
  pulse,
  className,
}) => {
  if (dot) {
    return (
      <span className={cn('relative inline-flex w-2.5 h-2.5', className)} aria-hidden="true">
        {pulse && (
          <span
            className={cn(
              'absolute inset-0 rounded-full pulse-ring',
              dotColors[variant].replace('bg-', 'text-')
            )}
          />
        )}
        <span
          className={cn(
            'relative inline-block w-2.5 h-2.5 rounded-full',
            dotColors[variant]
          )}
        />
      </span>
    )
  }

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 px-2 py-0.5',
        'text-xs font-medium rounded-full border',
        variantClasses[variant],
        className
      )}
    >
      {pulse && (
        <span className="relative inline-flex w-1.5 h-1.5">
          <span
            className={cn(
              'absolute inset-0 rounded-full pulse-ring',
              dotColors[variant].replace('bg-', 'text-')
            )}
          />
          <span
            className={cn('relative w-1.5 h-1.5 rounded-full', dotColors[variant])}
          />
        </span>
      )}
      {children}
    </span>
  )
}
