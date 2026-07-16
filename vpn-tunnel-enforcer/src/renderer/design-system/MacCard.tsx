import React from 'react'
import { cn } from './utils'

export interface MacCardProps extends React.HTMLAttributes<HTMLDivElement> {
  /** Remove padding */
  noPadding?: boolean
  /** Hover effect with elevated shadow */
  hoverable?: boolean
  /** Use a solid surface for dense lists where backdrop blur is expensive. */
  flat?: boolean
}

export const MacCard = React.forwardRef<HTMLDivElement, MacCardProps>(
  ({ className, noPadding, hoverable, flat, children, ...props }, ref) => {
    return (
      <div
        ref={ref}
        className={cn(
          flat
            ? 'bg-[var(--color-card)] border border-[var(--color-border)] rounded-[var(--radius-md)]'
            : 'glass rounded-[var(--radius-md)]',
          'transition-all duration-[var(--transition-normal)]',
          hoverable && 'hover:shadow-[var(--shadow-card-hover)] hover:-translate-y-px hover:border-[color-mix(in_srgb,var(--color-accent)_30%,var(--color-border))]',
          !noPadding && 'p-5',
          className
        )}
        {...props}
      >
        {children}
      </div>
    )
  }
)

MacCard.displayName = 'MacCard'
