import React from 'react'
import { cn } from './utils'

export interface MacCardProps extends React.HTMLAttributes<HTMLDivElement> {
  /** Remove padding */
  noPadding?: boolean
  /** Hover effect with elevated shadow */
  hoverable?: boolean
}

export const MacCard = React.forwardRef<HTMLDivElement, MacCardProps>(
  ({ className, noPadding, hoverable, children, ...props }, ref) => {
    return (
      <div
        ref={ref}
        className={cn(
          'bg-[var(--color-card)] rounded-[var(--radius-md)]',
          'border border-[var(--color-border)]',
          'shadow-[var(--shadow-card)]',
          'transition-all duration-[var(--transition-normal)]',
          hoverable && 'hover:shadow-[var(--shadow-card-hover)] hover:-translate-y-px hover:border-[color-mix(in_srgb,var(--color-accent)_25%,var(--color-border))]',
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
