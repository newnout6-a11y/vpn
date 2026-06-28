import React from 'react'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from './utils'

const buttonVariants = cva(
  [
    'inline-flex items-center justify-center font-medium select-none',
    'transition-all duration-[var(--transition-fast)]',
    'active:scale-[0.96] active:transition-[transform] active:duration-100',
    'hover:scale-[1.02] hover:transition-[transform] hover:duration-150',
    'disabled:opacity-50 disabled:pointer-events-none disabled:hover:scale-100',
    'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--color-bg)]',
  ].join(' '),
  {
    variants: {
      variant: {
        primary: [
          'bg-[var(--color-accent)] text-white',
          'hover:bg-[var(--color-accent-hover)]',
          'shadow-[var(--shadow-button)] hover:shadow-[var(--shadow-button-hover)]',
          'hover:shadow-[0_0_20px_rgb(var(--rgb-accent)/0.3)]',
        ].join(' '),
        secondary: [
          'glass text-[var(--color-text)]',
          'hover:bg-[color-mix(in_srgb,var(--rgb-accent)_8%,var(--rgb-card))]',
          'shadow-[var(--shadow-button)] hover:shadow-[var(--shadow-button-hover)]',
        ].join(' '),
        ghost: [
          'text-[var(--color-text)]',
          'hover:bg-[color-mix(in_srgb,var(--color-border)_60%,transparent)]',
          'hover:scale-[1.01]',
        ].join(' '),
        danger: [
          'bg-[var(--color-danger)] text-white',
          'hover:opacity-90',
          'shadow-[var(--shadow-button)] hover:shadow-[var(--shadow-button-hover)]',
          'hover:shadow-[0_0_20px_rgb(var(--rgb-danger)/0.3)]',
        ].join(' '),
      },
      size: {
        sm: 'text-xs px-3 py-1.5 rounded-[var(--radius-sm)]',
        md: 'text-sm px-4 py-2 rounded-[var(--radius-sm)]',
        lg: 'text-base px-5 py-2.5 rounded-[var(--radius-md)]',
      },
    },
    defaultVariants: {
      variant: 'primary',
      size: 'md',
    },
  }
)

export interface MacButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  loading?: boolean
}

export const MacButton = React.forwardRef<HTMLButtonElement, MacButtonProps>(
  ({ className, variant, size, loading, disabled, children, ...props }, ref) => {
    return (
      <button
        ref={ref}
        className={cn(buttonVariants({ variant, size }), className)}
        disabled={disabled || loading}
        {...props}
      >
        {loading && (
          <svg
            className="animate-spin -ml-1 mr-2 h-4 w-4"
            xmlns="http://www.w3.org/2000/svg"
            fill="none"
            viewBox="0 0 24 24"
          >
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
          </svg>
        )}
        {children}
      </button>
    )
  }
)

MacButton.displayName = 'MacButton'
