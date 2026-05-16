import React from 'react'
import { cn } from './utils'

export interface MacInputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  /** Label displayed above the input */
  label?: string
  /** Error message displayed below the input */
  error?: string
  /** Helper text displayed below the input */
  hint?: string
  /** Icon element displayed on the left side */
  leftIcon?: React.ReactNode
}

export const MacInput = React.forwardRef<HTMLInputElement, MacInputProps>(
  ({ className, label, error, hint, leftIcon, id, ...props }, ref) => {
    const inputId = id || label?.toLowerCase().replace(/\s+/g, '-')

    return (
      <div className="flex flex-col gap-1.5">
        {label && (
          <label
            htmlFor={inputId}
            className="text-sm font-medium text-[var(--color-text)]"
          >
            {label}
          </label>
        )}
        <div className="relative">
          {leftIcon && (
            <span className="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--color-text-secondary)]">
              {leftIcon}
            </span>
          )}
          <input
            ref={ref}
            id={inputId}
            className={cn(
              'w-full px-3 py-2 text-sm',
              'bg-[var(--color-card)] text-[var(--color-text)]',
              'border rounded-[var(--radius-sm)]',
              'placeholder:text-[var(--color-text-secondary)]',
              'transition-all duration-[var(--transition-fast)]',
              'focus:outline-none focus:ring-2 focus:ring-[color-mix(in_srgb,var(--color-accent)_50%,transparent)] focus:border-[var(--color-accent)]',
              'hover:border-[color-mix(in_srgb,var(--color-text-secondary)_50%,var(--color-border))]',
              'disabled:opacity-50 disabled:cursor-not-allowed',
              error
                ? 'border-[var(--color-danger)] focus:ring-[color-mix(in_srgb,var(--color-danger)_50%,transparent)] focus:border-[var(--color-danger)]'
                : 'border-[var(--color-border)]',
              leftIcon && 'pl-9',
              className
            )}
            aria-invalid={!!error}
            aria-describedby={error ? `${inputId}-error` : hint ? `${inputId}-hint` : undefined}
            {...props}
          />
        </div>
        {error && (
          <p id={`${inputId}-error`} className="text-xs text-[var(--color-danger)]">
            {error}
          </p>
        )}
        {!error && hint && (
          <p id={`${inputId}-hint`} className="text-xs text-[var(--color-text-secondary)]">
            {hint}
          </p>
        )}
      </div>
    )
  }
)

MacInput.displayName = 'MacInput'
