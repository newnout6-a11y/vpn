import React, { useEffect, useRef, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { MoreHorizontal } from 'lucide-react'
import { cn } from './utils'

export interface MacMenuItem {
  id: string
  label: string
  icon?: React.ReactNode
  onSelect: () => void
  disabled?: boolean
  /** Shown as a tooltip — use it to explain WHY an item is disabled. */
  title?: string
  /** Destructive items are tinted and pushed below a separator. */
  destructive?: boolean
  /** Replaces the icon while an action is in flight. */
  busy?: boolean
}

export interface MacMenuProps {
  items: MacMenuItem[]
  /** Accessible name for the trigger. */
  label: string
  className?: string
  align?: 'left' | 'right'
}

/**
 * Overflow menu for row actions.
 *
 * WHY THIS EXISTS. Server rows carried seven controls side by side — five
 * unlabelled ghost icons (proxy, ping, verify country, copy key, save key), the
 * primary Select button and a bare delete icon. All the same size and weight, so
 * there was no way to scan a row or build muscle memory, and the destructive
 * action sat one pixel away from routine ones. Collapsing the secondary actions
 * behind one trigger leaves the row with its primary action plus an overflow, and
 * gives every hidden action a real text label for the first time.
 *
 * Deliberately not the native `popover` attribute plus CSS anchor positioning,
 * even though this project's Chromium supports both: those need the trigger and
 * the popover to be wired by id, and top-layer elements escape the row's
 * click-stopping wrapper, which is what keeps a row click from opening the detail
 * modal. Absolute positioning inside the row keeps that containment.
 */
export const MacMenu: React.FC<MacMenuProps> = ({ items, label, className, align = 'right' }) => {
  const [open, setOpen] = useState(false)
  const containerRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    const onPointerDown = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) setOpen(false)
    }
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false)
    }
    document.addEventListener('mousedown', onPointerDown)
    document.addEventListener('keydown', onKeyDown)
    return () => {
      document.removeEventListener('mousedown', onPointerDown)
      document.removeEventListener('keydown', onKeyDown)
    }
  }, [open])

  const ordered = [...items.filter((i) => !i.destructive), ...items.filter((i) => i.destructive)]
  const firstDestructive = ordered.findIndex((i) => i.destructive)

  return (
    <div className={cn('relative', open && 'z-[120]', className)} ref={containerRef}>
      <button
        type="button"
        aria-label={label}
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={(e) => {
          e.stopPropagation()
          setOpen((v) => !v)
        }}
        className={cn(
          'inline-flex items-center justify-center h-7 w-7 rounded-[var(--radius-sm)]',
          'text-[var(--color-text-secondary)]',
          'transition-colors duration-[var(--transition-fast)]',
          'hover:bg-[color-mix(in_srgb,var(--color-border)_60%,transparent)] hover:text-[var(--color-text)]',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]',
          open && 'bg-[color-mix(in_srgb,var(--color-border)_70%,transparent)] text-[var(--color-text)]'
        )}
      >
        <MoreHorizontal size={16} />
      </button>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, y: -3 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -3 }}
            transition={{ duration: 0.12, ease: 'easeOut' }}
            role="menu"
            onClick={(e) => e.stopPropagation()}
            className={cn(
              'absolute z-[130] mt-1 min-w-[220px] py-1',
              align === 'right' ? 'right-0' : 'left-0',
              'bg-[var(--color-card-elevated)] rounded-[var(--radius-sm)]',
              'border border-[var(--color-border)] shadow-[var(--shadow-modal)]'
            )}
          >
            {ordered.map((item, index) => (
              <React.Fragment key={item.id}>
                {index === firstDestructive && firstDestructive > 0 && (
                  <div className="my-1 h-px bg-[var(--color-border)]" role="separator" />
                )}
                <button
                  type="button"
                  role="menuitem"
                  disabled={item.disabled || item.busy}
                  title={item.title}
                  onClick={(e) => {
                    e.stopPropagation()
                    setOpen(false)
                    item.onSelect()
                  }}
                  className={cn(
                    'w-full flex items-center gap-2.5 px-3 py-1.5 text-left text-sm',
                    'transition-colors duration-[var(--transition-fast)]',
                    'disabled:opacity-45 disabled:cursor-not-allowed',
                    item.destructive
                      ? 'text-[var(--color-danger)] enabled:hover:bg-[color-mix(in_srgb,var(--color-danger)_12%,transparent)]'
                      : 'text-[var(--color-text)] enabled:hover:bg-[color-mix(in_srgb,var(--color-border)_55%,transparent)]'
                  )}
                >
                  <span className="w-4 h-4 flex items-center justify-center flex-shrink-0">
                    {item.icon}
                  </span>
                  <span className="truncate">{item.label}</span>
                </button>
              </React.Fragment>
            ))}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
