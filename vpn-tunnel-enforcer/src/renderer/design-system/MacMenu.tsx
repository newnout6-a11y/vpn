import React, { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
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

const MENU_WIDTH = 220
const GAP = 4
const VIEWPORT_PAD = 8

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
 * The dropdown is portalled to `document.body` and positioned `fixed` against the
 * trigger's rect. The row it lives in — and the group card and collapse wrapper
 * around it — all clip `overflow: hidden`, so an absolutely-positioned panel gets
 * sheared off ("the menu falls behind the next row"). A portal escapes every
 * ancestor clip and the list's own scroll box. Row-click containment still holds:
 * the panel is not a DOM descendant of the row, so a click on a menu item never
 * bubbles into the row's open-detail handler, and the outside-click watcher
 * treats both the trigger and the portalled panel as "inside".
 */
export const MacMenu: React.FC<MacMenuProps> = ({ items, label, className, align = 'right' }) => {
  const [open, setOpen] = useState(false)
  const [coords, setCoords] = useState<{ top: number; left: number; placement: 'above' | 'below' } | null>(null)
  const triggerRef = useRef<HTMLButtonElement>(null)
  const menuRef = useRef<HTMLDivElement>(null)

  const reposition = useCallback(() => {
    const trigger = triggerRef.current
    if (!trigger) return
    const r = trigger.getBoundingClientRect()
    const menuHeight = menuRef.current?.offsetHeight ?? 0
    const spaceBelow = window.innerHeight - r.bottom - VIEWPORT_PAD
    const placeAbove = menuHeight > 0 && spaceBelow < menuHeight && r.top - VIEWPORT_PAD > spaceBelow
    const left = align === 'right'
      ? Math.max(VIEWPORT_PAD, Math.min(r.right - MENU_WIDTH, window.innerWidth - MENU_WIDTH - VIEWPORT_PAD))
      : Math.max(VIEWPORT_PAD, Math.min(r.left, window.innerWidth - MENU_WIDTH - VIEWPORT_PAD))
    setCoords({
      top: placeAbove ? r.top - GAP : r.bottom + GAP,
      left,
      placement: placeAbove ? 'above' : 'below'
    })
  }, [align])

  useLayoutEffect(() => {
    if (!open) {
      setCoords(null)
      return
    }
    reposition()
    // A second pass once the panel has a measured height, so the flip-above
    // decision (which needs offsetHeight) is correct on the frame it appears.
    const raf = requestAnimationFrame(reposition)
    return () => cancelAnimationFrame(raf)
  }, [open, reposition])

  useEffect(() => {
    if (!open) return
    const onPointerDown = (e: MouseEvent) => {
      const target = e.target as Node
      if (triggerRef.current?.contains(target)) return
      if (menuRef.current?.contains(target)) return
      setOpen(false)
    }
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false)
    }
    const onReflow = () => reposition()
    document.addEventListener('mousedown', onPointerDown)
    document.addEventListener('keydown', onKeyDown)
    window.addEventListener('resize', onReflow)
    // capture:true so the list's own scroll container also triggers a reflow.
    window.addEventListener('scroll', onReflow, true)
    return () => {
      document.removeEventListener('mousedown', onPointerDown)
      document.removeEventListener('keydown', onKeyDown)
      window.removeEventListener('resize', onReflow)
      window.removeEventListener('scroll', onReflow, true)
    }
  }, [open, reposition])

  const ordered = [...items.filter((i) => !i.destructive), ...items.filter((i) => i.destructive)]
  const firstDestructive = ordered.findIndex((i) => i.destructive)

  return (
    <div className={cn('inline-flex', className)}>
      <button
        ref={triggerRef}
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

      {typeof document !== 'undefined' &&
        createPortal(
          <AnimatePresence>
            {open && (
              <motion.div
                ref={menuRef}
                key="macmenu"
                initial={{ opacity: 0, y: coords?.placement === 'above' ? 3 : -3 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: coords?.placement === 'above' ? 3 : -3 }}
                transition={{ duration: 0.12, ease: 'easeOut' }}
                role="menu"
                onClick={(e) => e.stopPropagation()}
                style={{
                  position: 'fixed',
                  top: coords?.top ?? 0,
                  left: coords?.left ?? 0,
                  width: MENU_WIDTH,
                  transform: coords?.placement === 'above' ? 'translateY(-100%)' : undefined,
                  visibility: coords ? 'visible' : 'hidden'
                }}
                className={cn(
                  'z-[130] py-1',
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
          </AnimatePresence>,
          document.body
        )}
    </div>
  )
}
