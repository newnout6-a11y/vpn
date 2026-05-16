import React from 'react'
import { cn } from './utils'

export interface SidebarItem {
  id: string
  label: string
  icon: React.ReactNode
}

export type ConnectionStatus = 'connected' | 'disconnected' | 'connecting'

export interface MacSidebarProps {
  items: SidebarItem[]
  activeId: string
  onSelect: (id: string) => void
  connectionStatus?: ConnectionStatus
  statusLabels?: Partial<Record<ConnectionStatus, string>>
  className?: string
  header?: React.ReactNode
  footer?: React.ReactNode
}

const statusColors: Record<ConnectionStatus, string> = {
  connected: 'bg-[var(--color-success)]',
  disconnected: 'bg-[var(--color-text-secondary)]',
  connecting: 'bg-[var(--color-warning)]',
}

/**
 * macOS-style navigation sidebar with status indicator.
 * Items have hover effects (150ms transition), active item has rounded background highlight.
 */
export const MacSidebar: React.FC<MacSidebarProps> = ({
  items,
  activeId,
  onSelect,
  connectionStatus = 'disconnected',
  statusLabels,
  className,
  header,
  footer,
}) => {
  const defaultLabels: Record<ConnectionStatus, string> = {
    connected: 'Подключено',
    disconnected: 'Отключено',
    connecting: 'Подключение...',
  }
  const labels = { ...defaultLabels, ...statusLabels }
  return (
    <aside
      className={cn(
        'flex flex-col w-[220px] h-full',
        'bg-[var(--color-sidebar)] border-r border-[var(--color-border)]',
        'py-4 px-3',
        className
      )}
    >
      {/* Header area (e.g., app logo) */}
      {header && <div className="mb-4 px-2">{header}</div>}

      {/* Connection status indicator */}
      <div className="flex items-center gap-2 px-2 mb-4">
        <span className="relative inline-flex w-2.5 h-2.5">
          <span
            className={cn(
              'absolute inset-0 rounded-full',
              statusColors[connectionStatus],
              connectionStatus === 'connected' && 'pulse-ring text-[var(--color-success)]',
              connectionStatus === 'connecting' && 'animate-pulse'
            )}
          />
          <span
            className={cn(
              'relative w-2.5 h-2.5 rounded-full',
              statusColors[connectionStatus]
            )}
          />
        </span>
        <span className="text-xs text-[var(--color-text-secondary)] font-medium">
          {labels[connectionStatus]}
        </span>
      </div>

      {/* Navigation items */}
      <nav className="flex-1 space-y-1">
        {items.map((item) => {
          const isActive = item.id === activeId
          return (
            <button
              key={item.id}
              onClick={() => onSelect(item.id)}
              aria-current={isActive ? 'page' : undefined}
              className={cn(
                'group relative w-full flex items-center gap-3 px-3 py-2',
                'rounded-[var(--radius-sm)] text-left',
                'transition-all duration-[var(--transition-fast)]',
                'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]',
                isActive
                  ? 'bg-[color-mix(in_srgb,var(--color-accent)_12%,transparent)] text-[var(--color-accent)]'
                  : 'text-[var(--color-text)] hover:bg-[color-mix(in_srgb,var(--color-border)_50%,transparent)]'
              )}
            >
              {/* Active indicator: a thin accent rail on the left edge of the row.
                  Hidden on inactive items but present in DOM so width stays stable. */}
              <span
                aria-hidden="true"
                className={cn(
                  'absolute left-0 top-1.5 bottom-1.5 w-[3px] rounded-r-full',
                  'transition-opacity duration-[var(--transition-fast)]',
                  isActive ? 'bg-[var(--color-accent)] opacity-100' : 'opacity-0'
                )}
              />
              <span
                className={cn(
                  'w-5 h-5 flex items-center justify-center shrink-0',
                  'transition-transform duration-[var(--transition-fast)]',
                  'group-hover:scale-110'
                )}
              >
                {item.icon}
              </span>
              <span className="text-[13px] font-medium truncate">{item.label}</span>
            </button>
          )
        })}
      </nav>

      {/* Footer area */}
      {footer && <div className="mt-auto pt-4 px-2">{footer}</div>}
    </aside>
  )
}
