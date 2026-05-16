/**
 * Widget Engine — renders dashboard widgets based on layout configuration.
 *
 * Features:
 * - Fetches widget layout from main process via IPC on mount
 * - Renders widgets in a grid layout based on configuration
 * - Implements drag-and-drop reordering using @dnd-kit
 * - Only renders widgets where visible=true
 * - Supports compact and expanded sizes
 * - Persists layout changes back to main process via IPC
 * - Has an "edit mode" toggle for rearranging widgets
 */

import React, { useEffect, useState, useCallback } from 'react'
import {
  DndContext,
  closestCenter,
  KeyboardSensor,
  PointerSensor,
  useSensor,
  useSensors,
  type DragEndEvent
} from '@dnd-kit/core'
import {
  arrayMove,
  SortableContext,
  sortableKeyboardCoordinates,
  useSortable,
  rectSortingStrategy
} from '@dnd-kit/sortable'
import { CSS } from '@dnd-kit/utilities'
import { GripVertical, Settings2, Eye, EyeOff, Maximize2, Minimize2 } from 'lucide-react'
import type { WidgetLayout } from '../../shared/ipc-types'
import { StatusWidget } from './StatusWidget'
import { TrafficChartWidget } from './TrafficChartWidget'
import { IpWidget } from './IpWidget'
import { SpeedTestWidget } from './SpeedTestWidget'
import { ScheduleWidget } from './ScheduleWidget'
import { KillSwitchWidget } from './KillSwitchWidget'
import { RotationWidget } from './RotationWidget'

// ─── Widget Type Labels ──────────────────────────────────────────────────────

const WIDGET_LABELS: Record<string, string> = {
  status: 'Статус подключения',
  'traffic-chart': 'График трафика',
  ip: 'Текущий IP',
  'speed-test': 'Тест скорости',
  schedule: 'Расписание',
  'kill-switch': 'Kill-Switch',
  rotation: 'Ротация профилей'
}

const WIDGET_ICONS: Record<string, string> = {
  status: '🔌',
  'traffic-chart': '📊',
  ip: '🌐',
  'speed-test': '⚡',
  schedule: '📅',
  'kill-switch': '🛡️',
  rotation: '🔄'
}

// ─── Widget Component Registry ───────────────────────────────────────────────

const WIDGET_COMPONENTS: Record<
  string,
  React.FC<{ size: 'compact' | 'expanded' }>
> = {
  status: StatusWidget,
  'traffic-chart': TrafficChartWidget,
  ip: IpWidget,
  'speed-test': SpeedTestWidget,
  schedule: ScheduleWidget,
  'kill-switch': KillSwitchWidget,
  rotation: RotationWidget
}

// ─── Sortable Widget Card ────────────────────────────────────────────────────

interface SortableWidgetProps {
  widget: WidgetLayout
  editMode: boolean
  onToggleVisibility: (id: string) => void
  onToggleSize: (id: string) => void
}

const SortableWidget: React.FC<SortableWidgetProps> = ({
  widget,
  editMode,
  onToggleVisibility,
  onToggleSize
}) => {
  const { attributes, listeners, setNodeRef, transform, transition, isDragging } = useSortable({
    id: widget.id,
    disabled: !editMode
  })

  const style: React.CSSProperties = {
    transform: CSS.Transform.toString(transform),
    transition
  }

  const isExpanded = widget.size === 'expanded'

  return (
    <div
      ref={setNodeRef}
      style={style}
      className={[
        'relative rounded-[var(--radius-md)] border border-[var(--color-border)]',
        'bg-[var(--color-card)] shadow-[var(--shadow-card)]',
        'transition-all duration-[var(--transition-normal)]',
        isExpanded ? 'col-span-2 row-span-2' : 'col-span-1',
        isDragging ? 'z-50 shadow-[var(--shadow-modal)] opacity-90 scale-[1.02]' : '',
        editMode ? 'ring-1 ring-[var(--color-accent)]/30' : '',
        !widget.visible && editMode ? 'opacity-50' : ''
      ]
        .filter(Boolean)
        .join(' ')}
    >
      {/* Edit mode controls */}
      {editMode && (
        <div className="absolute top-2 right-2 flex items-center gap-1 z-10">
          <button
            onClick={() => onToggleSize(widget.id)}
            className="p-1 rounded-[var(--radius-sm)] hover:bg-[var(--color-border)] text-[var(--color-text-secondary)] transition-colors duration-[var(--transition-fast)]"
            title={isExpanded ? 'Компактный' : 'Расширенный'}
          >
            {isExpanded ? <Minimize2 size={14} /> : <Maximize2 size={14} />}
          </button>
          <button
            onClick={() => onToggleVisibility(widget.id)}
            className="p-1 rounded-[var(--radius-sm)] hover:bg-[var(--color-border)] text-[var(--color-text-secondary)] transition-colors duration-[var(--transition-fast)]"
            title={widget.visible ? 'Скрыть' : 'Показать'}
          >
            {widget.visible ? <Eye size={14} /> : <EyeOff size={14} />}
          </button>
        </div>
      )}

      {/* Drag handle */}
      {editMode && (
        <button
          className="absolute top-2 left-2 p-1 cursor-grab active:cursor-grabbing text-[var(--color-text-secondary)] hover:text-[var(--color-text)] transition-colors duration-[var(--transition-fast)] z-10"
          {...attributes}
          {...listeners}
          aria-label="Перетащить для изменения порядка"
        >
          <GripVertical size={16} />
        </button>
      )}

      {/* Widget content */}
      <div className={['p-4', editMode ? 'pt-8' : ''].filter(Boolean).join(' ')}>
        <div className="flex items-center gap-2 mb-2">
          <span className="text-lg">{WIDGET_ICONS[widget.type] || '📦'}</span>
          <h3 className="text-sm font-medium text-[var(--color-text)]">
            {WIDGET_LABELS[widget.type] || widget.type}
          </h3>
        </div>
        {WIDGET_COMPONENTS[widget.type] ? (
          React.createElement(WIDGET_COMPONENTS[widget.type], {
            size: widget.size
          })
        ) : (
          <div
            className={[
              'flex items-center justify-center rounded-[var(--radius-sm)]',
              'bg-[var(--color-bg)] border border-[var(--color-border)]',
              'text-[var(--color-text-secondary)] text-xs',
              isExpanded ? 'h-32' : 'h-16'
            ].join(' ')}
          >
            {WIDGET_LABELS[widget.type] || widget.type}
          </div>
        )}
      </div>
    </div>
  )
}

// ─── Widget Engine Component ─────────────────────────────────────────────────

export const WidgetEngine: React.FC = () => {
  const [layout, setLayout] = useState<WidgetLayout[]>([])
  const [editMode, setEditMode] = useState(false)
  const [loading, setLoading] = useState(true)

  // Fetch layout from main process on mount
  useEffect(() => {
    const fetchLayout = async () => {
      try {
        const api = (window as any).electronAPI
        if (api?.getWidgetLayout) {
          const result = await api.getWidgetLayout()
          setLayout(result)
        } else {
          // Fallback: use default layout if API not yet wired
          setLayout([
            { id: 'widget-status', type: 'status', position: 0, size: 'compact', visible: true },
            {
              id: 'widget-traffic-chart',
              type: 'traffic-chart',
              position: 1,
              size: 'compact',
              visible: true
            },
            { id: 'widget-ip', type: 'ip', position: 2, size: 'compact', visible: true },
            {
              id: 'widget-speed-test',
              type: 'speed-test',
              position: 3,
              size: 'compact',
              visible: true
            },
            { id: 'widget-schedule', type: 'schedule', position: 4, size: 'compact', visible: true },
            {
              id: 'widget-kill-switch',
              type: 'kill-switch',
              position: 5,
              size: 'compact',
              visible: true
            },
            { id: 'widget-rotation', type: 'rotation', position: 6, size: 'compact', visible: true }
          ])
        }
      } catch (err) {
        console.error('Failed to fetch widget layout:', err)
      } finally {
        setLoading(false)
      }
    }
    fetchLayout()
  }, [])

  // Persist layout changes to main process
  const persistLayout = useCallback(async (newLayout: WidgetLayout[]) => {
    try {
      const api = (window as any).electronAPI
      if (api?.setWidgetLayout) {
        await api.setWidgetLayout(newLayout)
      }
    } catch (err) {
      console.error('Failed to persist widget layout:', err)
    }
  }, [])

  // DnD sensors
  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 8 } }),
    useSensor(KeyboardSensor, {
      coordinateGetter: sortableKeyboardCoordinates
    })
  )

  // Handle drag end
  const handleDragEnd = useCallback(
    (event: DragEndEvent) => {
      const { active, over } = event
      if (!over || active.id === over.id) return

      setLayout((prev) => {
        const oldIndex = prev.findIndex((w) => w.id === active.id)
        const newIndex = prev.findIndex((w) => w.id === over.id)
        if (oldIndex === -1 || newIndex === -1) return prev

        const reordered = arrayMove(prev, oldIndex, newIndex).map((w, i) => ({
          ...w,
          position: i
        }))
        persistLayout(reordered)
        return reordered
      })
    },
    [persistLayout]
  )

  // Toggle widget visibility
  const handleToggleVisibility = useCallback(
    (id: string) => {
      setLayout((prev) => {
        const updated = prev.map((w) => (w.id === id ? { ...w, visible: !w.visible } : w))
        persistLayout(updated)
        return updated
      })
    },
    [persistLayout]
  )

  // Toggle widget size
  const handleToggleSize = useCallback(
    (id: string) => {
      setLayout((prev) => {
        const updated = prev.map((w) =>
          w.id === id ? { ...w, size: w.size === 'compact' ? 'expanded' : 'compact' } : w
        ) as WidgetLayout[]
        persistLayout(updated)
        return updated
      })
    },
    [persistLayout]
  )

  if (loading) {
    return (
      <div className="flex items-center justify-center h-32 text-[var(--color-text-secondary)] text-sm">
        Загрузка виджетов...
      </div>
    )
  }

  // In normal mode, only show visible widgets
  const visibleWidgets = editMode ? layout : layout.filter((w) => w.visible)

  return (
    <div className="space-y-3">
      {/* Edit mode toggle */}
      <div className="flex items-center justify-end">
        <button
          onClick={() => setEditMode((prev) => !prev)}
          className={[
            'flex items-center gap-1.5 px-3 py-1.5 rounded-[var(--radius-sm)] text-xs font-medium',
            'transition-colors duration-[var(--transition-fast)]',
            editMode
              ? 'bg-[var(--color-accent)] text-white'
              : 'bg-[var(--color-bg)] text-[var(--color-text-secondary)] hover:text-[var(--color-text)] border border-[var(--color-border)]'
          ].join(' ')}
        >
          <Settings2 size={14} />
          {editMode ? 'Готово' : 'Настроить'}
        </button>
      </div>

      {/* Widget grid */}
      <DndContext sensors={sensors} collisionDetection={closestCenter} onDragEnd={handleDragEnd}>
        <SortableContext items={visibleWidgets} strategy={rectSortingStrategy}>
          <div className="grid grid-cols-2 gap-3 auto-rows-auto">
            {visibleWidgets.map((widget) => (
              <SortableWidget
                key={widget.id}
                widget={widget}
                editMode={editMode}
                onToggleVisibility={handleToggleVisibility}
                onToggleSize={handleToggleSize}
              />
            ))}
          </div>
        </SortableContext>
      </DndContext>

      {/* Empty state */}
      {visibleWidgets.length === 0 && !editMode && (
        <div className="flex flex-col items-center justify-center h-32 text-[var(--color-text-secondary)] text-sm">
          <p>Нет видимых виджетов</p>
          <button
            onClick={() => setEditMode(true)}
            className="mt-2 text-[var(--color-accent)] hover:underline text-xs"
          >
            Настроить дашборд
          </button>
        </div>
      )}
    </div>
  )
}
