import React from 'react'
import {
  DndContext,
  closestCenter,
  KeyboardSensor,
  PointerSensor,
  useSensor,
  useSensors,
  type DragEndEvent,
} from '@dnd-kit/core'
import {
  arrayMove,
  SortableContext,
  sortableKeyboardCoordinates,
  useSortable,
  verticalListSortingStrategy,
} from '@dnd-kit/sortable'
import { CSS } from '@dnd-kit/utilities'
import { cn } from './utils'
import { GripVertical } from 'lucide-react'

export interface DragItem {
  id: string
  [key: string]: unknown
}

export interface MacDragListProps<T extends DragItem> {
  items: T[]
  onReorder: (items: T[]) => void
  renderItem: (item: T, index: number) => React.ReactNode
  className?: string
}

interface SortableItemProps {
  id: string
  children: React.ReactNode
}

const SortableItem: React.FC<SortableItemProps> = ({ id, children }) => {
  const {
    attributes,
    listeners,
    setNodeRef,
    transform,
    transition,
    isDragging,
  } = useSortable({ id })

  const style = {
    transform: CSS.Transform.toString(transform),
    transition,
  }

  return (
    <div
      ref={setNodeRef}
      style={style}
      className={cn(
        'flex items-center gap-2',
        'bg-[var(--color-card)] rounded-[var(--radius-sm)]',
        'border border-[var(--color-border)]',
        'transition-shadow duration-[var(--transition-fast)]',
        isDragging && 'shadow-[var(--shadow-modal)] z-10 opacity-90'
      )}
    >
      <button
        className={cn(
          'shrink-0 p-2 cursor-grab active:cursor-grabbing',
          'text-[var(--color-text-secondary)] hover:text-[var(--color-text)]',
          'transition-colors duration-[var(--transition-fast)]'
        )}
        {...attributes}
        {...listeners}
        aria-label="Drag to reorder"
      >
        <GripVertical size={16} />
      </button>
      <div className="flex-1 min-w-0">{children}</div>
    </div>
  )
}

/**
 * Drag-and-drop sortable list using @dnd-kit.
 * Each item has a grip handle for reordering.
 */
export function MacDragList<T extends DragItem>({
  items,
  onReorder,
  renderItem,
  className,
}: MacDragListProps<T>) {
  const sensors = useSensors(
    useSensor(PointerSensor),
    useSensor(KeyboardSensor, {
      coordinateGetter: sortableKeyboardCoordinates,
    })
  )

  const handleDragEnd = (event: DragEndEvent) => {
    const { active, over } = event
    if (over && active.id !== over.id) {
      const oldIndex = items.findIndex((item) => item.id === active.id)
      const newIndex = items.findIndex((item) => item.id === over.id)
      onReorder(arrayMove(items, oldIndex, newIndex))
    }
  }

  return (
    <DndContext
      sensors={sensors}
      collisionDetection={closestCenter}
      onDragEnd={handleDragEnd}
    >
      <SortableContext items={items} strategy={verticalListSortingStrategy}>
        <div className={cn('flex flex-col gap-2', className)}>
          {items.map((item, index) => (
            <SortableItem key={item.id} id={item.id}>
              {renderItem(item, index)}
            </SortableItem>
          ))}
        </div>
      </SortableContext>
    </DndContext>
  )
}
