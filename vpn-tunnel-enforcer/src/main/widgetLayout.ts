/**
 * Widget Layout — main process module for dashboard widget layout persistence.
 *
 * Responsibilities:
 * - Stores widget layout configuration in electron-store
 * - Provides default layout with all widgets visible in compact size
 * - Registers IPC handlers: widgets:get-layout, widgets:set-layout
 */

import { ipcMain } from 'electron'
import Store from 'electron-store'
import type { WidgetLayout } from '../shared/ipc-types'

// ─── Default Layout ──────────────────────────────────────────────────────────

const DEFAULT_LAYOUT: WidgetLayout[] = [
  { id: 'widget-status', type: 'status', position: 0, size: 'compact', visible: true },
  { id: 'widget-traffic-chart', type: 'traffic-chart', position: 1, size: 'compact', visible: true },
  { id: 'widget-ip', type: 'ip', position: 2, size: 'compact', visible: true },
  { id: 'widget-speed-test', type: 'speed-test', position: 3, size: 'compact', visible: true },
  { id: 'widget-schedule', type: 'schedule', position: 4, size: 'compact', visible: true },
  { id: 'widget-kill-switch', type: 'kill-switch', position: 5, size: 'compact', visible: true },
  { id: 'widget-rotation', type: 'rotation', position: 6, size: 'compact', visible: true }
]

// ─── Store ───────────────────────────────────────────────────────────────────

interface WidgetLayoutStoreSchema {
  widgetLayout: WidgetLayout[]
}

const widgetStore = new Store<WidgetLayoutStoreSchema>({
  name: 'widget-layout',
  defaults: {
    widgetLayout: DEFAULT_LAYOUT
  }
})

// ─── Helpers ─────────────────────────────────────────────────────────────────

function validateLayout(layout: WidgetLayout[]): WidgetLayout[] {
  if (!Array.isArray(layout) || layout.length === 0) {
    return DEFAULT_LAYOUT
  }

  return layout
    .filter(
      (item) =>
        item &&
        typeof item.id === 'string' &&
        typeof item.type === 'string' &&
        typeof item.position === 'number' &&
        (item.size === 'compact' || item.size === 'expanded') &&
        typeof item.visible === 'boolean'
    )
    .sort((a, b) => a.position - b.position)
}

// ─── Public API ──────────────────────────────────────────────────────────────

export const widgetLayoutManager = {
  getLayout(): WidgetLayout[] {
    const stored = widgetStore.get('widgetLayout')
    return validateLayout(stored)
  },

  setLayout(layout: WidgetLayout[]): void {
    const validated = validateLayout(layout)
    widgetStore.set('widgetLayout', validated)
  },

  resetToDefault(): void {
    widgetStore.set('widgetLayout', DEFAULT_LAYOUT)
  }
}

// ─── IPC Registration ────────────────────────────────────────────────────────

export function registerWidgetLayoutIpcHandlers(): void {
  ipcMain.handle('widgets:get-layout', () => {
    return widgetLayoutManager.getLayout()
  })

  ipcMain.handle('widgets:set-layout', (_event, layout: WidgetLayout[]) => {
    widgetLayoutManager.setLayout(layout)
    return widgetLayoutManager.getLayout()
  })
}
