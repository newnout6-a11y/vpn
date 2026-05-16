// macOS Design System - Component Library
// All primitives follow macOS design language:
// - Rounded corners (8px-16px)
// - Soft shadows (blur 8-24px, opacity ≤0.15)
// - Inter font family
// - Smooth transitions (150-300ms ease-out)
// - CSS custom properties for theming

export { MacButton, type MacButtonProps } from './MacButton'
export { MacCard, type MacCardProps } from './MacCard'
export { MacToggle, type MacToggleProps } from './MacToggle'
export {
  MacSegmentedControl,
  type MacSegmentedControlProps,
  type SegmentOption,
} from './MacSegmentedControl'
export {
  MacSidebar,
  type MacSidebarProps,
  type SidebarItem,
  type ConnectionStatus,
} from './MacSidebar'
export { MacModal, type MacModalProps } from './MacModal'
export {
  MacToast,
  type MacToastContainerProps,
  type MacToastProps,
  type ToastData,
  type ToastVariant,
} from './MacToast'
export { MacInput, type MacInputProps } from './MacInput'
export { MacSelect, type MacSelectProps, type SelectOption } from './MacSelect'
export { MacProgress, type MacProgressProps } from './MacProgress'
export { MacDragList, type MacDragListProps, type DragItem } from './MacDragList'
export { MacSwitch, type MacSwitchProps } from './MacSwitch'
export { MacBadge, type MacBadgeProps, type BadgeVariant } from './MacBadge'

// Utility
export { cn } from './utils'
