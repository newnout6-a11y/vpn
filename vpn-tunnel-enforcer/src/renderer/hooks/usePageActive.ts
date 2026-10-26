import { createContext, useContext, useSyncExternalStore } from 'react'

const PageActiveContext = createContext(true)
export const PageActivityProvider = PageActiveContext.Provider
const listeners = new Set<() => void>()
const notifyVisibility = () => { for (const listener of listeners) listener() }
const subscribeVisibility = (listener: () => void) => {
  if (listeners.size === 0) document.addEventListener('visibilitychange', notifyVisibility)
  listeners.add(listener)
  return () => {
    listeners.delete(listener)
    if (listeners.size === 0) document.removeEventListener('visibilitychange', notifyVisibility)
  }
}
const windowVisible = () => !document.hidden

// Visited forms remain mounted; only their background readers pause.
export function usePageActive(): boolean {
  const pageActive = useContext(PageActiveContext)
  const visible = useSyncExternalStore(subscribeVisibility, windowVisible, () => true)
  return pageActive && visible
}
