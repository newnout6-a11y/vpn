import React from 'react'
import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { RootErrorBoundary } from './RootErrorBoundary'

function ProblemChild({ shouldThrow }: { shouldThrow: boolean }) {
  if (shouldThrow) {
    throw new Error('Test crash in child component')
  }
  return <div>App Content Intact</div>
}

describe('RootErrorBoundary', () => {
  const originalElectronAPI = (window as any).electronAPI

  beforeEach(() => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    ;(window as any).electronAPI = {
      logRenderer: vi.fn()
    }
  })

  it('renders children normally when no error occurs', () => {
    render(
      <RootErrorBoundary>
        <ProblemChild shouldThrow={false} />
      </RootErrorBoundary>
    )

    expect(screen.getByText('App Content Intact')).toBeDefined()
  })

  it('catches render errors, logs to electronAPI, and displays error UI', () => {
    render(
      <RootErrorBoundary>
        <ProblemChild shouldThrow={true} />
      </RootErrorBoundary>
    )

    expect(screen.queryByText('App Content Intact')).toBeNull()
    expect(screen.getByText('Сбой интерфейса приложения')).toBeDefined()
    expect(screen.getByText('Перезагрузить интерфейс')).toBeDefined()
    expect(screen.getByText('Попробовать снова')).toBeDefined()
    expect(screen.getByText('Копировать детали')).toBeDefined()

    expect((window as any).electronAPI.logRenderer).toHaveBeenCalledWith(
      'error',
      expect.stringContaining('Test crash in child component')
    )
  })

  it('shows technical details containing the error message', () => {
    render(
      <RootErrorBoundary>
        <ProblemChild shouldThrow={true} />
      </RootErrorBoundary>
    )

    expect(screen.getByText('Технические подробности')).toBeDefined()
    expect(screen.getByText(/Test crash in child component/)).toBeDefined()
  })
})
