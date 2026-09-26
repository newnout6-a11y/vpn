import '@testing-library/jest-dom/vitest'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MacSelect } from './MacSelect'

afterEach(cleanup)

const options = [
  { value: 'auto', label: 'Auto' },
  { value: '1', label: '1 min' },
  { value: '60', label: '1 hr' }
]

describe('<MacSelect />', () => {
  it('renders a compact themed listbox and reports selection/open state', async () => {
    const onChange = vi.fn()
    const onOpenChange = vi.fn()

    render(
      <MacSelect
        ariaLabel="Auto-refresh interval"
        size="sm"
        className="w-[96px]"
        options={options}
        value="auto"
        onChange={onChange}
        onOpenChange={onOpenChange}
      />
    )

    const trigger = screen.getByRole('combobox', { name: 'Auto-refresh interval' })
    expect(trigger).toHaveClass('h-8', 'text-xs')

    fireEvent.click(trigger)
    const listbox = screen.getByRole('listbox', { name: 'Auto-refresh interval' })
    expect(listbox).toHaveClass('bg-[var(--color-card)]')
    expect(listbox).not.toHaveClass('bg-white')

    fireEvent.click(screen.getByRole('option', { name: '1 hr' }))
    expect(onChange).toHaveBeenCalledWith('60')
    expect(onOpenChange).toHaveBeenNthCalledWith(1, true)
    expect(onOpenChange).toHaveBeenLastCalledWith(false)
    await waitFor(() => expect(screen.queryByRole('listbox')).not.toBeInTheDocument())
  })

  it('supports arrow-key navigation and Enter selection', () => {
    const onChange = vi.fn()
    render(
      <MacSelect
        ariaLabel="Auto-refresh interval"
        options={options}
        value="auto"
        onChange={onChange}
      />
    )

    const trigger = screen.getByRole('combobox', { name: 'Auto-refresh interval' })
    fireEvent.keyDown(trigger, { key: 'ArrowDown' })
    expect(trigger).toHaveAttribute('aria-expanded', 'true')

    fireEvent.keyDown(trigger, { key: 'ArrowDown' })
    expect(trigger.getAttribute('aria-activedescendant')).toContain('option-1')

    fireEvent.keyDown(trigger, { key: 'Enter' })
    expect(onChange).toHaveBeenCalledWith('1')
    expect(trigger).toHaveAttribute('aria-expanded', 'false')
  })
})
