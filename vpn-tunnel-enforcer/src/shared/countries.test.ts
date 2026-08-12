import { describe, expect, it } from 'vitest'
import { countryFlagEmoji, inferCountryMetadata } from './countries'

describe('country metadata inference', () => {
  it('reads provider flag emoji', () => {
    expect(inferCountryMetadata('🇳🇱 Netherlands')?.iso2).toBe('NL')
  })

  it('reads concatenated provider profile names', () => {
    expect(inferCountryMetadata('latviavless4')?.label).toBe('Latvia')
    expect(inferCountryMetadata('netherlandsvless1')?.iso2).toBe('NL')
  })

  it('generates a regional-indicator flag for legacy text call sites', () => {
    expect(countryFlagEmoji('SE')).toBe('🇸🇪')
  })
})
