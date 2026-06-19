import { describe, expect, it } from 'vitest'
import { detectCountry } from './countryGlyph'

describe('countryGlyph', () => {
  it('detects Hong Kong separately from China', () => {
    expect(detectCountry('Hong Kong')?.iso2).toBe('HK')
    expect(detectCountry('HK')?.iso2).toBe('HK')
  })
})
