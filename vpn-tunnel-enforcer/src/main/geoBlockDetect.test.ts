/**
 * Tests for the geo-block detector. Covers the two strategies:
 *   - scoreSinglePage: HTTP 451/403, block-shaped final URL, title/body markers
 *     with the short-page gate that prevents long articles from false-positiving.
 *   - compareRenders: language-independent differential (foreign vs local).
 */

import { describe, it, expect } from 'vitest'
import { scoreSinglePage, compareRenders, type PageSignal } from './geoBlockDetect'

function sig(over: Partial<PageSignal> = {}): PageSignal {
  return {
    requestedUrl: 'https://example.com',
    finalUrl: 'https://example.com',
    title: 'Example',
    textSample: 'welcome to example, this is a normal page with content',
    textLength: 54,
    httpStatus: 200,
    ...over
  }
}

describe('scoreSinglePage', () => {
  it('does not flag a normal 200 page', () => {
    expect(scoreSinglePage(sig()).blocked).toBe(false)
  })

  it('flags HTTP 451 (legal block) outright', () => {
    const v = scoreSinglePage(sig({ httpStatus: 451 }))
    expect(v.blocked).toBe(true)
    expect(v.confidence).toBeGreaterThanOrEqual(0.9)
  })

  it('flags a 403 on a short page', () => {
    const v = scoreSinglePage(sig({ httpStatus: 403, textLength: 120 }))
    expect(v.blocked).toBe(false) // 0.5 alone is below threshold...
    const v2 = scoreSinglePage(sig({
      httpStatus: 403,
      textLength: 120,
      textSample: 'access denied in your country'
    }))
    expect(v2.blocked).toBe(true) // ...but 403 + marker on short page crosses it
  })

  it('flags a block-shaped final URL', () => {
    const v = scoreSinglePage(sig({ finalUrl: 'https://site.com/sorry/?error=country_unsupported' }))
    expect(v.blocked).toBe(true)
  })

  it('flags an English marker on a short interstitial', () => {
    const v = scoreSinglePage(sig({
      textSample: 'gemini isn\'t available in your country yet',
      textLength: 41
    }))
    expect(v.blocked).toBe(true)
  })

  it('flags a Russian marker on a short interstitial', () => {
    const v = scoreSinglePage(sig({
      textSample: 'сервис недоступен в вашей стране',
      textLength: 33
    }))
    expect(v.blocked).toBe(true)
  })

  it('does NOT flag a long article that merely mentions the phrase', () => {
    const v = scoreSinglePage(sig({
      textSample: 'in this article we discuss why some apps are not available in your country and how vpns work',
      textLength: 50000
    }))
    expect(v.blocked).toBe(false)
  })

  it('flags a marker in the title', () => {
    const v = scoreSinglePage(sig({ title: 'Not available in your region' }))
    expect(v.blocked).toBe(true)
  })
})

describe('compareRenders', () => {
  const foreignGood = sig({
    finalUrl: 'https://gemini.google.com/app',
    title: 'Gemini',
    textSample: 'a'.repeat(8000),
    textLength: 40000,
    httpStatus: 200
  })

  it('flags local side when foreign is full and local is a tiny notice', () => {
    const local = sig({
      finalUrl: 'https://gemini.google.com/app',
      title: 'Gemini',
      textSample: "gemini isn't available in your country yet",
      textLength: 42,
      httpStatus: 200
    })
    const v = compareRenders(foreignGood, local)
    expect(v.blocked).toBe(true)
  })

  it('flags local side on redirect-to-block-page divergence', () => {
    const local = sig({
      finalUrl: 'https://site.com/unavailable',
      textSample: 'short notice',
      textLength: 200
    })
    const foreign = sig({
      finalUrl: 'https://site.com/home',
      textSample: 'a'.repeat(8000),
      textLength: 9000
    })
    expect(compareRenders(foreign, local).blocked).toBe(true)
  })

  it('does NOT flag when both renders are equivalent full pages', () => {
    const local = sig({ ...foreignGood })
    expect(compareRenders(foreignGood, local).blocked).toBe(false)
  })

  it('bails (not blocked) when the foreign side itself looks blocked', () => {
    const foreignBlocked = sig({ httpStatus: 451 })
    const local = sig({ httpStatus: 451 })
    const v = compareRenders(foreignBlocked, local)
    expect(v.blocked).toBe(false)
    expect(v.confidence).toBe(0)
  })

  it('flags on marker-divergence even if sizes are similar', () => {
    const foreign = sig({ textSample: 'real content here', textLength: 1500, finalUrl: 'https://x.com/a' })
    const local = sig({
      textSample: 'this content is not available in your region',
      textLength: 1400,
      finalUrl: 'https://x.com/a'
    })
    expect(compareRenders(foreign, local).blocked).toBe(true)
  })
})
