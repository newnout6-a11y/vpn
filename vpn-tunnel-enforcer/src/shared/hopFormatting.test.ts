import { describe, expect, it } from 'vitest'
import { sanitizeHopLine, formatInfrastructureError } from './hopFormatting'

describe('hopFormatting', () => {
  it('replaces Russian OEM replacement characters with standard ms', () => {
    const rawWithDiamonds = '1  <1 \uFFFD\uFFFD  <1 \uFFFD\uFFFD  <1 \uFFFD\uFFFD  13.143.252.2'
    expect(sanitizeHopLine(rawWithDiamonds)).toBe('1 <1 ms <1 ms <1 ms 13.143.252.2')
  })

  it('normalizes Russian localized "мс" to "ms"', () => {
    const rawRussian = '  1    <1 мс    <1 мс    <1 мс  13.143.252.2'
    expect(sanitizeHopLine(rawRussian)).toBe('1 <1 ms <1 ms <1 ms 13.143.252.2')

    const numberedRussian = '  2    14 мс    18 мс    12 мс  10.0.0.1'
    expect(sanitizeHopLine(numberedRussian)).toBe('2 14 ms 18 ms 12 ms 10.0.0.1')
  })

  it('preserves and tidies standard English ms outputs', () => {
    const standardEnglish = '  1    <1 ms    <1 ms    <1 ms  13.143.252.2'
    expect(sanitizeHopLine(standardEnglish)).toBe('1 <1 ms <1 ms <1 ms 13.143.252.2')
  })

  it('normalizes Russian timeout lines to canonical English', () => {
    const russianTimeout = '  1  * * * Превышен интервал ожидания для запроса.'
    expect(sanitizeHopLine(russianTimeout)).toBe('1 * * * Request timed out.')

    const englishTimeout = '  2  * * * Request timed out.'
    expect(sanitizeHopLine(englishTimeout)).toBe('2 * * * Request timed out.')
  })

  it('formats raw 429 status code and rate limit errors cleanly', () => {
    expect(formatInfrastructureError('Request failed with status code 429')).toBe(
      'Превышен лимит запросов к сервису геолокации (429). Повторите попытку позже.'
    )
    expect(formatInfrastructureError('RateLimited')).toBe(
      'Превышен лимит запросов к сервису геолокации (429). Повторите попытку позже.'
    )
    expect(formatInfrastructureError('getaddrinfo ENOTFOUND ipapi.co')).toBe(
      'Не удалось подключиться к сервису геолокации.'
    )
    expect(formatInfrastructureError('User aborted probe')).toBe('Проверка отменена')
  })
})
