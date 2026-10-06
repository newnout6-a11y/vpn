import { describe, expect, it } from 'vitest'
import ru from './i18n/locales/ru.json'
import en from './i18n/locales/en.json'
import { tunnelStartedMessageKey } from './tunnelMessages'

describe('tunnel start feedback (AT-06-003 / AT-09-011)', () => {
  it.each([false, true])('has matching Russian/English feedback for Smart RU=%s', smartRu => {
    const key = tunnelStartedMessageKey(smartRu).split('.')[1] as keyof typeof ru.tunnel
    expect(ru.tunnel[key]).toContain('Проверяется')
    expect(en.tunnel[key]).toContain('being checked')
    if (smartRu) {
      expect(ru.tunnel[key]).toContain('напрямую')
      expect(en.tunnel[key]).toContain('directly')
    } else {
      expect(ru.tunnel[key]).not.toContain('Smart RU')
      expect(en.tunnel[key]).not.toContain('Smart RU')
    }
    expect(ru.tunnel[key]).not.toContain('весь трафик')
  })
})
