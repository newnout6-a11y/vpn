import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'
import en from './locales/en.json'
import ru from './locales/ru.json'

// Detect initial language from browser/system
const detectedLang = navigator.language?.startsWith('ru') ? 'ru' : 'en'

i18n.use(initReactI18next).init({
  resources: {
    en: { translation: en },
    ru: { translation: ru }
  },
  lng: detectedLang,
  fallbackLng: 'en',
  interpolation: {
    escapeValue: false
  },
  react: {
    useSuspense: false
  }
})

// After init, try to get persisted locale from main process
setTimeout(async () => {
  try {
    const api = (window as any).electronAPI
    if (api?.i18nGetLocale) {
      const savedLocale = await api.i18nGetLocale()
      if (savedLocale && savedLocale !== i18n.language) {
        i18n.changeLanguage(savedLocale)
      }
    }
  } catch {}
}, 100)

export default i18n
