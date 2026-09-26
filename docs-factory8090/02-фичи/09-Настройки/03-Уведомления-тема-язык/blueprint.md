# Уведомления, тема и язык

> Источник: https://factory.8090.ai/project/992274e4-1c6b-4d44-8c22-e4c038e690c2/blueprints/ab973a33-8ca9-4b24-9b94-0f66cd7d1926

## Feature Summary

Функция реализует параметры уведомлений, темы и языка для @Уведомления, тема и язык. Она соединяет renderer-настройки с main-процессом Electron через IPC и сохраняет выбор пользователя в `electron-store`. Уведомления поддерживают системную доставку Windows, встроенную доставку и оба способа, тема поддерживает светлый, тёмный и системный режимы, язык ограничен `ru` и `en`.

## Component Blueprint Composition

* **Renderer settings composition** — `LanguageSettings` и `ThemeSettings` в `Settings.tsx` показывают выбор языка и темы. `NotificationSettings` показывает типы уведомлений, способ доставки, звук и состояние Windows.
* **Main notification composition** — `notificationPrefs.ts` хранит настройки типов и способа доставки, а `notifications.ts` применяет глобальное включение уведомлений, фильтры по типам, системное состояние Windows и fallback во встроенное уведомление.
* **Main theme composition** — `themeManager.ts` хранит активную тему, предоставляет встроенные светлую, тёмную и системную темы, применяет системное изменение через `nativeTheme` и отправляет `theme-changed` в renderer.
* **Main locale composition** — `i18n.ts` определяет системную локаль через `app.getLocale()`, сохраняет выбранную локаль и отправляет `i18n:locale-changed`. Renderer использует `i18next` с ресурсами `en.json` и `ru.json`, начальным определением через `navigator.language` и fallback на английский.

## Feature-Specific Components

### Renderer

```component
name: NotificationSettings
container: Electron renderer
responsibilities:
	- Загружает настройки уведомлений через `notifications:get-prefs` и состояние Windows через `notifications:check-os-state`.
	- Сохраняет изменения типов, способа доставки и звука через `notifications:set-prefs` сразу после изменения.
	- Показывает fallback, предупреждение о блокировке Windows и действия сброса или открытия настроек Windows.
```

```component
name: ThemeProvider
container: Electron renderer
responsibilities:
	- Загружает активную тему и список тем через `theme:get-active` и `theme:list`.
	- Преобразует цвета `ThemeConfig` в CSS custom properties и устанавливает `data-theme`.
	- Применяет изменения темы, полученные через `theme-changed`.
```

```component
name: LanguageSettings
container: Electron renderer
responsibilities:
	- Показывает варианты `en` и `ru` в странице настроек.
	- Меняет язык `i18next` и сохраняет выбор через `i18n:set-locale`.
```

### Main process

```component
name: NotificationPreferencesService
container: Electron main process
responsibilities:
	- Хранит `NotificationPreferences` с включёнными типами, способом `system` и включённым звуком по умолчанию.
	- Обслуживает `notifications:get-prefs`, `notifications:set-prefs`, `notifications:check-os-state`, `notifications:reset-os-block` и `notifications:open-windows-settings`.
	- Передаёт провайдер настроек в #NotificationDispatcher.
```

```component
name: NotificationDispatcher
container: Electron main process
responsibilities:
	- Доставляет уведомления через Electron `Notification` или callback встроенного уведомления.
	- Обрабатывает блокировку Windows, неподдерживаемую платформу, ошибку системной доставки и повторяющиеся уведомления.
```

```component
name: ThemeManager
container: Electron main process
responsibilities:
	- Хранит активную тему и пользовательские темы.
	- Предоставляет встроенные темы `builtin-light`, `builtin-dark` и `builtin-system`.
	- Отправляет `theme-changed` при выборе темы и при изменении системной темы Windows.
```

```component
name: LocaleBackend
container: Electron main process
responsibilities:
	- Хранит локаль `en` или `ru` и определяет начальное значение из локали Windows.
	- Обслуживает `i18n:get-locale`, `i18n:set-locale` и `i18n:get-system-locale`.
	- Рассылает `i18n:locale-changed` окнам renderer после изменения локали.
```

# Отношения компонентов

#NotificationSettings зависит от #NotificationPreferencesService через IPC. Сервис возвращает нормализованные `NotificationPreferences`, а renderer отправляет частичные изменения без общего сохранения настроек.

#NotificationPreferencesService передаёт текущие параметры в #NotificationDispatcher. Диспетчер фильтрует событие по типу и выбирает системный, встроенный или двойной способ доставки.

#ThemeProvider получает состояние от #ThemeManager через IPC и событие `theme-changed`. Provider применяет палитру к документу renderer и синхронизирует системный режим с Windows.

#LanguageSettings зависит от #LocaleBackend для сохранения локали. Renderer меняет `i18next`, а событие `i18n:locale-changed` обновляет открытый интерфейс.

## System Contracts

### Key Contracts

* `NotificationPreferences` по умолчанию включает шесть типов уведомлений, использует способ `system` и включает звук.
* Изменения параметров уведомлений и темы применяются сразу, без общего действия «Сохранить».
* При выключенном типе уведомления #NotificationDispatcher отбрасывает последующие события этого типа.
* При выборе `inapp` системная доставка не выполняется. При выборе `both` выполняются обе доставки.
* Если Windows блокирует системные уведомления, событие направляется во встроенный fallback.
* Активной темой по умолчанию является `builtin-system`. При удалении активной пользовательской темы выбирается системная тема.
* Поддерживаются только локали `en` и `ru`. Неизвестная сохранённая локаль заменяется на `en`.
* Точное влияние поля `sound` на отдельные каналы доставки не подтверждено кодом и остаётся открытым вопросом.

### Integration Contracts

* IPC-каналы уведомлений: `notifications:get-prefs`, `notifications:set-prefs`, `notifications:check-os-state`, `notifications:reset-os-block`, `notifications:open-windows-settings`.
* IPC-каналы тем: `theme:list`, `theme:get-active`, `theme:set-active`, `theme:create`, `theme:delete`; событие renderer `theme-changed` переносит `ThemeConfig`.
* IPC-каналы локали: `i18n:get-locale`, `i18n:set-locale`, `i18n:get-system-locale`; событие renderer `i18n:locale-changed` переносит локаль.
* `NotificationDispatcher` использует Electron `Notification`, реестр Windows для определения блокировки и `ms-settings:notifications` для открытия настроек Windows.
* Renderer использует ресурсы `src/renderer/i18n/locales/en.json` и `src/renderer/i18n/locales/ru.json` с fallback `en`.

## Architecture Decision Records

### ADR-001: Отдельное немедленное применение пользовательских параметров

**Context:** Родительская страница настроек использует черновик и явное сохранение для общих параметров, а уведомления и тема имеют отдельный IPC-контур применения.

**Decision:** Сохранять изменения уведомлений и темы сразу после выбора. Не включать их в общий черновик страницы.

**Consequences:** Пользователь видит результат сразу, но на странице действуют разные модели сохранения. Это соответствует наблюдаемому коду и требует явного описания в требованиях.

### ADR-002: Fallback при блокировке системных уведомлений

**Context:** Windows может заблокировать уведомления приложения независимо от настройки приложения.

**Decision:** Проверять состояние Windows перед системной доставкой и направлять сообщение во встроенное уведомление при блокировке, ошибке или неподдерживаемой системной доставке.

**Consequences:** События остаются видимыми в приложении. Пользователь получает предупреждение и может сбросить блокировку или открыть системные настройки Windows.