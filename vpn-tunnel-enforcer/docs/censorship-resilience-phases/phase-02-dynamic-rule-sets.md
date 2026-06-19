# Фаза 2: динамические rule-set каналы

Приоритет: самый высокий.

## Цель

Заменить модель “только статические Smart-RU `.srs` из ресурсов” на управляемую
модель источников:

- bundled fallback `.srs`;
- app-managed кэш в `userData`;
- опциональное удалённое обновление;
- метаданные и диагностика.

Ключевое правило: туннель не должен падать из-за неудачного скачивания rule-set.

## Почему это важно

Цели блокировок и региональные маршруты меняются быстро. Статические
`geoip-ru` и `geosite-category-gov-ru` помогают, но приложению нужен безопасный
способ обновлять routing intelligence без выпуска новой версии.

## Что сделать

- Добавить managed-хранилище rule-set под `app.getPath('userData')`.
- Хранить метаданные:
  - имя файла;
  - source URL;
  - last checked;
  - last successful update;
  - размер;
  - hash;
  - last error.
- Добавить настройки:
  - bundled/managed mode;
  - auto-update on/off;
  - update interval;
  - direct/detoured download.
- На старте TUN брать managed cache только если он полный и валидный.
- Если managed cache отсутствует, битый или неполный, fallback на bundled.
- Добавить статус и ручное обновление в Settings UI.
- Включить состояние rule-set в system diagnostics и diagnostics ZIP.

## Вероятные файлы

- `src/main/smartRoute.ts`
- `src/main/settings.ts`
- `src/main/tunController.ts`
- `src/main/systemDiagnostics.ts`
- `src/main/index.ts`
- `src/preload/index.ts`
- `src/renderer/store.ts`
- `src/renderer/pages/Settings.tsx`

Новый вероятный файл:

- `src/main/ruleSetManager.ts`

## Чеклист реализации

1. Добавить каталог rule-set в `smartRoute.ts`.
2. Добавить defaults и normalization в `settings.ts`.
3. Реализовать manager для cache state, refresh, validation и source selection.
4. Скачивать атомарно: сначала временный файл, потом rename после проверки.
5. Считать SHA-256 и size после успешного скачивания.
6. Добавить IPC:
   - получить rule-set state;
   - обновить rule-set сейчас.
7. В `prepareRuntime()` выбирать managed cache только когда все файлы валидны.
8. Сохранить bundled fallback и безопасный старт туннеля при любых сбоях.
9. Добавить блок настроек и статуса в UI.
10. Добавить diagnostic items для source, freshness, completeness и last error.

## Проверка готовности

- Unit-тесты source selection:
  - managed полный -> используется managed;
  - managed неполный -> используется bundled;
  - download failure -> TUN всё равно стартует через bundled.
- Config-тест: `route.rule_set` указывает на локально staged files.
- Ручной UI test:
  - переключить mode;
  - нажать refresh;
  - увидеть last update/error;
  - перезапустить TUN и убедиться, что config локальный.

## Что не делать в этой фазе

- Не возвращать sing-box startup к remote rule-sets.
- Не делать доступность GitHub/network зависимостью старта туннеля.
- Не использовать широкий `category-ru`, который может увести YouTube/Google direct.

## Реализовано

- Добавлен `src/main/ruleSetManager.ts`: managed-кэш в `userData`, метаданные, SHA-256, size, last error, last refresh и атомарная загрузка через временный файл.
- Добавлены настройки `smartRuRuleSetMode`, `smartRuRuleSetAutoUpdate`, `smartRuRuleSetUseProxy`, `smartRuRuleSetUpdateIntervalHours`.
- `prepareRuntime()` выбирает managed rule-set только если кэш полный; иначе использует bundled fallback.
- Добавлены IPC/preload методы для получения статуса и ручного refresh.
- Settings UI получил блок управления Smart-RU списками, статус кэша и кнопку обновления.
- System Diagnostics показывает источник, полноту кэша, свежесть и ошибки managed rule-set.
- Проверено: targeted Vitest `3 passed / 62 tests`, полный `npm test` `30 passed / 343 tests`, `npm run build`.
