# Фаза 1: обновление sing-box и телеметрия runtime

Статус: реализовано.

Приоритет: самый высокий.

## Что сделано

- Bundled `sing-box.exe` обновлён до `1.13.13`.
- Из того же Windows AMD64 архива добавлен `libcronet.dll`.
- `electron-builder.yml` теперь кладёт `libcronet.dll` в packaged resources.
- Runtime staging копирует `libcronet.dll` рядом с `vpnte-sing-box.exe`.
- System diagnostics показывают:
  - bundled sing-box version;
  - runtime/staged sing-box version, если runtime уже staged;
  - наличие `sing-box.exe`, `wintun.dll`, `libcronet.dll`.
- `resources/README.md` обновлён: `libcronet.dll` теперь указан как обязательный сосед `sing-box.exe`.

## Проверено

- `resources/sing-box.exe version` -> `sing-box version 1.13.13`.
- `npm exec vitest -- --run src/main/tunControllerConfig.test.ts src/main/smartRoute.test.ts src/main/leakDiagnostics.test.ts` -> 3 files / 73 tests passed.
- `npm test` -> 29 files / 340 tests passed.
- `npm run build` -> passed.
- `npm run dist:portable` -> passed.
- `dist/win-unpacked/resources` содержит:
  - `sing-box.exe`;
  - `libcronet.dll`;
  - `wintun.dll`.

## Цель

Обновить bundled sing-box с `1.13.8` до актуальной стабильной версии `1.13.x`
и сделать точную версию runtime видимой в диагностике.

## Почему это первая фаза

Проект уже глубоко завязан на sing-box. Обновление runtime уменьшает отставание
от upstream, приносит исправления и создаёт безопасную базу для следующих фаз:
динамических rule-set, Naive, ECH и Hysteria2.

## Что сделать

- Заменить bundled Windows-бинарь sing-box.
- Проверить, что staging работает и в dev, и в packaged сборке.
- Добавить диагностику версий:
  - версия bundled binary;
  - версия staged runtime binary;
  - путь к runtime/config;
  - ошибка, если `sing-box version` не отработал.
- Добавить canary-тесты на форму генерируемого sing-box config.
- Пересмотреть дефолт `uTLS=chrome`:
  - оставить как совместимый fallback;
  - подготовить путь, чтобы будущие stealth-пресеты могли его переопределять.

## Вероятные файлы

- `src/main/tunController.ts`
- `src/main/systemDiagnostics.ts`
- `src/main/diagnosticsExport.ts`
- `resources/sing-box.exe`
- `electron-builder.yml`
- `src/main/tunControllerConfig.test.ts`
- `src/main/smartRoute.test.ts`

## Чеклист реализации

1. Выбрать стабильную версию sing-box `1.13.x`.
2. Положить новый Windows AMD64 binary в ресурсы приложения.
3. Проверить `getBundledResource('sing-box.exe')` для dev и packaged режимов.
4. Добавить helper для `sing-box.exe version` с timeout.
5. Вывести версию в system diagnostics и diagnostics ZIP.
6. Добавить тесты, что текущие config-структуры не сломались.
7. Убедиться, что staging всё ещё не копирует бинарь зря, если он не изменился.
8. Зафиксировать версию в документации или release notes.

## Проверка готовности

- `npx vitest --run`
- `npm run build`
- Ручной Windows smoke test:
  - старт TUN;
  - стоп TUN;
  - рестарт TUN;
  - экспорт диагностики;
  - в диагностике видна версия sing-box.

## Что не делать в этой фазе

- Не добавлять mihomo runtime.
- Не расширять импорт протоколов.
- Не включать alpha-only возможности sing-box по умолчанию.
