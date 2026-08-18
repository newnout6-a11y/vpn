# Маршрут ревью

## Если изменение касается туннеля или сети

1. Начать с публичного IPC-метода в `src/preload/index.ts`.
2. Найти handler в `src/main/index.ts` или соответствующем feature-модуле.
3. Проследить вызов в `connectionPlanner.ts` и `tunController.ts`.
4. Проверить связанные изменения `systemNetwork.ts`, `firewallKillSwitch.ts` и `physicalAdapterLockdown.ts`.
5. Отдельно проверить stop path, crash recovery, stale process и rollback.
6. Запустить тесты домена и `npm.cmd run typecheck`.

## Если изменение касается профилей и серверов

1. Проверить parsing/normalization в `vpnProfiles.ts`.
2. Проверить persistence и миграции в `serverPicker.ts`/`serverGroups.ts`.
3. Проверить health/probe paths и отсутствие реального туннеля в offline-тестах.
4. Проверить preload contract и страницу `src/renderer/pages/Servers.tsx`.
5. Убедиться, что секреты не попадают в логи, экспорт и ошибки.

## Если изменение касается диагностики

1. Определить источник истины для статуса: процесс, manifest или artifact.
2. Проверить stale-state reconciliation после crash/reinstall/stop.
3. Проверить redaction и ZIP export.
4. Проверить, что UI различает `running`, `warming up`, `stopped` и `warning`.
5. Добавить regression-тест на противоречивый статус, а не только happy path.

## Если изменение касается renderer

1. Страница должна вызывать только `window.electronAPI` и Zustand selectors.
2. Loading/error/empty states должны быть явными.
3. Долгие операции не должны блокировать навигацию и должны корректно переживать unmount.
4. Проверить i18n-ключи в `src/renderer/i18n/locales/ru.json` и `en.json`.
5. Для крупного экрана сначала выделять data hooks и row/card components, затем менять визуальную часть.

## Definition of done для структурной правки

- Новая ответственность имеет один очевидный владелец.
- IPC contract синхронизирован между shared/preload/main/renderer.
- Есть focused regression tests на изменённую границу.
- `npm.cmd run typecheck` проходит.
- `npm.cmd test -- --reporter=dot` проходит или в итогах явно указана причина пропуска.
- Документация карты модулей обновлена, если появился новый домен или runtime-слой.

