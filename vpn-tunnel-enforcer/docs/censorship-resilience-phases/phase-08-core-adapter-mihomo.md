# Фаза 8: CoreAdapter и будущая поддержка mihomo

Приоритет: средне-низкий на текущий момент.

## Цель

Создать чистую границу core engine, чтобы приложение могло позже поддержать
второй runtime, например mihomo, без превращения main process в хрупкий hybrid.

## Почему это важно

У mihomo есть привлекательные возможности: MASQUE, xhttp, provider/rule-provider
модели, chaining concepts. Но добавлять mihomo до engine boundary значит
умножить failure modes и усложнить диагностику.

## Что сделать

- Определить обязанности `CoreAdapter`:
  - generate config;
  - stage runtime;
  - start;
  - stop;
  - status;
  - health;
  - diagnostics;
  - cleanup.
- Постепенно вынести sing-box specifics за эту границу.
- Только после этого прототипировать mihomo sidecar.

## Вероятные файлы

- `src/main/tunController.ts`
- `src/main/systemDiagnostics.ts`
- `src/main/diagnosticsExport.ts`
- `src/main/vpnProfiles.ts`
- `src/main/serverPicker.ts`
- `src/main/urlAvailability.ts`

Новые вероятные файлы:

- `src/main/coreAdapter.ts`
- `src/main/singBoxAdapter.ts`
- `src/main/mihomoAdapter.ts` только после появления границы.

## Чеклист реализации

1. Вынести sing-box config generation за узкий interface.
2. Вынести runtime staging/start/stop lifecycle.
3. Сохранить текущее поведение под `SingBoxAdapter`.
4. Добавить diagnostics hooks в interface.
5. Добавить tests, что старое поведение пережило extraction.
6. Прототипировать mihomo только за adapter boundary.

## Проверка готовности

- Full test suite проходит после extraction.
- В sing-box mode нет user-facing regressions.
- Diagnostics сохраняют runtime-specific detail.
- Prototype не мешает sing-box startup/stop cleanup.

## Что не делать в этой фазе

- Не добавлять mihomo до появления adapter.
- Не переводить все sing-box config shapes в mihomo одним проходом.
- Не прятать engine-specific errors под generic tunnel failure.
