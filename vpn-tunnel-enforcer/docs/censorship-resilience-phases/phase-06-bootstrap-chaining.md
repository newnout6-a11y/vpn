# Фаза 6: bootstrap chaining и detour для загрузок

Приоритет: средне-высокий.

## Статус на 14.06.2026

Сделан рабочий слой фазы:

- Добавлен общий `src/main/bootstrapRoute.ts`.
- Введён режим `bootstrapRouteMode`:
  - `auto` — сначала direct, потом локальные proxy-кандидаты;
  - `direct` — только напрямую;
  - `localProxy` — только через локальный proxy.
- Режим используется для:
  - refresh подписок;
  - server group refresh;
  - Smart-RU rule-set downloads;
  - inspect/import subscription paths.
- Geo checks серверов (`serverPicker` geolocation) теперь используют тот же bootstrap route и fallback order.
- Health probes групп/ключей теперь используют тот же route policy:
  - direct;
  - SOCKS5 local proxy;
  - HTTP CONNECT через local proxy;
  - при активном TUN direct-probe идёт через sing-box `direct-out`, как и раньше.
- Smart-RU downloads теперь пробуют fallback по каждому файлу, а не падают сразу из-за мёртвого proxy.
- Для Smart-RU metadata сохраняется `lastRoute`, то есть видно, каким маршрутом файл реально скачался.
- В advanced settings добавлен компактный выбор маршрута служебных загрузок.
- System diagnostics показывает `bootstrapRouteMode`, а Smart-RU diagnostics показывает `lastRoute` по файлам.
- Добавлены unit-тесты `bootstrapRoute.test.ts`.
- Проверено:
  - targeted Vitest: `4 passed / 20 tests`;
  - полный Vitest: `33 passed / 363 tests`;
  - `npm run build`.

Что осталось за пределами безопасного слоя:

- `selected VPN profile` как cold-start bootstrap route не включён скрыто: для этого нужен отдельный временный sing-box runtime/detour. Если TUN уже запущен выбранным профилем, `direct` control-plane запросы всё равно идут через текущий системный маршрут/TUN.
- External bootstrap profile оставлен как отдельный future workflow.

## Цель

Отделить control-plane загрузки от user traffic и дать приложению управляемую
политику bootstrap route для:

- refresh подписок;
- rule-set downloads;
- geo checks;
- health probes.

## Почему это важно

В условиях блокировок часто ломается не сам data tunnel, а возможность
получить конфиг, обновить правила или подтянуть новый node. Приложению нужен
отдельный bootstrap route policy, концептуально похожий на provider detours и
`dialer-proxy`.

## Что сделать

- Ввести bootstrap route abstraction.
- Поддержать route choices:
  - direct;
  - current local proxy;
  - selected VPN profile;
  - future external bootstrap profile.
- Применить policy к:
  - subscription fetch;
  - server group refresh;
  - rule-set refresh;
  - geo checks;
  - health probes.
- Добавить UI и diagnostics для текущего bootstrap route.

## Вероятные файлы

- `src/main/serverGroups.ts`
- `src/main/vpnProfiles.ts`
- `src/main/externalProxy.ts`
- `src/main/ruleSetManager.ts`
- `src/main/serverProbe.ts`
- `src/main/urlAvailability.ts`
- `src/main/systemDiagnostics.ts`
- `src/renderer/pages/Settings.tsx`
- `src/renderer/pages/Servers.tsx`

Новый вероятный файл:

- `src/main/bootstrapRoute.ts`

## Чеклист реализации

1. Описать `BootstrapRoutePolicy`.
2. Реализовать fetch helpers, которые принимают route policy.
3. Начать с rule-set и subscription refresh paths.
4. Добавить timeout и fallback behavior по каждому route.
5. Добавить diagnostics: выбранный route, fallback, last error.
6. Не смешивать user traffic route и control-plane route.

## Проверка готовности

- Unit tests для policy selection.
- Tests для fallback order.
- Server group refresh работает без running tunnel.
- Rule-set refresh различает direct/proxy failure.

## Что не делать в этой фазе

- Не проксировать все network calls приложения через один скрытый global setting.
- Не рестартовать user tunnel молча из-за изменения bootstrap route.
- Не добавлять mihomo runtime только ради `dialer-proxy`.
