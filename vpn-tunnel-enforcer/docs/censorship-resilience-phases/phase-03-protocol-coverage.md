# Фаза 3: расширение протоколов и транспортов

Приоритет: высокий.

## Цель

Расширить app-layer так, чтобы импорт подписок и ключей поддерживал больше
того, что уже умеет sing-box.

## Целевое покрытие

Добавить импорт/экспорт или структурную поддержку:

- `naive`;
- `anytls`;
- `shadowtls`;
- `tuic`;
- `wireguard`.

Также расширить parsing транспортов для VLESS/VMess/Trojan там, где текущий
parser уже уже, чем возможности sing-box.

## Почему это важно

Сейчас ядро может больше, чем позволяет UX импорта. Современные подписки часто
приносят протоколы или транспорты, которые приложение отклоняет, теряет или
импортирует без нормальной диагностики.

## Что сделать

- Добавить protocol capability model.
- Расширять parsers консервативно, по одному семейству.
- Сохранять unknown fields там, где это безопасно.
- Валидировать опасные или неподдержанные комбинации.
- Показать capability badges в Servers UI.
- Давать понятные предупреждения по unsupported transport.

## Вероятные файлы

- `src/main/vpnProfiles.ts`
- `src/main/serverPicker.ts`
- `src/main/serverGroups.ts`
- `src/main/tunController.ts`
- `src/renderer/pages/Servers.tsx`
- `src/shared/ipc-types.ts`
- `src/main/vpnProfiles*.test.ts`
- `src/main/serverPicker*.test.ts`

## Чеклист реализации

1. Описать capability matrix для протоколов и транспортов.
2. Сначала добавить parser tests, потом менять parser behavior.
3. Добавлять поддержку по одному protocol family.
4. Проверить server group refresh для новых протоколов.
5. Показать badges и warnings в Servers UI.
6. Проверить, что export сохраняет достаточно данных для round-trip.
7. Сделать config generation детерминированным для тестов.

## Проверка готовности

- Parser tests для каждого добавленного протокола.
- Import tests для mixed subscription lists.
- Generated config tests для каждого supported protocol.
- UI smoke test на Servers page с разными протоколами.

## Что не делать в этой фазе

- Не переписывать весь parser одним большим risky-коммитом.
- Не добавлять mihomo-specific runtime behavior.
- Не молчать, если feature unsupported.

## Реализовано: первый слой совместимости

- Добавлен импорт URI для `naive://`, `anytls://`, `shadowtls://`, `tuic://`.
- Новые схемы извлекаются из обычного текста, base64/mixed subscription payload и deep-link распаковки.
- Расширен список sing-box outbound типов, которые принимаются из JSON/Clash-подписок.
- Добавлен экспорт обратно в URI для Naive, AnyTLS, ShadowTLS и TUIC.
- Для `naive` добавлен sanitizing: `tls.insecure` удаляется, потому что sing-box 1.13 rejects this field on naive outbound.
- Добавлены тесты `vpnProfilesProtocolCoverage.test.ts`.
- Проверено:
  - targeted Vitest на protocol/config/UI-smoke слой: `3 passed / 56 tests`;
  - полный Vitest: `32 passed / 359 tests`;
  - `sing-box check` на минимальных конфигах `naive`, `anytls`, `shadowtls`, `tuic`;
  - `npm run build`.

## Осталось в фазе 3

- WireGuard не включён в этот слой: в sing-box 1.13 старый WireGuard outbound требует отдельной endpoint/route интеграции, это нельзя безопасно добавить простым parser change.
- Более широкие предупреждения для partially-supported профилей за пределами уже добавленных Naive/ECH/Hysteria2 cases.
- Больше тестов на реальные provider subscription samples.
