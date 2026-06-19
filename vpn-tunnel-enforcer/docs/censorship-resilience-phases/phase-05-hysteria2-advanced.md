# Фаза 5: продвинутый режим Hysteria2

Приоритет: высокий.

## Статус на 14.06.2026

Сделан первый рабочий слой фазы:

- Расширен импорт `hysteria2://` / `hy2://`:
  - `obfs=salamander`;
  - `obfs-password` / `obfs_password`;
  - `mport` / `server_ports` / `serverPorts`;
  - `hop_interval`;
  - `upmbps` / `up_mbps`;
  - `downmbps` / `down_mbps`.
- Port hopping нормализуется под формат bundled sing-box 1.13.13:
  - `mport=8443-8450` превращается в `server_ports: "8443:8450"`;
  - обратный экспорт в URI снова отдаёт `mport=8443-8450`, а не внутренний `8443:8450`;
  - списки через запятую не прокидываются в runtime, потому что sing-box 1.13.13 их отвергает.
- Hysteria2 больше не импортируется как `network: "tcp"`.
  Это важно: HY2 работает поверх QUIC/UDP, а старый `network: "tcp"` мог включить правило блокировки UDP.
- Runtime-конфиг защищён от старых/будущих несовместимых профилей:
  - старый `network: "tcp"` у HY2 удаляется перед генерацией sing-box конфига;
  - невалидный raw JSON `server_ports` удаляется, и одиночный `server_port` остаётся fallback-портом;
  - 1.14-only поля (`gecko`, `hop_interval_max`, `realm`, `bbr_profile`, packet-size knobs) вычищаются перед `sing-box check`, чтобы bundled 1.13.13 не падал.
- Экспорт HY2 обратно в URI сохраняет стабильные advanced-поля.
- Capability diagnostics теперь предупреждают:
  - HY2 без obfs;
  - HY2 с `gecko` на sing-box 1.13.x;
  - HY2 с tcp-only routing.
- В системный отчёт добавлен active-profile diagnostics для HY2: видно, что профиль QUIC/UDP,
  какие `server_ports` / `hop_interval` импортированы, какой stealth preset выбран и какие warning-и требуют внимания.
- Health-check для HY2 теперь использует protocol-aware ephemeral sing-box probe:
  временный локальный `mixed` inbound дёргает настоящий HY2 outbound без TUN, а результат классифицируется как
  `hy2-udp-blocked`, `hy2-auth-failed`, `hy2-config-failed`, `hy2-tls-failed` или generic `hy2-handshake-failed`.
- Добавлены unit-тесты для HY2 advanced parsing/export/capability и UDP runtime guard.
- Проверен реальный `resources/sing-box.exe check` на HY2-конфиге с `server_ports`, `hop_interval`, `salamander`.
- После audit-fix проверено: targeted Vitest `3 passed / 56 tests`, полный Vitest `32 passed / 359 tests`, `npm run build`.
- После active-profile diagnostics проверено: targeted Vitest `3 passed / 58 tests`.
- После HY2 health probe проверено: targeted Vitest `4 passed / 66 tests`, `npm run build`, минимальный ephemeral HY2 `sing-box check`.

Что осталось в фазе:

- Вернуться к `gecko`, `realm`, `bbr_profile`, packet size после обновления bundled sing-box до 1.14+.
- Проверить на real known-good HY2 сервере, потому что `sing-box check` валидирует схему, но не подтверждает handshake.

## Цель

Сделать Hysteria2 не просто generic imported outbound, а first-class advanced
режим с protocol-specific настройками и диагностикой.

## Почему это важно

Hysteria развивается прямо в сторону антиблокировок: QUIC obfuscation,
fragmented handshake, rendezvous/NAT traversal. Это нужно вывести в продукт
явно, а не оставлять как “какой-то hy2 profile”.

## Что сделать

- Явная поддержка Hysteria2 опций:
  - `salamander`;
  - `gecko`, если выбранная версия sing-box поддерживает;
  - packet size options;
  - hop interval controls, если доступны.
- Добавить Hysteria Realms / rendezvous как advanced workflow.
- Добавить protocol-specific diagnostics:
  - QUIC blocked;
  - handshake obfs configured;
  - hole punching success/failure;
  - NAT hints, если можно получить.

## Вероятные файлы

- `src/main/vpnProfiles.ts`
- `src/main/tunController.ts`
- `src/main/serverProbe.ts`
- `src/main/systemDiagnostics.ts`
- `src/renderer/pages/Servers.tsx`
- `src/renderer/pages/Availability.tsx`

## Чеклист реализации

1. Провести audit текущего Hysteria2 import.
2. Добавить explicit model fields для obfs и advanced options.
3. Закрыть alpha-only options runtime version checks.
4. Добавить config generation tests для каждой supported option.
5. Добавить active-profile diagnostics для Hysteria2 — сделано через `active-profile-capabilities`.
6. Добавить UI advanced options без перегруза обычного пользователя.
7. На уровне probe различать UDP/QUIC block и bad credentials — сделано через HY2 ephemeral sing-box health probe.

## Проверка готовности

- Hysteria2 parser/config tests.
- Runtime version gate tests.
- Ручная UDP/QUIC availability проверка.
- Diagnostics/health-check объясняют вероятную причину failure — сделано для HY2 через `hy2-*` reason codes.

## Что не делать в этой фазе

- Не делать alpha-only `gecko` default.
- Не считать Hysteria2 универсальной заменой TCP/TLS профилей.
- Не прятать QUIC block под generic timeout.
