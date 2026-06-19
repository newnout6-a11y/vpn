# Фаза 4: трек Naive + ECH

Приоритет: высокий.

## Статус на 14.06.2026

Сделан первый рабочий слой фазы:

- `naive://` уже поддержан в фазе 3 как полноценный sing-box outbound.
- Добавлен импорт ECH из URI-параметров:
  - `ech=1`;
  - `echConfig` / `ech_config` / `ech-config`;
  - `echConfigPath` / `ech_config_path` / `ech-config-path`;
  - `echQueryServerName` / `ech_query_server_name` / `ech-query-server-name`.
- Добавлено сохранение ECH из Xray/Clash-like объектов, если upstream уже передал `ech`, `echSettings`, `ech-settings` или `ech-opts`.
- Экспорт профиля обратно в URI теперь сохраняет ECH-поля.
- Добавлена диагностическая функция `describeVpnProfileCapabilities()`:
  - определяет `naive-ech`, `naive`, `reality-utls`, `hysteria2-obfs`, `tls-utls`, `plain`;
  - показывает, есть ли TLS/ECH;
  - возвращает предупреждения для `tls.insecure` и неполного ECH.
- В списке серверов добавлен компактный бейдж capability: `ECH`, `Reality`, `Naive`, `OBFS`, `uTLS`, `TLS`, `Plain`.
  Это не второй protocol label, а короткий маркер transport/stealth состояния.
- В системный отчёт добавлен блок active-profile diagnostics: текущий профиль теперь показывает protocol, stealth preset,
  TLS/ECH состояние и warning-и из `describeVpnProfileCapabilities()`.
- Добавлены тесты на ECH parsing/export/capability summary.

Проверено:

- `npm exec vitest -- --run src/main/vpnProfilesProtocolCoverage.test.ts`
- `npm exec vitest -- --run src/main/vpnProfilesProtocolCoverage.test.ts src/main/vpnProfilesClientDevice.test.ts src/main/tunControllerConfig.test.ts`
- `npm exec vitest -- --run src/main/vpnProfilesProtocolCoverage.test.ts src/main/tunControllerConfig.test.ts src/renderer/components/countryGlyph.test.ts`
- `npm exec vitest -- --run --testTimeout 20000`
- `npm run build`
- `npm exec vitest -- --run src/main/systemDiagnostics.test.ts src/main/vpnProfilesProtocolCoverage.test.ts src/main/tunControllerConfig.test.ts --testTimeout 20000`

Что осталось в фазе:

- Не включать ECH автоматически без данных от профиля.
- Проверить known-good Naive+ECH профиль на реальном сервере, потому что fake `echConfig` нельзя валидно проверить через `sing-box check`.
- Отдельно решить, нужен ли явный UI-пресет выбора stealth mode или достаточно capability-бейджа.

## Цель

Добавить first-class путь для NaiveProxy-style TLS camouflage и ECH
configuration там, где профиль и sing-box это поддерживают.

## Почему это важно

Roadmap отдельно отмечает риск: полагаться только на browser-like uTLS
fingerprints недостаточно. Naive и ECH дают более чистое направление для
профилей, которые должны выглядеть как обычный browser TLS.

## Что сделать

- Добавить импорт Naive outbound и редактирование config.
- Добавить ECH поля в модель профиля там, где sing-box это поддерживает.
- Добавить stealth presets:
  - Reality/uTLS compatibility;
  - Naive + ECH;
  - Hysteria2 obfs.
- Добавить диагностику:
  - ECH configured/not configured;
  - cert/self-signed warnings;
  - TLS fallback observations, если можно получить;
  - warnings для unsupported ECH комбинаций.

## Вероятные файлы

- `src/main/vpnProfiles.ts`
- `src/main/tunController.ts`
- `src/main/systemDiagnostics.ts`
- `src/renderer/pages/Servers.tsx`
- `src/renderer/pages/Settings.tsx`
- `src/shared/ipc-types.ts`

## Чеклист реализации

1. Описать поля профиля для Naive и ECH.
2. Реализовать parsing Naive shares/config blocks.
3. Генерировать sing-box Naive outbound.
4. Добавить ECH validation rules.
5. Добавить UI labels и warnings для capabilities выбранного профиля.
6. Сделать stealth preset явным выбором, а не спрятанным за общим `stealthMode`.
7. Добавить diagnostics для active profile stealth mode — сделано через `active-profile-capabilities` в system diagnostics.

## Проверка готовности

- Parser tests для Naive.
- Config generation tests для Naive и ECH fields.
- Diagnostics показывают active stealth preset — сделано через `active-profile-capabilities`.
- Ручной start test с known-good Naive profile.

## Что не делать в этой фазе

- Не делать Naive обязательным.
- Не удалять существующий Reality/uTLS compatibility path.
- Не включать ECH вслепую при неполных данных профиля.
