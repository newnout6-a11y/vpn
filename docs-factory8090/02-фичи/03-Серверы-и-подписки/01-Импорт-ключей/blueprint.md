# Импорт ключей

> Источник: https://factory.8090.ai/project/992274e4-1c6b-4d44-8c22-e4c038e690c2/blueprints/7166e505-02da-4990-b72d-a74a3425cfff

## Feature Summary

Фича @Импорт ключей разбирает вставленные ключи и конфигурации в профили серверов для передачи в управление фичи @Серверы и подписки. Набор поддерживаемых входов включает прямые URI протоколов, смешанный текст, base64-варианты, sing-box/Xray JSON, Clash YAML и `happ://add/` с URL или прямым URI.

## Component Blueprint Composition

Фича использует `VpnProfile` и `VpnProtocol` как нормализованное представление результата разбора. Полученные профили передаются в поток управления профилями и группами, а получение и обновление удалённых источников остаётся в @Подписки и группы.

## Feature-Specific Components

### Разбор и нормализация

```component
name: VpnProfileParser
container: Electron Main Process
responsibilities:
	- Принимать текстовый ввод и распознавать `vless`, `trojan`, `shadowsocks`, `vmess`, `hysteria2`, `naive`, `anytls`, `shadowtls`, `tuic` и `wireguard` outbounds.
	- Извлекать URI из смешанного текста и пробовать ограниченные base64-варианты.
	- Разбирать sing-box/Xray JSON, JSON-обёртки и Clash YAML с секцией `proxies`.
	- Нормализовать endpoint, credentials, имя, TLS, Reality, ECH, транспорт и протокольные параметры в `VpnProfile`.
```

`VpnProfileParser` возвращает отдельные профили для независимых URI. Ошибка одного неподдерживаемого или повреждённого элемента не должна скрывать другие профили при разборе Clash YAML и смешанного текста, если такой путь уже допускает продолжение.

```component
name: HappLinkUnwrapper
container: Electron Main Process
responsibilities:
	- Распознавать `happ://add/` и извлекать URL подписки или прямой поддерживаемый URI.
	- Принимать URL-кодированный, bare и base64 payload.
	- Отклонять routing и encrypted Happ links с объясняемой ошибкой.
	- Отклонять неизвестный host или неподдерживаемый payload без возврата пустого профиля как успешного результата.
```

`HappLinkUnwrapper` передаёт извлечённый URL или URI в `VpnProfileParser`. Текущая реализация не подтверждает разбор `happ://add/<base64-json>` с полем `url`, а encrypted `crypt3`, `crypt4` и `crypt5` не расшифровывает.

```component
name: ClientDeviceProfileApplier
container: Electron Main Process
responsibilities:
	- Нормализовать профиль устройства `pc`, `android`, `ios` или `mac`.
	- Применять соответствующий uTLS fingerprint только к TLS-enabled outbound.
	- Строить стабильный device-specific HWID для совместимых источников.
	- Передавать device OS, version и model в source-fetch контрактах, когда они используются.
```

`ClientDeviceProfileApplier` изменяет только TLS-enabled outbound при применении device profile. Для профилей без TLS uTLS-параметры не добавляются.

```component
name: VpnProfileExporter
container: Electron Main Process
responsibilities:
	- Преобразовывать экспортируемые outbounds обратно в URI для поддержанных протоколов.
	- Сохранять поддержанные protocol-specific credentials и options при round-trip.
	- Возвращать отсутствие результата для outbound type, который не имеет URI-представления.
```

## System Contracts

### Key Contracts

* `parseVpnProfiles` возвращает только распознанные профили и не создаёт частичный профиль для URI с отсутствующим обязательным credential или некорректным портом.
* Профиль хранит `sourceUri`, если он был получен из прямого URI или source URL.
* Ошибки и диагностические тексты должны проходить через redaction для URI, URL, UUID и других секретных значений.
* ECH подтверждён на уровне разбора параметров. Успешный known-good handshake не подтверждён.
* Текущий parser path имеет открытые расхождения F-045, F-046, F-047 и F-048 из раздела S05 журнала аудита.

### Integration Contracts

* Входом являются текстовые ключи, JSON, YAML, base64-текст и `happ://` deep links.
* Выходом является массив `VpnProfile` с `name`, `protocol`, `outbound` и опциональными `sourceUri`, `clientDevice`, `clientFingerprint`.
* `buildSubscriptionHwid` и device headers используются в source-fetch path; полный контракт хранения профилей относится к @Серверы и подписки.
* Тестовое покрытие представлено `vpnProfilesProtocolCoverage.test.ts`, `vpnProfilesClientDevice.test.ts`, `vpnProfilesRegression.test.ts`, `scripts/test-vpn-profiles.mjs` и `scripts/verify-happ-unwrap.mjs`.

## Architecture Decision Records

### ADR-001: Нормализация в sing-box outbound

**Context:** Входные ключи используют разные URI, JSON и YAML представления, а runtime должен получить единое описание VPN-профиля.

**Decision:** Нормализовать поддержанные входы в `VpnProfile` с sing-box-style `outbound`, сохраняя protocol-specific параметры, которые текущий parser может распознать.

**Consequences:** Один поток может обрабатывать разные источники. Ограничения версии runtime и текущие расхождения WireGuard должны проверяться отдельно.

### ADR-002: Явный отказ для неподдержанных Happ payloads

**Context:** Routing и encrypted deep links не являются обычными server keys, а неизвестный payload нельзя безопасно трактовать как пустой импорт.

**Decision:** Возвращать объяснимую ошибку для routing, encrypted и неизвестных Happ payloads.

**Consequences:** Пользователь получает причину отказа. Поддержка зашифрованных форматов требует отдельного подтверждённого решения и ключей расшифровки.