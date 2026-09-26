# Генерация конфигурации sing-box

> Источник: https://factory.8090.ai/project/992274e4-1c6b-4d44-8c22-e4c038e690c2/blueprints/db198f85-aeed-43f5-86c8-bf351d2da3a7

# Генерация конфигурации sing-box

## Capability Summary

Возможность преобразует выбранный прокси или VPN-профиль в runtime-конфигурацию sing-box, добавляя TUN, локальные API, маршрутизацию, DNS и режимы совместимости. `generateSingboxConfig` получает исходящий профиль и настройки, а `ruleSetManager` поставляет managed или bundled rule-set. REALITY может направляться через Xray engine. Аудит фиксирует устаревшее поле `download_detour` как F-077.

## Core Components

### Генератор

```component
name: SingboxConfigGenerator
container: Main Process
responsibilities:
	- Строит конфигурацию sing-box из upstream, типа прокси и runtime options.
	- Настраивает TUN MTU, DNS, proxy-out, clash API, direct proxy и маршруты.
	- Применяет smart RU rules, process routing, QUIC policy и TLS/uTLS совместимость.
	- Не включает TLS record fragmentation для REALITY.
```

### Rule-set менеджер

```component
name: RuleSetManager
container: Main Process
responsibilities:
	- Выбирает bundled или managed источник smart-routing rule-set.
	- Скачивает файл через curl с bootstrap route, временный файл заменяет целевой атомарно.
	- Сохраняет размер, SHA-256, маршрут, время и ошибку обновления.
	- Передаёт каталог rule-set генератору конфигурации.
```

### Выбор proxy engine

```component
name: ProxyEngineResolver
container: Main Process
responsibilities:
	- Выбирает sing-box или Xray по настройке и типу outbound.
	- В auto-режиме выбирает Xray для outbound с включённым REALITY, если протокол поддержан.
```

```component
name: XrayOutboundAdapter
container: Main Process
responsibilities:
	- Преобразует sing-box outbound в Xray OutboundObject.
	- Переносит транспорт, TLS/REALITY, uTLS, flow и dialer proxy.
	- Отдельно запускает Xray SOCKS upstream для последующего использования sing-box.
```

#RuleSetManager передаёт путь к активным правилам в #SingboxConfigGenerator. #ProxyEngineResolver определяет, будет ли outbound исполняться самим sing-box или через #XrayOutboundAdapter и локальный SOCKS.

## System Contracts

### Key Contracts

* Результат генерации должен быть валидным для фактической bundled-версии sing-box.
* Профиль REALITY нельзя обрабатывать настройками, которые меняют его handshake и ломают аутентификацию.
* Managed rule-set должен заменяться атомарно и не активироваться по одному признаку непустого файла.
* При невозможности обновления managed rule-set должен использоваться явно определённый fallback, а ошибка должна быть доступна диагностике.
* Поля конфигурации должны соответствовать версии sing-box. `download_detour` требует решения о переходе на актуальный механизм, F-077.

### Integration Contracts

* #SingboxConfigGenerator получает upstream и options, включая smart-routing, MTU, порты и engine integration.
* #RuleSetManager предоставляет состояние источника и каталог файлов.
* #ProxyEngineResolver возвращает `sing-box` или `xray`.
* #XrayOutboundAdapter возвращает конфигурацию Xray и локальный SOCKS-порт для sing-box.

## Architecture Decision Records

### ADR-001: Генерация из нормализованного outbound

**Context:** Профили импортируются из разных URI и имеют разную форму транспорта и TLS.

**Decision:** Сначала использовать нормализованный outbound, затем применять runtime-совместимость и маршруты.

**Consequences:** Генерация единообразна, но изменения схемы sing-box требуют обновления sanitization и тестов.

### ADR-002: Xray для REALITY в auto-режиме

**Context:** Код учитывает отказ sing-box-клиента для части REALITY-серверов.

**Decision:** В auto-режиме направлять поддержанные REALITY outbounds через bundled Xray.

**Consequences:** Повышается совместимость, но появляются два engine lifecycle и преобразование конфигурации.

## Traceability

Связанные feature-блюпринты: [@Подключение VPN](https://factory.8090.ai/project/992274e4-1c6b-4d44-8c22-e4c038e690c2/blueprints/cd855824-11c3-4932-aa27-8c69b7d00a28), [@Маршрутизация](https://factory.8090.ai/project/992274e4-1c6b-4d44-8c22-e4c038e690c2/blueprints/dd03ac0b-2faf-44c8-ba8d-383aad183285), [@Серверы и подписки](https://factory.8090.ai/project/992274e4-1c6b-4d44-8c22-e4c038e690c2/blueprints/48edfb35-6624-4367-b392-ef927b7f877d).

Аудит: F-077.
