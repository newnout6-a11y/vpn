# AutoPilot

> Источник: https://factory.8090.ai/project/992274e4-1c6b-4d44-8c22-e4c038e690c2/blueprints/902d3e63-5502-4576-910a-d9074eec1729

## Feature Summary

AutoPilot анализирует текущий `RoutingPlan` и выбирает безопасный сценарий маршрутизации VPN Tunnel Enforcer. Он оставляет внешний VPN без изменений, проверяет локальный proxy перед запуском собственного TUN и возвращает `AutoPilotResult` с режимом, итогом, сообщением и шагами.

## Component Blueprint Composition

* `#AutoPilotRunner` реализует сценарий AutoPilot в Electron Main Process.
* `#RoutingPlanner` предоставляет активные туннели и локальные proxy listeners через `RoutingPlan`.
* `#TunController` останавливает принадлежащий VPNTE туннель и запускает Hard TUN.
* `#SystemNetworkBaseline` применяет и откатывает сетевой baseline, если это разрешено настройкой.

`#AutoPilotRunner` сначала читает `RoutingPlan` и состояние `#TunController`. После выбора проверенного proxy он сохраняет endpoint в настройках, при включённом `autoNetworkBaseline` применяет `#SystemNetworkBaseline`, а затем передаёт в `#TunController` параметры proxy, kill-switch, блокировки адаптера и stealth mode.

## Feature-Specific Components

```component
name: AutoPilotRunner
container: Electron Main Process
responsibilities:
	- Читает `RoutingPlan` и состояние `#TunController` перед изменением маршрутизации.
	- Останавливает только туннель VPNTE, если он уже работает.
	- Оставляет внешний туннель без изменений и не создаёт второй TUN.
	- Проверяет локальные proxy listeners по TCP и через SOCKS5 или HTTP probe.
	- Сохраняет проверенный proxy и запускает Hard TUN с параметрами `AppSettings`.
	- Ограничивает параллельные запуски и возвращает `AutoPilotResult`.
```

`#AutoPilotRunner` вызывает `#TunController` только после проверки внешних туннелей и рабочего proxy. При отказе запуска он вызывает `#SystemNetworkBaseline` для попытки восстановления ранее сохранённых системных proxy-настроек.

## System Contracts

### Key Contracts

* `runAutoPilot` не выполняет второй запуск, пока предыдущий не завершился. Повторный вызов возвращает предупреждение без изменения состояния.
* При наличии внешнего туннеля AutoPilot завершает работу в режиме `external` и не запускает VPNTE TUN.
* Без рабочего proxy AutoPilot завершает работу в режиме `off` и не запускает TUN.
* При включённом `AppSettings.autoNetworkBaseline` baseline применяется перед запуском TUN.
* При ошибке запуска после применения baseline AutoPilot пытается выполнить откат baseline.
* `AutoPilotResult` содержит `ranAt`, `summary`, `mode`, `title`, `message`, `changed`, `steps` и итоговый `RoutingPlan`.

### Integration Contracts

* IPC-канал `run-auto-pilot` вызывает `runAutoPilot` в Electron Main Process.
* `RoutingPlan` передаёт AutoPilot активные туннели, proxy listeners и проверенный proxy.
* `AppSettings.autoPilotEnabled` имеет значение по умолчанию `true`; в просмотренном обработчике `run-auto-pilot` отдельная проверка этого флага не подтверждена.
* Прямой вызов AutoPilot из обработчиков смены сети или сбоя сервера в просмотренных файлах не подтверждён.

## Architecture Decision Records

### ADR-001: Не создавать второй туннель

**Context:** Одновременный внешний VPN и TUN VPNTE создают конфликт маршрутизации.

**Decision:** Если после остановки собственного VPNTE туннеля в плане остаётся внешний туннель, AutoPilot не запускает собственный TUN.

**Consequences:** AutoPilot не ломает внешний VPN, но текущая реализация сначала останавливает собственный туннель, если он был активен. Это подтверждено находкой F-129.

### ADR-002: Проверять proxy перед запуском TUN

**Context:** Запуск TUN без доступного локального proxy может лишить систему рабочего выхода.

**Decision:** Перед запуском TUN проверять TCP-доступность и SOCKS5 или HTTP доступность listener, затем использовать только успешно проверенный endpoint.

**Consequences:** Ошибочный proxy предотвращает запуск, но проверки добавляют время до включения TUN.

### ADR-003: Открытый вопрос о едином координаторе

**Context:** Журнал аудита S13 фиксирует F-125: ротация, расписание, AutoPilot, ручная смена и adaptive retry не используют общую блокировку жизненного цикла.

**Decision:** Не заявлять единое правило приоритета, общей отмены или автоматического запуска AutoPilot на смену сети и сбой сервера до отдельного подтверждения.

**Consequences:** Поведение при одновременных действиях и часть автоматических триггеров остаются неподтверждёнными.