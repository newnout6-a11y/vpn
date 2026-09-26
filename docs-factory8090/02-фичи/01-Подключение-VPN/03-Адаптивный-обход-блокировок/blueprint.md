# Адаптивный обход блокировок

> Источник: https://factory.8090.ai/project/992274e4-1c6b-4d44-8c22-e4c038e690c2/blueprints/f8735bdf-c10c-4727-82b6-b215b74e750f

## Feature Summary

Summarize what this feature does from the user's perspective and which requirements it fulfills.

## Component Blueprint Composition

List the shared capabilities this feature composes and how each is configured or scoped. For example:

* **@Component Blueprint 1** — What this capability provides; how this feature configures or scopes it.
* **@Component Blueprint 2** — What this capability provides; using `#ComponentA` and `#ComponentB` to enable this feature.

## Feature-Specific Components

Components that exist only for this feature, defined as `component` blocks.

## System Contracts

### Key Contracts

Invariants, correctness rules, and reliability semantics (idempotency, ordering, consistency, retry behavior).

### Integration Contracts

Events published/consumed, API interfaces, webhooks, and composition expectations for consumers of this capability.

## Architecture Decision Records

### ADR-001: Decision Title

**Context:** Why this decision was needed.

**Decision:** What was chosen and how.

**Consequences:** Trade-offs, benefits, and implications.

# Адаптивный обход блокировок

## Обзор функции

Функция соединяет `adaptiveBypassEnabled`, `adaptiveBypassServerFallback`, состояние `AdaptiveBypassStatus` и жизненный цикл TUN для повышения надёжности подключения при сетевых ограничениях. Она не заявляет невидимость VPN и не гарантирует доступ в каждой сети. Связанные требования описаны в @Адаптивный обход блокировок.

## Состав архитектуры функции

### Координация подключения

```component
name: AdaptiveBypassCoordinator
container: Electron main process
responsibilities:
	- Выбирает `baseline`, `tls-compatibility`, `mtu-compatibility` или `external-managed` при запуске подключения.
	- Запускает отложенную проверку работающего туннеля.
	- Переходит к следующему доступному режиму, резервному серверу или ошибке.
	- Использует поколение проверки, чтобы не применять устаревший результат после нового жизненного цикла.
	- Передаёт выбранный режим в #TunController.
```

#AdaptiveBypassCoordinator вызывает #TunnelHealthProbe после запуска TUN. Проверка ждёт 20 секунд, затем выполняет три последовательные HTTP-пробы с интервалом 2,5 секунды. Результат считается успешным при двух или трёх успешных пробах.

### Локальное обучение

```component
name: AdaptiveLearningStore
container: Electron main process
responsibilities:
	- Хранит подтверждённые режимы в отдельном локальном electron-store.
	- Вычисляет HMAC-ключи на основе локальных сетевых и профильных сигналов.
	- Удаляет записи старше 30 дней и ограничивает хранилище 24 записями.
	- Сбрасывает все запомненные решения по команде пользователя.
```

#AdaptiveBypassCoordinator передаёт профиль и текущую сеть в #AdaptiveLearningStore. В открытом виде сохраняется только решение и время его использования, а исходные идентификаторы используются для вычисления ключа.

### Проверка туннеля

```component
name: TunnelHealthProbe
container: Electron main process
responsibilities:
	- Проверяет фактический выход трафика через работающий TUN.
	- Возвращает результаты последовательных проверок для решения о стабильности соединения.
```

### Управление туннелем

```component
name: TunController
container: Electron main process
responsibilities:
	- Запускает TUN с выбранным `AdaptiveBypassMode`.
	- Выполняет переход режима через `restartForAdaptiveChange()` без полного пользовательского stop.
	- Сохраняет kill switch, сетевой baseline и блокировку адаптера на время адаптивного перехода.
	- Выполняет обычную очистку при неуспешном запуске замены.
```

#TunController получает режим от #AdaptiveBypassCoordinator. При ошибке outbound координатор может выбрать соседний профиль той же группы, не меняя сохранённый активный профиль.

## Контракты системы

### Ключевые контракты

* `adaptiveBypassEnabled` включён по умолчанию.
* `adaptiveBypassServerFallback` включён по умолчанию и ограничивает резервный переход одной попыткой для одного подключения.
* Режим `external-managed` используется для локального прокси и пропускает адаптивную проверку.
* Для Reality режим совместимости TLS недоступен.
* Резервный профиль выбирается только из текущей группы и не имеет статуса `offline`.
* Успех адаптации требует не менее двух успешных проверок из трёх после 20-секундного окна стабилизации.
* Адаптивный переход не должен создавать полный разрыв сетевой защиты.

### Интеграционные контракты

* `AdaptiveBypassCoordinator` использует `AdaptiveBypassMode`, `AdaptiveCapabilities` и `AdaptiveBypassStatus` из `src/main/adaptiveBypass.ts`.
* `AdaptiveBypassCoordinator` получает фактическую проверку через `tunnelHttpProbe(true)` из `src/main/serverPicker.ts`.
* `AdaptiveBypassCoordinator` передаёт `adaptiveMode` в старт TUN и вызывает `restartForAdaptiveChange()` из `src/main/tunController.ts`.
* Настройки `adaptiveBypassEnabled` и `adaptiveBypassServerFallback` находятся в `src/main/settings.ts`.

## Журнал архитектурных решений

### ADR-001: Локальное подтверждение режима

**Контекст:** Стабильность подключения зависит от сети и профиля. Постоянная глобальная настройка не подходит для всех условий.

**Решение:** Сохранять подтверждённый режим локально по HMAC-ключу сети и профиля, с ограничением срока и размера кэша.

**Последствия:** Следующее подключение может начать с ранее подтверждённого режима. Сырые сетевые и профильные значения не сохраняются открыто.

### ADR-002: Внешнее управление транспортом

**Контекст:** В режиме локального прокси VPNTE не управляет upstream-транспортом.

**Решение:** Использовать состояние `external-managed` и не выполнять адаптивные TLS/MTU-переходы для внешнего транспорта.

**Последствия:** Проверка адаптивной совместимости не подтверждает upstream-транспорт. Надёжность внешнего VPN-клиента остаётся его ответственностью.

### ADR-003: Несогласованность плана и реализации

**Контекст:** План описывает единый координатор с отменой и несколькими эталонными точками, а текущий код распределяет координацию в `index.ts` и использует поколение проверки без явного abort.

**Решение:** В этом blueprint зафиксировано наблюдаемое поведение текущего кода. Выбор планового целевого поведения остаётся открытым вопросом в требованиях.

**Последствия:** Blueprint может потребовать синхронизации после решения F-127. Текущая реализация остаётся ограниченной рамками, описанными в коде.

### ADR-004: Обратная совместимость `stealthMode`

**Контекст:** План требует удалить старый переключатель после миграционного периода, а текущая реализация сохраняет его в настройках и использует как legacy-вход.

**Решение:** Зафиксировать текущее поведение без утверждения удаления или сохранения как конечного решения.

**Последствия:** Требования и blueprint требуют обновления после решения об удалении `stealthMode`.