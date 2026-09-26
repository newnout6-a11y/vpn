# Протокол AmneziaWG (план)

> Источник: https://factory.8090.ai/project/992274e4-1c6b-4d44-8c22-e4c038e690c2/blueprints/69605a67-c626-4eb1-8331-83b465d0f321

# Протокол AmneziaWG (план)

## Feature Summary

Это blueprint запланированного исследовательского трека, а не описание реализованного runtime. Он покрывает design spike и лабораторную матрицу из Фазы 7 для проверки возможной поддержки AmneziaWG. В текущем коде нет реализации AmneziaWG или подтверждённого execution path, поэтому blueprint не определяет рабочие компоненты и не добавляет кодовые связи.

## Component Blueprint Composition

Функция пока не композирует реализованные общие компоненты. Основной путь туннеля, kill-switch, очистка адаптера и диагностика являются ограничениями для будущего решения, но конкретный способ их подключения должен быть выбран после design spike.

## Feature-Specific Components

Feature-specific runtime components не определены, потому что Фаза 7 имеет статус следующей и ограничена исследованием. Любой будущий component block требует подтверждения candidate runtime и чтения его реализации.

## System Contracts

### Key Contracts

* До принятия отдельного архитектурного решения AmneziaWG не включается в основной путь туннеля.
* Исследование не должно ослаблять kill-switch или модель очистки адаптера.
* Результат Фазы 7 должен включать архитектурное решение, lab result table, packaging и licensing constraints, Windows privileges, cleanup model и diagnostics plan.
* Лабораторная матрица должна проверять блокировку известной сигнатуры WireGuard, блокировку QUIC, смешанные IPv4/IPv6-сети и мобильные сети с NAT.
* Решение о dedicated execution path должно быть согласовано с будущей границей `CoreAdapter`, если она будет выбрана как предварительное условие.

### Integration Contracts

* Подтверждённый API, конфигурационный формат, runtime-команда, схема импорта и диагностические контракты для AmneziaWG отсутствуют в текущем коде и не определяются этим планом.
* После design spike выбранный вариант должен описать границы между будущим runtime, основным путём туннеля, kill-switch, очисткой адаптера и диагностикой.
* Слияние prototype с production code допускается только после подтверждения cleanup и diagnostics plan.

## Architecture Decision Records

### ADR-001: Отложить реализацию до design spike

**Context:** Roadmap относит AmneziaWG к Фазе 7 и называет поддержку перспективной, но архитектурно более дорогой, чем расширение sing-box. В журнале аудита F-047 указано, что outbound WireGuard удалён в sing-box 1.13 и перенесён в endpoints. Фаза 3 исключает WireGuard из runtime.

**Decision:** Зафиксировать feature как план и сначала сравнить native dedicated execution path, second engine или sidecar, import-only compatibility и ожидание `CoreAdapter`. До этого не определять production runtime.

**Consequences:** План не создаёт пользовательскую возможность подключения. Архитектурные и операционные решения остаются открытыми до результатов design spike и лабораторной матрицы.