# Режимы подключения: через локальный прокси и прямой VPN

> Источник: https://factory.8090.ai/project/992274e4-1c6b-4d44-8c22-e4c038e690c2/blueprints/88dd602c-ab6f-4348-b318-8167fe8c6983

# Режимы подключения: через локальный прокси и прямой VPN

## Сводка функции

Функция реализует два системных пути из требований `REQ-CONN-MODE-001`–`REQ-CONN-MODE-005`: Hard TUN через локальный прокси и Direct VPN по выбранному VPN-профилю. Основной процесс Electron передаёт выбранный режим и параметры в `#TunController`, а Dashboard получает отображение Hard TUN или Direct VPN через общий жизненный цикл родительской функции @Подключение VPN.

## Состав архитектуры функции

Функция использует @Подключение VPN для единого запуска, остановки и публикации состояния. `#ProtectionLifecycleCoordinator` выбирает путь по `connectionMode`; `#TunController` выполняет preflight и поднимает системный TUN. Режим Soft намеренно остаётся отдельной функцией и не входит в эту композицию.

`#ConnectionPlanner` формирует план до запуска. Для localProxy он вызывает `#HappDetector`, а для directVpn проверяет активный `VPNProfile` без требования локального прокси. Результат плана используется для предупреждений и блокировки запуска при отсутствующем профиле или неготовом прокси.

## Компоненты, специфичные для функции

### Планирование и preflight

```component
name: ConnectionPlanner
container: Electron Main Process
responsibilities:
	- Выбирает ветку `localProxy` или `directVpn` по `connectionMode`.
	- Для localProxy проверяет наличие локального прокси и формирует предупреждения о конфликтующих TUN.
	- Для directVpn проверяет наличие активного `VPNProfile` и не требует локальный прокси.
	- Передаёт план и причины блокировки в #ProtectionLifecycleCoordinator.
```

```component
name: HappDetector
container: Electron Main Process
responsibilities:
	- Находит кандидаты локальных прокси по конфигурациям, настройкам Windows и loopback listeners.
	- Проверяет TCP-доступность и протокол HTTP или SOCKS5.
	- Определяет `ProxyOwner` и доступный внешний IP через найденный прокси.
```

`#ConnectionPlanner` использует `#HappDetector` только для localProxy. При фактическом запуске `#TunController` повторяет TCP-пробу, поиск владельца процесса и проверку полного туннеля, чтобы состояние preflight не устарело до применения маршрутов.

### Исполнение системного туннеля

```component
name: TunController
container: Electron Main Process
responsibilities:
	- В ветке `localProxy` проверяет локальный proxy endpoint и полный туннель перед запуском TUN.
	- В ветке `directVpn` принимает `VPNProfile` и готовит runtime для выбранного outbound.
	- Управляет системным TUN, сетевыми защитными мерами и жизненным циклом sing-box.
	- Возвращает ошибку запуска без публикации рабочего состояния при неуспешном preflight или запуске движка.
```

```component
name: ProxyEngineResolver
container: Electron Main Process
responsibilities:
	- Выбирает sing-box или Xray по outbound, настройке движка и наличию REALITY.
	- Возвращает `ProxyEngineMode` для directVpn.
```

```component
name: XrayEngine
container: Electron Main Process
responsibilities:
	- Запускает управляемый `vpnte-xray.exe` в runtime приложения.
	- Предоставляет loopback SOCKS5 endpoint для outbound, который обслуживает Xray.
	- Сохраняет управление TUN, DNS, маршрутизацией и kill-switch за sing-box.
```

`#TunController` выбирает `#ProxyEngineResolver` после получения `VPNProfile`. Если нужен Xray, `#XrayEngine` запускается до подготовки runtime и его loopback SOCKS5 передаётся как upstream для sing-box. F-022 показывает конфликт порядка очистки: обнаружение старого sing-box может удалить только что запущенный `vpnte-xray.exe` из той же runtime-папки.

## Системные контракты

### Ключевые контракты

* `connectionMode` принимает системные значения `localProxy` и `directVpn`; Soft не является режимом этой функции.
* Для `localProxy` запуск запрещён, если TCP-проба endpoint неуспешна или проверка полного туннеля не прошла.
* Ошибка недоступного прокси должна содержать сообщение: «Прокси недоступен. Убедитесь, что Happ запущен в режиме Proxy».
* Для `localProxy` процесс-владелец прокси используется для исключений direct-out, когда включён kill-switch.
* Для `directVpn` локальный прокси не является обязательной зависимостью; обязательна конфигурация активного `VPNProfile`.
* REALITY в режиме auto направляет совместимые outbound через Xray; остальные неподдерживаемые Xray протоколы остаются на sing-box.
* Ошибка запуска профиля не должна оставлять опубликованное состояние работающей защиты.
* MTU является параметром runtime-плана и может принимать значения 1280, 1380 или 1500 согласно текущей логике адаптации; этот документ не расширяет поведение adaptive bypass.
* F-047 фиксирует конфликт между импортом WireGuard как `type: wireguard` и поддержкой outbound в текущем sing-box. Совместимое поведение для такого профиля не подтверждено.

### Контракты интеграции

* `#ProtectionLifecycleCoordinator` передаёт в `#TunController` `mode`, `proxyAddr`, `proxyType`, `vpnProfile` и `proxyEngine`.
* `#ConnectionPlanner` возвращает план с `recommendedMode`, `canStartHard`, `proxy`, активными TUN и шагами для Dashboard.
* `#HappDetector` возвращает `ProxyInfo` с host, port, типом, признаком проверки и внешним IP через прокси.
* `#XrayEngine` предоставляет `socksPort`, путь runtime executable и статус процесса для `#TunController` и диагностики.
* Dashboard отображает localProxy как Hard TUN, directVpn как Direct VPN. События жизненного цикла остаются контрактом @Подключение VPN.
* `#AppHappPolling` опрашивает состояние Happ каждые 90 секунд. F-156 указывает, что опрос не учитывает `document.hidden`.

## Трассировка к коду и журналу аудита

Наблюдаемая реализация находится в `vpn-tunnel-enforcer/src/main/tunController.ts`, `connectionPlanner.ts`, `happDetector.ts`, `proxyEngine.ts`, `xrayEngine.ts` и `index.ts`. Подробные находки и ограничения записаны в [@Журналу аудита кода VPN Tunnel Enforcer](https://factory.8090.ai/project/992274e4-1c6b-4d44-8c22-e4c038e690c2/knowledge-base/eb72dd10-8123-4865-a5d5-01d28ab9de94), включая F-022, F-047 и F-156.

## Архитектурные решения

### ADR-001: Два системных пути подключения

**Контекст:** Пользователю нужен выбор между использованием уже работающего локального прокси и запуском VPN по импортированному профилю.

**Решение:** `#ProtectionLifecycleCoordinator` выбирает `localProxy` или `directVpn`, а `#TunController` сохраняет общий системный TUN и жизненный цикл. Soft вынесен за границы функции.

**Последствия:** Dashboard и Tray получают единый жизненный цикл, но оба пути зависят от корректного выбора и сохранения `connectionMode`.

### ADR-002: Xray как loopback upstream для REALITY

**Контекст:** Часть профилей с REALITY требует отдельного движка в текущей реализации.

**Решение:** `#ProxyEngineResolver` в режиме auto выбирает Xray для совместимых REALITY outbound. `#XrayEngine` предоставляет loopback SOCKS5, а sing-box продолжает владеть TUN и сетевыми мерами.

**Последствия:** Архитектура разделяет транспорт и системный туннель, но требует согласованного порядка запуска и очистки runtime. F-022 остаётся открытым риском.

### ADR-003: Неопределённая совместимость профилей ядра

**Контекст:** Импорт профиля не гарантирует, что текущий движок способен его запустить. WireGuard импортируется как outbound, хотя аудит F-047 указывает на несовместимость с sing-box 1.13.

**Решение:** В документации фиксируется необходимость понятного отказа до состояния работающей защиты для неподдерживаемого профиля. Решение о точном наборе отклоняемых профилей остаётся открытым вопросом.

**Последствия:** Пользователь должен получить безопасный отказ вместо ложного рабочего состояния, но каталог совместимости и окончательное поведение WireGuard требуют отдельного решения.