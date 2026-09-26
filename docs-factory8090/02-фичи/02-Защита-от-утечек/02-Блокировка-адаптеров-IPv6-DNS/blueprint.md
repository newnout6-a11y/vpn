# Блокировка физических адаптеров, IPv6 и DNS

> Источник: https://factory.8090.ai/project/992274e4-1c6b-4d44-8c22-e4c038e690c2/blueprints/30fd971f-7c75-4476-b0c0-9c2ea6c86374

## Feature Summary

Функция соединяет `TunController` с компонентами #PhysicalAdapterLockdown и #SystemNetworkBaseline. При запуске TUN она заранее ограничивает IPv6 и DNS на подходящих физических адаптерах, учитывает публичную Wi-Fi совместимость и выполняет ранний откат при неуспешной подготовке. TUN остаётся IPv4-only, поэтому IPv6 не объявляется как рабочий маршрут внутри туннеля.

## Component Blueprint Composition

`TunController` вызывает #PhysicalAdapterLockdown до подготовки runtime и проверки доступности прокси. Параметр `forceDns` отключается при `publicWifiCompatibility`, поэтому режим публичной Wi-Fi сети сохраняет DNS физических адаптеров, но использует отдельную совместимость MTU через `selectTunMtu`.

#PhysicalAdapterLockdown получает снимок активных физических адаптеров через PowerShell. Он исключает TUN, Wintun, TAP, WireGuard, Tailscale, виртуальные и loopback-интерфейсы, различает обычные адаптеры и адаптеры мобильной сети или tethering, отключает IPv6 только на обычных адаптерах и при необходимости направляет их IPv4 DNS к `TUN_IPV4_RESOLVER`.

#PhysicalAdapterLockdown также сохраняет и временно отключает Teredo, 6to4 и ISATAP. Журнал S04 классифицирует эти технологии как deprecated и указывает, что Windows 11 выключает их по умолчанию. Поэтому команды выполняются с предупреждениями при неподдерживаемой или отсутствующей технологии, а нормативная необходимость этой операции остаётся открытым вопросом.

#SystemNetworkBaseline сохраняет в ProgramData backup разделов HKCU Internet Settings, HKCU Environment и HKLM Internet Settings Connections. После сохранения он сбрасывает WinHTTP proxy, отключает WinINet proxy и PAC, удаляет proxy-переменные текущего процесса и сообщает предупреждения для нефатальных ошибок.

## Feature-Specific Components

```component
name: PhysicalAdapterLockdown
container: Electron Main Process
responsibilities:
	- Снимок активных физических адаптеров и их `AdapterSnapshot`
	- Исключение TUN и виртуальных интерфейсов
	- Определение `isCellularOrTethering` по имени, описанию, DNS и шлюзу
	- Отключение IPv6 на подходящих адаптерах через Disable-NetAdapterBinding
	- Опциональная установка IPv4 DNS на `TUN_IPV4_RESOLVER`
	- Снимок и отключение переходных IPv6-адаптеров Teredo, 6to4 и ISATAP
	- Сохранение манифеста в userData и ProgramData
	- Частичный откат с проверкой результата и предупреждениями
```

```component
name: SystemNetworkBaseline
container: Electron Main Process
responsibilities:
	- Создание `NetworkBackupManifest` до нормализации сетевых настроек
	- Сброс WinHTTP, WinINet, PAC и proxy-переменных
	- Сериализация операций baseline и отката
	- Восстановление разделов реестра через сохранённые backup-файлы
	- Идемпотентный пропуск отката при отсутствии активного манифеста
```

#TunController вызывает #PhysicalAdapterLockdown и #SystemNetworkBaseline в рамках защищённого жизненного цикла. При сбое разбора proxy, проверки full-tunnel, запуска runtime или создания TUN он вызывает `rollbackEarlyAdapterLockdown`; при штатной остановке и полном teardown откатывает сетевые изменения.

## System Contracts

### Key Contracts

* Манифест блокировки должен сохранять исходные значения IPv6, IPv4 DNS, DNS registry policy и состояния Teredo, 6to4 и ISATAP до изменения системы.
* Манифест baseline должен записываться только после создания обязательной копии HKCU Internet Settings. При ошибке обязательной копии нормализация должна быть отменена.
* Откат должен быть идемпотентным. Отсутствующий манифест означает, что соответствующее активное изменение не найдено.
* Ошибка отдельной команды должна становиться предупреждением, если код может продолжить безопасную обработку. Частичный откат должен логироваться как ошибка и не должен маскироваться успешным результатом.
* Операции baseline должны выполняться последовательно через очередь, чтобы параллельные apply и rollback не делили один временный манифест.

### Integration Contracts

* `TunController` передаёт `TUN_IPV4_RESOLVER` и `forceDns` в #PhysicalAdapterLockdown. `forceDns` равен `false` при `publicWifiCompatibility === true`.
* `PhysicalAdapterLockdown` предоставляет `applyPhysicalAdapterLockdown`, `rollbackPhysicalAdapterLockdownIfApplied`, `isPhysicalAdapterLockdownApplied` и `getLockdownManifestPaths`.
* `SystemNetworkBaseline` предоставляет `applyTunNetworkBaseline`, `rollbackTunNetworkBaseline`, `rollbackTunNetworkBaselineIfApplied`, `isBaselineApplied` и `getTunNetworkBaselineManifestPath`.
* TUN создаётся с IPv4-only конфигурацией без IPv6-адреса и IPv6-маршрутов. Внутренний комментарий `tunController.ts` связывает это с предотвращением выбора IPv6 приложениями и с тем, что IPv6 блокируется kill-switch и блокировкой физических адаптеров.
* Тесты `physicalAdapterLockdownSource.test.ts`, `systemNetwork.test.ts`, `networkCompatibility.test.ts` и `tunControllerRecoverySource.test.ts` фиксируют контракты обнаружения tethering, двойного хранения манифеста, обязательного backup, public Wi-Fi DNS-исключения и раннего отката.

## Architecture Decision Records

### ADR-001: IPv4-only TUN и защита IPv6 на физических интерфейсах

**Context:** Kill-switch сам по себе не блокирует IPv6, что зафиксировано в F-016. TUN с IPv6-маршрутами создавал бы путь, который приложение не обслуживает.

**Decision:** TUN не получает IPv6-адрес и IPv6-маршруты. Блокировка физических адаптеров отключает IPv6 на обычных физических интерфейсах, а адаптеры мобильной сети и tethering исключаются.

**Consequences:** Снижается риск IPv6-утечки и выбора IPv6 приложениями. Мобильные сети сохраняют необходимую работу 464XLAT/CLAT. Это решение зависит от корректного отката и требует проверки на Windows.

### ADR-002: Снимок и обратимое изменение DNS

**Context:** DNS, полученный через DHCP или настроенный статически, может оставаться на физическом адаптере и обходить DNS туннеля. При этом F-042 фиксирует расхождение между обещанием public Wi-Fi режима и фактическим default поведением вызывающего кода.

**Decision:** Сохранять IPv4 DNS и registry policy в манифесте, принуждать DNS только при `forceDns !== false`, а при public Wi-Fi передавать `forceDns: false`.

**Consequences:** Режим public Wi-Fi сохраняет совместимость с сетью, но не получает принудительную защиту DNS от физического адаптера. Точная нормативная политика для такого компромисса требует продуктового решения.

### ADR-003: Защита от устаревших переходных технологий

**Context:** F-039 показывает, что Teredo, 6to4 и ISATAP deprecated и обычно выключены в Windows 11. При этом код всё ещё снимает их состояние, пытается отключить их и восстанавливает сохранённое состояние.

**Decision:** Сохранить наблюдаемую попытку отключения и восстановление как текущий контракт, а влияние deprecated статуса явно отметить как открытый вопрос до решения о поддерживаемых версиях Windows.

**Consequences:** Старые системы получают дополнительный барьер от обходного IPv6-пути. На современных системах возможны предупреждения без изменения состояния. Команды требуют проверки на целевых версиях Windows.