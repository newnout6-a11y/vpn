# Kill-switch и исключения

> Источник: https://factory.8090.ai/project/992274e4-1c6b-4d44-8c22-e4c038e690c2/blueprints/7cbdc47e-d044-44c0-93f6-62f1a675ae1d

# Kill-switch и исключения

## Feature Summary

Функция реализует уровни `off`, `standard` и `strict`, управляет правилами Windows Firewall и хранит исключения приложений и IP/CIDR. Она связывает состояние VPN и sing-box с включением или отключением блокировки, передаёт состояние в Dashboard и системный трей и предоставляет ручное отключение и экстренный сброс Firewall. Реализация покрывает требования @Kill-switch и исключения.

## Component Blueprint Composition

* Эта функция использует `#FirewallKillSwitch` как компонент управления правилами Windows Firewall. Компонент сохраняет исходные исходящие политики, создаёт разрешающие правила и применяет `DefaultOutboundAction=Block`, затем удаляет свои правила и восстанавливает сохранённые политики при откате.
* `#GranularKillSwitch` задаёт уровень политики, связывает его с состоянием VPN и передаёт в `#FirewallKillSwitch` пути программ и IP/CIDR исключений.
* `#KillSwitchSettings` получает и изменяет уровень и список исключений через IPC. При изменении уровня компонент сразу вызывает применение политики и возвращает UI к прежнему состоянию при ошибке.
* `#FirewallControlIpc` предоставляет Dashboard операции ручного отключения, получения состояния, диагностики и экстренного сброса Firewall.

## Feature-Specific Components

### Управление Firewall

```component
name: FirewallKillSwitch
container: Electron main process
responsibilities:
	- Сохраняет `FirewallManifest` с исходными DefaultOutboundAction и созданными правилами.
	- Создаёт разрешения для sing-box, приложения, владельцев прокси, TUN, loopback, локальных сетей, DHCP/NTP и пользовательских IP/CIDR исключений.
	- Устанавливает DefaultOutboundAction=Block для профилей Domain, Private и Public.
	- Удаляет правила VPNTE и восстанавливает сохранённые исходящие политики.
	- Проверяет наличие манифеста и правил при определении активного состояния.
	- Выполняет targeted repair и nuclear firewall reset.
```

### Политика уровней и исключений

```component
name: GranularKillSwitch
container: Electron main process
responsibilities:
	- Хранит `KillSwitchLevel` и `KillSwitchException[]` в electron-store.
	- Применяет off, standard и strict в зависимости от состояния VPN.
	- Передаёт исключения приложений и IP/CIDR в #FirewallKillSwitch при включении.
	- Обрабатывает IPC get/set уровня, get/add/remove исключений и выбор исполняемого файла.
	- Синхронизирует granular уровень с legacy firewallKillSwitch и перечитывает импортированные значения.
```

### Настройки Renderer

```component
name: KillSwitchSettings
container: Electron renderer process
responsibilities:
	- Показывает текущий уровень и список исключений.
	- Позволяет выбрать уровень, добавить исключение приложения или IP и удалить исключение.
	- Вызывает `kill-switch:get-level`, `kill-switch:set-level`, `kill-switch:get-exceptions`, `kill-switch:add-exception`, `kill-switch:remove-exception` и `kill-switch:browse-app`.
	- Отображает состояние загрузки и откатывает локальное изменение уровня при ошибке применения.
```

### IPC и аварийное управление

```component
name: FirewallControlIpc
container: Electron main process, Electron renderer process
responsibilities:
	- Обрабатывает `disable-firewall-kill-switch` и `get-firewall-kill-switch-status`.
	- Обрабатывает `firewall:nuclear-reset` только с явным confirmation token.
	- Обрабатывает health probe и targeted repair правил VPNTE.
	- Возвращает результат операции и состояние Firewall для Dashboard.
```

#GranularKillSwitch передаёт #FirewallKillSwitch выбранный уровень и исключения. При смене состояния VPN #GranularKillSwitch вызывает политику, а #FirewallKillSwitch создаёт или снимает системные правила. Направление данных идёт от состояния туннеля к политике, затем к повышенному PowerShell-вызову Windows Firewall.

#KillSwitchSettings передаёт #GranularKillSwitch значения через IPC и получает сохранённые элементы для отображения. Значения приложения и IP/CIDR не преобразуются в отдельный пользовательский контракт в renderer.

#FirewallControlIpc вызывает #FirewallKillSwitch из Dashboard для ручного отключения, диагностики и экстренного сброса. Экстренный сброс экспортирует текущие правила, выполняет полный reset Windows Firewall, задаёт block inbound/allow outbound и удаляет локальный манифест.

## System Contracts

### Key Contracts

* `KillSwitchLevel` имеет значения `off`, `standard` и `strict`; значение по умолчанию в persistent store: `off`.
* `KillSwitchException` содержит `id`, `type` (`app` или `ip`), `value` и `label`.
* В стандартном режиме блокировка применяется при отсутствии VPN-соединения. В строгом режиме она сохраняется независимо от состояния VPN. В режиме off активный kill-switch снимается.
* Включение сначала сохраняет исходные профили и создаёт разрешения, затем применяет блокировку по умолчанию.
* Операция отключения идемпотентна и возвращает пропуск, если kill-switch уже не активен.
* Состояние активного kill-switch определяется по манифесту или по наличию правил с префиксом `VPNTE-killswitch`.
* Проверка IP/CIDR принимает IPv4 и IPv6 с префиксом от 1 до длины адреса; `0.0.0.0`, `::`, хостнеймы и неподходящие значения отклоняются перед созданием правила.
* Реализация не подтверждает нормативное поведение для потери или сбоя записи манифеста, немедленного применения изменений исключений, проверки пути приложения, удаления правила внешнего прокси, нормализации и импорта. Эти вопросы остаются открытыми в требованиях.

### Integration Contracts

* `#GranularKillSwitch` принимает состояние VPN через `setVpnConnected` и инициализируется путём sing-box через `init`.
* `#KillSwitchSettings` использует IPC-каналы уровня, исключений и выбора приложения, перечисленные в компоненте.
* `#FirewallControlIpc` предоставляет Dashboard IPC для ручного отключения, статуса, reset, health и repair.
* `#FirewallKillSwitch` взаимодействует с Windows Firewall через разрешённый elevated PowerShell и `netsh advfirewall` для полного сброса.
* `FirewallManifest` находится в `userData/firewall-killswitch/manifest.json`; конкретная схема включает `createdAt`, `ruleNames`, `singboxExePath` и `savedProfiles`.

## Architecture Decision Records

### ADR-001: Блокировка через DefaultOutboundAction

**Context:** Явное Block-правило на физическом адаптере блокировало бы также sing-box и разрешённые потоки. Нужна политика, которая оставляет только явно разрешённые направления.

**Decision:** Использовать сохранение текущих исходящих политик, создание Allow-правил и установку DefaultOutboundAction=Block для профилей Domain, Private и Public.

**Consequences:** Разрешения должны быть созданы до применения Block. Ошибки создания разрешений, записи манифеста и отката могут оставить систему в неопределённом состоянии и требуют отдельного решения.

### ADR-002: Экстренный полный сброс Firewall

**Context:** Обычное удаление правил может не восстановить сеть при повреждённом или неполном состоянии Firewall.

**Decision:** По явному подтверждению пользователя экспортировать текущие правила, выполнить `netsh advfirewall reset`, установить block inbound/allow outbound, удалить манифест и вернуть результат с путём резервной копии.

**Consequences:** Полный сброс удаляет также правила сторонних приложений. Резервная копия сохраняется для диагностики и возможного ручного восстановления.