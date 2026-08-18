# Карта модулей

## Дерево исходников

```text
src/
├── main/                  Electron main и Windows/VPN домены
│   ├── index.ts            bootstrap, app lifecycle, core IPC wiring
│   ├── tunController.ts    start/stop/recovery TUN runtime
│   ├── tunAdapter.ts       Wintun adapter operations
│   ├── systemNetwork.ts    routes, DNS baseline, rollback
│   ├── firewallKillSwitch.ts firewall policy and recovery
│   ├── physicalAdapterLockdown.ts adapter DNS/IPv6 lockdown
│   ├── vpnProfiles.ts       URI/config parsing and normalization
│   ├── serverPicker.ts      profile selection, import/export, migrations
│   ├── serverGroups.ts      subscription groups and refresh
│   ├── externalProxy.ts     isolated loopback proxy instances
│   ├── diagnostics*.ts      snapshots, leak checks, exports, forensics
│   └── <feature>.ts         one feature service plus its IPC registration
├── preload/                validated renderer-to-main contract
│   └── index.ts             ElectronAPI surface and argument assertions
├── renderer/               React UI only
│   ├── App.tsx              navigation, global state, app-level effects
│   ├── pages/               route-level screens and page data loading
│   ├── components/          reusable product components
│   ├── design-system/       Mac* primitives and visual tokens
│   ├── providers/           React context providers
│   ├── store.ts             Zustand application state
│   └── i18n/                translations and i18n setup
└── shared/                 types/constants used by more than one process
```

## Main-домены

| Домен | Основные файлы | Граница ответственности |
| --- | --- | --- |
| Tunnel runtime | `tunController.ts`, `tunAdapter.ts`, `connectionPlanner.ts`, `managedChildProcess.ts` | Создание и остановка sing-box/TUN, процессные recovery-сценарии |
| Network safety | `systemNetwork.ts`, `firewallKillSwitch.ts`, `physicalAdapterLockdown.ts`, `browserHardening.ts` | Windows baseline, kill-switch, DNS/IPv6 и rollback |
| Profiles | `vpnProfiles.ts`, `serverPicker.ts`, `serverGroups.ts`, `serverProbe.ts` | Нормализация ключей, группы, выбор, health checks, миграции |
| Routing | `smartRoute.ts`, `ruleSetManager.ts`, `domainRouting.ts`, `dnsProfiles.ts` | split routing, rule sets, DNS profiles и пользовательские правила |
| Observability | `appLogger.ts`, `systemDiagnostics.ts`, `leakDiagnostics.ts`, `trafficForensics.ts`, `systemSnapshot.ts` | Логи, диагностика, leak tests, packet forensics и экспорт |
| Automation | `scheduler.ts`, `profileRotation.ts`, `autoPilot.ts`, `adaptiveBypass.ts` | Планировщик, ротация профилей и автоматический recovery/выбор |
| UI support | `notifications.ts`, `themeManager.ts`, `i18n.ts`, `configManager.ts` | Уведомления, тема, локализация и импорт/экспорт настроек |

## IPC-домены

Основной bridge находится в `src/preload/index.ts`. Каналы группируются по префиксу:

- core: `start-tun`, `stop-tun`, `get-tun-status`, `get-settings`, `save-settings`;
- diagnostics/network: `run-*`, `network:*`, `firewall:*`, `system:*`, `get-traffic-*`;
- profiles: `servers:*`, `groups:*`, `server:*`;
- routing: `split-tunnel:*`, `domain-routing:*`, `dns:*`, `smart-route:*`;
- automation/history: `scheduler:*`, `rotation:*`, `connection-history:*`, `traffic-history:*`;
- UI/config: `notifications:*`, `config:*`, `theme:*`.

При добавлении канала меняются три места: реализация handler в main feature-модуле, метод `ElectronAPI`/`exposeInMainWorld` в preload и вызывающий код renderer. Для каждого канала должен существовать тест контракта или feature-тест.

## Правило размещения новых файлов

- Windows/VPN side effect → `src/main/<domain>.ts`.
- IPC registration → рядом с доменным сервисом, функция `register...Handlers`.
- Renderer-only state/view → `src/renderer/pages` или `src/renderer/components`.
- Shared contract → `src/shared`.
- Тест → рядом с исходным файлом, с тем же basename и суффиксом `.test.ts(x)`.
- Документ, объясняющий решение или инвариант → `docs/architecture` или тематический RFC в `docs/`.

