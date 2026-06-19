# Фаза 7: экспериментальный трек AmneziaWG

Приоритет: средний.

## Цель

Провести focused design spike для AmneziaWG или похожей WireGuard-obfuscation
поддержки до того, как тащить это в основной product path.

## Почему это важно

Обычный WireGuard легко fingerprint-ится. AmneziaWG-style mutation может помочь
против UDP signature blocking, но архитектурно это тяжелее, чем parser/config
работа вокруг sing-box.

## Что сделать

- Сравнить варианты интеграции:
  - native dedicated execution path;
  - second engine / sidecar;
  - import-only compatibility;
  - отложить до CoreAdapter.
- Собрать lab matrix:
  - known WireGuard signature blocking;
  - blocked QUIC;
  - mixed IPv4/IPv6;
  - mobile hotspot/NAT networks.
- Описать packaging, driver и cleanup risks на Windows.

## Вероятные зоны влияния

Прямую реализацию пока не предполагаем. Исследование, скорее всего, затронет:

- `src/main/tunController.ts`
- `src/main/tunAdapter.ts`
- `src/main/systemDiagnostics.ts`
- `src/main/serverPicker.ts`
- `electron-builder.yml`
- `resources/`

## Чеклист реализации

1. Описать candidate runtimes и licensing/packaging constraints.
2. Описать Windows privileges и cleanup model.
3. Сделать prototype вне основного tunnel path.
4. Сравнить diagnostics requirements с текущими sing-box diagnostics.
5. Решить, ждать ли CoreAdapter.

## Проверка готовности

- Написан architecture decision.
- Есть lab result table.
- Нет merge в production code без cleanup и diagnostics plan.

## Что не делать в этой фазе

- Не встраивать не изолированный WireGuard sidecar в основной TUN lifecycle.
- Не ослаблять kill-switch или adapter cleanup.
- Не считать AmneziaWG заменой sing-box-first фазам.
