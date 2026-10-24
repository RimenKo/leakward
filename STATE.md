# STATE — leakward (@rimenko-dev/leakward)
updated: 2026-10-16 05:20 (by: nightly)
stale: true

## Цель
npm-утилита для сканирования проектов на утечку секретов через AI-инструменты (Claude Code, Cursor, Copilot, Windsurf) перед `npm publish` и `git push`.

## Сейчас
- Версия: **0.1.14** (опубликована на npm)
- Пакет: `@rimenko-dev/leakward` (канон), `leakward` (unscoped для `npx leakward`)
- Alias: `@rimenko-dev/aiguard@0.1.14` deprecated, те же bin `leakward` + `aiguard`
- Запуск: `leakward` (глобально) или `npx leakward` / `npx @rimenko-dev/leakward`
- GitHub: https://github.com/RimenKo/leakward (старый RimenKo/aiguard → 301)
- Функции: 56+ паттернов, BIP39, Base64, git-история, Claude hook, output hook с редактированием секретов (поддержка MCP tool output, Bash), `--npm-only`, `--staged`, `leakward:allow` / `aiguard:allow` / `gitleaks:allow`, `.leakwardignore` / `.aiguardignore`
- Тесты: 66 + 53 + 33 (все зелёные)
- Локальные хуки: `~/.claude/bin/leakward-guard.sh`, `weekly-leakward-scan.sh`, launchd `com.claude.weekly-leakward-scan`
- Текущая работа: улучшение detection паттернов (KNOWN_GAPS, Azure/JWT, type annotations), redaction (quoted-user curl, escaped-space env, sshpass, redis-cli, zip, 7z, request-body), MCP tool output в output-hook

## Сделано (последние 5, с датами)
- 2026-08-19 — Ребрендинг публичных поверхностей aiguard → leakward, alias сохранён, опубликован 0.1.14 с коммитом f8a5c0b
- 2026-08-16 — feat: aiguard:allow и .aiguardignore (f8a5c0b)
- 2025-07-03 — Добавлен `.gitignore` для предотвращения утечки секретов
- 2025-07-03 — Версия 0.1.13: флаг `--npm-only`, поддержка AWS ASIA-ключей, сканирование по содержимому
- 2025-07-02 — Поддержка MultiEdit в Claude hook, сканирование `new_source`

## Дальше (1-3 шага)
1. Дальнейшие улучшения сканирования по приоритету

## Блокеры
Нет

## Ссылки
- npm: https://www.npmjs.com/package/@rimenko-dev/leakward
- npm alias: https://www.npmjs.com/package/@rimenko-dev/aiguard
- GitHub: https://github.com/RimenKo/leakward
