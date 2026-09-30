#!/usr/bin/env node
'use strict';

// Hook script for Claude Code PostToolUse (Bash).
// The write-time hook guards what goes INTO files; this one guards what comes
// OUT of commands: a `creds.sh get ...` or `cat .env` prints the secret into
// the tool result, and from there into the transcript and any logs of it.
// A PostToolUse hook cannot block (the command already ran), so it rewrites
// the result via hookSpecificOutput.updatedToolOutput with each secret
// replaced by a [REDACTED:<name>] marker.
//
// Fail-open on purpose: an error here must not hide the command's real output
// from the user. Failures are reported on stderr (non-blocking hook error).

const path = require('path');
const fs = require('fs');

let SECRET_PATTERNS;
try {
  ({ SECRET_PATTERNS } = require(path.join(__dirname, '..', 'src', 'patterns')));
} catch (err) {
  process.stderr.write(`leakward-output: не удалось загрузить паттерны — ${err.message}\nВывод НЕ проверен.\n`);
  process.exit(1);
}

// Skipped for output redaction: prose is full of dictionary words, so the
// BIP39 patterns would mangle ordinary text, and the base64 pattern flags
// every long hash / encoded blob. The write-time hook still covers them.
const SKIP_IN_OUTPUT = /BIP39|Base64/i;

// `"api_key": "value"` / `password: value` as printed by JSON credential
// dumps. The generic patterns above only look at KEY=value shapes, which is
// why a JSON secret store slipped through.
const SECRET_KEY_NAME = '(?:pass(?:word|wd)?|secret|token|api[_-]?key|api[_-]?secret|apikey|private[_-]?key|access[_-]?key|client[_-]?secret|auth)';
const JSON_FIELD = new RegExp(`("[A-Za-z0-9_.-]*${SECRET_KEY_NAME}[A-Za-z0-9_.-]*"\\s*:\\s*")([^"\\\\\\n]{8,})(")`, 'gi');

// 1 MB is far past any real secret; a huge output is not scanned rather than
// slowing every Bash call.
const MAX_TEXT_BYTES = 1024 * 1024;

function redactText(text, hits) {
  let out = text;
  for (const { name, regex, validate } of SECRET_PATTERNS) {
    if (SKIP_IN_OUTPUT.test(name)) continue;
    regex.lastIndex = 0;
    out = out.replace(regex, (m) => {
      if (m.length === 0) return m;
      if (validate) {
        try { if (!validate(m)) return m; } catch (_) { return m; }
      }
      hits.push(name);
      return `[REDACTED:${name}]`;
    });
  }
  out = out.replace(JSON_FIELD, (m, pre, value, post) => {
    if (value.startsWith('[REDACTED')) return m;
    hits.push('secret-like JSON field');
    return `${pre}[REDACTED:secret-like JSON field]${post}`;
  });
  return out;
}

let input;
try {
  input = JSON.parse(fs.readFileSync(0, 'utf8'));
} catch (_) {
  process.exit(0);
}

try {
  const resp = input && input.tool_response;
  if (resp == null) process.exit(0);

  const hits = [];
  let updated;
  if (typeof resp === 'string') {
    if (Buffer.byteLength(resp, 'utf8') > MAX_TEXT_BYTES) process.exit(0);
    updated = redactText(resp, hits);
  } else if (typeof resp === 'object') {
    updated = { ...resp };
    for (const field of ['stdout', 'stderr', 'output', 'content']) {
      if (typeof resp[field] !== 'string') continue;
      if (Buffer.byteLength(resp[field], 'utf8') > MAX_TEXT_BYTES) continue;
      updated[field] = redactText(resp[field], hits);
    }
  } else {
    process.exit(0);
  }

  if (hits.length === 0) process.exit(0);

  const kinds = [...new Set(hits)].join(', ');
  process.stdout.write(JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PostToolUse',
      updatedToolOutput: updated,
      additionalContext: `leakward: в выводе команды скрыты секреты (${kinds}). Значения читай в переменную окружения, а не в stdout.`,
    },
  }));
} catch (err) {
  process.stderr.write(`leakward-output: ошибка при проверке вывода — ${err.message}\nВывод НЕ проверен.\n`);
  process.exit(1);
}
