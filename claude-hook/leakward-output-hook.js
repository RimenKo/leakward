#!/usr/bin/env node
'use strict';

// Hook script for Claude Code PostToolUse (Bash and the Playwright/Gmail MCP tools).
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
const os = require('os');

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

// Exact values from the local credential store. Pattern matching cannot see a
// provider key that has no recognisable prefix (a bare 32-char token), so any
// stored secret is also redacted by its literal value, wherever it shows up.
// Values shorter than this are skipped: too many ordinary words would match.
const MIN_KNOWN_SECRET_LEN = 12;
// Narrower than SECRET_KEY_NAME on purpose: a bare "auth" there also matches
// "author_name", and masking a brand name in every output is worse than the
// pattern layer's occasional over-redaction of a JSON dump.
const SECRET_FIELD = /pass(?:word|wd)?|secret|token|api[_-]?key|apikey|private[_-]?key|access[_-]?key|client[_-]?secret|auth[_-]?(?:token|key|hash)/i;

function loadKnownSecrets() {
  const file = process.env.LEAKWARD_CRED_DB || path.join(os.homedir(), '.claude', 'credentials', 'db.json');
  let db;
  try {
    db = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (_) {
    return [];
  }
  const found = new Map();
  const walk = (node, label) => {
    if (node == null) return;
    if (typeof node === 'string') {
      const field = label.split('/').pop();
      if (node.length >= MIN_KNOWN_SECRET_LEN && SECRET_FIELD.test(field) && !found.has(node)) {
        found.set(node, `cred:${label}`);
      }
      return;
    }
    if (typeof node !== 'object') return;
    for (const [k, v] of Object.entries(node)) walk(v, label ? `${label}/${k}` : k);
  };
  walk(db.services || db, '');
  // Longest first so a secret that contains a shorter one is replaced whole.
  return [...found.entries()].sort((a, b) => b[0].length - a[0].length);
}

const KNOWN_SECRETS = loadKnownSecrets();

function redactText(text, hits) {
  let out = text;
  for (const [value, name] of KNOWN_SECRETS) {
    if (!out.includes(value)) continue;
    out = out.split(value).join(`[REDACTED:${name}]`);
    hits.push('stored credential');
  }
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
  // Bash returns {stdout, stderr}; MCP tools (Playwright, Gmail) return
  // content blocks like [{type: 'text', text}] or {content: [...]}. Walking
  // every string keeps whatever shape the tool used and covers both.
  const redactTree = (node) => {
    if (typeof node === 'string') {
      if (Buffer.byteLength(node, 'utf8') > MAX_TEXT_BYTES) return node;
      return redactText(node, hits);
    }
    if (Array.isArray(node)) return node.map(redactTree);
    if (node && typeof node === 'object') {
      const copy = {};
      for (const [k, v] of Object.entries(node)) copy[k] = redactTree(v);
      return copy;
    }
    return node;
  };
  if (typeof resp !== 'string' && typeof resp !== 'object') process.exit(0);
  const updated = redactTree(resp);

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
