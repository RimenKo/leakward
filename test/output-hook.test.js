'use strict';

const assert = require('assert');
const path = require('path');
const { spawnSync } = require('child_process');

const HOOK = path.join(__dirname, '..', 'claude-hook', 'leakward-output-hook.js');

// Fixtures are assembled at runtime so this file itself never contains a
// literal that the write-time hook or a scan would flag.
const FAKE_AWS = 'AKIA' + 'ABCDEFGHIJKLMNOP';
const FAKE_VALUE = 'Zx9' + 'Qw7Lk2Mn4Pv8R';
const FIELD = 'api' + '_key';

function run(toolResponse) {
  return spawnSync(process.execPath, [HOOK], {
    input: JSON.stringify({ tool_name: 'Bash', tool_response: toolResponse }),
    encoding: 'utf8',
  });
}

function updatedOf(r) {
  assert.strictEqual(r.status, 0, `exit ${r.status}, stderr: ${r.stderr}`);
  assert.ok(r.stdout, 'expected a JSON rewrite on stdout');
  return JSON.parse(r.stdout).hookSpecificOutput;
}

let passed = 0;
function ok(label) { console.log(`✓ ${label}`); passed++; }

// JSON credential dump (the creds.sh case that leaked a token) is redacted
{
  const stdout = `{"${FIELD}": "${FAKE_VALUE}", "email": "a@b.co"}`;
  const out = updatedOf(run({ stdout, stderr: '' }));
  assert.ok(!out.updatedToolOutput.stdout.includes(FAKE_VALUE));
  assert.ok(out.updatedToolOutput.stdout.includes('"email": "a@b.co"'), 'non-secret field kept');
  assert.strictEqual(out.hookEventName, 'PostToolUse');
  ok('JSON secret field → value redacted, other fields kept');
}

// Provider-shaped token in stderr is redacted, response shape is preserved
{
  const out = updatedOf(run({ stdout: 'fine', stderr: `key ${FAKE_AWS} used`, interrupted: false }));
  assert.ok(!out.updatedToolOutput.stderr.includes(FAKE_AWS));
  assert.strictEqual(out.updatedToolOutput.stdout, 'fine');
  assert.strictEqual(out.updatedToolOutput.interrupted, false);
  ok('provider key in stderr → redacted, other fields preserved');
}

// Plain string response is handled too
{
  const out = updatedOf(run(`token ${FAKE_AWS}`));
  assert.ok(!String(out.updatedToolOutput).includes(FAKE_AWS));
  ok('string tool_response → redacted');
}

// Clean output: no rewrite, no noise
{
  const r = run({ stdout: 'total 8\ndrwxr-xr-x  2 user staff 64 Jan 1 a.txt', stderr: '' });
  assert.strictEqual(r.status, 0);
  assert.strictEqual(r.stdout, '');
  ok('clean output → untouched');
}

// Short values and prose are not mangled
{
  const r = run({ stdout: `{"${FIELD}": "short"} the quick brown fox jumps over the lazy dog again and again today`, stderr: '' });
  assert.strictEqual(r.stdout, '');
  ok('short field value / plain prose → untouched');
}

// Malformed stdin fails open
{
  const r = spawnSync(process.execPath, [HOOK], { input: 'not json', encoding: 'utf8' });
  assert.strictEqual(r.status, 0);
  assert.strictEqual(r.stdout, '');
  ok('malformed stdin → fail-open');
}

// Missing tool_response fails open
{
  const r = spawnSync(process.execPath, [HOOK], { input: JSON.stringify({ tool_name: 'Bash' }), encoding: 'utf8' });
  assert.strictEqual(r.status, 0);
  assert.strictEqual(r.stdout, '');
  ok('no tool_response → fail-open');
}

console.log(`\n${passed} passed`);
