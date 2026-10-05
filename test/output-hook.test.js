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

// A stored credential with no recognisable shape (bare 32-char token) is
// redacted by its exact value, in Bash output and in MCP content blocks
{
  const fs = require('fs');
  const os = require('os');
  const dbFile = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'lw-')), 'db.json');
  const BARE = 'Kq8' + 'Zr2Wm5Xt9Bn3Vc7Ld1Hs4Fg6Jp0Ye';
  const SHORT = 'tiny';
  const BRAND = 'Example Brand Team';
  fs.writeFileSync(dbFile, JSON.stringify({ services: { 'dash.example.io': { [FIELD]: BARE, email: 'a@b.co', password: SHORT, author_name: BRAND } } }));
  const runWithDb = (tool, toolResponse) => spawnSync(process.execPath, [HOOK], {
    input: JSON.stringify({ tool_name: tool, tool_response: toolResponse }),
    encoding: 'utf8',
    env: { ...process.env, LEAKWARD_CRED_DB: dbFile },
  });

  let out = updatedOf(runWithDb('Bash', { stdout: `key is ${BARE} ok`, stderr: '' }));
  assert.ok(!out.updatedToolOutput.stdout.includes(BARE));
  assert.ok(out.updatedToolOutput.stdout.includes('[REDACTED:cred:dash.example.io/' + FIELD + ']'));
  ok('bare stored credential in Bash stdout → redacted by exact value');

  out = updatedOf(runWithDb('mcp__playwright__browser_run_code_unsafe', [{ type: 'text', text: `"result": "${BARE}"` }, { type: 'image', data: 'abc' }]));
  assert.ok(Array.isArray(out.updatedToolOutput));
  assert.ok(!JSON.stringify(out.updatedToolOutput).includes(BARE));
  assert.strictEqual(out.updatedToolOutput[1].type, 'image');
  ok('MCP content array → redacted, structure preserved');

  out = updatedOf(runWithDb('mcp__playwright__browser_snapshot', { content: [{ type: 'text', text: `dialog: remove ${BARE} ?` }], isError: false }));
  assert.ok(!JSON.stringify(out.updatedToolOutput).includes(BARE));
  assert.strictEqual(out.updatedToolOutput.isError, false);
  ok('MCP {content:[...]} object → redacted, other fields preserved');

  const r = runWithDb('Bash', { stdout: `the word ${SHORT} and ${'a@b.co'} stay`, stderr: '' });
  assert.strictEqual(r.status, 0);
  assert.strictEqual(r.stdout, '');
  ok('short stored value / email field are not treated as secrets');

  const rb = runWithDb('Bash', { stdout: `posted by ${BRAND}`, stderr: '' });
  assert.strictEqual(rb.status, 0);
  assert.strictEqual(rb.stdout, '');
  ok('author_name (contains "auth") is not a secret field');
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
