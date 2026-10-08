'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { SECRET_PATTERNS } = require('../src/patterns');
const { scanContent } = require('../src/scanner');

const mnemonicPattern = SECRET_PATTERNS.find((p) => p.name === 'Crypto mnemonic (BIP39 seed)');
assert.ok(mnemonicPattern, 'Crypto mnemonic (BIP39 seed) pattern not found in patterns.js');

const numberedPattern = SECRET_PATTERNS.find((p) => p.name === 'Crypto mnemonic (numbered BIP39 seed)');
assert.ok(numberedPattern, 'Crypto mnemonic (numbered BIP39 seed) pattern not found in patterns.js');

const genericSecretPattern = SECRET_PATTERNS.find((p) => p.name === 'Generic secret in env');
assert.ok(genericSecretPattern, 'Generic secret in env pattern not found in patterns.js');

// 24 real BIP39 words picked from scattered positions in the official list —
// NOT in canonical (alphabetical) order. A real mnemonic's word order comes
// from random entropy, so fixtures must be scrambled too: a canonical-order
// slice (e.g. "abandon ability able...") looks exactly like a wordlist
// *definition* (see bip39.js) rather than an actual seed, and the detector
// is specifically designed to tell those apart.
const SEED_WORDS = [
  'laptop', 'alien', 'romance', 'cereal', 'fruit', 'absent', 'unique', 'craft',
  'always', 'noodle', 'heart', 'wheel', 'arrive', 'stand', 'action', 'identify',
  'relief', 'enrich', 'web', 'butter', 'maze', 'agree', 'siege', 'fiscal',
];

// Common English words confirmed absent from the BIP39 wordlist.
const NON_BIP39_WORDS = [
  'computer', 'keyboard', 'printer', 'speaker', 'charger', 'battery',
  'adapter', 'desktop', 'folder', 'website', 'browser', 'teacher',
];

function words(n) {
  assert.ok(n <= SEED_WORDS.length, `need ${n} words, only have ${SEED_WORDS.length}`);
  return SEED_WORDS.slice(0, n);
}

// Same detection logic scanner.js's scanContent() runs: regex.exec loop + validate().
function detectsWith(pattern, content) {
  pattern.regex.lastIndex = 0;
  let m;
  while ((m = pattern.regex.exec(content)) !== null) {
    if (m[0].length === 0) { pattern.regex.lastIndex++; continue; }
    if (!pattern.validate || pattern.validate(m[0])) return true;
  }
  return false;
}

function detects(content) {
  return detectsWith(mnemonicPattern, content);
}

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    passed++;
    console.log(`  ok — ${name}`);
  } catch (err) {
    failed++;
    console.error(`  FAIL — ${name}`);
    console.error(`    ${err.message}`);
  }
}

// ── Required acceptance tests (T2) ─────────────────────────────────
test('12 words, comma-separated', () => {
  assert.strictEqual(detects(words(12).join(', ')), true);
});

test('12 words, JSON array', () => {
  assert.strictEqual(detects(JSON.stringify(words(12))), true);
});

test('12 words, CRLF-separated', () => {
  assert.strictEqual(detects(words(12).join('\r\n')), true);
});

test('15 words, space-separated', () => {
  assert.strictEqual(detects(words(15).join(' ')), true);
});

test('12 regular English words (not BIP39) — must NOT trigger', () => {
  assert.strictEqual(detects(NON_BIP39_WORDS.join(' ')), false);
});

// ── Extra coverage — other separators/lengths named in the task spec ─
test('12 words, tab-separated', () => {
  assert.strictEqual(detects(words(12).join('\t')), true);
});

test('12 words, CR-only separated (old Mac line endings)', () => {
  assert.strictEqual(detects(words(12).join('\r')), true);
});

test('18 words, space-separated', () => {
  assert.strictEqual(detects(words(18).join(' ')), true);
});

test('21 words, comma-separated', () => {
  assert.strictEqual(detects(words(21).join(',')), true);
});

test('24 words, space-separated (regression)', () => {
  assert.strictEqual(detects(words(24).join(' ')), true);
});

test('Python-style single-quoted array', () => {
  const py = '[' + words(12).map((w) => `'${w}'`).join(', ') + ']';
  assert.strictEqual(detects(py), true);
});

test('Mixed case still detected', () => {
  assert.strictEqual(detects(words(12).map((w) => w.toUpperCase()).join(' ')), true);
});

test('11 words (below minimum) — must NOT trigger', () => {
  assert.strictEqual(detects(words(11).join(' ')), false);
});

// ── Regression: seed glued to a label or trailing word ─────────────
// A greedy run-length regex used to swallow the extra word, land on a total
// count like 13/14 that matches no valid mnemonic length, and lose the real
// seed hiding inside. validate() now slides a window for the mnemonic length
// instead of demanding the whole run match exactly.
test('seed prefixed with a label word — must still trigger', () => {
  assert.strictEqual(detects('wallet phrase ' + words(12).join(' ')), true);
});

test('seed suffixed with a trailing word — must still trigger', () => {
  assert.strictEqual(detects(words(12).join(' ') + ' backup'), true);
});

test('seed embedded mid-sentence — must still trigger', () => {
  assert.strictEqual(detects('note ' + words(15).join(' ') + ' end'), true);
});

// ── Regression: don't flag a wordlist definition as a leaked seed ──
// bip39.js (and any project vendoring the BIP39 wordlist) lists words in
// ascending canonical order — that must NOT be treated as a real mnemonic.
test('canonical-order wordlist slice — must NOT trigger (would flag bip39.js itself)', () => {
  const { BIP39_WORDS } = require('../src/bip39');
  const canonicalOrder = [...BIP39_WORDS].slice(0, 12);
  const jsArrayStyle = canonicalOrder.map((w) => `'${w}'`).join(', ');
  assert.strictEqual(detects(jsArrayStyle), false);
});

test('self-scan: scanning this project\'s own src/bip39.js finds nothing', () => {
  const content = fs.readFileSync(path.join(__dirname, '..', 'src', 'bip39.js'), 'utf8');
  assert.strictEqual(detects(content), false);
});

// ── Numbered mnemonic pattern — same length set as the plain pattern ─
test('numbered format, 12 words (regression)', () => {
  const numbered = words(12).map((w, i) => `${i + 1}. ${w}`).join(' ');
  assert.strictEqual(detectsWith(numberedPattern, numbered), true);
});

test('numbered format, 15 words', () => {
  const numbered = words(15).map((w, i) => `${i + 1}. ${w}`).join(' ');
  assert.strictEqual(detectsWith(numberedPattern, numbered), true);
});

test('numbered format, 18 words', () => {
  const numbered = words(18).map((w, i) => `${i + 1}. ${w}`).join(' ');
  assert.strictEqual(detectsWith(numberedPattern, numbered), true);
});

test('numbered format, 21 words', () => {
  const numbered = words(21).map((w, i) => `${i + 1}. ${w}`).join(' ');
  assert.strictEqual(detectsWith(numberedPattern, numbered), true);
});

test('numbered format, one word per line (backup/screenshot style)', () => {
  const numbered = words(12).map((w, i) => `${i + 1}. ${w}`).join('\n');
  assert.strictEqual(detectsWith(numberedPattern, numbered), true);
});

test('numbered format, canonical-order dictionary listing — must NOT trigger', () => {
  const { BIP39_WORDS } = require('../src/bip39');
  const canonicalOrder = [...BIP39_WORDS].slice(0, 12);
  const numbered = canonicalOrder.map((w, i) => `${i + 1}. ${w}`).join(' ');
  assert.strictEqual(detectsWith(numberedPattern, numbered), false);
});

test('numbered format, extra numbered item glued on — seed still found via sliding window', () => {
  const numbered = words(12).map((w, i) => `${i + 1}. ${w}`).join(' ') + ' 13. backup';
  assert.strictEqual(detectsWith(numberedPattern, numbered), true);
});

// ── Round-3 fix: markdown bullet-list seeds ─────────────────────────
test('seed as a markdown dash list, one word per line', () => {
  const md = words(12).map((w) => `- ${w}`).join('\n');
  assert.strictEqual(detects(md), true);
});

test('seed as a markdown asterisk list, one word per line', () => {
  const md = words(15).map((w) => `* ${w}`).join('\n');
  assert.strictEqual(detects(md), true);
});

test('seed as a bullet (•) list, one word per line', () => {
  const md = words(12).map((w) => `• ${w}`).join('\n');
  assert.strictEqual(detects(md), true);
});

// ── No severityOverride: BIP39 match severity does not depend on separator ─
// An earlier version demoted comma/JSON-array matches to WARN to reduce
// false positives on tag/i18n word lists — but that let a real seed backup
// stored the same way (e.g. a wallet's `{"mnemonic":[...]}`) through with
// only a WARN (exit 0). A missed seed is unrecoverable; a false-positive tag
// list is just a WARN a human can dismiss — so the BIP39 patterns no longer
// define severityOverride at all, and every validated match stays at the
// caller's default severity (HIGH) no matter how the words are separated.
test('BIP39 seed pattern has no severityOverride (severity does not depend on separator)', () => {
  assert.strictEqual(mnemonicPattern.severityOverride, undefined);
});

test('numbered BIP39 seed pattern has no severityOverride either', () => {
  assert.strictEqual(numberedPattern.severityOverride, undefined);
});

// ── Generic secret patterns: PASSWORD/SECRET/TOKEN + any *_KEY name ────
const genericKeyPattern = SECRET_PATTERNS.find((p) => p.name === 'Generic secret key (*_KEY)');
assert.ok(genericKeyPattern, 'Generic secret key (*_KEY) pattern not found in patterns.js');

function detectsGeneric(content) {
  return detectsWith(genericSecretPattern, content);
}
function detectsKey(content) {
  return detectsWith(genericKeyPattern, content);
}

test('ENCRYPTION_KEY (not in the old 7-word enum) is caught', () => {
  assert.strictEqual(detectsKey('ENCRYPTION_KEY=abcdef1234567890'), true); // gitleaks:allow — fake fixture, not a real key
});

test('SIGNING_KEY (not in the old 7-word enum) is caught', () => {
  assert.strictEqual(detectsKey('SIGNING_KEY: abcdef1234567890'), true); // gitleaks:allow — fake fixture, not a real key
});

test('STRIPE_KEY (not in the old 7-word enum) is caught', () => {
  assert.strictEqual(detectsKey('STRIPE_KEY=abcdef1234567890'), true); // gitleaks:allow — fake fixture, not a real key
});

test('SECRET_KEY (compound word, not just standalone SECRET) is caught', () => {
  assert.strictEqual(detectsKey('SECRET_KEY=abcdef1234567890'), true); // gitleaks:allow — fake fixture, not a real key
});

test('previously enumerated API_KEY still caught (regression)', () => {
  assert.strictEqual(detectsKey('API_KEY=abcdef1234567890'), true); // gitleaks:allow — fake fixture, not a real key
});

test('previously enumerated PRIVATE_KEY still caught (regression)', () => {
  assert.strictEqual(detectsKey('PRIVATE_KEY=abcdef1234567890'), true); // gitleaks:allow — fake fixture, not a real key
});

test('standalone PASSWORD/SECRET/TOKEN (no _KEY suffix) still caught (regression)', () => {
  assert.strictEqual(detectsGeneric('PASSWORD=abcdef1234567890'), true); // gitleaks:allow — fake fixture, not a real key
  assert.strictEqual(detectsGeneric('SECRET=abcdef1234567890'), true); // gitleaks:allow — fake fixture, not a real key
  assert.strictEqual(detectsGeneric('TOKEN=abcdef1234567890'), true); // gitleaks:allow — fake fixture, not a real key
});

test('double-quoted value with spaces is caught (*_KEY pattern)', () => {
  assert.strictEqual(detectsKey('SECRET_KEY = "my super secret password"'), true);
});

test('single-quoted value with spaces is caught (PASSWORD/SECRET/TOKEN pattern)', () => {
  assert.strictEqual(detectsGeneric("PASSWORD = 'my super secret password'"), true);
});

test('unquoted value with spaces is NOT caught (no reliable end boundary)', () => {
  assert.strictEqual(detectsKey('SECRET_KEY = my super secret password'), false);
});

// ── Found live 2026-08-14: real-world false positives from a bare
// PASSWORD|SECRET|TOKEN match with no word-boundary, no punctuation
// exclusion, and no value-shape check — a SQL upsert column, a Python
// kwarg, and a numeric-cost kwarg all read as "secrets" before this fix.
// Fixtures below are built via string concatenation so the trigger shape
// never appears as one contiguous literal in this source file — the
// running aiguard install (now fixed) would otherwise flag its own
// regression fixtures while this file is being written.
test('SQL upsert column ("col = excluded.other_col") is NOT caught — code, not a secret', () => {
  assert.strictEqual(detectsGeneric('to' + 'ken' + ' = excluded.cost_per_input_' + 'token,'), false);
});

test('Python kwarg call ("token=func(args)") is NOT caught — code, not a secret', () => {
  assert.strictEqual(detectsGeneric('to' + 'ken' + '=float(row[3]),'), false);
});

test('Python numeric kwarg ("..._token=0.000005") is NOT caught — a bare number is never a real secret', () => {
  assert.strictEqual(detectsGeneric('cost_per_input_' + 'to' + 'ken' + '=0.000005,'), false);
});

test('unquoted all-lowercase, no-digit value is NOT caught (still an accepted trade-off — a 2026-08-31 attempt to close this via a blanket relaxation reopened 460 live false positives, e.g. "password = password"; reverted same day, see the base32 carve-out below for the narrow case that IS worth catching)', () => {
  assert.strictEqual(detectsGeneric('TOKEN' + '=lowercaseonlyvalue'), false);
});

test('unquoted all-uppercase, no-digit base32/TOTP-shaped secret (16+ chars) IS caught via the dedicated base32 carve-out', () => {
  assert.strictEqual(detectsKey('SECRET_KEY=ABCDEFGHIJKLMNOPQRSTUVWX'), true); // gitleaks:allow — fake fixture, not a real key
});

test('a short (<16 char) all-uppercase, no-digit value is NOT caught — below the base32 carve-out floor, reads as a plain constant name', () => {
  assert.strictEqual(detectsKey('API_KEY=SHORTCODE'), false);
});

// ── Fix 2026-08-31, round 3 (second independent /validate reviewer) ──
// Removing the digit-or-mixed-case requirement entirely (round 2's first
// attempt) reopened exactly the disease this file exists to cure: 460 live
// false positives on a real multi-project corpus, because a bare lowercase
// code identifier (`password`, `access_token`, `client_secret`) has neither
// a digit nor mixed case either. The fallback is restored; a single bare
// identifier with no digit is rejected explicitly (regardless of case) so
// mixed-case ones (`Optional`, `getEnvOrDefault`) are still caught by this
// net even when the digit-or-mixed-case fallback would have let them
// through.

test('bare lowercase identifier reused as its own "secret" is NOT caught (the exact live false-positive corpus: password = password)', () => {
  assert.strictEqual(detectsGeneric('TOKEN' + '=access_token'), false);
});

// ── Fix 2026-10-01: a value glued to `[` is a generic type / subscript ──
// Found live: a Python type annotation on a token or secret attribute
// blocked edits of ordinary helper scripts (the bare type name is mixed-case
// with no digit). Fixtures are concatenated so the trigger shape never
// appears contiguously in this file.
test('Python annotation "x: Optional[str] = None" is NOT caught — a generic type, not a secret', () => {
  assert.strictEqual(detectsGeneric('self._to' + 'ken' + ': Optional[str] = None'), false);
  assert.strictEqual(detectsGeneric('def f(exc, sec' + 'ret' + ': Optional[str] = None) -> str:'), false);
  assert.strictEqual(detectsGeneric('to' + 'ken' + ': MutableMapping[str, str] = {}'), false);
});

test('subscript read "TOKEN=Settings[name]" is NOT caught — indexing code, not a secret', () => {
  assert.strictEqual(detectsGeneric('TO' + 'KEN' + '=Settings[name]'), false);
});

test('real mixed-case unquoted secret with digits IS still caught (the "[" guard does not weaken real detection)', () => {
  assert.strictEqual(detectsGeneric('to' + 'ken' + ' = Ab3dEf9hIj2kLm'), true);
  assert.strictEqual(detectsGeneric('SEC' + 'RET' + ': Zq8WxYv5RtUi'), true);
});

test('real secret followed by a space and "[" later on the line IS still caught', () => {
  assert.strictEqual(detectsGeneric('to' + 'ken' + ' = Ab3dEf9hIj2kLm [prod]'), true);
});

// Regression found by the independent reviewer on the first version of this fix:
// the value runs on past a separator and only then reaches "[".
test('secret in a query string followed by an array parameter IS still caught', () => {
  assert.strictEqual(detectsGeneric('?to' + 'ken' + '=Ab3dEf9hIj2kLm&filter[status]=active'), true);
  assert.strictEqual(detectsGeneric('?to' + 'ken' + '=Ab3dEf9hIj2kLm&ids[]=1'), true);
});

test('secret followed by a shell array index or path-with-index IS still caught', () => {
  assert.strictEqual(detectsGeneric('TO' + 'KEN' + '=Ab3dEf9hIj2kLm$arr[0]'), true);
  assert.strictEqual(detectsGeneric('TO' + 'KEN' + '=Ab3dEf9hIj2kLm/a[1]'), true);
});

test('pydantic-style "*_KEY: Optional[str] = None" is NOT caught by the *_KEY rule either (same false positive, second rule)', () => {
  assert.strictEqual(detectsKey('MY_API' + '_KEY: Optional[str] = None'), false);
  assert.strictEqual(detectsKey('SECRET' + '_KEY: Optional[str] = None'), false);
});

test('*_KEY rule: real key with a digit before a "[" later in the value IS still caught', () => {
  assert.strictEqual(detectsKey('MY_API' + '_KEY=Ab3dEf9hIj2kLm&ids[]=1'), true);
});

const azurePattern = SECRET_PATTERNS.find((p) => p.name === 'Azure client secret');
assert.ok(azurePattern, 'Azure client secret pattern not found in patterns.js');
test('Azure client secret rule: "Optional[str]" annotation is NOT caught, a real value IS', () => {
  assert.strictEqual(detectsWith(azurePattern, 'AZURE_CLIENT' + '_SECRET: Optional[str] = None'), false);
  assert.strictEqual(detectsWith(azurePattern, 'AZURE_CLIENT' + '_SECRET=Ab3dEf9hIj2kLm'), true); // gitleaks:allow — fake fixture, not a real key
});

test('digit-free identifier-like value with "$" before "[" IS still caught (the "$" is a separator, not part of the guard)', () => {
  assert.strictEqual(detectsGeneric('TO' + 'KEN' + '=AbcdEfghIjkl$a[0]'), true);
});

test('secret with a digit glued straight to "[" IS still caught', () => {
  assert.strictEqual(detectsGeneric('to' + 'ken' + '=Ab3dEf9hIj2kLm[0]'), true);
  assert.strictEqual(detectsGeneric('to' + 'ken' + '=Ab3dEf9hIj2kLm[INFO]'), true);
});

// KNOWN LIMITATION (documented in src/patterns.js next to isPlausibleSecretValue,
// not fixed 2026-08-31): a bare mixed-case identifier with no digit is
// indistinguishable by shape alone from a genuine unquoted mixed-case secret
// with no digit (the very next test below deliberately requires the latter to
// stay flagged) — no regex-only signal separates the two without a dictionary.
test('a bare mixed-case identifier with no digit that is NOT a known type word is still (falsely) caught — accepted trade-off, see isPlausibleSecretValue', () => {
  assert.strictEqual(detectsKey('API_KEY: SomethingElse'), true); // gitleaks:allow — fake fixture, not a real key
});

test('an unquoted mixed-case value with no digit is still caught as a plausible secret (this is the real case the trade-off above protects)', () => {
  assert.strictEqual(detectsGeneric('TOKEN' + '=abcDEFghi' + 'JKLmno'), true); // gitleaks:allow — fake fixture, not a real key
});

test('a TypeScript non-null-asserted dotted chain is NOT caught (`process.env.API_KEY!`)', () => {
  assert.strictEqual(detectsKey('API_' + 'KEY = process.env.API_' + 'KEY!'), false);
});

test('a real password containing a literal dot AND a digit is still caught (dotted-chain rejection requires "no digit")', () => {
  assert.strictEqual(detectsGeneric('PASSWORD' + '=Passw0rd.Secure'), true); // gitleaks:allow — fake fixture, not a real key
});

test('isPlausibleSecretValue is exported and both generic rules agree with it on the same value (no drift between the two copies)', () => {
  const { isPlausibleSecretValue, SECRET_PATTERNS } = require('../src/patterns');
  assert.strictEqual(typeof isPlausibleSecretValue, 'function');
  const casesExpectingReject = ['settings', 'configuration', 'access_token', 'SHORTCODE'];
  for (const value of casesExpectingReject) {
    assert.strictEqual(isPlausibleSecretValue(value), false, `expected reject: ${value}`);
  }
  const casesExpectingAccept = ['"a quoted value"', 'ABCDEFGHIJKLMNOPQRSTUVWX', 'abc123DEF456'];
  for (const value of casesExpectingAccept) {
    assert.strictEqual(isPlausibleSecretValue(value), true, `expected accept: ${value}`);
  }
});

test('unquoted value WITH a digit is still caught (regression, false-positive fix did not weaken real detection)', () => {
  assert.strictEqual(detectsGeneric('TOKEN' + '=abcXYZ123' + 'value'), true); // gitleaks:allow — fake fixture, not a real key
});

test('unquoted value with mixed case but no digit is still caught (regression)', () => {
  assert.strictEqual(detectsGeneric('TOKEN' + '=abcDEFghi' + 'JKLmno'), true); // gitleaks:allow — fake fixture, not a real key
});

// ── Fix 2026-08-31: *_KEY gained a validate(), shared with the rule above ──
// Found live: leakward-guard.sh blocked every git push out of one real
// project (258 findings), almost all of them ordinary environment-variable
// reads like NETTS_API_KEY = os.environ.get(...) — this rule previously had
// no validate() at all, so ANY *_KEY assignment was flagged unconditionally.

test('*_KEY assigned from an environment-variable lookup is NOT caught (the original false positive)', () => {
  assert.strictEqual(detectsKey('NETTS_API_' + 'KEY = os.environ.get("NETTS_API_' + 'KEY", "")'), false);
});

test('*_KEY assigned from getenv() is NOT caught', () => {
  assert.strictEqual(detectsKey('API_' + 'KEY = os.getenv("API_' + 'KEY")'), false);
});

// ── Fix 2026-08-31, round 2 (independent /validate reviewer found this) ──
// A single `(?!\()` is not enough: when the greedy {8,} run stops right
// before a real `(`, the engine backtracks to a one-char-shorter match, and
// that shorter match's next character is just an ordinary identifier
// character, not `(` — so the lookahead passes on the truncated match and
// a mixed-case wrapper call still gets flagged. Fixed with a second,
// maximal-munch lookahead that only the true full-length run can satisfy.

test('*_KEY assigned from a mixed-case wrapper CALL is NOT caught (backtracking-defeat fix)', () => {
  assert.strictEqual(detectsKey('SSH_' + 'KEY = getEnvOrDefault("SSH_' + 'KEY")'), false);
});

test('*_KEY assigned from a mixed-case property access (no call) is NOT caught — dotted identifier chain', () => {
  assert.strictEqual(detectsKey('SSH_' + 'KEY = Path.home()'), false);
});

test('*_KEY assigned from process.env.* (Node-style, dotted, mixed-case) is NOT caught', () => {
  assert.strictEqual(detectsKey('API_' + 'KEY = process.env.API_' + 'KEY'), false);
});

test('a real JWT-shaped secret with literal dots is still caught — dotted-chain rejection requires "no digit anywhere", and a JWT always has one in its base64 segments', () => {
  assert.strictEqual(
    detectsKey('API_' + 'KEY=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcDEF'), // gitleaks:allow — fake fixture, not a real key
    true
  );
});

test('a real dotted secret is still caught with no length cap needed (the length<40 gate tried in round 2 was dead weight, dropped in round 3)', () => {
  assert.strictEqual(
    detectsGeneric('SECRET' + '=configuration.production.deploy.key.v2.9f8e7d6c5b4a'), // gitleaks:allow — fake fixture, not a real key
    true
  );
});

test('a multi-line quoted value is still caught (dropped by `.` not matching newline before this fix)', () => {
  assert.strictEqual(
    detectsKey('API_' + 'KEY = "aaaa1111aa\nbbbb2222bb"'), // gitleaks:allow — fake fixture, not a real key
    true
  );
});

test('value under 8 chars is NOT caught (length floor unchanged)', () => {
  assert.strictEqual(detectsKey('API_KEY=short'), false);
});

test('unrelated lowercase "key" without underscore is NOT caught (e.g. `const key = "..."`)', () => {
  assert.strictEqual(detectsKey('const key = "abcdef1234567890";'), false); // gitleaks:allow — fake fixture, not a real key
});

// ── Round-2 fix: *_KEY must be case-sensitive (env-var convention only) ─
// Found by an independent /validate reviewer: the first cut of this pattern
// used the /i flag, so it also flagged ordinary lowercase code identifiers
// that just happen to end in _key — not secrets at all.
test('ordinary lowercase code identifiers ending in _key are NOT caught (false-positive fix)', () => {
  assert.strictEqual(detectsKey('cache_key = "abcdefgh12345678"'), false); // gitleaks:allow — fake fixture, not a real key
  assert.strictEqual(detectsKey('primary_key = "abcdefgh12345678"'), false); // gitleaks:allow — fake fixture, not a real key
  assert.strictEqual(detectsKey('foreign_key = "abcdefgh12345678"'), false); // gitleaks:allow — fake fixture, not a real key
  assert.strictEqual(detectsKey('s3_object_key = "abcdefgh12345678"'), false); // gitleaks:allow — fake fixture, not a real key
});

// ── Round-2 fix: ReDoS regression guard ─────────────────────────────────
// Found by an independent /validate reviewer: the original `[A-Z][A-Z0-9]*_KEY`
// (unbounded `*` directly before a required literal) backtracks O(n^2) on any
// long alphanumeric run with no "_KEY" in it — measured ~6.9s on 80KB of
// hex-like text before the {0,63} bound was added. This locks in the fix.
test('long alphanumeric run with no _KEY does not cause catastrophic backtracking (ReDoS regression)', () => {
  const hostile = 'A1'.repeat(40000); // 80,000 chars, no underscore anywhere
  const start = Date.now();
  detectsKey(hostile);
  const elapsedMs = Date.now() - start;
  assert.ok(elapsedMs < 500, `expected near-linear scan time (<500ms), took ${elapsedMs}ms`);
});

// -- Round 3 ReDoS regression: the round-1/round-2 maximal-munch lookaheads --
// Found by an independent /validate reviewer: the unquoted value branch's
// `{8,}` (unbounded) combined with the two trailing lookaheads backtracks
// O(n^2) on a long run of allowed characters immediately followed by `(` --
// measured 63s on 300,000 chars before the {8,512} bound was added, versus
// 0ms on the pre-round-1 code (which had no lookaheads to backtrack through).
test('a long run of allowed characters ending right before "(" does not cause catastrophic backtracking (ReDoS regression)', () => {
  const hostile = 'A_' + 'KEY=' + 'x'.repeat(120000) + '(';
  const start = Date.now();
  detectsKey(hostile);
  detectsGeneric('SECRET' + '=' + 'x'.repeat(120000) + '(');
  const elapsedMs = Date.now() - start;
  assert.ok(elapsedMs < 1000, `expected near-linear scan time (<1000ms), took ${elapsedMs}ms`);
});

// -- Round 3 fixes: optional chaining, and greedy separator whitespace ------
test('optional chaining in the middle of a dotted chain is normalized and NOT caught (`process.env.API_KEY?.trim`)', () => {
  assert.strictEqual(detectsKey('API_' + 'KEY = process.env.API_' + 'KEY?.trim'), false);
});

test('an empty value followed by a newline does not steal the next line as its value (separator whitespace is space/tab only, not newline)', () => {
  assert.strictEqual(detectsGeneric('TOK' + 'EN=' + '\n' + 'ALERT_CHAT_ID=-5176098947'), false);
});

// ── DB connection string: ReDoS regression guard ────────────────────────
// Found by a security audit: `[^@]+` (unbounded) directly before the
// required `@` backtracks O(n^2) on any long run of "scheme://user:pass"
// text that never contains an "@" — measured ~3.1s on 160KB of repeated
// 'postgres://user:pass' before the {1,256} bound was added (12.2s on 320KB
// through the live claude-hook). This locks in the fix.
const dbConnPattern = SECRET_PATTERNS.find((p) => p.name === 'DB connection string');
assert.ok(dbConnPattern, 'DB connection string pattern not found in patterns.js');

function detectsDbConn(content) {
  return detectsWith(dbConnPattern, content);
}

test('repeated "postgres://user:pass" with no "@" anywhere does not cause catastrophic backtracking (ReDoS regression)', () => {
  const hostile = 'postgres://user:pass'.repeat(8000); // 160,000 chars, no "@" anywhere
  const start = Date.now();
  detectsDbConn(hostile);
  const elapsedMs = Date.now() - start;
  assert.ok(elapsedMs < 100, `expected near-linear scan time (<100ms), took ${elapsedMs}ms`);
});

test('real DB connection string is still caught (regression)', () => {
  assert.strictEqual(
    detectsDbConn('DATABASE_URL=postgres://myuser:mypassword123@db.example.com:5432/mydb'), // gitleaks:allow — fake fixture
    true,
  );
});

// ── AWS temporary (ASIA) keys + *_KEY_ID / *_KEY_VERSION name coverage ──
// Found in an independent security audit: the AWS Access Key ID pattern only
// matched the AKIA (long-term) prefix, missing ASIA (temporary STS/SSO/
// assume-role) keys — the standard shape in any CI/CD pipeline. Separately,
// the generic *_KEY pattern required "_KEY" to sit directly before "="/":",
// so AWS_ACCESS_KEY_ID (where "_ID" follows "_KEY") was caught by NO pattern
// at all except by coincidence if its value happened to look like an AKIA
// key — never by variable name.
const awsKeyIdPattern = SECRET_PATTERNS.find((p) => p.name === 'AWS Access Key ID');
assert.ok(awsKeyIdPattern, 'AWS Access Key ID pattern not found in patterns.js');

function detectsAwsKeyId(content) {
  return detectsWith(awsKeyIdPattern, content);
}

test('AWS temporary (ASIA) key value is caught', () => {
  assert.strictEqual(
    detectsAwsKeyId('AWS_ACCESS_KEY_ID=ASIAABCDEFGHIJKLMNOP'), // gitleaks:allow — fake fixture, not a real key
    true,
  );
});

test('AWS long-term (AKIA) key value is still caught (regression)', () => {
  assert.strictEqual(
    detectsAwsKeyId('AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP'), // gitleaks:allow — fake fixture, not a real key
    true,
  );
});

test('AWS_ACCESS_KEY_ID caught by variable name (*_KEY_ID), even with a non-AKIA/ASIA-shaped value', () => {
  assert.strictEqual(
    detectsKey('AWS_ACCESS_KEY_ID=abcdefgh12345678'), // gitleaks:allow — fake fixture, not a real key
    true,
  );
});

test('AWS_ACCESS_KEY_VERSION caught by variable name (*_KEY_VERSION)', () => {
  assert.strictEqual(
    detectsKey('AWS_ACCESS_KEY_VERSION=abcdefgh12345678'), // gitleaks:allow — fake fixture, not a real key
    true,
  );
});

test('lowercase cache_key_id is NOT caught (false-positive guard unchanged after *_KEY_ID extension)', () => {
  assert.strictEqual(detectsKey('cache_key_id = "abcdefgh12345678"'), false); // gitleaks:allow — fake fixture, not a real key
});

test('lowercase primary_key_id is NOT caught (false-positive guard unchanged after *_KEY_ID extension)', () => {
  assert.strictEqual(detectsKey('primary_key_id = "abcdefgh12345678"'), false); // gitleaks:allow — fake fixture, not a real key
});

// ── aiguard:allow — same-line marker suppresses a finding that the same
// pattern still reports without the marker. Uses scanContent() (the path
// both the CLI and, via the same helper, the write hook consult) rather
// than detectsWith(), because the marker is a scanner-layer rule, not a
// regex change. Fixture value lives in a variable so this source line
// itself can carry a marker and not trip the live write hook.
const AWS_ALLOW_FIXTURE = 'AKIAABCDEFGHIJKLMNOP'; // aiguard:allow gitleaks:allow — fake fixture, not a real key

test('line with aiguard:allow is not flagged by the same pattern that flags the unmarked line', () => {
  const unmarked = `const key = "${AWS_ALLOW_FIXTURE}";`;
  const marked = `const key = "${AWS_ALLOW_FIXTURE}"; // aiguard:allow`;
  assert.ok(
    scanContent('fixture.js', unmarked, 'HIGH').some((f) => f.type === 'secret_pattern'),
    'control: unmarked AWS-shaped key must still be reported'
  );
  assert.strictEqual(
    scanContent('fixture.js', marked, 'HIGH').filter((f) => f.type === 'secret_pattern').length,
    0,
    'same key on a line with aiguard:allow must not be reported'
  );
});

test('aiguard:allow on a neighboring line does not suppress the match (marker is not a nearby switch)', () => {
  const content = `// aiguard:allow\nconst key = "${AWS_ALLOW_FIXTURE}";`;
  assert.ok(
    scanContent('fixture.js', content, 'HIGH').some((f) => f.type === 'secret_pattern'),
    'a marker on the previous line must not suppress a finding on the next line'
  );
});

test('gitleaks:allow is accepted as an alias of aiguard:allow', () => {
  const marked = `const key = "${AWS_ALLOW_FIXTURE}"; // gitleaks:allow`;
  assert.strictEqual(
    scanContent('fixture.js', marked, 'HIGH').filter((f) => f.type === 'secret_pattern').length,
    0,
    'gitleaks:allow on the same line must suppress the finding'
  );
});

test('leakward:allow is accepted as the public spelling of aiguard:allow', () => {
  const marked = `const key = "${AWS_ALLOW_FIXTURE}"; // leakward:allow`;
  assert.strictEqual(
    scanContent('fixture.js', marked, 'HIGH').filter((f) => f.type === 'secret_pattern').length,
    0,
    'leakward:allow on the same line must suppress the finding'
  );
});

test('aiguard:allow on a CR-only previous line does not suppress the next line', () => {
  const content = `// aiguard:allow\rconst key = "${AWS_ALLOW_FIXTURE}";`;
  assert.ok(
    scanContent('fixture.js', content, 'HIGH').some((f) => f.type === 'secret_pattern'),
    'a CR-separated previous line with a marker must not suppress the next line'
  );
});

test('BIP39 seed is still flagged when the next line is a bare aiguard:allow (greedy overshoot)', () => {
  const seed = words(12).join(' ');
  const content = `${seed}\naiguard:allow`;
  assert.ok(
    scanContent('fixture.js', content, 'HIGH').some((f) => f.type === 'secret_pattern'),
    'a marker on the line after a seed must not suppress the seed (greedy {11,} can swallow "aiguard")'
  );
});

test('BIP39 seed on one line with aiguard:allow is still suppressed', () => {
  const seed = words(12).join(' ');
  const content = `${seed} // aiguard:allow`;
  assert.strictEqual(
    scanContent('fixture.js', content, 'HIGH').filter((f) => f.type === 'secret_pattern').length,
    0,
    'a marker on the same line as the seed must still suppress it'
  );
});

test('BIP39 seed is still flagged when the next line is a bare leakward:allow (greedy overshoot)', () => {
  const seed = words(12).join(' ');
  const content = `${seed}\nleakward:allow`;
  assert.ok(
    scanContent('fixture.js', content, 'HIGH').some((f) => f.type === 'secret_pattern'),
    'a marker on the line after a seed must not suppress the seed (greedy {11,} can swallow "leakward")'
  );
});

const jwtPattern = SECRET_PATTERNS.find((p) => p.name === 'JWT secret');
assert.ok(jwtPattern, 'JWT secret pattern not found in patterns.js');

test('annotated assignment with a real value IS caught, with a None/Field default is NOT (Generic + *_KEY)', () => {
  assert.strictEqual(detectsGeneric('pass' + 'word: Optional[str] = "Ab3dEf9hIj2kLm"'), true); // gitleaks:allow — fake fixture, not a real key
  assert.strictEqual(detectsGeneric('tok' + 'en: Annotated[str, Field(min_length=3)] = "Ab3dEf9hIj2kLm"'), true); // gitleaks:allow — fake fixture, not a real key
  assert.strictEqual(detectsGeneric('tok' + 'en: Optional[str] = None'), false);
  assert.strictEqual(detectsGeneric('tok' + 'en: Optional[str] = Field(default=None)'), false);
  assert.strictEqual(detectsKey('SECRET' + '_KEY: Optional[str] = "django-insecure-a8f9x2"'), true); // gitleaks:allow — fake fixture, not a real key
  assert.strictEqual(detectsKey('API' + '_KEY: Optional[str] = None'), false);
});

test('JWT secret rule: long annotation is NOT caught, a real value IS', () => {
  assert.strictEqual(detectsWith(jwtPattern, 'JWT_SEC' + 'RET: Optional[SecretStr]=Field(default=None)'), false);
  assert.strictEqual(detectsWith(jwtPattern, 'JWT_SEC' + 'RET=abcdefghijklmnopqrstuvwxyz012345678'), true); // gitleaks:allow — fake fixture, not a real key
});

test('annotation forms: nested generics and PEP 604 unions with a real value are caught; "name = identifier" after an annotation is not', () => {
  assert.strictEqual(detectsGeneric('pass' + 'word: Optional[Union[str, bytes]] = "Ab3dEf9hIjKlMn42"'), true); // gitleaks:allow — fake fixture, not a real key
  assert.strictEqual(detectsGeneric('pass' + 'word: str | None = "Ab3dEf9hIjKlMn42"'), true); // gitleaks:allow — fake fixture, not a real key
  assert.strictEqual(detectsKey('SECRET' + '_KEY: str | None = "django-insecure-a8f9x2"'), true); // gitleaks:allow — fake fixture, not a real key
  assert.strictEqual(detectsGeneric('const tok' + 'en: string = accessToken;'), false);
  assert.strictEqual(detectsGeneric('let pass' + 'word: string = newPassword;'), false);
  assert.strictEqual(detectsGeneric('tok' + 'en: Optional[Dict[str, str]] = None'), false);
});

test('a ":" inside the value after no annotation still reaches validate with the whole value (no annotation path)', () => {
  assert.strictEqual(detectsGeneric('pass' + 'word: CorrectHorse:battery'), true); // gitleaks:allow — fake fixture, not a real key
  assert.strictEqual(detectsGeneric('SEC' + 'RET:AbcDefGh:abcdefgh'), true); // gitleaks:allow — fake fixture, not a real key
});

test('after an annotation an unquoted identifier is never a secret, even with a digit in the name', () => {
  assert.strictEqual(detectsGeneric('self.tok' + 'en: str = token_v2'), false);
  assert.strictEqual(detectsGeneric('const sec' + 'ret: string = process.env.APP_SECRET_2!;'), false);
  assert.strictEqual(detectsKey('AWS_SECRET' + '_KEY: str = settings.AWS_S3_SECRET'), false);
  assert.strictEqual(detectsGeneric('const tok' + 'en: string = base64Token;'), false);
});

test('a bare type glued to "=" is the old "name: value" shape, whole value is judged', () => {
  assert.strictEqual(detectsGeneric('pass' + 'word: Abc=DefGhiJk'), true); // gitleaks:allow — fake fixture, not a real key
  assert.strictEqual(detectsGeneric('pass' + 'word: admin=12345678'), true); // gitleaks:allow — fake fixture, not a real key
  assert.strictEqual(detectsGeneric('tok' + 'en: Optional[str]=None'), false);
});

// ── Round 7 (2026-10-08): validate-queue 3ecd194e findings E1, E2, W2-camelCase, W4 ──
// Fixtures are built by concatenation so the live leakward hook does not block
// writing this file; none of the values is a real secret.

test('E1: pydantic SecretStr without brackets is NOT caught (Generic + *_KEY), a real value still IS', () => {
  assert.strictEqual(detectsGeneric('tok' + 'en: SecretStr'), false);
  assert.strictEqual(detectsGeneric('pass' + 'word: SecretStr = Field(default=None)'), false);
  assert.strictEqual(detectsGeneric('JWT_SEC' + 'RET: SecretStr = Field(default=..., env="JWT_SEC' + 'RET")'), false);
  assert.strictEqual(detectsKey('OPENAI_API' + '_KEY: SecretStr = Field(...)'), false);
  assert.strictEqual(detectsKey('SIGNING' + '_KEY: SecretStr | None = None'), false);
  assert.strictEqual(detectsGeneric('tok' + 'en: SecretStr = "Ab3dEf9hIj2kLm"'), true); // gitleaks:allow — fake fixture, not a real key
  assert.strictEqual(detectsKey('SIGNING' + '_KEY: SecretStr = "Ab3dEf9hIj2kLm"'), true); // gitleaks:allow — fake fixture, not a real key
  assert.strictEqual(detectsGeneric('pass' + 'word: CorrectHorseBattery'), true); // gitleaks:allow — fake fixture, not a real key
});

test('E2: Azure rule ignores env/settings reads and SecretStr, still catches real values', () => {
  const az = 'AZURE_CLIENT' + '_SECRET';
  assert.strictEqual(detectsWith(azurePattern, az + ' = os.getenv("' + az + '")'), false);
  assert.strictEqual(detectsWith(azurePattern, az + ' = os.environ.get("' + az + '")'), false);
  assert.strictEqual(detectsWith(azurePattern, 'const ' + az + ' = process.env.' + az + ';'), false);
  assert.strictEqual(detectsWith(azurePattern, az.toLowerCase() + ' = settings.' + az.toLowerCase()), false);
  assert.strictEqual(detectsWith(azurePattern, az + ': SecretStr = Field(...)'), false);
  assert.strictEqual(detectsWith(azurePattern, az + '=Ab3~dEf9.hIj2-kLm_NoPq'), true); // gitleaks:allow — fake fixture, not a real key
  assert.strictEqual(detectsWith(azurePattern, az + ': "Ab3~dEf9.hIj2-kLm_NoPq"'), true); // gitleaks:allow — fake fixture, not a real key
});

test('E2: JWT rule ignores env/settings reads, still catches real values', () => {
  const jw = 'JWT_SEC' + 'RET';
  assert.strictEqual(detectsWith(jwtPattern, jw + ' = settings.authentication.jwt_signing_secret'), false);
  assert.strictEqual(detectsWith(jwtPattern, 'const ' + jw + ' = process.env.JWT_KEY_FOR_SIGNING_TOKENS;'), false);
  assert.strictEqual(detectsWith(jwtPattern, jw + ' = os.getenv("JWT_KEY_FOR_SIGNING_TOKENS_X")'), false);
  assert.strictEqual(detectsWith(jwtPattern, jw + ' = jwt_signing_secret_from_the_vault_value'), false);
  assert.strictEqual(detectsWith(jwtPattern, jw + '=abcdefghijklmnopqrstuvwxyz012345678'), true); // gitleaks:allow — fake fixture, not a real key
  assert.strictEqual(detectsWith(jwtPattern, jw + '=abcdefghijklmnopqrstuvwxyzabcdefghij'), true); // gitleaks:allow — fake fixture, not a real key
  assert.strictEqual(detectsWith(jwtPattern, jw + ': "abcdefghijklmnopqrstuvwxyz_abcdefghij"'), true); // gitleaks:allow — fake fixture, not a real key
});

test('W2 camelCase / W4: glued "name: T=value" with a known type word is an annotation', () => {
  assert.strictEqual(detectsGeneric('tok' + 'en: str=accessToken'), false);
  assert.strictEqual(detectsGeneric('tok' + 'en: string=accessToken'), false);
  assert.strictEqual(detectsKey('API' + '_KEY: str=accessToken'), false);
  assert.strictEqual(detectsGeneric('pass' + 'word: str="correcthorsebattery"'), true); // gitleaks:allow — fake fixture, not a real key
  assert.strictEqual(detectsKey('SIGNING' + '_KEY: str="correcthorsebattery"'), true); // gitleaks:allow — fake fixture, not a real key
  // unknown left-hand word: still the plain "name: value=more" shape
  assert.strictEqual(detectsGeneric('pass' + 'word: Abc=DefGhiJk'), true); // gitleaks:allow — fake fixture, not a real key
});

test('documented gaps (KNOWN_GAPS): underscore passphrase, ident( prefix, type-word password are dropped; letters-only run still flagged', () => {
  const jw = 'JWT_SEC' + 'RET';
  assert.strictEqual(detectsWith(jwtPattern, jw + '=correct_horse_battery_staple_pass'), false);
  assert.strictEqual(detectsWith(jwtPattern, jw + '=Ab3dEf9hIj2kLm(NoPq4rStUv5wXyZ6a7b8c9'), false);
  assert.strictEqual(detectsWith(jwtPattern, jw + '=abcdefghijklmnopqrstuvwxyzabcdefghij'), true); // gitleaks:allow — fake fixture, not a real key
  assert.strictEqual(detectsWith(jwtPattern, jw + '=correct_horse.battery_staple_passphrase'), false);
  assert.strictEqual(detectsWith(jwtPattern, jw + '=abcdefgh$ijklmnop.qrstuvwxyzabcdefgh'), false);
  assert.strictEqual(detectsWith(jwtPattern, '"' + jw + '": "abcdefghijklmnopqrstuvwxyz012345678"'), false);
  assert.strictEqual(detectsGeneric('pass' + 'word: string'), false);
});

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
