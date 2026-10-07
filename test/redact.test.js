'use strict';

// Tests for src/redact.js (context layer + shape layer used by the Bash log
// masker). Fixtures write ':' as § , '=' as ¤ and ' ' as ¦ right before a
// synthetic secret, so this file holds no user:pass / Bearer text for a secret
// scanner to flag. They are expanded at runtime, before redactText sees them.

const assert = require('assert');
const {
  redactText, maskContextSecrets, isLiteralSecret, segmentEnd, inSegments,
} = require('../src/redact');

function expand(text) {
  return text.replace(/§/g, ':').replace(/¤/g, '=').replace(/¦/g, ' ');
}

function run(input) {
  return { out: redactText(expand(input)).text };
}

let passed = 0;
let failed = 0;

function check(name, fn) {
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

// Pieces are joined at runtime so the source file itself holds no secret-shaped text.
const W = ['PASS', 'WORD'].join('');
const w = W.toLowerCase();
const PG = ['postgres', '://dbuser§SynthDbPass1@db.example.test:5432/app'].join('');
const MYPWD = ['MYSQL', '_PWD'].join('');
const B64 = Buffer.from('SyntheticBasicTokenValue').toString('base64');

// [name, input, secret substrings that must vanish, substrings that must remain]
const MASKED = [
  ['curl -u quoted', "curl -s -u 'K123456789§FakePassw0rdXYZ_synthetic' https://robot-ws.example.test/server", ['FakePassw0rdXYZ_synthetic'], ["curl -s -u 'K123456789:", 'https://robot-ws.example.test/server']],
  ['curl -u bare', 'curl -u admin§SynthPass123 https://example.test/', ['SynthPass123'], ['curl -u admin:', 'https://example.test/']],
  ['curl -u double quotes', 'curl -u "bob§Sy nth Pass" https://example.test/', ['Sy nth Pass'], ['curl -u "bob:']],
  ['curl --user', 'curl --user svc§SynthPass456 https://example.test/x', ['SynthPass456'], ['--user svc:']],
  ['curl --user=', 'curl --user=svc§SynthPass789 https://example.test/x', ['SynthPass789'], ['--user=svc:']],
  ['curl -su combined', 'curl -su svc§SynthPassABC https://example.test/x', ['SynthPassABC'], ['-su svc:']],
  ['curl -uattached', 'curl -usvc§SynthPassDEF https://example.test/x', ['SynthPassDEF'], ['-usvc:']],
  ['curl --proxy-user', 'curl -x http://proxy.test:3128 --proxy-user px§SynthProxyPw https://example.test/', ['SynthProxyPw'], ['--proxy-user px:']],
  ['curl flag after url', 'curl -s https://example.test/a -u u1§SynthLatePw -o /tmp/out', ['SynthLatePw'], ['-o /tmp/out', 'u1:']],
  ['Authorization Basic', `curl -H 'Authorization: Basic ${B64}' https://example.test/`, [B64], ["-H 'Authorization: Basic ", 'https://example.test/']],
  ['Authorization Bearer', 'curl -H "Authorization: Bearer¦SynthBearerValue123" https://example.test/', ['SynthBearerValue123'], ['"Authorization: Bearer ']],
  ['authorization lowercase', "curl -H 'authorization: basic¦SynthLowerCaseTok' https://example.test/", ['SynthLowerCaseTok'], ["'authorization: basic "]],
  ['Proxy-Authorization', "curl -H 'Proxy-Authorization: Basic¦SynthProxyAuthTok' https://example.test/", ['SynthProxyAuthTok'], ['Proxy-Authorization: Basic ']],
  ['URL userinfo', 'git clone https://deploy§SynthUrlPass99@git.example.test/repo.git', ['SynthUrlPass99'], ['https://deploy:', '@git.example.test/repo.git']],
  ['URL userinfo with @ in pass', 'curl https://u:p@ss-SynthAt@host.example.test/', ['p@ss-SynthAt'], ['https://u:', '@host.example.test/']],
  ['db URL', `psql ${PG}`, ['SynthDbPass1'], ['psql ']],  // leakward's own DB-URL pattern may mask the whole URL: stronger, fine
  ['sshpass -p space', 'sshpass -p SynthSshPass1 ssh -p 22 root@host.example.test uptime', ['SynthSshPass1'], ['sshpass -p ', 'ssh -p 22 root@host.example.test uptime']],
  ['sshpass -p quoted attached', "sshpass -p'SynthSshPass2' ssh root@host.example.test", ['SynthSshPass2'], ["sshpass -p'", 'ssh root@host.example.test']],
  ['sshpass with flag before', 'sshpass -v -p SynthSshPass3 scp a root@host.example.test:/tmp/', ['SynthSshPass3'], ['scp a root@host.example.test:/tmp/']],
  ['mysql -pPASS', 'mysql -u root -pSynthMysqlPw1 -h db.example.test app', ['SynthMysqlPw1'], ['mysql -u root -p', '-h db.example.test app']],
  ['mysqldump -p quoted', "mysqldump -uroot -p'SynthMysqlPw2' app > /tmp/d.sql", ['SynthMysqlPw2'], ['mysqldump -uroot -p', '> /tmp/d.sql']],
  ['wget long flag =', `wget --user=ftpu --${w}=SynthWgetPw1 ftp://ftp.example.test/f`, ['SynthWgetPw1'], ['--user=ftpu', `--${w}=`, 'ftp://ftp.example.test/f']],
  ['wget --http flag space', `wget --http-user=h --http-${w} SynthWgetPw2 https://example.test/f`, ['SynthWgetPw2'], ['--http-user=h', `--http-${w} `]],
  ['docker login -p', 'docker login -u svc -p SynthDockerPw registry.example.test', ['SynthDockerPw'], ['docker login -u svc -p ', 'registry.example.test']],
  ['PG env', `PG${W}=SynthPgPw1 psql -h db.example.test -U app`, ['SynthPgPw1'], [`PG${W}=`, 'psql -h db.example.test -U app']],
  ['export DB env', `export DB_${W}='SynthDbEnvPw1' && ./run.sh`, ['SynthDbEnvPw1'], [`export DB_${W}='`, './run.sh']],
  ['mysql pwd env', `${MYPWD}=SynthMyPwd1 mysql -e "select 1"`, ['SynthMyPwd1'], ['mysql -e "select 1"']],
];

for (const [name, input, gone, kept] of MASKED) {
  check(`mask: ${name}`, () => {
    const { out } = run(input);
    for (const g of gone) assert.ok(!out.includes(g), `secret "${g}" still present in: ${out}`);
    for (const k of kept) assert.ok(out.includes(k), `expected "${k}" missing in: ${out}`);
    assert.ok(out.includes('***['), `no mask marker in: ${out}`);
  });
}

// Normal commands must stay byte-identical (context layer must not touch them).
const UNCHANGED = [
  'ls -la /tmp',
  'git push -u origin main',
  'sort -u a.txt b.txt',
  'docker run -u 1000:1000 --rm alpine id',
  'curl -s https://example.test/health',
  'curl -u admin https://example.test/ (prompts for the secret)',
  'curl -u "$USER:$PASS" https://example.test/',
  'curl -u user:$API_PASS https://example.test/',
  'curl -u user:${API_PASS} https://example.test/',
  'curl -H "Authorization: Bearer $TOKEN" https://example.test/',
  'curl -H "Authorization: Basic $(printf %s u:p | base64)" https://example.test/',
  'ssh -p 2222 root@host.example.test',
  'mysql -p -u root app',
  'mysql --protocol=tcp -h db.example.test app',
  `docker login --${w}-stdin registry.example.test`,
  'git clone https://github.com/example/repo.git',
  'curl https://user@host.example.test/path',
  `PG${W.slice(0, 4)}FILE=/tmp/.pgpass psql -h db.example.test`,
  `echo "${w} reset email sent"`,
  `python3 script.py --${w}-file /tmp/pw.txt`,
  'sshpass -f /tmp/pwfile ssh root@host.example.test',
  'mysql -u root -P3306 -h db.example.test app',
  'mysqldump -P 3306 -h db.example.test app',
  `python3 -c 'for w in ("${w}=", "passwd", "secret"): print(w)'`,
  `grep -n "${w}=" config.ini`,
  `python3 -c 'for w in ("${W}=", "x"): print(w)'`,
  'grep -rn "Authorization:" src/',
  'tar -xzf a.tgz -C /tmp && npm test -- --grep "x:y"',
];
for (const input of UNCHANGED) {
  check(`unchanged: ${input}`, () => {
    const { out } = run(input);
    assert.strictEqual(out, input);
  });
}

// Robustness / idempotency / exit code.
check('idempotent', () => {
  const once = run("curl -u 'u§SynthIdemPw1' https://example.test/").out;
  const twice = run(once).out;
  assert.strictEqual(twice, once);
});
check('multiple secrets in one line', () => {
  const { out } = run("curl -u a§SynthMultiOne https://u2§SynthMultiTwo@h.example.test/ -H 'Authorization: Bearer¦SynthMultiThree'");
  for (const s of ['SynthMultiOne', 'SynthMultiTwo', 'SynthMultiThree']) assert.ok(!out.includes(s), `${s} present: ${out}`);
});
check('multiline input keeps structure', () => {
  const { out } = run('echo start\ncurl -u a§SynthMlPw https://example.test/\necho end');
  assert.ok(out.startsWith('echo start\n') && out.endsWith('\necho end'), out);
  assert.ok(!out.includes('SynthMlPw'));
});
check('empty input', () => {
  assert.strictEqual(run('').out, '');
});
check('long line performance', () => {
  const big = 'curl ' + 'x'.repeat(200000) + ' --user a§SynthBigPw https://example.test/';
  const t0 = Date.now();
  const { out } = run(big);
  assert.ok(Date.now() - t0 < 5000, 'too slow');
  assert.ok(!out.includes('SynthBigPw'));
});

// ---- cases from the independent review (added after v1) ----
const MASKED2 = [
  ['curl continuation -u', 'curl -s \\\n  -u USER§SynthContPw1 https://h.example.test', ['SynthContPw1'], ['https://h.example.test']],
  ['curl continuation --user', 'curl -s \\\n  --user USER§SynthContPw2 https://h.example.test', ['SynthContPw2'], ['--user USER:']],
  ['quoted & before -u', "curl 'https://h.example.test/?a=1&b=2' -u USER§SynthAmpPw1", ['SynthAmpPw1'], ["a=1&b=2' -u USER:"]],
  ['quoted ; before -u', "curl -X POST -d 'a=1;b=2' -u USER§SynthSemiPw1 https://h.example.test", ['SynthSemiPw1'], ["'a=1;b=2'"]],
  ['quoted | before -u', "curl -H 'X: a|b' -u USER§SynthPipePw1 https://h.example.test", ['SynthPipePw1'], ["'X: a|b'"]],
  ['mysql quoted ; before -p', "mysql -e 'select 1; x' -u root -pSynthMyPw9", ['SynthMyPw9'], ["'select 1; x'"]],
  ['curl -u attached single quote', "curl -u'USER§SynthAttQ1' https://h.example.test", ['SynthAttQ1'], ['https://h.example.test']],
  ['curl -u attached double quote', 'curl -u"USER§SynthAttQ2" https://h.example.test', ['SynthAttQ2'], ['https://h.example.test']],
  ['empty user URL', 'redis-cli -u redis://:SynthRedisPw1@h.example.test:6379 ping', ['SynthRedisPw1'], ['@h.example.test:6379 ping']],
  ['env after pipe', `echo 1|PG${W}=SynthPipeEnv1 psql`, ['SynthPipeEnv1'], ['psql']],
  ['API_PASSWD env', 'API_PASSWD¤SynthPasswdEnv1 ./run', ['SynthPasswdEnv1'], ['./run']],
  ['DB_PWD env', 'DB_PWD¤SynthPwdEnv1 ./run', ['SynthPwdEnv1'], ['./run']],
  ['KEY_PASSPHRASE env', 'KEY_PASSPHRASE¤SynthPassphr1 ./run', ['SynthPassphr1'], ['./run']],
  ['curl -U proxy-user', 'curl -U USER§SynthProxyU1 -x http://p.example.test:3128 https://h.example.test', ['SynthProxyU1'], ['-x http://p.example.test:3128']],
  ['docker login -pPASS', 'docker login -u u -pSynthDockAtt1 registry.example.test', ['SynthDockAtt1'], ['registry.example.test']],
];
for (const [name, input, gone, kept] of MASKED2) {
  check(`mask2: ${name}`, () => {
    const { out } = run(input);
    for (const g of gone) assert.ok(!out.includes(g), `secret "${g}" still present in: ${out}`);
    for (const k of kept) assert.ok(out.includes(k), `expected "${k}" missing in: ${out}`);
  });
}
const UNCHANGED2 = [
  'curl -fsSu https://h.example.test/',
  'SKIP_PASS=true ./run',
  'REQUIRE_' + W + '=false ./run',
  'echo "Authorization: none"',
  'url = f"postgresql://{user}:{pw}@{host}"',
  'curl -s https://h.example.test/ && echo done ; ls -u',
];
for (const input of UNCHANGED2) {
  check(`unchanged2: ${input}`, () => assert.strictEqual(run(input).out, input));
}
// Linear time on hostile long lines (the hook has a 5 s timeout).
const PERF = {
  mysql: 'mysql' + ' -p'.repeat(100000),
  docker: 'docker login' + ' -p '.repeat(60000),
  curl: 'curl' + ' -u'.repeat(100000),
  curlsoup: 'curl -x http://p.example.test ' + 'a '.repeat(100000),
  pwflag: ' --' + w + ' x'.repeat(100000),
  sshpass: 'sshpass' + ' -a'.repeat(100000),
  urls: 'a.'.repeat(100000) + '://x',
  manyCurl: 'curl '.repeat(40000),
  quotes: "curl '" + 'x'.repeat(200000),
};
for (const [name, line] of Object.entries(PERF)) {
  check(`perf: ${name}`, () => {
    const t0 = Date.now();
    run(line);
    const ms = Date.now() - t0;
    assert.ok(ms < 2000, `${ms} ms for ${line.length} chars`);
  });
}

// ---- round 2 (second review) ----
const MASKED3 = [
  ['CRLF continuation -u', 'curl -s \\\r\n  -u USER§SynthCrlfPw1 https://h.example.test', ['SynthCrlfPw1'], ['https://h.example.test']],
  ['curl -su attached quote', "curl -su'USER§SynthShortQ1' https://h.example.test", ['SynthShortQ1'], ['https://h.example.test']],
  ['curl -su attached bare', 'curl -suUSER§SynthShortB1 https://h.example.test', ['SynthShortB1'], ['https://h.example.test']],
  ['password after apostrophe word', "echo it's curl -u USER§SynthAposPw1 https://h.example.test", ['SynthAposPw1'], ['https://h.example.test']],
];
for (const [name, input, gone, kept] of MASKED3) {
  check(`mask3: ${name}`, () => {
    const { out } = run(input);
    for (const g of gone) assert.ok(!out.includes(g), `secret "${g}" still present in: ${JSON.stringify(out)}`);
    for (const k of kept) assert.ok(out.includes(k), `expected "${k}" missing in: ${out}`);
  });
}
const UNCHANGED3 = [
  "echo 'curl' ; docker run -u 1000:1000 img",
  'echo "curl" ; docker run -u 1000:1000 img',
  'echo "don\'t use curl"\ndocker run -u 1000:1000 img',
  "curl -s https://h.example.test # it's fine\nps -u root:wheel",
  'SAVED_PWD=/tmp/work ./run',
  'OLD_PWD=/home/u ./run',
];
for (const input of UNCHANGED3) {
  check(`unchanged3: ${JSON.stringify(input)}`, () => assert.strictEqual(run(input).out, input));
}

// ---- library-level contract (not reachable through the CLI) ----
check('redactText reports both layers as applied', () => {
  const r = redactText('echo hi');
  assert.strictEqual(r.contextOk, true);
  assert.strictEqual(r.patternsLoaded, true);
  assert.strictEqual(r.text, 'echo hi');
});
check('shape layer still runs after the context layer', () => {
  const key = ['AKIA', 'ABCDEFGHIJKLMNOP'].join('');
  const { out } = run(`echo ${key}`);
  assert.ok(!out.includes(key), out);
  assert.ok(out.includes('***['), out);
});
check('context layer and shape layer both apply to one line', () => {
  const key = ['AKIA', 'ABCDEFGHIJKLMNOP'].join('');
  const { out } = run(`curl -u a§SynthBothPw1 https://h.example.test/ ${key}`);
  assert.ok(!out.includes('SynthBothPw1') && !out.includes(key), out);
});
check('non-string input is coerced, never throws', () => {
  assert.strictEqual(redactText(undefined).text, 'undefined');
});
check('isLiteralSecret: variables, substitutions, markers and flags words are not secrets', () => {
  for (const v of ['', '$VAR', '`cmd`', '\\$x', '{x}', '***[5]', 'true', 'NONE', '0']) {
    assert.strictEqual(isLiteralSecret(v), false, JSON.stringify(v));
  }
  assert.strictEqual(isLiteralSecret('SynthLiteral1'), true);
});
check('segmentEnd stops at an unquoted ; | & newline and skips quoted ones', () => {
  assert.strictEqual(segmentEnd('a b; c', 0), 3);
  assert.strictEqual(segmentEnd("a 'b;c' d; e", 0), 9);
  assert.strictEqual(segmentEnd('a \\\n b\nc', 0), 6);
  assert.strictEqual(segmentEnd('abc', 0), 3);
});
check('inSegments applies fn to each matching segment only', () => {
  const out = inSegments('x1; curl a; y; curl b', String.raw`\bcurl\b`, (s) => s.toUpperCase());
  assert.strictEqual(out, 'x1; CURL A; y; CURL B');
});
check('maskContextSecrets alone leaves shape-only secrets to the shape layer', () => {
  const key = ['AKIA', 'ABCDEFGHIJKLMNOP'].join('');
  assert.strictEqual(maskContextSecrets(`echo ${key}`), `echo ${key}`);
});

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
