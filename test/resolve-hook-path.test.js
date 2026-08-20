'use strict';

const assert = require('assert');
const path = require('path');
const { resolveHookPath } = require('../claude-hook/resolve-hook-path');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ok — ${name}`);
    passed++;
  } catch (err) {
    console.log(`  FAIL — ${name}: ${err.message}`);
    failed++;
  }
}

function fakeResolve(map) {
  return (spec) => {
    if (Object.prototype.hasOwnProperty.call(map, spec)) {
      const value = map[spec];
      if (value instanceof Error) throw value;
      return value;
    }
    const err = new Error('Cannot find module ' + spec);
    err.code = 'MODULE_NOT_FOUND';
    throw err;
  };
}

test('subpath resolve of leakward-hook.js wins without requiring package main', () => {
  const hook = '/tmp/fake/claude-hook/leakward-hook.js';
  const result = resolveHookPath({
    requireResolve: fakeResolve({
      '@rimenko-dev/leakward/package.json': '/tmp/fake/package.json',
      '@rimenko-dev/leakward/claude-hook/leakward-hook.js': hook,
    }),
    existsSync: (p) => p === hook || p.endsWith('package.json'),
    join: path.join,
    execSync: () => { throw new Error('npm should not be needed'); },
  });
  assert.deepStrictEqual(result, { status: 'ok', path: hook });
});

test('require.resolve(pkg) MODULE_NOT_FOUND does not fail-open when subpath exists', () => {
  const hook = '/tmp/fake/claude-hook/leakward-hook.js';
  const result = resolveHookPath({
    requireResolve: fakeResolve({
      '@rimenko-dev/leakward/claude-hook/leakward-hook.js': hook,
    }),
    existsSync: (p) => p === hook,
    join: path.join,
    execSync: () => { throw new Error('npm should not be needed'); },
  });
  assert.deepStrictEqual(result, { status: 'ok', path: hook });
});

test('package.json present but hook file missing is broken (fail-closed), not missing', () => {
  const result = resolveHookPath({
    requireResolve: fakeResolve({
      '@rimenko-dev/leakward/package.json': '/tmp/broken/package.json',
    }),
    existsSync: () => false,
    join: path.join,
    execSync: () => { throw new Error('no npm'); },
  });
  assert.deepStrictEqual(result, { status: 'broken' });
});

test('global install is used when local require.resolve cannot see the package', () => {
  const hook = '/usr/global/@rimenko-dev/leakward/claude-hook/leakward-hook.js';
  const result = resolveHookPath({
    requireResolve: fakeResolve({}),
    existsSync: (p) => p === hook || p === '/usr/global/@rimenko-dev/leakward/package.json',
    join: path.join,
    execSync: () => '/usr/global\n',
  });
  assert.deepStrictEqual(result, { status: 'ok', path: hook });
});

test('neither package installed is missing (fail-open for projects without the scanner)', () => {
  const result = resolveHookPath({
    requireResolve: fakeResolve({}),
    existsSync: () => false,
    join: path.join,
    execSync: () => { throw new Error('no npm'); },
  });
  assert.deepStrictEqual(result, { status: 'missing' });
});

test('global package.json without hook file is broken', () => {
  const result = resolveHookPath({
    requireResolve: fakeResolve({}),
    existsSync: (p) => p === '/usr/global/@rimenko-dev/leakward/package.json',
    join: path.join,
    execSync: () => '/usr/global',
  });
  assert.deepStrictEqual(result, { status: 'broken' });
});

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
