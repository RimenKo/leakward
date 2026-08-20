#!/usr/bin/env node
'use strict';

// Claude Code PreToolUse bootstrap. Settings.json locates this file, then
// this process locates leakward-hook.js and runs it with the same stdin.
const path = require('path');
const fs = require('fs');
const { spawnSync, execSync } = require('child_process');
const { resolveHookPath } = require('./resolve-hook-path');

const result = resolveHookPath({
  requireResolve: require.resolve.bind(require),
  execSync,
  existsSync: fs.existsSync.bind(fs),
  join: path.join,
});

if (result.status === 'missing') process.exit(0);
if (result.status !== 'ok' || !result.path) {
  process.stderr.write('leakward: scanner unavailable — операция заблокирована.\n');
  process.exit(2);
}

const spawned = spawnSync(process.execPath, [result.path], { stdio: 'inherit' });
if (spawned.status == null) {
  process.stderr.write('leakward: scanner produced no exit status — операция заблокирована.\n');
  process.exit(2);
}
process.exit(spawned.status);
