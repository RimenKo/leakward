#!/usr/bin/env node
'use strict';

// Public hook entry. The implementation still lives in aiguard-hook.js so
// existing Claude Code settings that resolve that path keep working.
// Fail-closed: Claude PreToolUse only blocks on exit 2. An uncaught
// require here would be exit 1 and let the write through.
try {
  require('./aiguard-hook.js');
} catch (err) {
  const message = err && err.message ? err.message : String(err);
  process.stderr.write(`leakward: не удалось загрузить хук — ${message}\nОперация заблокирована.\n`);
  process.exit(2);
}
