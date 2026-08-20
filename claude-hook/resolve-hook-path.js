'use strict';

// Locate the Write/Edit hook file. require.resolve(pkg) is useless here:
// this package has no "main"/index.js, so Node throws MODULE_NOT_FOUND even
// when the package is installed. Resolve the hook file as a subpath instead.
//
// Fail-closed if a leakward/aiguard package is present but the hook file is
// missing (broken install). Fail-open only when neither package is installed,
// so projects without the scanner are not blocked.

const HOOK_SPECS = [
  ['@rimenko-dev/leakward', 'leakward-hook.js'],
  ['@rimenko-dev/leakward', 'aiguard-hook.js'],
  ['@rimenko-dev/aiguard', 'aiguard-hook.js'],
];

function packageName(pkg) {
  const parts = String(pkg).split('/');
  return parts[parts.length - 1];
}

function resolveHookPath(deps) {
  if (!deps || typeof deps.requireResolve !== 'function') {
    return { status: 'broken' };
  }
  const requireResolve = deps.requireResolve;
  const execSync = deps.execSync;
  const existsSync = deps.existsSync;
  const join = deps.join;
  let sawPackage = false;

  for (const [pkg, file] of HOOK_SPECS) {
    try {
      requireResolve(pkg + '/package.json');
      sawPackage = true;
    } catch (_) { /* not in this node_modules tree */ }
    try {
      const resolved = requireResolve(pkg + '/claude-hook/' + file);
      if (resolved && existsSync(resolved)) return { status: 'ok', path: resolved };
    } catch (_) { /* subpath not resolvable here */ }
  }

  let globalRoot = '';
  if (typeof execSync === 'function') {
    try {
      globalRoot = String(execSync('npm root -g 2>/dev/null', { timeout: 3000 })).trim();
    } catch (_) { /* npm missing from PATH — still fail-closed if we saw a package */ }
  }

  if (globalRoot && typeof existsSync === 'function' && typeof join === 'function') {
    for (const [pkg, file] of HOOK_SPECS) {
      const pkgDir = join(globalRoot, '@rimenko-dev', packageName(pkg));
      if (existsSync(join(pkgDir, 'package.json'))) sawPackage = true;
      const candidate = join(pkgDir, 'claude-hook', file);
      if (existsSync(candidate)) return { status: 'ok', path: candidate };
    }
  }

  if (sawPackage) return { status: 'broken' };
  return { status: 'missing' };
}

module.exports = { HOOK_SPECS, resolveHookPath };
