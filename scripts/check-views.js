#!/usr/bin/env node
// Pre-push syntax guard: validate server code AND every inline <script>
// block inside HTML views. The dashboard's JS lives inside dashboard.html,
// so `node --check server.js` alone never caught breakage there — a stray
// brace shipped to production and hung the dashboard. This script makes
// that class of bug impossible to push silently.
//
// Usage: npm run check   (fails with exit code 1 on any syntax error)

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const root = __dirname.includes('scripts') ? path.join(__dirname, '..') : __dirname;
const fail = (msg) => {
  console.error('✗ ' + msg);
  process.exitCode = 1;
};
const ok = (msg) => console.log('✓ ' + msg);

// 1) Server JS — plain node --check
try {
  execFileSync(process.execPath, ['--check', path.join(root, 'server.js')], { stdio: 'pipe' });
  ok('server.js');
} catch (e) {
  fail('server.js: ' + (e.stderr ? e.stderr.toString() : e.message));
}

// 2) Inline scripts in HTML views
const viewsDir = path.join(root, 'views');
for (const file of fs.readdirSync(viewsDir).filter((f) => f.endsWith('.html'))) {
  const html = fs.readFileSync(path.join(viewsDir, file), 'utf8');
  const blocks = [...html.matchAll(/<script(?:[^>]*)>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
  if (blocks.length === 0) {
    ok(file + ' (no inline scripts)');
    continue;
  }
  for (let i = 0; i < blocks.length; i++) {
    try {
      new Function(blocks[i]); // eslint-disable-line no-new-func
    } catch (e) {
      fail(`${file} script block #${i}: ${e.message}`);
      continue;
    }
  }
  ok(file + ' (' + blocks.length + ' script block(s))');
}

if (process.exitCode) {
  console.error('\nSyntax check FAILED — do not deploy.');
  process.exit(1);
}
console.log('\nAll syntax checks passed.');
