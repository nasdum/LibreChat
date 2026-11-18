'use strict';
const fs = require('node:fs');
const core = require('./provision.cjs');

async function main() {
  const args = process.argv.slice(2);
  const prepare = args.includes('--prepare');
  if (args.length !== 3 || !['--check', '--prepare'].includes(args[0]) || args[1] !== '--request-file') throw new Error('USAGE_CHECK_OR_PREPARE_REQUEST_FILE');
  const bytes = fs.readFileSync(args[2]);
  if (bytes.length > 4096) throw new Error('REQUEST_TOO_LARGE');
  let request;
  try { request = JSON.parse(bytes); } catch { throw new Error('INVALID_REQUEST_JSON'); }
  core.validateRequest(request);
  const runtime = require('./server-runtime.cjs');
  const deps = await runtime.connect(request);
  try { return await core.run(request, deps, prepare); }
  finally { await deps.close(); }
}

if (require.main === module) {
  // Library stdout/stderr must never expose secret-bearing exceptions or helper results.
  const output = process.stdout.write.bind(process.stdout);
  process.stdout.write = () => true;
  process.stderr.write = () => true;
  main().then((result) => output(JSON.stringify(result) + '\n', () => process.exit(0))).catch((error) => {
    const code = typeof error.message === 'string' && /^[A-Z0-9_]+$/.test(error.message) ? error.message : 'PROVISION_FAILED_REQUIRES_INSPECTION';
    output(JSON.stringify({ schema: 1, error_code: code, credentials_printed: false, automatic_rollback: false }) + '\n', () => process.exit(1));
  });
}

module.exports = { main };
