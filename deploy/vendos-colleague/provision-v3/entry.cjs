'use strict';
// Six reviewed CJS/JSON modules are compiled in memory. No application file is written.
const fs = require('node:fs');
const crypto = require('node:crypto');
const Module = require('node:module');
const path = require('node:path');
const output = process.stdout.write.bind(process.stdout);
const fail = (value, code) => { if (!value) throw new Error(code); };
const names = ['cli.cjs','mongo-storage.cjs','policy.cjs','policy.json','provision.cjs','server-runtime.cjs'];

function modules(packet) {
  fail(packet && packet.schema === 1 && ['check','prepare'].includes(packet.mode), 'INVALID_RUNTIME_PACKET');
  fail(Object.keys(packet.files).sort().join('|') === names.sort().join('|'), 'WRONG_RUNTIME_FILE_SET');
  const cache = new Map();
  const native = Module.createRequire('/app/package.json');
  function load(name) {
    fail(names.includes(name), 'UNEXPECTED_LOCAL_IMPORT');
    if (cache.has(name)) return cache.get(name).exports;
    const file = packet.files[name];
    fail(file && typeof file.text === 'string' && Buffer.byteLength(file.text) < 1000000 &&
      crypto.createHash('sha256').update(file.text).digest('hex') === file.sha256, 'RUNTIME_SOURCE_CHANGED');
    const item = new Module('/vendos-reviewed-provision-v3/' + name);
    cache.set(name, item);
    if (name.endsWith('.json')) { item.exports = JSON.parse(file.text); return item.exports; }
    item.require = (request) => request.startsWith('./')
      ? load(path.posix.normalize(request).replace(/^\.\//, '')) : native(request);
    item._compile(file.text, item.id);
    return item.exports;
  }
  return load;
}

async function run(packet) {
  fail(process.cwd() === '/app', 'EXPECTED_LIBRECHAT_APP_ROOT');
  fail(String(process.env.OPENAI_MODERATION || '').trim().toLowerCase() !== 'true', 'NON_CLAUDE_MODERATION_ENABLED');
  const load = modules(packet);
  const core = load('provision.cjs');
  core.validateRequest(packet.request);
  const runtime = load('server-runtime.cjs');
  const deps = await runtime.connect(packet.request);
  try { return await core.run(packet.request, deps, packet.mode === 'prepare'); }
  finally { await deps.close(); }
}

module.exports = { modules, run };
if (require.main === module || process.argv[1] === undefined || process.argv[1] === '-') {
  process.stdout.write = () => true;
  process.stderr.write = () => true;
  let packet;
  try {
    const bytes = fs.readFileSync(0);
    fail(bytes.length < 1000000, 'RUNTIME_PACKET_TOO_LARGE');
    packet = JSON.parse(bytes);
  } catch { output(JSON.stringify({schema:1,error_code:'INVALID_RUNTIME_INPUT',credentials_printed:false,automatic_rollback:false})+'\n'); process.exit(1); }
  run(packet).then(result => output(JSON.stringify(result)+'\n', () => process.exit(0))).catch(error => {
    const code = typeof error.message === 'string' && /^[A-Z0-9_]{1,100}$/.test(error.message) ? error.message : 'PROVISION_FAILED_REQUIRES_INSPECTION';
    output(JSON.stringify({schema:1,error_code:code,credentials_printed:false,automatic_rollback:false})+'\n', () => process.exit(1));
  });
}
