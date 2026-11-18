'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

test('native wrapper uses only bounded reads, actual conversation collection and per-user credentials', async () => {
  const calls = [];
  let dependencies;
  const db = {
    collection(name) {
      return {
        async findOne(query, options) { calls.push({ name, operation: 'findOne', query, options }); return null; },
        find(query, options) {
          const record = { name, operation: 'find', query, options };
          calls.push(record);
          return { limit(n) { record.limit = n; return this; }, sort(value) { record.sort = value; return this; }, async toArray() { return []; } };
        },
      };
    },
  };
  class ObjectId { constructor(value) { this.value = value; } toString() { return this.value; } }
  const mocks = {
    mongoose: { connection: { db }, Types: { ObjectId } },
    '@librechat/api': { GenerationJobManager: { getJob: async (id) => ({ id }), getActiveJobIdsForUser: async () => [] } },
    '@librechat/api/vendos': { VENDOS_RESTRICTED_COLLECTION: 'vendos_colleague_provisions_v3', createVendosRestrictedChat: (deps) => { dependencies = deps; return () => {}; } },
    './optionalJwtAuth': () => {},
  };
  const module = { exports: {} };
  const source = fs.readFileSync(path.join(__dirname, '../api/server/middleware/vendosRestrictedChat.js'), 'utf8');
  vm.runInNewContext(`(function(require,module,exports){${source}\n})`, {})(
    (name) => { assert.ok(Object.hasOwn(mocks, name), `unexpected import ${name}`); return mocks[name]; }, module, module.exports,
  );
  const id = '222222222222222222222222';
  await dependencies.provision(id);
  await dependencies.conversation('synthetic-id');
  await dependencies.conversations(id);
  assert.equal(calls.length, 6);
  assert.equal(calls[0].name, 'vendos_colleague_provisions_v3');
  assert.equal(calls[0].query._id, id);
  assert.equal(calls[0].options.projection.token_ciphertext, 0);
  assert.equal(calls[1].name, 'configs');
  assert.equal(calls[1].query.isActive, true);
  assert.equal(calls[1].limit, 3);
  assert.equal(calls[2].query.name, 'VENDOS pilot');
  assert.equal(String(calls[2].query.userId.$in[1]), id);
  assert.equal(calls[2].limit, 3);
  assert.equal(calls[3].query.userId, id);
  assert.equal(calls[3].query.pluginKey, 'mcp_vendos_pilot');
  assert.equal(calls[3].query.authField, 'VENDOS_PILOT_KEY');
  assert.equal(calls[4].name, 'conversations');
  assert.equal(calls[5].name, 'conversations');
  assert.equal(calls[5].query.user, id);
  assert.equal(calls[5].query.spec, 'vendos-consultation');
  assert.equal(calls[5].query.model, 'claude-sonnet-5-5');
  assert.equal(calls[5].limit, 100);
});

test('actual entrypoint installs both guards before all API route mounts', () => {
  const source = fs.readFileSync(path.join(__dirname, '../api/server/index.js'), 'utf8');
  const fence = source.indexOf("app.use('/api', require('./middleware/vendosRestrictedChat'))");
  assert.ok(fence > source.indexOf('app.use(passport.initialize())'));
  assert.ok(fence < source.indexOf("app.use('/oauth'"));
  assert.ok(fence < source.indexOf("app.use('/api/auth'"));
  assert.ok(source.includes("app.use('/images', require('./middleware/vendosRestrictedChat'))"));
});
