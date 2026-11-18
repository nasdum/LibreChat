'use strict';
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const root = path.resolve(__dirname, '..');
const auth = require(process.env.AUTH_TEST_BUNDLE || '../packages/api/src/vendos/googleEmailException.ts');
const email = 'invited.person@example.net';
const hash = createHash('sha256').update(email).digest('hex');
process.env.VENDOS_GOOGLE_EMAIL_SHA256_ALLOWLIST = hash;

function load(relative, deps, env = {}) {
  const module = { exports: {} };
  const context = vm.createContext({ module, exports: module.exports, process: { env } });
  const source = fs.readFileSync(path.join(root, relative), 'utf8');
  const run = new vm.Script(`(function(require,module,exports){${source}\n})`).runInContext(context);
  run((name) => {
    if (!Object.hasOwn(deps, name)) throw new Error(`Unexpected dependency ${name}`);
    return deps[name];
  }, module, module.exports);
  return module.exports;
}

function fixture(identity, existing = null) {
  const operations = { created: 0, existing: 0, updated: 0 };
  const config = { registration: { allowedDomains: ['company.test'] } };
  const deps = {
    '@librechat/data-schemas': { logger: { error() {}, warn() {}, info() {} } },
    'librechat-data-provider': { ErrorTypes: { AUTH_FAILED: 'AUTH_FAILED' } },
    '@librechat/api': {
      isEnabled: (value) => value === 'true',
      isEmailDomainAllowed: (value, domains) => domains.includes(value?.split('@')[1]?.toLowerCase()),
      getAppConfigOptionsFromUser: () => ({}),
      resolveAppConfigForUser: async () => config,
    },
    '@librechat/api/vendos': auth,
    './process': {
      createSocialUser: async (user) => { operations.created++; return { ...user, googleId: user.providerId, _id: 'synthetic-user', role: 'USER' }; },
      handleExistingUser: async () => { operations.existing++; },
    },
    '~/server/services/Config': { getAppConfig: async () => config },
    '~/models': {
      findUser: async () => existing,
      updateUser: async () => { operations.updated++; },
    },
  };
  return { operations, deps, identity };
}

async function login(identity, existing = null, options = {}) {
  const f = fixture(identity, existing);
  const handler = load('api/strategies/socialLogin.js', f.deps, {
    ALLOW_SOCIAL_REGISTRATION: 'true', VENDOS_GOOGLE_EMAIL_SHA256_ALLOWLIST: hash,
  });
  let result;
  await handler(identity.provider, () => ({ ...identity, id: identity.googleId }), options)(
    null, null, null, {}, (error, user) => { result = { error, user }; },
  );
  return { ...result, operations: f.operations };
}

async function callback(identity) {
  const f = fixture(identity);
  const handler = load('api/server/middleware/checkDomainAllowed.js', f.deps);
  let next = false;
  let redirected = false;
  await handler({ user: identity }, { redirect() { redirected = true; } }, () => { next = true; });
  return { next, redirected };
}

const corporate = { provider: 'google', email: 'owner@company.test', emailVerified: true, googleId: '100000000000000000001' };

test('unverified Google corporate-domain profile is denied before create or existing-user updates', async () => {
  for (const emailVerified of [false, undefined, null, 'true', 1]) {
    for (const existing of [null, { ...corporate, _id: 'synthetic-owner', role: 'ADMIN' }]) {
      const result = await login({ ...corporate, emailVerified }, existing);
      assert.ok(result.error || !result.user, `verification ${String(emailVerified)} must fail`);
      assert.deepEqual(result.operations, { created: 0, existing: 0, updated: 0 });
    }
  }
});

test('unverified persisted Google corporate identity is denied at final OAuth callback', async () => {
  for (const emailVerified of [false, undefined, null, 'true', 1]) {
    assert.deepEqual(await callback({ ...corporate, emailVerified }), { next: false, redirected: true });
  }
});

test('verified corporate owner standard and existing-admin Google login remain allowed', async () => {
  const owner = { ...corporate, _id: 'synthetic-owner', role: 'ADMIN' };
  for (const options of [{}, { existingUsersOnly: true }]) {
    const result = await login(corporate, owner, options);
    assert.equal(result.error, null);
    assert.equal(result.user._id, owner._id);
    assert.deepEqual(result.operations, { created: 0, existing: 1, updated: 0 });
  }
  assert.deepEqual(await callback(owner), { next: true, redirected: false });
});

test('new verified exact external identity is permitted but another external Google account is rejected', async () => {
  const target = { ...corporate, email, googleId: '100000000000000000002' };
  const accepted = await login(target);
  assert.equal(accepted.error, null);
  assert.equal(accepted.operations.created, 1);
  for (const patch of [{ email: 'another@example.net' }, { emailVerified: false }, { googleId: '' }]) {
    const result = await login({ ...target, ...patch });
    assert.ok(result.error || !result.user);
    assert.deepEqual(result.operations, { created: 0, existing: 0, updated: 0 });
  }
});

test('external identity does not gain access through admin-existingUsersOnly exception', async () => {
  const target = { ...corporate, email, googleId: '100000000000000000002', _id: 'synthetic-colleague', role: 'USER' };
  const result = await login(target, target, { existingUsersOnly: true });
  assert.ok(result.error || !result.user);
  assert.deepEqual(result.operations, { created: 0, existing: 0, updated: 0 });
});
