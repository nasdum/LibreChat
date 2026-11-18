const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const root = path.resolve(__dirname, '..');
const auth = require(
  process.env.AUTH_TEST_BUNDLE || '../packages/api/src/vendos/googleEmailException.ts',
);
const email = 'invited.person@example.net';
const hash = createHash('sha256').update(email).digest('hex');
const identity = {
  provider: 'google',
  email,
  emailVerified: true,
  googleId: '123456789012345678901',
};
const allowedDomains = ['company.test'];
const domainAllowed = (value, domains) =>
  !domains?.length || domains.includes(value?.split('@')[1]?.toLowerCase());

function loadWrapper(relative, dependencies, env = {}) {
  const module = { exports: {} };
  const context = vm.createContext({ module, exports: module.exports, process: { env } });
  const source = fs.readFileSync(path.join(root, relative), 'utf8');
  const wrapper = new vm.Script(`(function(require,module,exports){${source}\n})`, {
    filename: relative,
  }).runInContext(context);
  wrapper(
    (name) => {
      if (!Object.hasOwn(dependencies, name)) throw new Error(`Unexpected dependency: ${name}`);
      return dependencies[name];
    },
    module,
    module.exports,
  );
  return module.exports;
}

function helperDependencies(hashes = hash) {
  return {
    isVerifiedGoogleEmailException: (value) => auth.isVerifiedGoogleEmailException(value, hashes),
    isSameGoogleExceptionIdentity: auth.isSameGoogleExceptionIdentity,
    isVerifiedGoogleIdentity: auth.isVerifiedGoogleIdentity,
  };
}

async function login({
  profile = identity,
  hashes = hash,
  existing = null,
  options = {},
  registration = true,
  domains = allowedDomains,
} = {}) {
  const operations = { created: 0, updated: 0, existing: 0 };
  const config = { registration: { allowedDomains: domains } };
  const dependencies = {
    '@librechat/data-schemas': { logger: { error() {}, warn() {}, info() {} } },
    'librechat-data-provider': { ErrorTypes: { AUTH_FAILED: 'AUTH_FAILED' } },
    '@librechat/api': {
      isEnabled: (value) => value === 'true',
      isEmailDomainAllowed: domainAllowed,
      resolveAppConfigForUser: async () => config,
    },
    '@librechat/api/vendos': helperDependencies(hashes),
    './process': {
      createSocialUser: async (value) => {
        operations.created++;
        return { ...value, googleId: value.providerId, _id: 'synthetic-user', role: 'USER' };
      },
      handleExistingUser: async () => {
        operations.existing++;
      },
    },
    '~/server/services/Config': { getAppConfig: async () => config },
    '~/models': {
      findUser: async () => existing,
      updateUser: async () => {
        operations.updated++;
      },
    },
  };
  const socialLogin = loadWrapper('api/strategies/socialLogin.js', dependencies, {
    ALLOW_SOCIAL_REGISTRATION: String(registration),
  });
  let result;
  await socialLogin(profile.provider, () => ({ ...profile, id: profile.googleId }), options)(
    null,
    null,
    null,
    {},
    (error, user) => {
      result = { error, user };
    },
  );
  return { ...result, operations };
}

async function callback(user, hashes = hash) {
  let continued = false;
  let redirect = null;
  const middleware = loadWrapper('api/server/middleware/checkDomainAllowed.js', {
    '@librechat/data-schemas': { logger: { error() {} } },
    '@librechat/api': {
      getAppConfigOptionsFromUser: () => ({}),
      isEmailDomainAllowed: domainAllowed,
    },
    '@librechat/api/vendos': helperDependencies(hashes),
    '~/server/services/Config': {
      getAppConfig: async () => ({ registration: { allowedDomains } }),
    },
  });
  await middleware(
    { user },
    {
      redirect: (value) => {
        redirect = value;
      },
    },
    () => {
      continued = true;
    },
  );
  return { continued, redirect };
}

test('exact verified Google identity matches a private SHA256 allowlist', () => {
  assert.equal(auth.isVerifiedGoogleEmailException(identity, hash), true);
  assert.equal(
    auth.isVerifiedGoogleEmailException(
      { ...identity, email: '  INVITED.PERSON@EXAMPLE.NET  ' },
      hash,
    ),
    true,
  );
  assert.equal(auth.isVerifiedGoogleEmailException(identity, ` ${hash.toUpperCase()} `), true);
});

for (const [label, patch] of [
  ['wrong email', { email: 'someone.else@example.net' }],
  ['suffix email', { email: `${email}.attacker.test` }],
  ['wrong provider', { provider: 'facebook' }],
  ['missing provider', { provider: undefined }],
  ['unverified email', { emailVerified: false }],
  ['string verification flag', { emailVerified: 'true' }],
  ['missing Google subject', { googleId: '' }],
  ['malformed Google subject', { googleId: '123\n456' }],
  ['control character email', { email: `${email}\n` }],
  ['double at-sign email', { email: 'a@b@example.net' }],
]) {
  test(`denies ${label}`, () =>
    assert.equal(auth.isVerifiedGoogleEmailException({ ...identity, ...patch }, hash), false));
}

test('empty, absent and malformed allowlists fail closed', () => {
  for (const hashes of ['', ' ', 'not-a-hash', `${hash},`, `${hash},bad`, 'a'.repeat(10001)]) {
    assert.equal(auth.isVerifiedGoogleEmailException(identity, hashes), false);
  }
  const previous = process.env[auth.GOOGLE_EMAIL_EXCEPTION_ENV];
  try {
    delete process.env[auth.GOOGLE_EMAIL_EXCEPTION_ENV];
    assert.equal(auth.isVerifiedGoogleEmailException(identity), false);
  } finally {
    if (previous === undefined) delete process.env[auth.GOOGLE_EMAIL_EXCEPTION_ENV];
    else process.env[auth.GOOGLE_EMAIL_EXCEPTION_ENV] = previous;
  }
});

test('exact external Google identity can register through existing enabled registration', async () => {
  const result = await login();
  assert.equal(result.error, null);
  assert.equal(result.user.googleId, identity.googleId);
  assert.equal(result.user.emailVerified, true);
  assert.equal(result.user.role, 'USER');
  assert.equal(result.operations.created, 1);
  assert.equal(result.operations.updated, 0);
});

test('new external exception never overrides disabled social registration', async () => {
  const result = await login({ registration: false });
  assert.equal(result.error.code, 'AUTH_FAILED');
  assert.equal(result.operations.created, 0);
});

test('existing exact verified subject can log in without enabled registration', async () => {
  const result = await login({
    existing: { ...identity, _id: 'synthetic-user' },
    registration: false,
  });
  assert.equal(result.error, null);
  assert.equal(result.operations.existing, 1);
  assert.equal(result.operations.updated, 0);
});

test('external existing email fallback cannot link another or missing Google subject', async () => {
  for (const patch of [
    { googleId: '999' },
    { googleId: undefined },
    { emailVerified: false },
    { provider: 'local' },
    { email: 'other@example.net' },
  ]) {
    const result = await login({ existing: { ...identity, ...patch } });
    assert.equal(result.error.code, 'AUTH_FAILED');
    assert.equal(
      result.operations.created + result.operations.updated + result.operations.existing,
      0,
    );
  }
});

test('exception does not apply to the existing-users-only administrator OAuth flow', async () => {
  const result = await login({ existing: identity, options: { existingUsersOnly: true } });
  assert.equal(result.error.code, 'AUTH_FAILED');
  assert.equal(
    result.operations.created + result.operations.updated + result.operations.existing,
    0,
  );
});

test('wrong provider, unverified identity, wrong email and empty allowlist stop before create', async () => {
  for (const input of [
    { profile: { ...identity, provider: 'discord' } },
    { profile: { ...identity, emailVerified: false } },
    { profile: { ...identity, email: 'wrong@example.net' } },
    { hashes: '' },
  ]) {
    const result = await login(input);
    assert.equal(result.error.code, 'AUTH_FAILED');
    assert.equal(
      result.operations.created + result.operations.updated + result.operations.existing,
      0,
    );
  }
});

test('verified corporate Google and existing non-Google domain flow need no exception', async () => {
  for (const provider of ['google', 'discord']) {
    const profile = { ...identity, provider, email: 'owner@company.test', emailVerified: provider === 'google' };
    const result = await login({ profile, hashes: '' });
    assert.equal(result.error, null);
    assert.equal(result.operations.created, 1);
  }
});

test('callback checks persisted Google provider, verified email and subject', async () => {
  assert.deepEqual(await callback(identity), { continued: true, redirect: null });
  for (const patch of [
    { provider: 'local' },
    { emailVerified: false },
    { googleId: undefined },
    { email: 'wrong@example.net' },
  ]) {
    assert.deepEqual(await callback({ ...identity, ...patch }), {
      continued: false,
      redirect: '/login',
    });
  }
  assert.deepEqual(await callback(identity, ''), { continued: false, redirect: '/login' });
});

test('callback keeps verified corporate Google and original non-Google behavior', async () => {
  assert.deepEqual(await callback({ ...identity, email: 'owner@company.test' }, ''), {
    continued: true,
    redirect: null,
  });
  assert.deepEqual(await callback({ email: 'employee@company.test', provider: 'discord' }, ''), {
    continued: true,
    redirect: null,
  });
});

for (const verified of [false, undefined, 'true', 1]) {
  test(`company Google login rejects unverified claim ${String(verified)}`, async () => {
    const result = await login({ profile: { ...identity, email: 'staff@company.test', emailVerified: verified } });
    assert.ok(result.error);
    assert.equal(result.operations.created, 0);
    assert.equal(result.operations.existing, 0);
  });
  test(`company Google callback rejects persisted verification ${String(verified)}`, async () => {
    const result = await callback({ ...identity, email: 'staff@company.test', emailVerified: verified });
    assert.equal(result.continued, false);
    assert.equal(result.redirect, '/login');
  });
}
test('verified company Google identity remains allowed without external exception', async () => {
  const profile = { ...identity, email: 'staff@company.test' };
  const result = await login({ profile, hashes: '' });
  assert.equal(result.error, null);
  assert.ok(result.user);
  assert.equal((await callback(profile, '')).continued, true);
});
