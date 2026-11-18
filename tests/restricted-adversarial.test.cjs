'use strict';
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const http = require('node:http');
const { test } = require('node:test');
const express = require('express');
const api = require(process.env.AUTH_TEST_BUNDLE || '../payload/vendos.cjs');

const hash = (text) => createHash('sha256').update(text).digest('hex');
const id = '222222222222222222222222';
const ownerId = '111111111111111111111111';
const email = 'invited.person@example.net';
const now = Date.parse('2026-11-18T20:00:00Z');
const expiry = now / 1000 + 86400;
process.env.VENDOS_GOOGLE_EMAIL_SHA256_ALLOWLIST = hash(email);
const endpoint = 'VENDOS pilot';
const model = 'claude-sonnet-5-5';
const spec = 'vendos-consultation';
const identity = { id, _id: id, email, emailVerified: true, provider: 'google', googleId: '100000000000000000002', role: 'USER' };

function records() {
  return {
    journal: { _id: id, state: 'prepared', access_policy: 'vendos-chat-only-v1', target_email_sha256: hash(email),
      google_subject_sha256: hash(identity.googleId), expires_at: expiry,
      config_id: 'c'.repeat(24), model_key_id: 'd'.repeat(24), mcp_token_id: 'e'.repeat(24),
      config_sha256: api.vendosRestrictedDigest(api.vendosRestrictedOverrides()),
      model_key_ciphertext_sha256: hash('SYNTHETIC_ENCRYPTED_CLAUDE'), mcp_token_ciphertext_sha256: hash('SYNTHETIC_ENCRYPTED_MCP') },
    activeConfigs: [{ _id: 'c'.repeat(24), principalType: 'user', principalId: id, principalModel: 'User', isActive: true, priority: 1000,
      tombstones: [], overrides: api.vendosRestrictedOverrides() }],
    keys: [{ _id: 'd'.repeat(24), userId: id, name: endpoint, value: 'SYNTHETIC_ENCRYPTED_CLAUDE', expiresAt: new Date(expiry * 1000) }],
    plugins: [{ _id: 'e'.repeat(24), userId: id, pluginKey: 'mcp_vendos_pilot', authField: 'VENDOS_PILOT_KEY', value: 'SYNTHETIC_ENCRYPTED_MCP' }],
  };
}

function config() {
  return { ...api.vendosRestrictedOverrides(), endpoints: { custom: [
    { name: endpoint, apiKey: 'user_provided', provider: 'anthropic', baseURL: 'https://api.anthropic.com', titleConvo: false,
      activityLabel: false, models: { default: [model], fetch: false } },
    { name: 'Unrelated endpoint', apiKey: 'synthetic-unused', provider: 'openai', baseURL: 'https://never.called.invalid' },
  ] }, mcpConfig: { vendos_pilot: { url: 'https://synthetic-mcp.invalid/mcp', headers: { Authorization: 'Bearer {{VENDOS_PILOT_KEY}}' }, customUserVars: { VENDOS_PILOT_KEY: { sensitive: true } } },
    unrelated: { url: 'https://never.called.invalid/mcp' } } };
}

function body(extra = {}) {
  return { endpoint, model, spec, endpointType: 'custom', conversationId: 'new', text: 'Jaké jsou výsledky VENDOS?',
    parentMessageId: '00000000-0000-0000-0000-000000000000', messageId: 'synthetic-message', ...extra };
}

async function server(t) {
  const state = { identity: structuredClone(identity), records: records(), config: config(), calls: [], lookups: [],
    conversations: new Map(), generations: new Map(), failProvision: false };
  api.verifyVendosRestrictedAccess(state.identity, state.records, now);
  state.conversations.set('own-vendos', { user: id, conversationId: 'own-vendos', endpoint, model, spec });
  state.conversations.set('own-other', { user: id, conversationId: 'own-other', endpoint: 'anthropic', model, spec: 'different' });
  state.conversations.set('owner-vendos', { user: ownerId, conversationId: 'owner-vendos', endpoint, model, spec });
  state.generations.set('own-vendos', { streamId: 'own-vendos', conversationId: 'own-vendos', metadata: { userId: id, endpoint, model } });
  state.generations.set('own-other', { streamId: 'own-other', metadata: { userId: id, endpoint: 'openAI', model: 'other' } });
  state.generations.set('owner-vendos', { streamId: 'owner-vendos', metadata: { userId: ownerId, endpoint, model } });
  const app = express();
  app.use(express.json());
  const fence = api.createVendosRestrictedChat({
    hashes: () => hash(email), now: () => now,
    authenticate(req, _res, next) {
      if (req.headers.authorization === 'Bearer synthetic-target') req.user = structuredClone(state.identity);
      if (req.headers.authorization === 'Bearer synthetic-owner') req.user = { ...identity, id: ownerId, _id: ownerId, email: 'owner@company.test', role: 'ADMIN' };
      next();
    },
    provision: async () => { if (state.failProvision) throw new Error('synthetic-db-failure'); return state.records; },
    conversation: async (value) => { state.lookups.push(value); return state.conversations.get(value) || null; },
    conversations: async (user) => [...state.conversations.values()].filter((row) => row.user === user && row.endpoint === endpoint),
    generation: async (value) => state.generations.get(value) || null,
    generations: async (user) => [...state.generations.values()].filter((row) => row.metadata.userId === user && row.metadata.endpoint === endpoint),
  });
  // Same mounting boundary as the staged real server. Express default route casing is retained.
  app.use('/api', fence);
  app.use('/images', fence);
  app.use(['/api', '/images'], (req, res) => {
    try {
      if (req.method === 'POST' && req.originalUrl.startsWith('/api/agents/chat')) {
        req.config = structuredClone(state.config);
        api.enforceVendosRestrictedConfig(req);
        if (!req.originalUrl.startsWith('/api/agents/chat/abort')) api.enforceVendosRestrictedBody(req);
      }
      state.calls.push({ method: req.method, path: req.originalUrl, body: req.body, config: req.config });
      res.status(201).json({ downstream: true, body: req.body, config: req.config });
    } catch { res.status(403).json({ error: 'BLOCKED_BY_POSTCONFIG_HOOK' }); }
  });
  app.use((_req, res) => res.status(404).json({ unknownRoute: true }));
  app.use((_error, _req, res, _next) => res.status(403).json({ error: 'DENIED' }));
  const listener = app.listen(0, '127.0.0.1');
  await new Promise((resolve) => listener.once('listening', resolve));
  t.after(() => new Promise((resolve, reject) => listener.close((error) => error ? reject(error) : resolve())));
  const request = (path, method = 'GET', payload, token = 'synthetic-target') => new Promise((resolve, reject) => {
    const serialized = payload === undefined ? null : JSON.stringify(payload);
    const req = http.request({ host: '127.0.0.1', port: listener.address().port, path, method,
      headers: { Authorization: `Bearer ${token}`, ...(serialized === null ? {} : { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(serialized) }) } }, (res) => {
      let text = ''; res.setEncoding('utf8'); res.on('data', (chunk) => { text += chunk; });
      res.on('end', () => { let value; try { value = JSON.parse(text); } catch { value = null; } resolve({ status: res.statusCode, value }); });
    });
    req.on('error', reject); if (serialized !== null) req.write(serialized); req.end();
  });
  return { state, request };
}

const forbidden = [
  ['POST', '/api/agents/chat/openAI'], ['POST', '/api/agents/chat/anthropic'], ['POST', '/api/agents/chat/agents'],
  ['POST', '/api/agents/v1/chat/completions'], ['POST', '/api/agents/v1/responses'], ['GET', '/api/agents/v1/models'],
  ['GET', '/api/agents'], ['POST', '/api/agents'], ['GET', '/api/agents/tools'], ['POST', '/api/agents/tools/any/call'],
  ['GET', '/api/files'], ['POST', '/api/files'], ['GET', '/images/private.png'], ['GET', '/api/files/download/any'],
  ['PUT', '/api/keys'], ['DELETE', '/api/keys'], ['GET', '/api/keys?name=anthropic'], ['POST', '/api/api-keys'], ['GET', '/api/api-keys'],
  ['GET', '/api/skills'], ['POST', '/api/skills'], ['GET', '/api/prompts'], ['GET', '/api/projects'], ['POST', '/api/projects'],
  ['GET', '/api/mcp/servers'], ['POST', '/api/mcp/servers'], ['GET', '/api/mcp/tools'], ['GET', '/api/mcp/vendos_pilot/auth-values'],
  ['GET', '/api/mcp/other/oauth/initiate'], ['POST', '/api/mcp/vendos_pilot/oauth/bind'], ['GET', '/api/actions'],
  ['GET', '/api/share'], ['GET', '/api/share/public-data'], ['POST', '/api/share'], ['GET', '/api/search?q=private'],
  ['GET', '/api/memories'], ['GET', '/api/admin/users'], ['POST', '/api/user/plugins'], ['GET', '/api/user/settings'],
  ['POST', '/api/convos/fork'], ['POST', '/api/convos/duplicate'], ['POST', '/api/convos/import'], ['POST', '/api/convos/update'],
  ['POST', '/api/messages/branch'], ['POST', '/api/messages/artifact/any'], ['PUT', '/api/messages/own-vendos/any'],
];

test('actual Express fence blocks other endpoint, tool, data, settings and key surfaces', async (t) => {
  const { state, request } = await server(t);
  for (const [method, path] of forbidden) {
    const before = state.calls.length;
    const result = await request(path, method, method === 'GET' ? undefined : body());
    assert.equal(result.status, 403, `${method} ${path}`);
    assert.equal(state.calls.length, before, `${path} reached downstream`);
  }
});

test('route casing, encoded separators, double slashes and dot segments never bypass the fence', async (t) => {
  const { state, request } = await server(t);
  for (const path of ['/API/keys', '/api/KEYS', '/Api/agents/v1/responses', '/api//keys', '//api/keys', '/api/%2fkeys', '/api/%5ckeys', '/api/%2e%2e/keys', '/api/%252fkeys', '/api/../api/keys', '/%61pi/keys']) {
    const result = await request(path);
    assert.ok([403, 404].includes(result.status), path);
    assert.equal(state.calls.length, 0, path);
  }
});

test('normal VENDOS chat survives with a canonical corporate endpoint and only the delegated MCP', async (t) => {
  const { request } = await server(t);
  for (const conversationId of ['new', 'own-vendos']) {
    const result = await request('/api/agents/chat/VENDOS%20pilot', 'POST', body({ conversationId }));
    assert.equal(result.status, 201);
    assert.equal(result.value.body.text, body().text);
    assert.equal(result.value.body.model, model);
    assert.deepEqual(result.value.body.ephemeralAgent.mcp, ['vendos_pilot']);
    assert.equal(result.value.body.ephemeralAgent.web_search, false);
    assert.equal(result.value.body.ephemeralAgent.execute_code, false);
    assert.deepEqual(Object.keys(result.value.config.mcpConfig), ['vendos_pilot']);
    assert.deepEqual(result.value.config.endpoints.custom.map((item) => item.name), [endpoint]);
  }
});

test('raw alternate agents, tools, skills, prompt overrides and attached files are rejected', async (t) => {
  const { state, request } = await server(t);
  const attacks = [
    { endpoint: 'openAI' }, { model: 'claude-opus-4-6' }, { spec: 'other' }, { endpointType: 'agents' },
    { addedConvo: { endpoint: 'openAI', model: 'foreign' } }, { agent_id: 'foreign-agent' }, { assistant_id: 'foreign-assistant' },
    { ephemeralAgent: { mcp: ['other_server'] } }, { ephemeralAgent: { mcp: ['vendos_pilot', 'other_server'] } },
    ...['execute_code', 'web_search', 'file_search', 'skills', 'memory', 'run_in_background', 'ask_user_question'].map((key) => ({ ephemeralAgent: { [key]: true } })),
    { files: [{ file_id: 'foreign-file' }] }, { attachments: [{ file_id: 'foreign-file' }] }, { tools: ['search'] },
    { manualSkills: ['foreign-skill'] }, { alwaysAppliedSkills: ['foreign-skill'] }, { promptPrefix: 'override' },
    { instructions: 'override' }, { system: 'override' }, { context: 'override' }, { chatProjectId: 'foreign-project' },
    { overrideConvoId: 'own-other' }, { recoverySteerId: 'other-steer' }, { isTemporary: true },
  ];
  for (const attack of attacks) {
    const before = state.calls.length;
    const result = await request('/api/agents/chat/VENDOS%20pilot', 'POST', body(attack));
    assert.equal(result.status, 403, JSON.stringify(attack));
    assert.equal(state.calls.length, before);
  }
});

test('unknown raw provider and endpointOption parameters cannot survive canonical rewriting', async (t) => {
  const { request } = await server(t);
  const result = await request('/api/agents/chat/VENDOS%20pilot', 'POST', body({
    provider: 'openai', apiKey: 'synthetic-foreign', baseURL: 'https://never.called.invalid', endpointOption: { endpoint: 'openAI' },
    model_parameters: { model: 'foreign' }, max_tokens: 999999, top_p: 0.01,
  }));
  assert.equal(result.status, 201);
  for (const key of ['provider', 'apiKey', 'baseURL', 'endpointOption', 'model_parameters', 'max_tokens', 'top_p']) {
    assert.equal(Object.hasOwn(result.value.body, key), false, key);
  }
});

test('own non-VENDOS and owner conversations cannot be read, continued, streamed or aborted', async (t) => {
  const { state, request } = await server(t);
  for (const convo of ['own-other', 'owner-vendos']) {
    for (const path of [`/api/convos/${convo}`, `/api/messages/${convo}`, `/api/messages/${convo}/message`, `/api/agents/chat/stream/${convo}`, `/api/agents/chat/status/${convo}`]) {
      assert.equal((await request(path)).status, 403, path);
    }
    assert.equal((await request('/api/agents/chat/VENDOS%20pilot', 'POST', body({ conversationId: convo }))).status, 403);
    assert.equal((await request('/api/agents/chat/abort', 'POST', { conversationId: convo })).status, 403);
  }
  assert.equal(state.calls.length, 0);
});

test('route-name conversation IDs do not open the separate generation title route', async (t) => {
  const { state, request } = await server(t);
  state.conversations.set('gen_title', { user: id, conversationId: 'gen_title', endpoint, model, spec });
  assert.equal((await request('/api/convos/gen_title/own-other')).status, 403);
  assert.equal(state.calls.length, 0);
});

test('own VENDOS read, stream, status, abort and resume remain available', async (t) => {
  const { request } = await server(t);
  for (const path of ['/api/convos/own-vendos', '/api/messages/own-vendos', '/api/messages/own-vendos/message',
    '/api/agents/chat/stream/own-vendos?resume=true&generationCreatedAt=123', '/api/agents/chat/status/own-vendos']) {
    assert.equal((await request(path)).status, 201, path);
  }
  assert.equal((await request('/api/agents/chat/abort', 'POST', { conversationId: 'own-vendos', generationCreatedAt: 123 })).status, 201);
  assert.equal((await request('/api/agents/chat/resume', 'POST', body({ conversationId: 'own-vendos', generationCreatedAt: 123, actionId: 'synthetic-action', decisions: [] }))).status, 201);
});

test('fixed bootstrap exposes only VENDOS and pending state never permits generation', async (t) => {
  const { state, request } = await server(t);
  assert.deepEqual(Object.keys((await request('/api/endpoints')).value), [endpoint]);
  assert.deepEqual((await request('/api/models')).value, { [endpoint]: [model] });
  assert.equal((await request('/api/config')).value.modelSpecs.enforce, true);
  assert.equal((await request('/api/config')).value.vendosAccess, 'ready');
  const result = await request('/api/keys?name=VENDOS%20pilot');
  assert.deepEqual(Object.keys(result.value), ['expiresAt']);
  assert.equal(result.value.expiresAt, new Date(expiry * 1000).toISOString());
  state.records.journal = null;
  assert.equal((await request('/api/config')).value.vendosAccess, 'pending');
  assert.equal((await request('/api/keys?name=VENDOS%20pilot')).value.expiresAt, null);
  assert.equal((await request('/api/agents/chat/VENDOS%20pilot', 'POST', body())).status, 403);
  assert.equal(state.calls.length, 0);
});

test('alternate API-key-authenticated remote agent path rejects target after authentication', () => {
  for (const patch of [{}, { provider: 'local' }, { emailVerified: false }]) {
    let reached = false;
    let status;
    api.denyVendosRestrictedRemote({ user: { ...identity, ...patch } }, {
      status(value) { status = value; return this; }, json() {},
    }, () => { reached = true; });
    assert.equal(reached, false);
    assert.equal(status, 403);
  }
  let reached = false;
  api.denyVendosRestrictedRemote({ user: { ...identity, email: 'owner@company.test' } }, {
    status() { throw new Error('Owner unexpectedly denied'); },
  }, () => { reached = true; });
  assert.equal(reached, true);
});

test('missing, stale, foreign or changed provisioning denies model requests on each call', async (t) => {
  const { state, request } = await server(t);
  const pristine = records();
  const changes = [
    (r) => { r.journal = null; }, (r) => { r.journal.access_policy = 'old-v2'; },
    (r) => { r.journal.expires_at = now / 1000; }, (r) => { r.journal.google_subject_sha256 = '0'.repeat(64); },
    (r) => { r.activeConfigs.push({ principalType: 'role', isActive: true }); }, (r) => { r.activeConfigs[0].overrides.modelSpecs.enforce = false; },
    (r) => { r.keys[0].value = 'changed-user-key'; }, (r) => { r.keys[0].expiresAt = new Date((expiry + 1) * 1000); },
    (r) => { r.plugins[0].value = 'changed-token'; }, (r) => { r.plugins.push({ ...r.plugins[0] }); },
    (r) => { r.activeConfigs[0]._id = 'f'.repeat(24); }, (r) => { r.keys[0]._id = 'f'.repeat(24); }, (r) => { r.plugins[0]._id = 'f'.repeat(24); },
  ];
  for (const change of changes) {
    state.records = structuredClone(pristine); change(state.records);
    assert.equal((await request('/api/agents/chat/VENDOS%20pilot', 'POST', body())).status, 403);
  }
  state.records = pristine;
  state.failProvision = true;
  assert.equal((await request('/api/agents/chat/VENDOS%20pilot', 'POST', body())).status, 403);
  assert.equal(state.calls.length, 0);
});

test('base-config fallback cannot silently loosen modelSpec or corporate credentials', async (t) => {
  const { state, request } = await server(t);
  for (const change of [
    (c) => { delete c.modelSpecs; }, (c) => { c.modelSpecs.enforce = false; },
    (c) => { c.endpoints.custom[0].apiKey = 'foreign'; }, (c) => { c.endpoints.custom[0].baseURL = 'https://foreign.invalid'; },
    (c) => { c.endpoints.custom[0].titleConvo = true; }, (c) => { c.mcpConfig.vendos_pilot.headers.Authorization = 'Bearer foreign'; },
  ]) {
    state.config = config(); change(state.config);
    assert.equal((await request('/api/agents/chat/VENDOS%20pilot', 'POST', body())).status, 403);
  }
  assert.equal(state.calls.length, 0);
});

test('legitimate inherited modelSpecs optional fields are stripped after canonical enforcement', async (t) => {
  const { state, request } = await server(t);
  state.config.modelSpecs.addedEndpoints = ['openAI', 'anthropic'];
  const result = await request('/api/agents/chat/VENDOS%20pilot', 'POST', body());
  assert.equal(result.status, 201);
  assert.deepEqual(result.value.config.modelSpecs, api.vendosRestrictedOverrides().modelSpecs);
  assert.equal(Object.hasOwn(result.value.config.modelSpecs, 'addedEndpoints'), false);
  assert.deepEqual(Object.keys(result.value.config.mcpConfig), ['vendos_pilot']);
});

test('unverified or non-Google target remains restricted instead of falling through as ordinary user', async (t) => {
  const { state, request } = await server(t);
  for (const patch of [{ emailVerified: false }, { provider: 'local' }, { googleId: '' }, { role: 'ADMIN' }, { tenantId: 'other' }]) {
    state.identity = { ...identity, ...patch };
    assert.equal((await request('/api/agents/chat/VENDOS%20pilot', 'POST', body())).status, 403);
    assert.equal((await request('/api/keys', 'PUT', { name: 'anthropic' })).status, 403);
  }
  assert.equal(state.calls.length, 0);
});

test('unrelated corporate owner requests and payloads are not changed by colleague fence', async (t) => {
  const { state, request } = await server(t);
  const original = { endpoint: 'openAI', model: 'synthetic-owner-model', arbitrary: 'preserve', ephemeralAgent: { web_search: true } };
  for (const [method, path] of forbidden) {
    const result = await request(path, method, method === 'GET' ? undefined : original, 'synthetic-owner');
    assert.equal(result.status, 201, path);
    if (method !== 'GET') assert.deepEqual(result.value.body, original);
  }
  assert.equal(state.calls.length, forbidden.length);
});
