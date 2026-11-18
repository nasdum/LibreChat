'use strict';
const fs = require('node:fs');
const { createHash } = require('node:crypto');
const { createRequire } = require('node:module');
const BASE_SHA = '1c9153e513deac86b9845ecdc566173202b834f7dfafbf6179ac41fa24380c27';
const PRIVATE_MCP_URL = 'http://172.21.0.1:18089/mcp';
const BUNDLE_SHA = '8a7b070137826d1fb89ca64be9a2dda636fa9b9d2cc63fd4852d834ccfb8ebbd';
const SERVICE_REVIEW_SHA = '728efbe1ff7f66f217776c0fbc1dbe7bc1d0bdf64acd0030a8ebab8763135673';
const PROJECT = 'vendos-cz';
const BAD_PROJECT = '__vendos_readback_denied_not_a_project__';
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const SAFE_ERROR_CODES = new Set([
  'USAGE_VERIFY_EMAIL_SHA256', 'EXPECTED_LIBRECHAT_APP_ROOT', 'RUNTIME_BUNDLE_DRIFT',
  'UNTRUSTED_CONFIG_PATH', 'BASE_CONFIG_DRIFT', 'MCP_CONFIG_DRIFT', 'MCP_DESTINATION_UNSAFE', 'BROWSER_SERIALIZATION_DRIFT', 'APP_SERVICE_CONFIG_NOT_RESOLVED',
  'NON_CLAUDE_MODERATION_ENABLED', 'UNEXPECTED_DATABASE', 'USER_LOOKUP_TOO_LARGE',
  'TARGET_IDENTITY_NOT_UNIQUE', 'TARGET_IDENTITY_NOT_ALLOWED', 'VENDOS_ACCESS_RESTRICTED',
  'MCP_ACTOR_JOURNAL_MISMATCH', 'ACTUAL_CONFIG_RESOLVER_UNAVAILABLE', 'EFFECTIVE_CONFIG_MERGE_MISMATCH',
  'MCP_TOKEN_JOURNAL_MISMATCH', 'IDENTITY_CHANGED_DURING_READBACK', 'TOKEN_CHANGED_DURING_READBACK',
  'MCP_RESPONSE_BODY_UNAVAILABLE', 'MCP_RESPONSE_TOO_LARGE', 'MCP_INVALID_JSON', 'MCP_RPC_FAILED',
  'MCP_READ_TOOL_FAILED', 'MCP_READ_RESULT_MISSING', 'MCP_READ_RESULT_SHAPE', 'MCP_HTTP_FAILED',
  'MCP_INVALID_SESSION', 'MCP_PROTOCOL_UNSUPPORTED', 'MCP_TOOL_CATALOG_INCOMPLETE',
  'MCP_REQUIRED_TOOL_MISSING', 'MCP_PROJECT_ACCESS_NOT_EXACT', 'MCP_PROJECT_REPORT_SHAPE',
  'MCP_CALLER_ACCESS_INVALID', 'MCP_SCOPES_NOT_EXACT', 'MCP_NEGATIVE_AUTHORIZATION_NOT_PROVEN',
  'LIVE_FENCE_REQUEST_REJECTED', 'LIVE_FENCE_CONFIG_REJECTED', 'LIVE_FENCE_UNEXPECTED_LOOKUP',
]);
const hash = (value) => createHash('sha256').update(value).digest('hex');
const fail = (condition, code) => { if (!condition) throw new Error(code); };
const object = (value) => value && typeof value === 'object' && !Array.isArray(value);

function trustedMcpDestination(value, configSha256) {
  fail(configSha256 === BASE_SHA && value === PRIVATE_MCP_URL, 'MCP_DESTINATION_UNSAFE');
  return new URL(value);
}

async function verifyInstalledFence(fence, user, records, mergedConfig, createPayload, withTenant) {
  fail(fence.isVerifiedGoogleEmailException(user), 'LIVE_FENCE_REQUEST_REJECTED');
  const conversation = { conversationId: 'new', endpoint: 'VENDOS pilot', endpointType: 'custom',
    model: 'claude-sonnet-5-5', spec: 'vendos-consultation' };
  // Match the disabled tool state produced by applyModelSpecEphemeralAgent in the browser.
  const { server, payload } = createPayload({
    conversation, endpointOption: conversation, isTemporary: false, manualSkills: [],
    userMessage: { text: 'Read-only startup verification', parentMessageId: '00000000-0000-0000-0000-000000000000' },
    ephemeralAgent: { mcp: ['vendos_pilot'], web_search: false, file_search: false,
      execute_code: false, memory: false, artifacts: '' },
  });
  fail(payload.ephemeralAgent?.artifacts === '', 'BROWSER_SERIALIZATION_DRIFT');
  const originalUrl = new URL(server, 'https://chat.nasdum.cz').pathname;
  fail(originalUrl === '/api/agents/chat/VENDOS%20pilot', 'BROWSER_SERIALIZATION_DRIFT');
  const request = { method: 'POST', originalUrl, user, config: mergedConfig,
    path: originalUrl, headers: {}, body: JSON.parse(JSON.stringify(payload)) };
  const unavailable = async () => { throw new Error('LIVE_FENCE_UNEXPECTED_LOOKUP'); };
  const middleware = fence.createVendosRestrictedChat({
    authenticate(req, res, next) { fail(req.user === user, 'LIVE_FENCE_REQUEST_REJECTED'); withTenant(req, res, next); },
    provision: async () => records,
    conversation: unavailable, conversations: unavailable, generation: unavailable, generations: unavailable,
  });
  await new Promise((resolve, reject) => {
    const response = { status() { return this; }, json() { reject(new Error('LIVE_FENCE_REQUEST_REJECTED')); } };
    middleware(request, response, (error) => {
      if (error) { reject(new Error('LIVE_FENCE_REQUEST_REJECTED')); return; }
      try {
        fence.enforceVendosRestrictedConfig(request);
        fence.enforceVendosRestrictedBody(request);
        fail(!Object.hasOwn(request.body.ephemeralAgent, 'artifacts'), 'LIVE_FENCE_CONFIG_REJECTED');
        resolve();
      } catch { reject(new Error('LIVE_FENCE_CONFIG_REJECTED')); }
    });
  });
  return { installed_request_fence_verified: true, installed_effective_config_guard_verified: true,
    browser_payload_serialization_verified: true, http_jwt_authentication_exercised: false };
}

const NEGATIVE = [
  ['feedback', 'coordinator_feedback', { project: PROJECT, job_id: '__readback_no_such_job__', expected_revision: -1, decision: '__invalid_readback_decision__', reason: 'Authorization readback only; no change requested.' }],
  ['execution', 'execute_approved_change', { project: PROJECT, plan_id: '__readback_no_such_plan__', plan_hash: '__invalid_readback_hash__', approval_summary: '', approval_receipt: '' }],
  // These tools have no second inert argument. An unknown project prevents work even if scope validation regresses.
  ['model_bad_project', 'rank_with_claude', { project: BAD_PROJECT }],
  ['source_bad_project', 'refresh_source', { project: BAD_PROJECT }],
];

async function boundedBody(response) {
  fail(response.body && typeof response.body.getReader === 'function', 'MCP_RESPONSE_BODY_UNAVAILABLE');
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      fail(size <= MAX_RESPONSE_BYTES, 'MCP_RESPONSE_TOO_LARGE');
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  return Buffer.concat(chunks).toString('utf8');
}

function parseRpc(raw, contentType, id) {
  let values;
  try {
    values = contentType.includes('text/event-stream')
      ? raw.split(/\r?\n\r?\n/).map((part) => part.split(/\r?\n/).filter((line) => line.startsWith('data:')).map((line) => line.slice(5).trimStart()).join('\n')).filter(Boolean).map((part) => JSON.parse(part))
      : [JSON.parse(raw)];
  } catch { throw new Error('MCP_INVALID_JSON'); }
  const matched = values.filter((value) => object(value) && value.id === id);
  fail(matched.length === 1 && matched[0].jsonrpc === '2.0' && !matched[0].error && object(matched[0].result), 'MCP_RPC_FAILED');
  return matched[0].result;
}

function toolData(result) {
  fail(object(result) && result.isError !== true, 'MCP_READ_TOOL_FAILED');
  if (object(result.structuredContent)) return result.structuredContent;
  const text = result.content?.filter((item) => item.type === 'text').map((item) => item.text).join('\n');
  fail(typeof text === 'string', 'MCP_READ_RESULT_MISSING');
  try { const value = JSON.parse(text); fail(object(value), 'MCP_READ_RESULT_SHAPE'); return value; }
  catch { throw new Error('MCP_READ_RESULT_SHAPE'); }
}

function authorizationDenied(result) {
  return result?.isError === true && Array.isArray(result.content) && result.content.some((item) =>
    item.type === 'text' && typeof item.text === 'string' && item.text.includes('Not authorized for this project or operation'));
}

function makeRpc(url, token, fetchFn = fetch) {
  let nextId = 1;
  let session = null;
  let protocol = '2025-03-26';
  async function rpc(method, params, notification = false) {
    const id = nextId++;
    const headers = { Authorization: `Bearer ${token}`, Accept: 'application/json, text/event-stream', 'Content-Type': 'application/json', 'MCP-Protocol-Version': protocol };
    if (session) headers['Mcp-Session-Id'] = session;
    const body = notification ? { jsonrpc: '2.0', method, params } : { jsonrpc: '2.0', id, method, params };
    const response = await fetchFn(url, { method: 'POST', headers, body: JSON.stringify(body), redirect: 'error', signal: AbortSignal.timeout(20000) });
    fail(response.ok, 'MCP_HTTP_FAILED');
    if (notification) { if (response.body) await response.body.cancel(); return null; }
    const result = parseRpc(await boundedBody(response), response.headers.get('content-type') || '', id);
    const nextSession = response.headers.get('mcp-session-id');
    if (nextSession) { fail(nextSession.length <= 256 && !/[\r\n]/.test(nextSession), 'MCP_INVALID_SESSION'); session = nextSession; }
    if (method === 'initialize') {
      fail(['2025-03-26', '2025-06-18', '2025-11-25'].includes(result.protocolVersion), 'MCP_PROTOCOL_UNSUPPORTED');
      protocol = result.protocolVersion;
    }
    return result;
  }
  return rpc;
}

async function verifyMcp(rpc, expectedActor) {
  await rpc('initialize', { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'vendos-scoped-access-readback', version: '1' } });
  await rpc('notifications/initialized', {}, true);
  const catalog = await rpc('tools/list', {});
  fail(Array.isArray(catalog.tools) && !catalog.nextCursor, 'MCP_TOOL_CATALOG_INCOMPLETE');
  const required = ['list_projects', 'project_report', 'coordinator_report', ...NEGATIVE.map((entry) => entry[1])];
  fail(required.every((name) => catalog.tools.some((tool) => tool.name === name)), 'MCP_REQUIRED_TOOL_MISSING');
  const call = (name, args) => rpc('tools/call', { name, arguments: args });
  const projects = toolData(await call('list_projects', {}));
  fail(Array.isArray(projects.projects) && projects.projects.length === 1 && projects.projects[0].id === PROJECT, 'MCP_PROJECT_ACCESS_NOT_EXACT');
  const report = toolData(await call('project_report', { project: PROJECT }));
  fail(object(report.coordinator) && object(report.model_status), 'MCP_PROJECT_REPORT_SHAPE');
  const coordinator = toolData(await call('coordinator_report', { project: PROJECT }));
  const access = coordinator.caller_access;
  fail(object(access) && access.actor === expectedActor && access.memory_scope === 'shared_project' && access.can_submit === true, 'MCP_CALLER_ACCESS_INVALID');
  fail(Array.isArray(access.scopes) && access.scopes.length === 2 && [...access.scopes].sort().join(',') === 'coordinator:submit,project:read', 'MCP_SCOPES_NOT_EXACT');
  const negative = {};
  for (const [kind, name, args] of NEGATIVE) {
    fail(authorizationDenied(await call(name, args)), 'MCP_NEGATIVE_AUTHORIZATION_NOT_PROVEN');
    negative[kind] = true;
  }
  return {
    initialized: true, required_tools_present: true, only_vendos_project: true,
    project_report_read: true, coordinator_report_read: true,
    caller_actor_matches: true, shared_project_memory: true, can_submit: true,
    exact_scopes_read_and_submit: true, feedback_scope_absent: true, execution_scope_absent: true,
    model_scope_absent: true, source_sync_scope_absent: true,
    negative_feedback_vendos_denied: negative.feedback,
    negative_execution_vendos_denied: negative.execution,
    negative_model_unknown_project_denied: negative.model_bad_project,
    negative_source_unknown_project_denied: negative.source_bad_project,
    direct_model_scope_only_test_performed: false, direct_source_scope_only_test_performed: false,
    model_calls: 0, coordinator_submissions: 0, business_actions: 0,
  };
}

async function main(args = process.argv.slice(2)) {
  if (!args.length) return { schema: 1, status: 'not_run', production_connected: false };
  fail(args.length === 3 && args[0] === '--verify' && args[1] === '--email-sha256' && /^[a-f0-9]{64}$/.test(args[2]), 'USAGE_VERIFY_EMAIL_SHA256');
  fail(process.cwd() === '/app', 'EXPECTED_LIBRECHAT_APP_ROOT');
  const targetHash = args[2];
  process.env.LOG_TO_FILE = 'false'; process.env.DEBUG_LOGGING = 'false'; process.env.DEBUG_CONSOLE = 'false';
  const appRequire = createRequire('/app/package.json');
  const bundlePath = appRequire.resolve('@librechat/api/vendos');
  fail(fs.realpathSync(bundlePath) === '/app/packages/api/dist/vendos.cjs' && hash(fs.readFileSync(bundlePath)) === BUNDLE_SHA, 'RUNTIME_BUNDLE_DRIFT');
  const fence = appRequire('@librechat/api/vendos');
  const configPath = process.env.CONFIG_PATH || '/app/librechat.yaml';
  fail(configPath === '/app/librechat.yaml' && fs.realpathSync(configPath) === configPath, 'UNTRUSTED_CONFIG_PATH');
  const rawConfig = fs.readFileSync(configPath);
  fail(rawConfig.length < 2097152 && hash(rawConfig) === BASE_SHA, 'BASE_CONFIG_DRIFT');
  const yaml = appRequire('js-yaml');
  const base = yaml.load(rawConfig.toString('utf8'));
  const mcp = base.mcpServers?.vendos_pilot;
  fail(mcp?.headers?.Authorization === 'Bearer {{VENDOS_PILOT_KEY}}' && mcp.customUserVars?.VENDOS_PILOT_KEY?.sensitive === true, 'MCP_CONFIG_DRIFT');
  const url = trustedMcpDestination(mcp.url, hash(rawConfig));
  fail(String(process.env.OPENAI_MODERATION || '').trim().toLowerCase() !== 'true', 'NON_CLAUDE_MODERATION_ENABLED');
  const schemas = appRequire('@librechat/data-schemas');
  schemas.logger.silent = true;
  const api = appRequire('@librechat/api');
  const mongoose = appRequire('mongoose');
  mongoose.set('autoCreate', false);
  mongoose.set('autoIndex', false);
  const { MongoClient, ObjectId } = mongoose.mongo;
  const client = new MongoClient(process.env.MONGO_URI, { maxPoolSize: 2, serverSelectionTimeoutMS: 5000, socketTimeoutMS: 15000 });
  let token = null;
  try {
    await client.connect();
    const db = client.db();
    fail(db.databaseName === 'LibreChat', 'UNEXPECTED_DATABASE');
    const users = await db.collection('users').find({ provider: 'google', emailVerified: true }, { projection: { email: 1, provider: 1, emailVerified: 1, googleId: 1, role: 1, tenantId: 1 } }).limit(1001).toArray();
    fail(users.length <= 1000, 'USER_LOOKUP_TOO_LARGE');
    const matches = users.filter((user) => typeof user.email === 'string' && hash(user.email.trim().toLowerCase()) === targetHash);
    fail(matches.length === 1, 'TARGET_IDENTITY_NOT_UNIQUE');
    const user = matches[0];
    const id = String(user._id);
    user.id = id;
    user.idOnTheSource ??= null;
    fail(id !== process.env.VENDOS_BRIEFING_OWNER_ID && fence.isVerifiedGoogleEmailException(user), 'TARGET_IDENTITY_NOT_ALLOWED');
    const records = {
      journal: await db.collection(fence.VENDOS_RESTRICTED_COLLECTION).findOne({ _id: id }, { projection: { token_ciphertext: 0 } }),
      activeConfigs: await db.collection('configs').find({ isActive: true }).limit(3).toArray(),
      keys: await db.collection('keys').find({ userId: { $in: [id, new ObjectId(id)] }, name: 'VENDOS pilot' }).limit(3).toArray(),
      plugins: await db.collection('pluginauths').find({ userId: id, pluginKey: 'mcp_vendos_pilot', authField: 'VENDOS_PILOT_KEY' }).limit(3).toArray(),
    };
    fence.verifyVendosRestrictedAccess(user, records, Date.now());
    fail(records.journal.subject === `vendos-colleague:${hash(id).slice(0, 24)}`, 'MCP_ACTOR_JOURNAL_MISMATCH');
    // Run the installed config service in this process with memory-only caches
    // and automatic Mongo collection/index creation disabled. No controllers run.
    mongoose.connection.setClient(client);
    schemas.createModels(mongoose);
    const methods = schemas.createMethods(mongoose);
    const provider = appRequire('librechat-data-provider');
    const memoryCache = new Map();
    const loadCustomConfig = appRequire('/app/api/server/services/Config/loadCustomConfig.js');
    const { getAppConfig } = api.createAppConfigService({
      loadBaseConfig: async () => schemas.AppService({ config: await loadCustomConfig(false) }),
      setCachedTools: async () => {},
      getCache: () => memoryCache,
      cacheKeys: provider.CacheKeys,
      getApplicableConfigs: methods.getApplicableConfigs,
      getUserPrincipals: methods.getUserPrincipals,
    });
    const merged = await getAppConfig(api.getAppConfigOptionsFromUser(user));
    const canonical = fence.vendosRestrictedOverrides().modelSpecs;
    fail(Object.entries(canonical).every(([key, value]) => fence.vendosRestrictedDigest(merged.modelSpecs?.[key]) === fence.vendosRestrictedDigest(value)), 'APP_SERVICE_CONFIG_NOT_RESOLVED');
    const guardProof = await verifyInstalledFence(fence, user, records, merged, provider.createPayload, api.tenantContextMiddleware);
    token = await api.decrypt(records.plugins[0].value);
    fail(typeof token === 'string' && token.length >= 40 && token.length <= 512 && !/[\r\n]/.test(token) && hash(token) === records.journal.token_sha256, 'MCP_TOKEN_JOURNAL_MISMATCH');
    const result = await verifyMcp(makeRpc(url.href, token), records.journal.subject);
    // Detect concurrent identity/config/credential drift before declaring success.
    const currentUser = await db.collection('users').findOne({ _id: user._id }, { projection: { email: 1, provider: 1, emailVerified: 1, googleId: 1, role: 1, tenantId: 1 } });
    fail(currentUser && fence.isSameGoogleExceptionIdentity(currentUser, user), 'IDENTITY_CHANGED_DURING_READBACK');
    const current = {
      journal: await db.collection(fence.VENDOS_RESTRICTED_COLLECTION).findOne({ _id: id }, { projection: { token_ciphertext: 0 } }),
      activeConfigs: await db.collection('configs').find({ isActive: true }).limit(3).toArray(),
      keys: await db.collection('keys').find({ userId: { $in: [id, new ObjectId(id)] }, name: 'VENDOS pilot' }).limit(3).toArray(),
      plugins: await db.collection('pluginauths').find({ userId: id, pluginKey: 'mcp_vendos_pilot', authField: 'VENDOS_PILOT_KEY' }).limit(3).toArray(),
    };
    fence.verifyVendosRestrictedAccess(currentUser, current, Date.now());
    fail(current.journal.token_sha256 === records.journal.token_sha256, 'TOKEN_CHANGED_DURING_READBACK');
    return { schema: 1, status: 'verified', verified_at: new Date().toISOString(), target_identity_sha256: hash(id),
      runtime_bundle_sha256: BUNDLE_SHA, base_config_sha256: BASE_SHA, mcp_url_sha256: hash(url.href),
      notebook_authorize_first_review_sha256: SERVICE_REVIEW_SHA, live_notebook_source_hash_read: false,
      fence_access_verified_before_and_after: true, installed_pure_config_merge_verified: true,
      installed_config_service_with_memory_cache_verified: true,
      full_runtime_config_loader_invoked: false, credential_values_printed: false, business_report_printed: false,
      mongodb_writes: false, ...guardProof, ...result };
  } finally { token = null; await client.close(); }
}

if (require.main === module || process.argv[1] === '-') {
  const output = process.stdout.write.bind(process.stdout);
  process.stdout.write = () => true; process.stderr.write = () => true;
  main().then((result) => output(JSON.stringify(result) + '\n', () => process.exit(0))).catch((error) => {
    const code = SAFE_ERROR_CODES.has(error.message) ? error.message : 'READBACK_FAILED_REQUIRES_INSPECTION';
    output(JSON.stringify({ schema: 1, status: 'stopped', error_code: code, credential_values_printed: false, business_report_printed: false }) + '\n', () => process.exit(1));
  });
}
module.exports = { main, makeRpc, parseRpc, toolData, verifyMcp, verifyInstalledFence, authorizationDenied, trustedMcpDestination, NEGATIVE, BASE_SHA, BUNDLE_SHA };
