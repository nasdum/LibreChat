'use strict';
const { createHash, randomBytes, randomUUID } = require('node:crypto');

const ENDPOINT = 'VENDOS pilot';
const MODEL = 'claude-sonnet-5-5';
const PLUGIN = 'mcp_vendos_pilot';
const AUTH_FIELD = 'VENDOS_PILOT_KEY';
const COLLECTION = 'vendos_colleague_provisions_v3';
const policy = require('./policy.cjs');
const hash = (value) => createHash('sha256').update(value, 'utf8').digest('hex');
const stable = (value) => JSON.stringify(value, Object.keys(value).sort());
const fail = (condition, code) => { if (!condition) throw new Error(code); };
const normalizedEmailHash = (value) => typeof value === 'string' ? hash(value.trim().toLowerCase()) : null;
const subjectFor = (id) => `vendos-colleague:${hash(id).slice(0, 24)}`;

function validateRequest(request, now = Date.now()) {
  fail(request && typeof request === 'object' && !Array.isArray(request), 'INVALID_REQUEST');
  const fields = ['schema', 'request_id', 'target_email_sha256', 'expected_user_sha256', 'expected_corporate_key_sha256', 'expected_vendos_bundle_sha256', 'expires_at'];
  fail(Object.keys(request).length === fields.length && fields.every((key) => Object.hasOwn(request, key)), 'INVALID_REQUEST_FIELDS');
  fail(request.schema === 1 && typeof request.request_id === 'string' && /^[a-z0-9-]{8,80}$/.test(request.request_id), 'INVALID_REQUEST_ID');
  for (const key of ['target_email_sha256', 'expected_corporate_key_sha256', 'expected_vendos_bundle_sha256']) fail(typeof request[key] === 'string' && /^[a-f0-9]{64}$/.test(request[key]), 'INVALID_FINGERPRINT');
  fail(request.expected_user_sha256 === null || (typeof request.expected_user_sha256 === 'string' && /^[a-f0-9]{64}$/.test(request.expected_user_sha256)), 'INVALID_USER_FINGERPRINT');
  fail(Number.isSafeInteger(request.expires_at) && request.expires_at > now / 1000 && request.expires_at <= now / 1000 + 366 * 86400, 'INVALID_TOKEN_EXPIRY');
  return request;
}

function consultationOverrides() { return policy.overrides(); }

function desiredConfig(record) {
  return record && record.isActive === true && record.priority === 1000 &&
    record.principalType === 'user' && record.principalModel === 'User' &&
    (Array.isArray(record.tombstones) && record.tombstones.length === 0) &&
    policy.digest(record.overrides) === policy.digest(consultationOverrides());
}

async function inspect(request, deps) {
  validateRequest(request, deps.now());
  const ownerId = await deps.ownerId();
  fail(typeof ownerId === 'string' && /^[a-f0-9]{24}$/.test(ownerId), 'OWNER_ID_UNAVAILABLE');
  fail(await deps.bundleHash() === request.expected_vendos_bundle_sha256, 'RUNTIME_BUNDLE_DRIFT');
  const matches = await deps.usersByEmailHash(request.target_email_sha256);
  fail(matches.length !== 0, 'FIRST_GOOGLE_LOGIN_REQUIRED');
  fail(matches.length === 1, 'TARGET_IDENTITY_AMBIGUOUS');
  const user = matches[0];
  const targetId = String(user._id);
  fail(/^[a-f0-9]{24}$/.test(targetId) && targetId !== ownerId, 'OWNER_CANNOT_BE_PROVISION_TARGET');
  fail(request.expected_user_sha256 === null || request.expected_user_sha256 === hash(targetId), 'TARGET_USER_FINGERPRINT_MISMATCH');
  fail(user.provider === 'google' && user.emailVerified === true && typeof user.googleId === 'string' && user.googleId.length > 0 && !/[\s\u0000-\u001f\u007f]/u.test(user.googleId), 'TARGET_IDENTITY_NOT_VERIFIED_GOOGLE');
  fail(user.role === 'USER' && !user.tenantId && normalizedEmailHash(user.email) === request.target_email_sha256, 'TARGET_IDENTITY_OR_ROLE_MISMATCH');
  const googleSubjectHash = hash(user.googleId);
  const owner = await deps.user(ownerId);
  fail(owner && owner.emailVerified === true && !owner.tenantId, 'OWNER_IDENTITY_UNAVAILABLE');
  const config = await deps.baseConfig();
  const endpoint = config.endpoints?.custom?.find((entry) => entry.name === ENDPOINT);
  fail(endpoint && endpoint.apiKey === 'user_provided' && endpoint.provider === 'anthropic' && endpoint.baseURL === 'https://api.anthropic.com', 'CORPORATE_ENDPOINT_MISMATCH');
  fail(endpoint.titleConvo === false && endpoint.activityLabel === false && endpoint.models?.default?.includes(MODEL) && endpoint.models.fetch === false, 'CORPORATE_MODEL_CONFIGURATION_DRIFT');
  const mcp = (config.mcpConfig || config.mcpServers)?.vendos_pilot;
  fail(mcp?.headers?.Authorization === 'Bearer {{VENDOS_PILOT_KEY}}' && mcp.customUserVars?.VENDOS_PILOT_KEY?.sensitive === true, 'MCP_USER_AUTH_TEMPLATE_MISMATCH');
  const ownerKey = await deps.modelKey(ownerId);
  fail(typeof ownerKey === 'string' && ownerKey.length > 20 && hash(ownerKey) === request.expected_corporate_key_sha256, 'CORPORATE_KEY_FINGERPRINT_MISMATCH');
  const journal = await deps.journal(targetId);
  if (journal) {
    fail(journal.request_hash === hash(stable(request)) && journal.subject === subjectFor(targetId), 'PROVISION_REQUEST_CONFLICT');
    fail(journal.google_subject_sha256 === googleSubjectHash, 'GOOGLE_SUBJECT_CHANGED');
    fail(journal.target_email_sha256 === request.target_email_sha256 && journal.access_policy === policy.POLICY && journal.expires_at === request.expires_at && journal.config_sha256 === policy.digest(consultationOverrides()), 'RESTRICTED_JOURNAL_POLICY_DRIFT');
    fail(typeof journal.token_ciphertext === 'string' && /^[a-f0-9]{64}$/.test(journal.token_sha256), 'PROVISION_JOURNAL_INVALID');
  }
  const key = await deps.modelKey(targetId, true);
  fail(key === null || hash(key) === request.expected_corporate_key_sha256, 'TARGET_MODEL_KEY_ALREADY_DIFFERENT');
  fail(key === null || await deps.modelKeyExpiry(targetId) === request.expires_at, 'TARGET_MODEL_KEY_EXPIRY_MISMATCH');
  const token = await deps.pluginToken(targetId);
  fail(token === null || (journal && hash(token) === journal.token_sha256), 'TARGET_MCP_AUTH_ALREADY_DIFFERENT');
  const override = await deps.userConfig(targetId);
  const activeConfigs = await deps.activeConfigs();
  fail(activeConfigs.length === 0 || (activeConfigs.length === 1 && activeConfigs[0].principalId === targetId && journal && desiredConfig(activeConfigs[0])), 'ACTIVE_CONFIG_SCOPE_DRIFT');
  fail(override === null || (journal && desiredConfig(override)), 'TARGET_CONFIG_ALREADY_PRESENT_OR_CHANGED');
  if (journal?.state === 'prepared') await deps.verifyAccess(user, await deps.accessRecords(targetId));
  return { user, googleSubjectHash, ownerKey, journal, key, token, override };
}

function publicResult(request, userId, journal, phase, now) {
  return {
    schema: 1, phase, request_id: request.request_id, user_sha256: hash(userId),
    subject: subjectFor(userId),
    token_sha256: journal?.token_sha256 || null, expires_at: request.expires_at,
    token_manifest_entry: journal ? { sha256: journal.token_sha256, user: journal.subject,
      scopes: ['project:read', 'coordinator:submit'], projects: ['vendos-cz'], expires_at: request.expires_at, revoked: false } : null,
    notebook_registration_performed: false, owner_approval_granted: false,
    conversation_created_or_shared: false, financial_configuration_changed: false,
    activation_not_before: phase === 'prepared' ? new Date(now + 65000).toISOString() : null,
    live_login_and_mcp_readback_required: true,
  };
}

async function run(request, deps, prepare = false) {
  const initial = await inspect(request, deps);
  const targetId = String(initial.user._id);
  if (!prepare) return publicResult(request, targetId, initial.journal, 'checked_no_writes', deps.now());
  fail(request.expected_user_sha256 !== null, 'CHECKED_USER_FINGERPRINT_REQUIRED');
  let journal = initial.journal;
  if (!journal) {
    const token = randomBytes(48).toString('base64url');
    const candidate = { _id: targetId, request_id: request.request_id,
      request_hash: hash(stable(request)), subject: subjectFor(targetId),
      google_subject_sha256: initial.googleSubjectHash,
      target_email_sha256: request.target_email_sha256, access_policy: policy.POLICY, expires_at: request.expires_at, config_sha256: policy.digest(consultationOverrides()),
      token_sha256: hash(token), token_ciphertext: await deps.encrypt(token),
      created_at: new Date(deps.now()).toISOString(), state: 'prepared_credentials_pending' };
    fail(candidate.token_ciphertext !== token && candidate.token_ciphertext.length > 20, 'TOKEN_ENCRYPTION_FAILED');
    await deps.insertJournal(candidate);
    journal = (await inspect(request, deps)).journal;
  }
  const lease = randomUUID();
  fail(await deps.acquire(targetId, lease, deps.now()), 'PROVISION_BUSY');
  try {
    const recheck = async () => {
      fail(await deps.renew(targetId, lease, deps.now()), 'PROVISION_LEASE_LOST');
      return inspect(request, deps);
    };
    let current = await recheck();
    if (current.key === null) await deps.saveModelKey(targetId, current.ownerKey, request.expires_at);
    current = await recheck();
    fail(current.key !== null, 'MODEL_KEY_READBACK_FAILED');
    const token = await deps.decrypt(journal.token_ciphertext);
    fail(hash(token) === journal.token_sha256, 'TOKEN_JOURNAL_READBACK_FAILED');
    if (current.token === null) await deps.savePluginToken(targetId, token);
    current = await recheck();
    fail(current.token !== null && hash(current.token) === journal.token_sha256, 'PLUGIN_TOKEN_READBACK_FAILED');
    if (current.override === null) await deps.saveUserConfig(targetId, consultationOverrides());
    current = await recheck();
    fail(desiredConfig(current.override), 'CONFIG_READBACK_FAILED');
    await deps.invalidateCaches();
    const records = await deps.accessRecords(targetId);
    fail(records.activeConfigs.length === 1 && records.keys.length === 1 && records.plugins.length === 1, 'RESTRICTED_CREDENTIAL_RECORDS_AMBIGUOUS');
    await deps.verifyCredentialSnapshot(records, request.expected_corporate_key_sha256, journal.token_sha256);
    const fields = { config_id: String(records.activeConfigs[0]._id), model_key_id: String(records.keys[0]._id), mcp_token_id: String(records.plugins[0]._id), model_key_ciphertext_sha256: hash(records.keys[0].value), mcp_token_ciphertext_sha256: hash(records.plugins[0].value) };
    await deps.verifyAccess(current.user, { ...records, journal: { ...current.journal, ...fields, state: 'prepared' } });
    await deps.complete(targetId, lease, deps.now(), fields);
    await deps.verifyAccess((await inspect(request, deps)).user, await deps.accessRecords(targetId));
    return publicResult(request, targetId, journal, 'prepared', deps.now());
  } finally {
    await deps.release(targetId, lease);
  }
}

module.exports = { run, inspect, validateRequest, consultationOverrides, desiredConfig, hash, normalizedEmailHash, COLLECTION, ENDPOINT, MODEL, PLUGIN, AUTH_FIELD };
