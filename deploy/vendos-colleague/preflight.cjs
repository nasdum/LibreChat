'use strict';
// Read-only, standalone container probe. No application bootstrap, ODM, indexes,
// writes, external HTTP, model calls, decryption, chats, or credential output.
const fs = require('node:fs');
const crypto = require('node:crypto');
const path = require('node:path');
const { createRequire } = require('node:module');
const MARKER = 'VENDOS_COLLEAGUE_PREFLIGHT_V1';
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const flag = (v) => typeof v === 'string' && v.toLowerCase() === 'true';
const present = (v) => typeof v === 'string' && v.length > 0;
const finite = (v) => typeof v === 'number' && Number.isFinite(v) ? v : null;
function keyKind(value, env) {
  if (typeof value !== 'string' || !value) return { kind: 'absent', configured: false };
  if (value === 'user_provided') return { kind: 'user_provided', configured: true };
  const m = /^\$\{([A-Z][A-Z0-9_]*)\}$/.exec(value);
  if (m) return { kind: 'server_environment', configured: true, environment_value_present: present(env[m[1]]) };
  return { kind: 'server_literal_or_unknown', configured: true };
}
function summarizeConfig(cfg, env, email) {
  const domains = cfg?.registration?.allowedDomains;
  const validDomains = Array.isArray(domains) && domains.every((v) => typeof v === 'string');
  const unrestricted = domains == null || (validDomains && domains.length === 0);
  const domain = typeof email === 'string' ? email.trim().toLowerCase().split('@')[1] : null;
  const servers = cfg?.mcpServers || {};
  const vendos = servers.vendos_pilot || servers['vendos-pilot'] || null;
  const authorization = vendos?.headers?.Authorization ?? vendos?.headers?.authorization;
  const authKind = typeof authorization !== 'string' ? 'absent' :
    /^Bearer\s+\{\{VENDOS_PILOT_KEY\}\}$/.test(authorization) ? 'per_user_template' :
    authorization.includes('${') ? 'global_environment_or_mixed' : 'literal_or_unknown';
  const customs = Array.isArray(cfg?.endpoints?.custom) ? cfg.endpoints.custom : [];
  const targets = customs.filter((v) => typeof v?.name === 'string' && /vendos/i.test(v.name));
  const endpoints = targets.map((v) => {
    let urlClass = 'unknown';
    try {
      const u = new URL(v.baseURL);
      urlClass = u.hostname === 'api.anthropic.com' ? 'anthropic_direct' :
        /^(localhost|127\.0\.0\.1|host\.docker\.internal)$/.test(u.hostname) ? 'local' : 'other';
    } catch {}
    return { name_sha256: sha(v.name), api_key: keyKind(v.apiKey, env), base_url_class: urlClass,
      models: (Array.isArray(v?.models?.default) ? v.models.default : []).map((m) =>
        typeof m === 'string' && /^claude-[a-z0-9.:-]{1,100}$/i.test(m) ? m : 'other'),
      model_fetch_enabled: v?.models?.fetch === true };
  });
  return {
    config_scope: 'base_yaml_only_until_no_active_overrides_confirmed',
    allowed_domains: { present: domains != null, valid: domains == null || validDomains,
      count: validDomains ? domains.length : null,
      sha256: validDomains ? sha(JSON.stringify(domains)) : null,
      unrestricted, target_domain_allowed: unrestricted ? true : domain && validDomains ?
        domains.some((v) => v.toLowerCase() === domain) : null },
    login: { email_login_enabled: env.ALLOW_EMAIL_LOGIN == null || env.ALLOW_EMAIL_LOGIN.toLowerCase() !== 'false',
      registration_enabled: flag(env.ALLOW_REGISTRATION), social_registration_enabled: flag(env.ALLOW_SOCIAL_REGISTRATION),
      google_client_configured: present(env.GOOGLE_CLIENT_ID) && present(env.GOOGLE_CLIENT_SECRET) },
    vendos_mcp: { present: !!vendos, authorization_kind: authKind,
      custom_user_variable_declared: !!vendos?.customUserVars?.VENDOS_PILOT_KEY,
      server_api_key_configured: !!vendos?.apiKey,
      global_vendos_key_present: present(env.VENDOS_PILOT_KEY) },
    vendos_endpoints: endpoints,
    anthropic: { server_key: keyKind(env.ANTHROPIC_API_KEY, {}),
      configured_in_base_yaml: !!cfg?.endpoints?.anthropic,
      billing_workspace: 'not_proven_by_configuration' },
    manual_spend: { balance_enabled: typeof cfg?.balance?.enabled === 'boolean' ? cfg.balance.enabled : flag(env.CHECK_BALANCE),
      yaml_start_balance: finite(cfg?.balance?.startBalance),
      transactions_enabled: cfg?.transactions?.enabled !== false,
      notebook_limits_apply_to_manual_chat: false,
      monetary_limit_proven: false,
      rate_controls_configured: ['MESSAGE_IP_MAX','MESSAGE_IP_WINDOW','MESSAGE_USER_MAX','MESSAGE_USER_WINDOW','LIMIT_CONCURRENT_MESSAGES']
        .filter((k) => present(env[k])) },
  };
}
function selectTarget(rows, targetHash) {
  const matches = rows.filter((v) => typeof v.email === 'string' && sha(v.email.trim().toLowerCase()) === targetHash);
  const user = matches.length === 1 ? matches[0] : null;
  const id = user ? String(user._id) : null;
  return { user, output: { matches: matches.length, id: id && /^[a-f0-9]{24}$/i.test(id) ? id : null,
    verified: user ? user.emailVerified === true : null,
    provider: user ? ['local','google','openid','github','discord','facebook','apple','saml'].includes(user.provider) ? user.provider : 'other' : null } };
}
async function main(targetHash) {
  const result = { marker: MARKER, schema: 1, read_only: true, status: 'error', errors: [] };
  if (!/^[a-f0-9]{64}$/.test(targetHash || '')) return { ...result, errors: ['invalid_target_hash'] };
  const appRequire = createRequire('/app/package.json');
  let cfg = null, client = null;
  try {
    const configPath = process.env.CONFIG_PATH || '/app/librechat.yaml';
    if (/^https?:/i.test(configPath)) result.errors.push('remote_config_not_fetched');
    else {
      const p = path.resolve('/app', configPath);
      const stat = fs.statSync(p);
      if (!stat.isFile() || stat.size > 2 * 1024 * 1024) throw new Error('bounds');
      const raw = fs.readFileSync(p);
      cfg = appRequire('js-yaml').load(raw.toString('utf8')) || {};
      result.base_config_sha256 = sha(raw);
    }
  } catch { result.errors.push('base_config_unavailable'); }
  try {
    if (!present(process.env.MONGO_URI)) throw new Error('missing');
    const { MongoClient } = appRequire('mongodb');
    client = new MongoClient(process.env.MONGO_URI, { maxPoolSize: 1, serverSelectionTimeoutMS: 5000,
      connectTimeoutMS: 5000, socketTimeoutMS: 5000, retryWrites: false, monitorCommands: false });
    await client.connect();
    const db = client.db();
    const rows = await db.collection('users').find({}, { projection: { _id: 1, email: 1, emailVerified: 1, provider: 1 }, maxTimeMS: 5000 }).limit(501).toArray();
    if (rows.length > 500) throw new Error('bounds');
    const selected = selectTarget(rows, targetHash);
    result.user = selected.output;
    result.active_config_overrides_present = !!await db.collection('configs').findOne({ isActive: true }, { projection: { _id: 1 }, maxTimeMS: 5000 });
    if (cfg) result.config = summarizeConfig(cfg, process.env, selected.user?.email);
    if (selected.output.id) {
      result.user.vendos_auth_record_present = !!await db.collection('pluginauths').findOne({ userId: selected.output.id,
        authField: 'VENDOS_PILOT_KEY', pluginKey: 'mcp_vendos_pilot' }, { projection: { _id: 1 }, maxTimeMS: 5000 });
      const bal = await db.collection('balances').findOne({ user: selected.user._id }, {
        projection: { _id: 0, tokenCredits: 1, autoRefillEnabled: 1, refillIntervalValue: 1, refillIntervalUnit: 1, refillAmount: 1 }, maxTimeMS: 5000 });
      result.manual_balance = { record_present: !!bal, token_credits: finite(bal?.tokenCredits),
        auto_refill_enabled: typeof bal?.autoRefillEnabled === 'boolean' ? bal.autoRefillEnabled : null,
        refill_amount: finite(bal?.refillAmount), refill_interval_value: finite(bal?.refillIntervalValue),
        refill_interval_unit: ['seconds','minutes','hours','days','weeks','months'].includes(bal?.refillIntervalUnit) ? bal.refillIntervalUnit : null };
    }
  } catch { result.errors.push('mongo_read_unavailable_or_bound_exceeded'); }
  finally { if (client) await client.close().catch(() => {}); }
  if (cfg && !result.config) result.config = summarizeConfig(cfg, process.env, null);
  result.source_hashes = {};
  for (const file of ['api/server/services/VendosBriefing.js','api/server/controllers/agents/request.js','packages/api/dist/vendos.cjs','api/server/services/MCP.js','api/server/services/PluginService.js','api/strategies/socialLogin.js','api/server/middleware/checkDomainAllowed.js','packages/api/package.json']) {
    try { result.source_hashes[file] = sha(fs.readFileSync(path.join('/app', file))); } catch { result.source_hashes[file] = null; }
  }
  result.status = result.errors.length ? 'partial_or_error' : 'ok';
  return result;
}
module.exports = { MARKER, sha, keyKind, summarizeConfig, selectTarget, main };
if (require.main === module || process.argv[1] === '-') {
  // Preserve exactly one structured output line. Suppress dependency diagnostics
  // which could otherwise include connection strings. No application is imported.
  const write = process.stdout.write.bind(process.stdout);
  process.stdout.write = () => true;
  process.stderr.write = () => true;
  main(process.argv[2]).then((r) => write(JSON.stringify(r) + '\n')).catch(() => {
    write(JSON.stringify({ marker: MARKER, schema: 1, read_only: true, status: 'error', errors: ['unhandled_preflight_error'] }) + '\n');
    process.exitCode = 1;
  });
}
