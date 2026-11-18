import { createHash } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { isVerifiedGoogleEmailException } from './googleEmailException';

type Obj = Record<string, unknown>;
type Next = (error?: unknown) => void;
interface Request {
  method: string;
  originalUrl: string;
  user?: Obj;
  body?: Obj;
  config?: Obj;
}
interface Response {
  status(code: number): Response;
  json(value: unknown): unknown;
}
export interface RestrictedAccessRecords {
  journal: Obj | null;
  activeConfigs: Obj[];
  keys: Obj[];
  plugins: Obj[];
}
export interface VendosRestrictedDependencies {
  authenticate(req: Request, res: Response, next: Next): void;
  provision(id: string): Promise<RestrictedAccessRecords>;
  conversation(id: string): Promise<Obj | null>;
  conversations(id: string): Promise<Obj[]>;
  generation(id: string): Promise<Obj | null>;
  generations(id: string): Promise<Obj[]>;
  now?: () => number;
  hashes?: () => string | undefined;
}

export const VENDOS_RESTRICTED_POLICY = 'vendos-chat-only-v1';
export const VENDOS_RESTRICTED_COLLECTION = 'vendos_colleague_provisions_v3';
export const VENDOS_RESTRICTED_ENDPOINT = 'VENDOS pilot';
export const VENDOS_RESTRICTED_MODEL = 'claude-sonnet-5-5';
export const VENDOS_RESTRICTED_SPEC = 'vendos-consultation';
const ENDPOINT = VENDOS_RESTRICTED_ENDPOINT;
const MODEL = VENDOS_RESTRICTED_MODEL;
const SPEC = VENDOS_RESTRICTED_SPEC;
const uuid = /^[a-zA-Z0-9_-]{1,128}$/;
const states = new WeakMap<object, { userId: string; ready: boolean }>();
const object = (value: unknown): Obj => value != null && typeof value === 'object' && !Array.isArray(value) ? value as Obj : {};
const hash = (value: string): string => createHash('sha256').update(value, 'utf8').digest('hex');
const emailHash = (email: unknown): string => typeof email === 'string' ? hash(email.trim().toLowerCase()) : '';
const idOf = (user: Obj): string => String(user.id ?? user._id ?? '');
const deny = (): never => { throw new Error('VENDOS_ACCESS_RESTRICTED'); };
const check = (condition: unknown): void => { if (!condition) deny(); };

export function vendosRestrictedOverrides(): Obj {
  return {
    modelSpecs: {
      enforce: true,
      prioritize: true,
      list: [{
        name: SPEC,
        label: 'VENDOS konzultace a návrhy',
        description: 'Společné podklady VENDOS a zadání pro analytika a kontrolora. Schvalování a provedení patří vlastníkovi.',
        showOnLanding: true,
        webSearch: false, fileSearch: false, executeCode: false, memory: false, skills: false,
        askUserQuestion: false, runInBackground: false,
        mcpServers: ['vendos_pilot'],
        preset: {
          endpoint: ENDPOINT, model: MODEL,
          promptPrefix: 'Jsi konzultační marketingový koordinátor VENDOS, projekt vendos-cz. Mluv česky. Nejprve načti project_report a coordinator_report z MCP vendos_pilot; pro úplné podklady použij konkrétní job_id. Uváděj zdroje, stáří a omezení. Respektuj caller_access. Na výslovné nové zadání uživatele smíš použít coordinator_submit pro návrh do společné místní fronty analytika a kontrolora; sděl skutečné ID a stav. Nezakládej zadání při pouhém dotazu. Neprováděj schvalování obsahu, feedback, změny strategie, prepare_execution, execute_approved_change, reklamy, e-maily, publikování ani firemní úkoly. Souhlas tohoto uživatele nenahrazuje schválení vlastníka. Připomínky formuluj jako návrh k předání vlastníkovi. Fronta návrhů není firemní úkol. Používáš firemní Claude; ruční chat sdílí stávající limit workspace, automatická fronta má vlastní společné limity. Bez nástrojem ověřeného výsledku netvrď, že něco bylo uloženo nebo provedeno.',
        },
      }],
    },
  };
}

export function vendosRestrictedDigest(value: unknown): string {
  const stable = (input: unknown): unknown => Array.isArray(input)
    ? input.map(stable)
    : input != null && typeof input === 'object'
      ? Object.fromEntries(Object.entries(input).sort(([a], [b]) => a.localeCompare(b)).map(([key, val]) => [key, stable(val)]))
      : input;
  return hash(JSON.stringify(stable(value)));
}

export function isVendosRestrictedIdentity(user: Obj | undefined, hashes = process.env.VENDOS_GOOGLE_EMAIL_SHA256_ALLOWLIST): boolean {
  if (!user) return false;
  const target = emailHash(user.email);
  return typeof hashes === 'string' && hashes.split(',').some((value) => value.trim().toLowerCase() === target);
}

/** Alternate API-key/OIDC authentication happens after the global JWT boundary. */
export function denyVendosRestrictedRemote(req: Request, res: Response, next: Next): void {
  if (isVendosRestrictedIdentity(req.user)) { res.status(403).json({ error: 'VENDOS_ACCESS_RESTRICTED' }); return; }
  next();
}

export function verifyVendosRestrictedAccess(user: Obj, records: RestrictedAccessRecords, now = Date.now()): void {
  const userId = idOf(user);
  const j = records.journal;
  check(/^[a-f0-9]{24}$/.test(userId) && user.role === 'USER' && !user.tenantId);
  check(j && j._id === userId && j.state === 'prepared' && j.access_policy === VENDOS_RESTRICTED_POLICY);
  check(j!.target_email_sha256 === emailHash(user.email) && j!.google_subject_sha256 === hash(String(user.googleId)));
  check(typeof j!.expires_at === 'number' && j!.expires_at > now / 1000);
  check(j!.config_sha256 === vendosRestrictedDigest(vendosRestrictedOverrides()));
  check(records.activeConfigs.length === 1 && records.keys.length === 1 && records.plugins.length === 1);
  const c = records.activeConfigs[0];
  check(typeof j!.config_id === 'string' && String(c._id) === j!.config_id);
  check(c.principalType === 'user' && c.principalId === userId && c.principalModel === 'User' && c.isActive === true && c.priority === 1000);
  check(Array.isArray(c.tombstones) && c.tombstones.length === 0 && isDeepStrictEqual(c.overrides, vendosRestrictedOverrides()));
  const key = records.keys[0];
  check(typeof j!.model_key_id === 'string' && String(key._id) === j!.model_key_id);
  check(String(key.userId) === userId && key.name === ENDPOINT && typeof key.value === 'string');
  check(hash(String(key.value)) === j!.model_key_ciphertext_sha256 && new Date(String(key.expiresAt)).getTime() === Number(j!.expires_at) * 1000);
  const plugin = records.plugins[0];
  check(typeof j!.mcp_token_id === 'string' && String(plugin._id) === j!.mcp_token_id);
  check(plugin.userId === userId && plugin.pluginKey === 'mcp_vendos_pilot' && plugin.authField === 'VENDOS_PILOT_KEY' && typeof plugin.value === 'string');
  check(hash(String(plugin.value)) === j!.mcp_token_ciphertext_sha256);
}

function ownConversation(row: Obj | null, userId: string): boolean {
  return !!row && row.user === userId && row.endpoint === ENDPOINT && row.spec === SPEC && row.model === MODEL && row.isTemporary !== true;
}
function ownGeneration(row: Obj | null, userId: string): boolean {
  const meta = object(row?.metadata);
  return !!row && meta.userId === userId && !meta.tenantId && meta.endpoint === ENDPOINT && meta.model === MODEL && !meta.agent_id && meta.isTemporary !== true;
}
function restrictedInterface(): Obj {
  return { modelSelect: false, parameters: false, presets: false, sidePanel: false, bookmarks: false, multiConvo: false, temporaryChat: false, prompts: false, agents: false, memories: false, marketplace: false, remoteAgents: false, runCode: false, webSearch: false, fileSearch: false, fileCitations: false, peoplePicker: false, mcpServers: false };
}
function safeSpecs(): Obj {
  const specs = object(vendosRestrictedOverrides().modelSpecs);
  const list = (specs.list as Obj[]).map((spec) => ({ ...spec, preset: { endpoint: ENDPOINT, model: MODEL } }));
  return { ...specs, list };
}
function safeRole(): Obj {
  const names = ['PROMPTS', 'BOOKMARKS', 'AGENTS', 'MEMORIES', 'MULTI_CONVO', 'TEMPORARY_CHAT', 'RUN_CODE', 'WEB_SEARCH', 'PEOPLE_PICKER', 'MARKETPLACE', 'FILE_SEARCH', 'FILE_CITATIONS', 'MCP_SERVERS', 'REMOTE_AGENTS', 'SKILLS', 'SHARED_LINKS'];
  const disabled = { USE: false, CREATE: false, UPDATE: false, READ: false, DELETE: false, SHARE: false, SHARE_PUBLIC: false, VIEW_USERS: false, VIEW_GROUPS: false, VIEW_ROLES: false, CONFIGURE_OBO: false };
  return { name: 'USER', permissions: Object.fromEntries(names.map((name) => [name, disabled])) };
}

/** This is also called after resume-context reconstruction, before loadAgent sees raw request fields. */
export function enforceVendosRestrictedBody(req: Request): void {
  const state = states.get(req);
  if (!state) { if (isVendosRestrictedIdentity(req.user)) deny(); return; }
  check(state.ready);
  const body = object(req.body);
  check(body.endpoint === ENDPOINT && body.spec === SPEC && (!body.model || body.model === MODEL));
  check(body.endpointType == null || body.endpointType === 'custom');
  for (const field of ['addedConvo', 'agent_id', 'assistant_id', 'chatProjectId', 'projectId', 'manualSkills', 'alwaysAppliedSkills', 'files', 'attachments', 'quotes', 'tools', 'promptPrefix', 'instructions', 'system', 'context', 'examples', 'customParams', 'overrideConvoId', 'overrideUserMessageId', 'recoverySteerId']) {
    const value = body[field];
    check(value == null || value === '' || (Array.isArray(value) && value.length === 0));
  }
  check(body.isTemporary !== true);
  const ephemeral = object(body.ephemeralAgent);
  check(Object.entries(ephemeral).every(([key, value]) => key === 'mcp' ? Array.isArray(value) && value.every((item) => item === 'vendos_pilot') : value === false || value == null));
  const allowed = ['text', 'conversationId', 'parentMessageId', 'messageId', 'responseMessageId', 'clientRequestId', 'isRegenerate', 'regenerate', 'isContinued', 'clientTimestamp', 'timezone', 'generationProtocolVersion', 'expectedPredecessorCreatedAt', 'actionId', 'generationCreatedAt', 'decisions', 'answers', 'action', 'response', 'value'];
  const clean: Obj = {};
  for (const key of allowed) if (body[key] !== undefined) clean[key] = body[key];
  req.body = { ...clean, endpoint: ENDPOINT, endpointType: 'custom', model: MODEL, spec: SPEC, isTemporary: false, ephemeralAgent: { mcp: ['vendos_pilot'], execute_code: false, web_search: false, file_search: false, memory: false, skills: false, ask_user_question: false, run_in_background: false } };
}

/** Never allow the existing config loader's base-config fallback to weaken this policy. */
export function enforceVendosRestrictedConfig(req: Request): void {
  const state = states.get(req);
  if (!state) { if (isVendosRestrictedIdentity(req.user)) deny(); return; }
  check(state.ready);
  const config = object(req.config);
  const canonicalSpecs = object(vendosRestrictedOverrides().modelSpecs);
  const loadedSpecs = object(config.modelSpecs);
  check(Object.entries(canonicalSpecs).every(([key, value]) => isDeepStrictEqual(loadedSpecs[key], value)));
  const endpoints = object(config.endpoints);
  const custom = Array.isArray(endpoints.custom) ? endpoints.custom as Obj[] : [];
  const selected = custom.filter((entry) => entry.name === ENDPOINT);
  check(selected.length === 1);
  const endpoint = selected[0];
  check(endpoint.apiKey === 'user_provided' && endpoint.provider === 'anthropic' && endpoint.baseURL === 'https://api.anthropic.com');
  check(endpoint.titleConvo === false && endpoint.activityLabel === false && object(endpoint.models).fetch === false);
  check(Array.isArray(object(endpoint.models).default) && (object(endpoint.models).default as unknown[]).includes(MODEL));
  const mcp = object(object(config.mcpConfig).vendos_pilot);
  check(object(mcp.headers).Authorization === 'Bearer {{VENDOS_PILOT_KEY}}' && object(object(mcp.customUserVars).VENDOS_PILOT_KEY).sensitive === true);
  check(typeof mcp.url === 'string' &&
    (mcp.url === 'http://172.21.0.1:18089/mcp' || /^https:\/\/[^\s]+$/.test(mcp.url)));
  req.config = { ...config, ...vendosRestrictedOverrides(), interfaceConfig: restrictedInterface(), endpoints: { custom: [{ ...endpoint, models: { default: [MODEL], fetch: false } }], agents: { capabilities: [], allowedProviders: [ENDPOINT] } }, mcpConfig: { vendos_pilot: mcp }, memory: undefined, webSearch: undefined, actions: undefined };
}

export function createVendosRestrictedChat(deps: VendosRestrictedDependencies) {
  const now = deps.now ?? Date.now;
  const hashes = deps.hashes ?? (() => process.env.VENDOS_GOOGLE_EMAIL_SHA256_ALLOWLIST);
  return (req: Request, res: Response, next: Next): void => {
    deps.authenticate(req, res, (authError) => {
      if (authError) { next(authError); return; }
      if (!isVendosRestrictedIdentity(req.user, hashes())) { next(); return; }
      void (async () => {
        const user = req.user!;
        check(isVerifiedGoogleEmailException(user, hashes()) && user.role === 'USER' && !user.tenantId);
        const userId = idOf(user);
        check(/^[a-f0-9]{24}$/.test(userId));
        const rawPath = req.originalUrl.split('?')[0];
        check(!/%(?:2f|5c|2e|25)|\\|\/\//i.test(rawPath));
        const path = decodeURIComponent(rawPath).replace(/\/$/, '');
        check(!path.split('/').some((part) => part === '.' || part === '..'));
        const url = new URL(req.originalUrl, 'https://vendos.invalid');
        check(new Set(url.searchParams.keys()).size === [...url.searchParams.keys()].length);
        const method = req.method.toUpperCase();
        if (method === 'POST' && ['/api/auth/refresh', '/api/auth/logout'].includes(path)) { next(); return; }
        const records = await deps.provision(userId);
        let ready = false;
        try { verifyVendosRestrictedAccess(user, records, now()); ready = true; } catch { /* Pending/changed provisioning never authorizes a model request. */ }
        states.set(req, { userId, ready });
        if (method === 'GET' && path === '/api/user') {
          const visible = ['id', '_id', 'name', 'username', 'email', 'emailVerified', 'provider', 'role', 'termsAccepted', 'createdAt', 'updatedAt'];
          res.json(Object.fromEntries(visible.filter((key) => user[key] !== undefined).map((key) => [key, user[key]]))); return;
        }
        if (method === 'GET' && path === '/api/config') { res.json({ appTitle: 'VENDOS', interface: restrictedInterface(), modelSpecs: safeSpecs(), sharedLinksEnabled: false, publicSharedLinksEnabled: false, agents: false, speech: false, balance: { enabled: false }, vendosAccess: ready ? 'ready' : 'pending' }); return; }
        if (method === 'GET' && path === '/api/endpoints') { res.json({ [ENDPOINT]: { type: 'custom', userProvide: true, userProvideURL: false, modelDisplayLabel: 'VENDOS' } }); return; }
        if (method === 'GET' && path === '/api/models') { res.json({ [ENDPOINT]: [MODEL] }); return; }
        if (method === 'GET' && path === '/api/roles/USER') { res.json(safeRole()); return; }
        if (method === 'GET' && path === '/api/keys') {
          check([...url.searchParams.keys()].every((key) => key === 'name') && url.searchParams.get('name') === ENDPOINT);
          res.json({ expiresAt: ready ? new Date(Number(records.journal!.expires_at) * 1000).toISOString() : null }); return;
        }
        check(ready);
        if (method === 'GET' && path === '/api/convos') {
          check([...url.searchParams.keys()].every((key) => ['limit', 'cursor', 'isArchived', 'sortBy', 'sortDirection'].includes(key)));
          const conversations = await deps.conversations(userId);
          check(conversations.every((row) => ownConversation(row, userId)));
          res.json({ conversations, nextCursor: null }); return;
        }
        if (method === 'GET' && path === '/api/messages') {
          check([...url.searchParams.keys()].every((key) => ['conversationId', 'messageId', 'pageSize', 'cursor', 'sortBy', 'sortDirection'].includes(key)));
          const id = url.searchParams.get('conversationId');
          check(id && uuid.test(id) && ownConversation(await deps.conversation(id), userId));
          next(); return;
        }
        const convoPath = path.match(/^\/api\/convos\/([a-zA-Z0-9_-]{1,128})$/)
          ?? path.match(/^\/api\/messages\/([a-zA-Z0-9_-]{1,128})(?:\/([a-zA-Z0-9_-]{1,128}))?$/);
        if (method === 'GET' && convoPath) {
          check(ownConversation(await deps.conversation(convoPath[1]), userId));
          check([...url.searchParams.keys()].every((key) => ['limit', 'cursor'].includes(key)));
          next(); return;
        }
        if (method === 'GET' && path === '/api/agents/chat/active') {
          const jobs = await deps.generations(userId);
          check(jobs.every((job) => ownGeneration(job, userId)));
          res.json({ activeJobIds: jobs.map((job) => job.streamId ?? job.conversationId) }); return;
        }
        const streamPath = path.match(/^\/api\/agents\/chat\/(?:stream|status)\/([a-zA-Z0-9_-]{1,128})$/);
        if (method === 'GET' && streamPath) {
          const job = await deps.generation(streamPath[1]);
          check(job ? ownGeneration(job, userId) : ownConversation(await deps.conversation(streamPath[1]), userId));
          next(); return;
        }
        if (method === 'POST' && path === '/api/agents/chat/abort') {
          const id = req.body?.streamId ?? req.body?.conversationId;
          check(typeof id === 'string' && uuid.test(id) && ownGeneration(await deps.generation(String(id)), userId));
          check(req.body?.conversationId == null || req.body.conversationId === id);
          check(req.body?.abortKey == null || (typeof req.body.abortKey === 'string' && req.body.abortKey.split(':')[0] === id));
          req.body = { streamId: id, conversationId: id, generationCreatedAt: req.body?.generationCreatedAt };
          next(); return;
        }
        if (method === 'POST' && ['/api/agents/chat/VENDOS pilot', '/api/agents/chat', '/api/agents/chat/resume'].includes(path)) {
          const id = req.body?.conversationId;
          check(id == null || id === 'new' || (typeof id === 'string' && uuid.test(id)));
          if (id && id !== 'new') {
            const conversation = await deps.conversation(String(id));
            check(!conversation || ownConversation(conversation, userId));
          }
          if (path.endsWith('/resume')) check(typeof id === 'string' && ownGeneration(await deps.generation(id), userId));
          enforceVendosRestrictedBody(req);
          next(); return;
        }
        deny();
      })().catch(() => { res.status(403).json({ error: 'VENDOS_ACCESS_RESTRICTED' }); });
    });
  };
}
