Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });
let node_crypto = require("node:crypto");
let node_util = require("node:util");
//#region packages/api/src/vendos/googleEmailException.ts
/** Private server configuration, never a client-supplied registration field. */
const GOOGLE_EMAIL_EXCEPTION_ENV = "VENDOS_GOOGLE_EMAIL_SHA256_ALLOWLIST";
function normalizeEmail(email) {
	if (typeof email !== "string") return null;
	const normalized = email.trim().toLowerCase();
	if (normalized.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/u.test(normalized) || /[\u0000-\u001f\u007f]/u.test(email)) return null;
	return normalized;
}
function validGoogleId(id) {
	return typeof id === "string" && id.length > 0 && id.length <= 255 && !/\s|[\u0000-\u001f\u007f]/u.test(id);
}
/**
* Adds one identity exception to the caller's existing domain policy. It does
* not replace that policy, grant a role, enable registration, or link accounts.
* The boolean verification claim must come from the Google OAuth profile, or
* from the corresponding persisted Google user at the OAuth callback boundary.
*/
function isVerifiedGoogleEmailException(identity, configuredHashes = process.env[GOOGLE_EMAIL_EXCEPTION_ENV]) {
	if (identity.provider !== "google" || identity.emailVerified !== true || !validGoogleId(identity.googleId) || typeof configuredHashes !== "string" || !configuredHashes.trim() || configuredHashes.length > 1e4) return false;
	const hashes = configuredHashes.split(",").map((value) => value.trim().toLowerCase());
	if (hashes.some((value) => !/^[a-f0-9]{64}$/.test(value))) return false;
	const email = normalizeEmail(identity.email);
	if (email === null) return false;
	const hash = (0, node_crypto.createHash)("sha256").update(email, "utf8").digest("hex");
	return hashes.includes(hash);
}
/** Exact binding prevents the existing email fallback from linking an exception to another subject. */
function isSameGoogleExceptionIdentity(stored, verified) {
	const email = normalizeEmail(verified.email);
	return stored.provider === "google" && verified.provider === "google" && stored.emailVerified === true && verified.emailVerified === true && validGoogleId(stored.googleId) && stored.googleId === verified.googleId && email !== null && normalizeEmail(stored.email) === email;
}
/** Google External OAuth must provide a verified email before any domain authorization. */
function isVerifiedGoogleIdentity(identity) {
	return identity.provider === "google" && identity.emailVerified === true && normalizeEmail(identity.email) !== null && validGoogleId(identity.googleId);
}
//#endregion
//#region packages/api/src/vendos/restricted.ts
const VENDOS_RESTRICTED_POLICY = "vendos-chat-only-v1";
const VENDOS_RESTRICTED_COLLECTION = "vendos_colleague_provisions_v3";
const VENDOS_RESTRICTED_ENDPOINT = "VENDOS pilot";
const VENDOS_RESTRICTED_MODEL = "claude-sonnet-5-5";
const VENDOS_RESTRICTED_SPEC = "vendos-consultation";
const ENDPOINT = VENDOS_RESTRICTED_ENDPOINT;
const MODEL = VENDOS_RESTRICTED_MODEL;
const SPEC = VENDOS_RESTRICTED_SPEC;
const uuid = /^[a-zA-Z0-9_-]{1,128}$/;
const states = /* @__PURE__ */ new WeakMap();
const object = (value) => value != null && typeof value === "object" && !Array.isArray(value) ? value : {};
const hash = (value) => (0, node_crypto.createHash)("sha256").update(value, "utf8").digest("hex");
const emailHash = (email) => typeof email === "string" ? hash(email.trim().toLowerCase()) : "";
const idOf = (user) => String(user.id ?? user._id ?? "");
const deny = () => {
	throw new Error("VENDOS_ACCESS_RESTRICTED");
};
const check$1 = (condition) => {
	if (!condition) deny();
};
function vendosRestrictedOverrides() {
	return { modelSpecs: {
		enforce: true,
		prioritize: true,
		list: [{
			name: SPEC,
			label: "VENDOS konzultace a návrhy",
			description: "Společné podklady VENDOS a zadání pro analytika a kontrolora. Schvalování a provedení patří vlastníkovi.",
			showOnLanding: true,
			webSearch: false,
			fileSearch: false,
			executeCode: false,
			memory: false,
			skills: false,
			askUserQuestion: false,
			runInBackground: false,
			mcpServers: ["vendos_pilot"],
			preset: {
				endpoint: ENDPOINT,
				model: MODEL,
				promptPrefix: "Jsi konzultační marketingový koordinátor VENDOS, projekt vendos-cz. Mluv česky. Nejprve načti project_report a coordinator_report z MCP vendos_pilot; pro úplné podklady použij konkrétní job_id. Uváděj zdroje, stáří a omezení. Respektuj caller_access. Na výslovné nové zadání uživatele smíš použít coordinator_submit pro návrh do společné místní fronty analytika a kontrolora; sděl skutečné ID a stav. Nezakládej zadání při pouhém dotazu. Neprováděj schvalování obsahu, feedback, změny strategie, prepare_execution, execute_approved_change, reklamy, e-maily, publikování ani firemní úkoly. Souhlas tohoto uživatele nenahrazuje schválení vlastníka. Připomínky formuluj jako návrh k předání vlastníkovi. Fronta návrhů není firemní úkol. Používáš firemní Claude; ruční chat sdílí stávající limit workspace, automatická fronta má vlastní společné limity. Bez nástrojem ověřeného výsledku netvrď, že něco bylo uloženo nebo provedeno."
			}
		}]
	} };
}
function vendosRestrictedDigest(value) {
	const stable = (input) => Array.isArray(input) ? input.map(stable) : input != null && typeof input === "object" ? Object.fromEntries(Object.entries(input).sort(([a], [b]) => a.localeCompare(b)).map(([key, val]) => [key, stable(val)])) : input;
	return hash(JSON.stringify(stable(value)));
}
function isVendosRestrictedIdentity(user, hashes = process.env.VENDOS_GOOGLE_EMAIL_SHA256_ALLOWLIST) {
	if (!user) return false;
	const target = emailHash(user.email);
	return typeof hashes === "string" && hashes.split(",").some((value) => value.trim().toLowerCase() === target);
}
/** Alternate API-key/OIDC authentication happens after the global JWT boundary. */
function denyVendosRestrictedRemote(req, res, next) {
	if (isVendosRestrictedIdentity(req.user)) {
		res.status(403).json({ error: "VENDOS_ACCESS_RESTRICTED" });
		return;
	}
	next();
}
function verifyVendosRestrictedAccess(user, records, now = Date.now()) {
	const userId = idOf(user);
	const j = records.journal;
	check$1(/^[a-f0-9]{24}$/.test(userId) && user.role === "USER" && !user.tenantId);
	check$1(j && j._id === userId && j.state === "prepared" && j.access_policy === "vendos-chat-only-v1");
	check$1(j.target_email_sha256 === emailHash(user.email) && j.google_subject_sha256 === hash(String(user.googleId)));
	check$1(typeof j.expires_at === "number" && j.expires_at > now / 1e3);
	check$1(j.config_sha256 === vendosRestrictedDigest(vendosRestrictedOverrides()));
	check$1(records.activeConfigs.length === 1 && records.keys.length === 1 && records.plugins.length === 1);
	const c = records.activeConfigs[0];
	check$1(typeof j.config_id === "string" && String(c._id) === j.config_id);
	check$1(c.principalType === "user" && c.principalId === userId && c.principalModel === "User" && c.isActive === true && c.priority === 1e3);
	check$1(Array.isArray(c.tombstones) && c.tombstones.length === 0 && (0, node_util.isDeepStrictEqual)(c.overrides, vendosRestrictedOverrides()));
	const key = records.keys[0];
	check$1(typeof j.model_key_id === "string" && String(key._id) === j.model_key_id);
	check$1(String(key.userId) === userId && key.name === ENDPOINT && typeof key.value === "string");
	check$1(hash(String(key.value)) === j.model_key_ciphertext_sha256 && new Date(String(key.expiresAt)).getTime() === Number(j.expires_at) * 1e3);
	const plugin = records.plugins[0];
	check$1(typeof j.mcp_token_id === "string" && String(plugin._id) === j.mcp_token_id);
	check$1(plugin.userId === userId && plugin.pluginKey === "mcp_vendos_pilot" && plugin.authField === "VENDOS_PILOT_KEY" && typeof plugin.value === "string");
	check$1(hash(String(plugin.value)) === j.mcp_token_ciphertext_sha256);
}
function ownConversation(row, userId) {
	return !!row && row.user === userId && row.endpoint === ENDPOINT && row.spec === SPEC && row.model === MODEL && row.isTemporary !== true;
}
function ownGeneration(row, userId) {
	const meta = object(row?.metadata);
	return !!row && meta.userId === userId && !meta.tenantId && meta.endpoint === ENDPOINT && meta.model === MODEL && !meta.agent_id && meta.isTemporary !== true;
}
function restrictedInterface() {
	return {
		modelSelect: false,
		parameters: false,
		presets: false,
		sidePanel: false,
		bookmarks: false,
		multiConvo: false,
		temporaryChat: false,
		prompts: false,
		agents: false,
		memories: false,
		marketplace: false,
		remoteAgents: false,
		runCode: false,
		webSearch: false,
		fileSearch: false,
		fileCitations: false,
		peoplePicker: false,
		mcpServers: false
	};
}
function safeSpecs() {
	const specs = object(vendosRestrictedOverrides().modelSpecs);
	const list = specs.list.map((spec) => ({
		...spec,
		preset: {
			endpoint: ENDPOINT,
			model: MODEL
		}
	}));
	return {
		...specs,
		list
	};
}
function safeRole() {
	const names = [
		"PROMPTS",
		"BOOKMARKS",
		"AGENTS",
		"MEMORIES",
		"MULTI_CONVO",
		"TEMPORARY_CHAT",
		"RUN_CODE",
		"WEB_SEARCH",
		"PEOPLE_PICKER",
		"MARKETPLACE",
		"FILE_SEARCH",
		"FILE_CITATIONS",
		"MCP_SERVERS",
		"REMOTE_AGENTS",
		"SKILLS",
		"SHARED_LINKS"
	];
	const disabled = {
		USE: false,
		CREATE: false,
		UPDATE: false,
		READ: false,
		DELETE: false,
		SHARE: false,
		SHARE_PUBLIC: false,
		VIEW_USERS: false,
		VIEW_GROUPS: false,
		VIEW_ROLES: false,
		CONFIGURE_OBO: false
	};
	return {
		name: "USER",
		permissions: Object.fromEntries(names.map((name) => [name, disabled]))
	};
}
/** This is also called after resume-context reconstruction, before loadAgent sees raw request fields. */
function enforceVendosRestrictedBody(req) {
	const state = states.get(req);
	if (!state) {
		if (isVendosRestrictedIdentity(req.user)) deny();
		return;
	}
	check$1(state.ready);
	const body = object(req.body);
	check$1(body.endpoint === ENDPOINT && body.spec === SPEC && (!body.model || body.model === MODEL));
	check$1(body.endpointType == null || body.endpointType === "custom");
	for (const field of [
		"addedConvo",
		"agent_id",
		"assistant_id",
		"chatProjectId",
		"projectId",
		"manualSkills",
		"alwaysAppliedSkills",
		"files",
		"attachments",
		"quotes",
		"tools",
		"promptPrefix",
		"instructions",
		"system",
		"context",
		"examples",
		"customParams",
		"overrideConvoId",
		"overrideUserMessageId",
		"recoverySteerId"
	]) {
		const value = body[field];
		check$1(value == null || value === "" || Array.isArray(value) && value.length === 0);
	}
	check$1(body.isTemporary !== true);
	const ephemeral = object(body.ephemeralAgent);
	check$1(Object.entries(ephemeral).every(([key, value]) => key === "mcp" ? Array.isArray(value) && value.every((item) => item === "vendos_pilot") : value === false || value == null));
	const allowed = [
		"text",
		"conversationId",
		"parentMessageId",
		"messageId",
		"responseMessageId",
		"clientRequestId",
		"isRegenerate",
		"regenerate",
		"isContinued",
		"clientTimestamp",
		"timezone",
		"generationProtocolVersion",
		"expectedPredecessorCreatedAt",
		"actionId",
		"generationCreatedAt",
		"decisions",
		"answers",
		"action",
		"response",
		"value"
	];
	const clean = {};
	for (const key of allowed) if (body[key] !== void 0) clean[key] = body[key];
	req.body = {
		...clean,
		endpoint: ENDPOINT,
		endpointType: "custom",
		model: MODEL,
		spec: SPEC,
		isTemporary: false,
		ephemeralAgent: {
			mcp: ["vendos_pilot"],
			execute_code: false,
			web_search: false,
			file_search: false,
			memory: false,
			skills: false,
			ask_user_question: false,
			run_in_background: false
		}
	};
}
/** Never allow the existing config loader's base-config fallback to weaken this policy. */
function enforceVendosRestrictedConfig(req) {
	const state = states.get(req);
	if (!state) {
		if (isVendosRestrictedIdentity(req.user)) deny();
		return;
	}
	check$1(state.ready);
	const config = object(req.config);
	const canonicalSpecs = object(vendosRestrictedOverrides().modelSpecs);
	const loadedSpecs = object(config.modelSpecs);
	check$1(Object.entries(canonicalSpecs).every(([key, value]) => (0, node_util.isDeepStrictEqual)(loadedSpecs[key], value)));
	const endpoints = object(config.endpoints);
	const selected = (Array.isArray(endpoints.custom) ? endpoints.custom : []).filter((entry) => entry.name === ENDPOINT);
	check$1(selected.length === 1);
	const endpoint = selected[0];
	check$1(endpoint.apiKey === "user_provided" && endpoint.provider === "anthropic" && endpoint.baseURL === "https://api.anthropic.com");
	check$1(endpoint.titleConvo === false && endpoint.activityLabel === false && object(endpoint.models).fetch === false);
	check$1(Array.isArray(object(endpoint.models).default) && object(endpoint.models).default.includes(MODEL));
	const mcp = object(object(config.mcpConfig).vendos_pilot);
	check$1(object(mcp.headers).Authorization === "Bearer {{VENDOS_PILOT_KEY}}" && object(object(mcp.customUserVars).VENDOS_PILOT_KEY).sensitive === true);
	check$1(typeof mcp.url === "string" && /^https:\/\/[^\s]+$/.test(mcp.url));
	req.config = {
		...config,
		...vendosRestrictedOverrides(),
		interfaceConfig: restrictedInterface(),
		endpoints: {
			custom: [{
				...endpoint,
				models: {
					default: [MODEL],
					fetch: false
				}
			}],
			agents: {
				capabilities: [],
				allowedProviders: [ENDPOINT]
			}
		},
		mcpConfig: { vendos_pilot: mcp },
		memory: void 0,
		webSearch: void 0,
		actions: void 0
	};
}
function createVendosRestrictedChat(deps) {
	const now = deps.now ?? Date.now;
	const hashes = deps.hashes ?? (() => process.env.VENDOS_GOOGLE_EMAIL_SHA256_ALLOWLIST);
	return (req, res, next) => {
		deps.authenticate(req, res, (authError) => {
			if (authError) {
				next(authError);
				return;
			}
			if (!isVendosRestrictedIdentity(req.user, hashes())) {
				next();
				return;
			}
			(async () => {
				const user = req.user;
				check$1(isVerifiedGoogleEmailException(user, hashes()) && user.role === "USER" && !user.tenantId);
				const userId = idOf(user);
				check$1(/^[a-f0-9]{24}$/.test(userId));
				const rawPath = req.originalUrl.split("?")[0];
				check$1(!/%(?:2f|5c|2e|25)|\\|\/\//i.test(rawPath));
				const path = decodeURIComponent(rawPath).replace(/\/$/, "");
				check$1(!path.split("/").some((part) => part === "." || part === ".."));
				const url = new URL(req.originalUrl, "https://vendos.invalid");
				check$1(new Set(url.searchParams.keys()).size === [...url.searchParams.keys()].length);
				const method = req.method.toUpperCase();
				if (method === "POST" && ["/api/auth/refresh", "/api/auth/logout"].includes(path)) {
					next();
					return;
				}
				const records = await deps.provision(userId);
				let ready = false;
				try {
					verifyVendosRestrictedAccess(user, records, now());
					ready = true;
				} catch {}
				states.set(req, {
					userId,
					ready
				});
				if (method === "GET" && path === "/api/user") {
					res.json(Object.fromEntries([
						"id",
						"_id",
						"name",
						"username",
						"email",
						"emailVerified",
						"provider",
						"role",
						"termsAccepted",
						"createdAt",
						"updatedAt"
					].filter((key) => user[key] !== void 0).map((key) => [key, user[key]])));
					return;
				}
				if (method === "GET" && path === "/api/config") {
					res.json({
						appTitle: "VENDOS",
						interface: restrictedInterface(),
						modelSpecs: safeSpecs(),
						sharedLinksEnabled: false,
						publicSharedLinksEnabled: false,
						agents: false,
						speech: false,
						balance: { enabled: false },
						vendosAccess: ready ? "ready" : "pending"
					});
					return;
				}
				if (method === "GET" && path === "/api/endpoints") {
					res.json({ [ENDPOINT]: {
						type: "custom",
						userProvide: true,
						userProvideURL: false,
						modelDisplayLabel: "VENDOS"
					} });
					return;
				}
				if (method === "GET" && path === "/api/models") {
					res.json({ [ENDPOINT]: [MODEL] });
					return;
				}
				if (method === "GET" && path === "/api/roles/USER") {
					res.json(safeRole());
					return;
				}
				if (method === "GET" && path === "/api/keys") {
					check$1([...url.searchParams.keys()].every((key) => key === "name") && url.searchParams.get("name") === ENDPOINT);
					res.json({ expiresAt: ready ? (/* @__PURE__ */ new Date(Number(records.journal.expires_at) * 1e3)).toISOString() : null });
					return;
				}
				check$1(ready);
				if (method === "GET" && path === "/api/convos") {
					check$1([...url.searchParams.keys()].every((key) => [
						"limit",
						"cursor",
						"isArchived",
						"sortBy",
						"sortDirection"
					].includes(key)));
					const conversations = await deps.conversations(userId);
					check$1(conversations.every((row) => ownConversation(row, userId)));
					res.json({
						conversations,
						nextCursor: null
					});
					return;
				}
				if (method === "GET" && path === "/api/messages") {
					check$1([...url.searchParams.keys()].every((key) => [
						"conversationId",
						"messageId",
						"pageSize",
						"cursor",
						"sortBy",
						"sortDirection"
					].includes(key)));
					const id = url.searchParams.get("conversationId");
					check$1(id && uuid.test(id) && ownConversation(await deps.conversation(id), userId));
					next();
					return;
				}
				const convoPath = path.match(/^\/api\/convos\/([a-zA-Z0-9_-]{1,128})$/) ?? path.match(/^\/api\/messages\/([a-zA-Z0-9_-]{1,128})(?:\/([a-zA-Z0-9_-]{1,128}))?$/);
				if (method === "GET" && convoPath) {
					check$1(ownConversation(await deps.conversation(convoPath[1]), userId));
					check$1([...url.searchParams.keys()].every((key) => ["limit", "cursor"].includes(key)));
					next();
					return;
				}
				if (method === "GET" && path === "/api/agents/chat/active") {
					const jobs = await deps.generations(userId);
					check$1(jobs.every((job) => ownGeneration(job, userId)));
					res.json({ activeJobIds: jobs.map((job) => job.streamId ?? job.conversationId) });
					return;
				}
				const streamPath = path.match(/^\/api\/agents\/chat\/(?:stream|status)\/([a-zA-Z0-9_-]{1,128})$/);
				if (method === "GET" && streamPath) {
					const job = await deps.generation(streamPath[1]);
					check$1(job ? ownGeneration(job, userId) : ownConversation(await deps.conversation(streamPath[1]), userId));
					next();
					return;
				}
				if (method === "POST" && path === "/api/agents/chat/abort") {
					const id = req.body?.streamId ?? req.body?.conversationId;
					check$1(typeof id === "string" && uuid.test(id) && ownGeneration(await deps.generation(String(id)), userId));
					check$1(req.body?.conversationId == null || req.body.conversationId === id);
					check$1(req.body?.abortKey == null || typeof req.body.abortKey === "string" && req.body.abortKey.split(":")[0] === id);
					req.body = {
						streamId: id,
						conversationId: id,
						generationCreatedAt: req.body?.generationCreatedAt
					};
					next();
					return;
				}
				if (method === "POST" && [
					"/api/agents/chat/VENDOS pilot",
					"/api/agents/chat",
					"/api/agents/chat/resume"
				].includes(path)) {
					const id = req.body?.conversationId;
					check$1(id == null || id === "new" || typeof id === "string" && uuid.test(id));
					if (id && id !== "new") {
						const conversation = await deps.conversation(String(id));
						check$1(!conversation || ownConversation(conversation, userId));
					}
					if (path.endsWith("/resume")) check$1(typeof id === "string" && ownGeneration(await deps.generation(id), userId));
					enforceVendosRestrictedBody(req);
					next();
					return;
				}
				deny();
			})().catch(() => {
				res.status(403).json({ error: "VENDOS_ACCESS_RESTRICTED" });
			});
		});
	};
}
//#endregion
//#region packages/api/src/vendos/drafts.ts
/** Content-only protocol; callers must supply authenticated, persisted message provenance. */
const HASH$1 = /^[0-9a-f]{64}$/;
const JOB_ID = /^vnd-[a-z0-9]{16}$/;
const ITEM_KEY = /^[a-z0-9-]{3,40}$/;
const UUID$1 = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const CONTROL = /[\u0000-\u001f\u007f]/;
const MAX_AGE_MS = 3e5;
var DraftApprovalError = class extends Error {};
function fail(reason) {
	throw new DraftApprovalError(reason);
}
function check(condition, reason) {
	if (!condition) fail(reason);
}
function text(value, max = 200) {
	return typeof value === "string" && value.length > 0 && value.length <= max && !CONTROL.test(value);
}
function integer(value, min = 1, max = Number.MAX_SAFE_INTEGER) {
	return typeof value === "number" && Number.isSafeInteger(value) && value >= min && value <= max;
}
function sha256$1(value) {
	return (0, node_crypto.createHash)("sha256").update(value, "utf8").digest("hex");
}
/** Only these two exact non-executing Czech sentences are recognized. */
function parseDraftApproval(raw) {
	check(text(raw, 500), "Ambiguous content approval");
	const normalized = raw.normalize("NFC").replace(/^ +| +$/g, "").toLowerCase();
	if (/^souhlasím se všemi body\.?$/.test(normalized)) return { all: true };
	const match = /^souhlasím s obsahem strategie v([1-9][0-9]*), (?:body|bod) ([1-9][0-9]*(?:(?:, | a )[1-9][0-9]*)*)\.?$/.exec(normalized);
	check(match !== null, "Use an exact content-only approval sentence");
	const revision = Number(match[1]);
	const points = match[2].match(/[0-9]+/g).map(Number);
	check(integer(revision) && points.length <= 50 && points.every((p) => integer(p, 1, 50)) && new Set(points).size === points.length, "Duplicate, unsafe or excessive selection");
	return {
		all: false,
		revision,
		points: points.sort((a, b) => a - b)
	};
}
function checkPolicy(policy) {
	check(text(policy?.project) && text(policy?.owner) && typeof policy.thread_id === "string" && UUID$1.test(policy.thread_id), "Invalid trusted policy");
}
function expires(value) {
	check(typeof value === "string" && /T.*(?:Z|[+-][0-9]{2}:[0-9]{2})$/.test(value), "Expiry requires explicit timezone");
	const at = Date.parse(value);
	check(Number.isFinite(at), "Invalid expiry");
	return at;
}
/** Resolve exclusively from the raw immutable payload received by authenticated notebook poll.
* UI text, parsed Markdown, user-supplied metadata and reconstructed JSON are not sources.
*/
function resolveDraftTargets(bundle, selection, policy, nowMs) {
	checkPolicy(policy);
	check(integer(nowMs), "Invalid server clock");
	check(bundle && text(bundle.id) && bundle.project === policy.project && bundle.owner === policy.owner && bundle.thread_id === policy.thread_id, "Wrong private bundle owner or conversation");
	check(typeof bundle.payload === "string" && bundle.payload.length <= 2e6 && typeof bundle.bundle_hash === "string" && HASH$1.test(bundle.bundle_hash) && sha256$1(bundle.payload) === bundle.bundle_hash, "Immutable bundle hash mismatch");
	let payload;
	try {
		payload = JSON.parse(bundle.payload);
	} catch {
		return fail("Invalid immutable bundle JSON");
	}
	check(payload !== null && typeof payload === "object" && !Array.isArray(payload), "Invalid immutable bundle object");
	check(payload.id === bundle.id && payload.project === policy.project && payload.owner === policy.owner && payload.thread_id === policy.thread_id && payload.expires_at === bundle.expires_at && payload.decision_type === "draft", "Bundle is not an exact advisory draft offer");
	check(expires(bundle.expires_at) > nowMs, "Draft offer expired");
	check(typeof bundle.source_message_id === "string" && UUID$1.test(bundle.source_message_id) && integer(bundle.acknowledged_at_ms) && bundle.acknowledged_at_ms <= nowMs + 2e3, "The exact source has no valid delivery acknowledgement");
	check(Array.isArray(payload.items) && payload.items.length > 0 && payload.items.length <= 50, "Invalid advisory manifest");
	const identities = /* @__PURE__ */ new Set();
	const targets = payload.items.map((value, i) => {
		check(value !== null && typeof value === "object" && !Array.isArray(value), "Invalid manifest item");
		const item = value;
		check(item.number === i + 1 && item.decision_type === "draft" && item.executable === false && item.plan_id === null && item.plan_hash === null && item.approval_summary === null && (item.execution_action === void 0 || item.execution_action === null), "Mixed or executable bundle is not a draft decision");
		check(typeof item.job_id === "string" && JOB_ID.test(item.job_id) && integer(item.revision) && typeof item.item_key === "string" && ITEM_KEY.test(item.item_key) && typeof item.draft_sha256 === "string" && HASH$1.test(item.draft_sha256) && typeof item.review_sha256 === "string" && HASH$1.test(item.review_sha256), "Missing exact draft/review metadata");
		const identity = JSON.stringify([
			item.job_id,
			item.revision,
			item.item_key
		]);
		check(!identities.has(identity), "Duplicate target identity");
		identities.add(identity);
		return Object.freeze({
			number: item.number,
			job_id: item.job_id,
			revision: item.revision,
			item_key: item.item_key,
			draft_sha256: item.draft_sha256,
			review_sha256: item.review_sha256
		});
	});
	check(selection && (selection.all === true || selection.all === false), "Invalid selection");
	if (selection.all) return targets;
	check(integer(selection.revision) && Array.isArray(selection.points) && selection.points.length > 0 && selection.points.length <= 50 && selection.points.every((p, i) => integer(p, 1, targets.length) && (i === 0 || p > selection.points[i - 1])), "Selection must be sorted, unique and present");
	const chosen = selection.points.map((p) => targets[p - 1]);
	check(chosen.every((target) => target.revision === selection.revision), "Explicit revision does not match every selected target");
	return chosen;
}
function checkAncestry(context) {
	const { policy, bundle, message, ancestors } = context;
	check(Array.isArray(ancestors) && ancestors.length > 0 && ancestors.length <= 100, "Missing trusted ancestry");
	const nodes = /* @__PURE__ */ new Map();
	for (const node of ancestors) {
		check(node && typeof node.message_id === "string" && UUID$1.test(node.message_id) && node.thread_id === policy.thread_id && typeof node.is_created_by_user === "boolean" && (node.parent_message_id === null || typeof node.parent_message_id === "string" && UUID$1.test(node.parent_message_id)) && !nodes.has(node.message_id) && node.message_id !== message.message_id, "Invalid trusted ancestor");
		nodes.set(node.message_id, node);
	}
	let cursor = message.parent_message_id;
	const seen = /* @__PURE__ */ new Set();
	while (cursor !== null) {
		check(!seen.has(cursor), "Cyclic message ancestry");
		seen.add(cursor);
		const node = nodes.get(cursor);
		check(node !== void 0, "Source is not on the persisted parent chain");
		if (node.message_id === bundle.source_message_id) {
			check(node.is_created_by_user === false, "Source delivery cannot be a human message");
			return;
		}
		cursor = node.parent_message_id;
	}
	fail("No ancestor binds this owner message to the exact delivered bundle");
}
/** The adapter must supply reread persisted/authenticated records, never model or body fields.
* This signs a CONTENT DECISION ONLY; no execution parser or executor is called.
*/
function buildDraftDecision(context, serverKey, nowMs) {
	check(!!(context && context.message && context.latest_briefing), "Missing trusted decision context");
	const { policy, bundle, message, latest_briefing: latest } = context;
	checkPolicy(policy);
	check(integer(nowMs) && typeof serverKey === "string" && Buffer.byteLength(serverKey, "utf8") >= 32, "Invalid server clock or signing key");
	check(message.actor === policy.owner && message.thread_id === policy.thread_id && message.is_created_by_user === true && typeof message.message_id === "string" && UUID$1.test(message.message_id) && typeof message.parent_message_id === "string" && UUID$1.test(message.parent_message_id), "Only the persisted authenticated owner message may authorize a content decision");
	check(integer(message.created_at_ms) && nowMs - message.created_at_ms >= -2e3 && nowMs - message.created_at_ms <= MAX_AGE_MS, "Owner message is not fresh");
	const targets = resolveDraftTargets(bundle, parseDraftApproval(message.message_text), policy, nowMs);
	check(latest.bundle_id === bundle.id && latest.bundle_hash === bundle.bundle_hash && latest.source_message_id === bundle.source_message_id, "A newer or conflicting acknowledged briefing exists");
	check(message.message_id !== bundle.source_message_id && message.created_at_ms >= bundle.acknowledged_at_ms, "Owner message predates the acknowledged offer");
	checkAncestry(context);
	const selected = targets.map((target) => target.number);
	const receiptPayload = {
		v: 2,
		kind: "vendos_draft_decision",
		actor: policy.owner,
		thread_id: policy.thread_id,
		bundle_id: bundle.id,
		bundle_hash: bundle.bundle_hash,
		message_id: message.message_id,
		source_message_id: bundle.source_message_id,
		selected_points: selected,
		message_sha256: sha256$1(message.message_text),
		nonce: "draft-message:" + message.message_id,
		issued_at: nowMs
	};
	const body = Buffer.from(JSON.stringify(receiptPayload), "utf8").toString("base64url");
	const receipt = body + "." + (0, node_crypto.createHmac)("sha256", serverKey).update(body, "utf8").digest("hex");
	return {
		receipt_payload: receiptPayload,
		targets,
		endpoint_args: {
			project: policy.project,
			bundle_id: bundle.id,
			bundle_hash: bundle.bundle_hash,
			message_id: message.message_id,
			message_text: message.message_text,
			selected_points: selected,
			approval_receipt: receipt
		}
	};
}
//#endregion
//#region packages/api/src/vendos.ts
const PROJECT = "vendos-cz";
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const HASH = /^[a-f0-9]{64}$/;
const NO_PARENT = "00000000-0000-0000-0000-000000000000";
function sha256(text) {
	return (0, node_crypto.createHash)("sha256").update(text, "utf8").digest("hex");
}
function isVendosDecisionText(text) {
	return typeof text === "string" && /^(?:schvaluji|souhlasim)\b/.test(text.normalize("NFD").replace(/[\u0300-\u036f]/g, "").trim().toLowerCase());
}
function isVendosGenerationBusy(job) {
	return !!job && (job.metadata?.terminalPersistencePending === true || ![
		"complete",
		"error",
		"aborted"
	].includes(job.status));
}
function isDraftLanguage(text) {
	const normalized = text.normalize("NFD").replace(/[\u0300-\u036f]/g, "").trim().toLowerCase();
	return /^souhlasim (?:se|s obsahem)\b/.test(normalized);
}
function parseApproval(text) {
	if (text.length > 400 || /[\n\r"'`>[\]{}]/.test(text)) return null;
	const normalized = text.normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase().trim();
	const match = /^(?:schvaluji (?:body|bod)|souhlasim s (?:body|bodem)) ([1-9][0-9]?(?:\s*(?:,|a)\s*[1-9][0-9]?)*)\s*,?\s+(?:proved|implementuj)(?:\s+(?:je|to))?\.?$/.exec(normalized);
	if (!match) return null;
	const points = match[1].split(/\s*(?:,|a)\s*/).map(Number);
	return points.length <= 20 && new Set(points).size === points.length ? points.sort((a, b) => a - b) : null;
}
function signReceipt(payload, key) {
	if (key.length < 24) throw new Error("vendos_invalid_key");
	const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
	return `${body}.${(0, node_crypto.createHmac)("sha256", key).update(body).digest("hex")}`;
}
async function callMCP(url, name, args, key) {
	const headers = {
		"Content-Type": "application/json",
		Accept: "application/json, text/event-stream",
		"MCP-Protocol-Version": "2025-03-26",
		Authorization: `Bearer ${key}`
	};
	const response = await fetch(url, {
		method: "POST",
		headers,
		body: JSON.stringify({
			jsonrpc: "2.0",
			id: (0, node_crypto.randomUUID)(),
			method: "tools/call",
			params: {
				name,
				arguments: args
			}
		}),
		signal: AbortSignal.timeout(2e4)
	});
	if (!response.ok) throw new Error(`vendos_mcp_http_${response.status}`);
	const body = await response.json();
	if (body.error || body.result?.isError) throw new Error("vendos_mcp_rejected");
	const result = body.result?.structuredContent ?? body.result?.content?.find((part) => part.type === "text")?.text;
	if (result == null) throw new Error("vendos_mcp_empty_result");
	return typeof result === "string" ? JSON.parse(result) : result;
}
function validDelivery(delivery) {
	return !!delivery && typeof delivery.delivery_id === "string" && delivery.delivery_id.length <= 150 && (delivery.kind === "briefing" || delivery.kind === "result") && typeof delivery.bundle_id === "string" && delivery.bundle_id.length <= 150 && HASH.test(delivery.bundle_hash) && UUID.test(delivery.message_id) && typeof delivery.body === "string" && delivery.body.length > 0 && delivery.body.length <= 1e5 && Array.isArray(delivery.items) && delivery.items.length <= 50 && delivery.items.every((item) => Number.isInteger(item.number) && item.number > 0 && item.number <= 99 && typeof item.executable === "boolean" && (!item.executable || typeof item.plan_id === "string" && /^act-[a-f0-9]{20}$/.test(item.plan_id) && HASH.test(item.plan_hash ?? "") && typeof item.approval_summary === "string" && item.approval_summary.length > 0 && item.approval_summary.length <= 2e4 && delivery.body.includes(item.approval_summary))) && new Set(delivery.items.map((item) => item.number)).size === delivery.items.length;
}
/** Only the authenticated request controller may call handle; no MCP/model hook exposes it. */
function createVendosBriefing(options) {
	const { db } = options;
	const preset = Object.fromEntries(Object.entries(options.preset).filter(([, value]) => value != null));
	const { ownerId: VENDOS_OWNER, threadId: VENDOS_THREAD } = options;
	if (!/^[a-f0-9]{24}$/.test(VENDOS_OWNER) || !UUID.test(VENDOS_THREAD) || !options.ownerEmail) throw new Error("vendos_invalid_configuration");
	const messages = db.collection("messages");
	const conversations = db.collection("conversations");
	const deliveries = db.collection("vendos_briefing_deliveries");
	const approvals = db.collection("vendos_briefing_approvals");
	const draftDecisions = db.collection("vendos_briefing_draft_decisions");
	const leases = db.collection("vendos_briefing_leases");
	const now = options.now ?? (() => /* @__PURE__ */ new Date());
	const rpc = options.rpc ?? ((name, args, key) => callMCP(options.mcpUrl, name, args, key));
	const holder = (0, node_crypto.randomUUID)();
	const draftPolicy = {
		project: PROJECT,
		owner: `librechat-${VENDOS_OWNER}`,
		thread_id: VENDOS_THREAD
	};
	let timer;
	let inFlight = false;
	async function identity() {
		const owner = await options.getOwner();
		if (!owner || owner.email?.toLowerCase() !== options.ownerEmail.toLowerCase()) throw new Error("vendos_owner_not_verified");
		return {
			user: VENDOS_OWNER,
			conversationId: VENDOS_THREAD,
			...owner.tenantId ? { tenantId: owner.tenantId } : { tenantId: { $exists: false } }
		};
	}
	async function lock() {
		if (inFlight) return false;
		inFlight = true;
		try {
			const acquired = (await leases.findOneAndUpdate({
				_id: VENDOS_THREAD,
				$or: [{ until: { $lt: now() } }, { holder }]
			}, { $set: {
				holder,
				until: new Date(now().getTime() + 12e4)
			} }, {
				upsert: true,
				returnDocument: "after"
			}))?.holder === holder;
			if (!acquired) inFlight = false;
			return acquired;
		} catch {
			inFlight = false;
			return false;
		}
	}
	async function unlock() {
		try {
			await leases.updateOne({
				_id: VENDOS_THREAD,
				holder
			}, { $set: { until: /* @__PURE__ */ new Date(0) } });
		} catch {
			options.log("vendos_lease_release_pending");
		} finally {
			inFlight = false;
		}
	}
	async function ensureConversation() {
		const scope = await identity();
		const existing = await conversations.findOne(scope);
		if (existing) {
			if (existing.spec !== "vendos-pilot" || existing.endpoint !== preset.endpoint) throw new Error("vendos_conversation_changed");
			return scope;
		}
		const owner = await options.getOwner();
		await conversations.insertOne({
			conversationId: VENDOS_THREAD,
			user: VENDOS_OWNER,
			...owner?.tenantId ? { tenantId: owner.tenantId } : {},
			title: "VENDOS — marketing a schvalování",
			spec: "vendos-pilot",
			...preset,
			isArchived: false,
			isTemporary: false,
			createdAt: now(),
			updatedAt: now()
		});
		return scope;
	}
	async function saveMessage(messageId, text, parentMessageId, fromUser) {
		const scope = await identity();
		const existing = await messages.findOne({
			...scope,
			messageId
		});
		if (existing) {
			if (existing.text !== text || existing.parentMessageId !== parentMessageId || existing.isCreatedByUser !== fromUser) throw new Error("vendos_message_conflict");
			return;
		}
		if (await messages.findOne({ messageId })) throw new Error("vendos_message_id_owned_elsewhere");
		const owner = await options.getOwner();
		const createdAt = now();
		await messages.insertOne({
			messageId,
			conversationId: VENDOS_THREAD,
			user: VENDOS_OWNER,
			...owner?.tenantId ? { tenantId: owner.tenantId } : {},
			parentMessageId,
			text,
			content: [{
				type: "text",
				text
			}],
			isCreatedByUser: fromUser,
			sender: fromUser ? "User" : "VENDOS koordinátor",
			endpoint: preset.endpoint,
			model: preset.model,
			unfinished: false,
			isTemporary: false,
			createdAt,
			updatedAt: createdAt
		});
		await conversations.updateOne(scope, { $set: { updatedAt: now() } });
	}
	async function deliver(delivery, key) {
		if (!validDelivery(delivery)) throw new Error("vendos_invalid_delivery");
		if (delivery.kind === "briefing" && delivery.decision_type === "draft") {
			if (typeof delivery.payload !== "string" || !delivery.expires_at) throw new Error("vendos_missing_draft_manifest");
			resolveDraftTargets({
				id: delivery.bundle_id,
				project: PROJECT,
				owner: draftPolicy.owner,
				thread_id: VENDOS_THREAD,
				payload: delivery.payload,
				bundle_hash: delivery.bundle_hash,
				source_message_id: delivery.message_id,
				acknowledged_at_ms: now().getTime(),
				expires_at: delivery.expires_at
			}, { all: true }, draftPolicy, now().getTime());
		}
		const scope = await ensureConversation();
		const payloadHash = sha256(JSON.stringify(delivery));
		const existing = await deliveries.findOne({ _id: delivery.delivery_id });
		if (existing && existing.payloadHash !== payloadHash) throw new Error("vendos_delivery_changed");
		const savedMessage = await messages.findOne({
			...scope,
			messageId: delivery.message_id
		});
		const latest = savedMessage ?? await messages.findOne(scope, { sort: {
			createdAt: -1,
			_id: -1
		} });
		const parent = savedMessage?.parentMessageId ?? latest?.messageId ?? NO_PARENT;
		await saveMessage(delivery.message_id, delivery.body, parent, false);
		await deliveries.updateOne({ _id: delivery.delivery_id }, { $setOnInsert: {
			...delivery,
			payload: delivery,
			payloadHash,
			storedAt: now()
		} }, { upsert: true });
		const receipt = signReceipt({
			v: 2,
			kind: "vendos_delivery_ack",
			actor: `librechat-${VENDOS_OWNER}`,
			thread_id: VENDOS_THREAD,
			delivery_id: delivery.delivery_id,
			message_id: delivery.message_id,
			bundle_hash: delivery.bundle_hash,
			nonce: `delivery:${delivery.delivery_id}`,
			issued_at: now().getTime()
		}, key);
		await rpc("briefing_ack", {
			project: PROJECT,
			delivery_id: delivery.delivery_id,
			message_id: delivery.message_id,
			approval_receipt: receipt
		}, key);
		await deliveries.updateOne({ _id: delivery.delivery_id }, { $set: { ackedAt: now() } });
	}
	async function submitApproval(record, key) {
		if (await draftDecisions.findOne({ _id: record.messageId })) throw new Error("vendos_cross_type_message_reuse");
		await saveMessage(record.messageId, record.text, record.parentMessageId, true);
		await approvals.updateOne({
			_id: record._id,
			state: "pending"
		}, {
			$inc: { attempts: 1 },
			$set: { lastAttemptAt: now() }
		});
		const receipt = signReceipt({
			v: 2,
			kind: "vendos_message_approval",
			actor: `librechat-${VENDOS_OWNER}`,
			thread_id: VENDOS_THREAD,
			bundle_id: record.bundleId,
			bundle_hash: record.bundleHash,
			message_id: record.messageId,
			source_message_id: record.sourceMessageId,
			selected_points: record.points,
			message_sha256: sha256(record.text),
			nonce: `message:${record.messageId}`,
			issued_at: now().getTime()
		}, key);
		const result = await rpc("briefing_approve", {
			project: PROJECT,
			bundle_id: record.bundleId,
			bundle_hash: record.bundleHash,
			message_id: record.messageId,
			message_text: record.text,
			selected_points: record.points,
			approval_receipt: receipt
		}, key);
		if (!["accepted", "already_accepted"].includes(result.status) || !result.approval_id) throw new Error("vendos_approval_not_accepted");
		const resultText = `Přijal jsem schválení bodů ${record.points.join(" a ")}. Boti provedou pouze tyto body v zobrazené verzi. Výsledky jednotlivých kroků dorazí sem; toto potvrzení ještě neznamená dokončení změn.`;
		await approvals.updateOne({
			_id: record._id,
			state: "pending"
		}, { $set: {
			state: "accepted",
			approvalId: result.approval_id,
			acceptedAt: now(),
			resultText
		} });
		await saveMessage(record.responseMessageId, resultText, record.messageId, false);
	}
	function draftBundle(record) {
		if (record.decision_type !== "draft" || typeof record.payload.payload !== "string" || !record.ackedAt || !record.expires_at) throw new Error("vendos_not_a_draft_offer");
		return {
			id: record.bundle_id,
			project: PROJECT,
			owner: draftPolicy.owner,
			thread_id: VENDOS_THREAD,
			payload: record.payload.payload,
			bundle_hash: record.bundle_hash,
			source_message_id: record.message_id,
			acknowledged_at_ms: record.ackedAt.getTime(),
			expires_at: record.expires_at
		};
	}
	function exactStoredText(message, text) {
		return message.text === text && Array.isArray(message.content) && message.content.length === 1 && message.content[0].type === "text" && message.content[0].text === text && message.updatedAt.getTime() === message.createdAt.getTime();
	}
	async function draftContext(record, stored) {
		const scope = await identity();
		const [offer, latest, source, attached, earlierDecisions] = await Promise.all([
			deliveries.findOne({
				kind: "briefing",
				bundle_id: record.bundleId,
				message_id: record.sourceMessageId
			}),
			deliveries.findOne({
				kind: "briefing",
				ackedAt: { $exists: true }
			}, { sort: {
				storedAt: -1,
				_id: -1
			} }),
			messages.findOne({
				...scope,
				messageId: record.sourceMessageId,
				isCreatedByUser: false
			}),
			deliveries.find({
				bundle_id: record.bundleId,
				bundle_hash: record.bundleHash
			}).toArray(),
			draftDecisions.find({
				ownerId: VENDOS_OWNER,
				threadId: VENDOS_THREAD,
				bundleId: record.bundleId,
				bundleHash: record.bundleHash,
				state: "accepted"
			}).limit(100).toArray()
		]);
		if (!offer || !latest || !source || !exactStoredText(source, offer.body) || offer.bundle_hash !== record.bundleHash) throw new Error("vendos_draft_source_changed");
		const trusted = new Map(attached.map((item) => [item.message_id, item]));
		const earlierMessages = new Map(earlierDecisions.flatMap((item) => [[item.messageId, {
			text: item.text,
			parent: item.parentMessageId,
			human: true
		}], [item.responseMessageId, {
			text: item.resultText,
			parent: item.messageId,
			human: false
		}]]));
		const ancestors = [];
		const seen = /* @__PURE__ */ new Set();
		let cursor = stored.parentMessageId;
		for (let depth = 0; depth < 100; depth++) {
			if (seen.has(cursor)) throw new Error("vendos_cyclic_draft_parent");
			seen.add(cursor);
			const journal = trusted.get(cursor);
			const earlier = earlierMessages.get(cursor);
			const ancestor = await messages.findOne({
				...scope,
				messageId: cursor
			});
			const trustedDelivery = !!journal?.ackedAt && !!ancestor && !ancestor.isCreatedByUser && exactStoredText(ancestor, journal.body);
			const trustedDecision = !!earlier && !!ancestor && ancestor.isCreatedByUser === earlier.human && ancestor.parentMessageId === earlier.parent && exactStoredText(ancestor, earlier.text);
			if (!ancestor || !trustedDelivery && !trustedDecision) throw new Error("vendos_untrusted_draft_parent");
			ancestors.push({
				message_id: ancestor.messageId,
				thread_id: ancestor.conversationId,
				parent_message_id: ancestor.parentMessageId === NO_PARENT ? null : ancestor.parentMessageId,
				is_created_by_user: ancestor.isCreatedByUser
			});
			if (cursor === record.sourceMessageId) break;
			cursor = ancestor.parentMessageId;
		}
		return {
			policy: draftPolicy,
			bundle: draftBundle(offer),
			ancestors,
			message: {
				message_id: stored.messageId,
				thread_id: stored.conversationId,
				actor: draftPolicy.owner,
				is_created_by_user: stored.isCreatedByUser,
				message_text: stored.text,
				parent_message_id: stored.parentMessageId,
				created_at_ms: stored.createdAt.getTime()
			},
			latest_briefing: {
				bundle_id: latest.bundle_id,
				bundle_hash: latest.bundle_hash,
				source_message_id: latest.message_id
			}
		};
	}
	async function submitDraftDecision(record, key) {
		const age = now().getTime() - record.createdAt.getTime();
		if (record.ownerId !== VENDOS_OWNER || record.threadId !== VENDOS_THREAD || age < -2e3 || age > 3e5 || await approvals.findOne({ _id: record.messageId })) throw new Error("vendos_draft_message_not_fresh_or_reused");
		await saveMessage(record.messageId, record.text, record.parentMessageId, true);
		const scope = await identity();
		const stored = await messages.findOne({
			...scope,
			messageId: record.messageId,
			isCreatedByUser: true
		});
		if (!stored || !exactStoredText(stored, record.text) || stored.parentMessageId !== record.parentMessageId) throw new Error("vendos_draft_owner_message_changed");
		let receipt = record.approvalReceipt;
		if (!receipt) {
			const decision = buildDraftDecision(await draftContext(record, stored), key, now().getTime());
			if (JSON.stringify(decision.endpoint_args.selected_points) !== JSON.stringify(record.points)) throw new Error("vendos_draft_selection_changed");
			receipt = decision.endpoint_args.approval_receipt;
			await draftDecisions.updateOne({
				_id: record._id,
				state: "pending"
			}, { $set: {
				approvalReceipt: receipt,
				attestedAt: now()
			} });
		}
		await draftDecisions.updateOne({
			_id: record._id,
			state: "pending"
		}, {
			$inc: { attempts: 1 },
			$set: { lastAttemptAt: now() }
		});
		const result = await rpc("briefing_approve_draft", {
			project: PROJECT,
			bundle_id: record.bundleId,
			bundle_hash: record.bundleHash,
			message_id: record.messageId,
			message_text: record.text,
			selected_points: record.points,
			approval_receipt: receipt
		}, key);
		if (result.status !== "draft_decision_saved" || result.decision !== "approve_draft" || typeof result.decision_id !== "string" || !result.decision_id || result.decision_id.length > 150 || result.execution_allowed !== false) throw new Error("vendos_draft_decision_not_confirmed");
		const resultText = `Uložil jsem váš souhlas s obsahem bodů ${record.points.join(" a ")} této přesné verze strategie. Reklamy, rozesílky, publikování ani firemní úkoly se tím nemění. Případné provedení dostane samostatný konkrétní návrh ke schválení.`;
		await draftDecisions.updateOne({
			_id: record._id,
			state: "pending"
		}, { $set: {
			state: "accepted",
			decisionId: result.decision_id,
			acceptedAt: now(),
			resultText
		} });
		await saveMessage(record.responseMessageId, resultText, record.messageId, false);
	}
	async function recoverDraftDecisions(key) {
		const pending = await draftDecisions.find({
			ownerId: VENDOS_OWNER,
			threadId: VENDOS_THREAD,
			state: "pending",
			$or: [{ lastAttemptAt: { $exists: false } }, { lastAttemptAt: { $lt: /* @__PURE__ */ new Date(now().getTime() - 6e4) } }]
		}).sort({ createdAt: 1 }).limit(1).toArray();
		for (const record of pending) {
			if (record.attempts >= 3 || now().getTime() - record.createdAt.getTime() > 3e5) {
				await draftDecisions.updateOne({
					_id: record._id,
					state: "pending"
				}, { $set: { state: "attention" } });
				await saveMessage(record.responseMessageId, "Obsahový souhlas se nepodařilo spolehlivě potvrdit. Automatické opakování je zastavené; je třeba ověřit uložený stav. Žádné oprávnění k provedení změn tím nevzniklo.", record.messageId, false);
				continue;
			}
			try {
				await submitDraftDecision(record, key);
			} catch {
				options.log("vendos_draft_decision_waiting_for_receipt");
			}
		}
		const accepted = await draftDecisions.find({
			ownerId: VENDOS_OWNER,
			threadId: VENDOS_THREAD,
			state: "accepted"
		}).sort({ createdAt: -1 }).limit(10).toArray();
		for (const record of accepted) await saveMessage(record.responseMessageId, record.resultText, record.messageId, false);
	}
	async function tick() {
		if (!await lock()) return;
		try {
			if (await options.isBusy()) return;
			const key = await options.getKey();
			if (!key || key.length < 24) return;
			await recoverDraftDecisions(key);
			const pending = await approvals.find({
				state: "pending",
				$or: [{ lastAttemptAt: { $exists: false } }, { lastAttemptAt: { $lt: /* @__PURE__ */ new Date(now().getTime() - 6e4) } }]
			}).sort({ createdAt: 1 }).limit(1).toArray();
			for (const record of pending) {
				if (record.attempts >= 3) {
					await approvals.updateOne({
						_id: record._id,
						state: "pending"
					}, { $set: { state: "attention" } });
					await saveMessage(record.responseMessageId, "Přijetí schválení se nepodařilo spolehlivě ověřit. Opakování je zastavené, aby nevznikly další nejasnosti. Případné výsledky už přijatých akcí se dál zobrazí zde; schválení zatím znovu neposílejte.", record.messageId, false);
					continue;
				}
				try {
					await submitApproval(record, key);
				} catch {
					options.log("vendos_approval_waiting_for_receipt");
				}
			}
			const accepted = await approvals.find({ state: "accepted" }).sort({ createdAt: -1 }).limit(10).toArray();
			for (const record of accepted) await saveMessage(record.responseMessageId, record.resultText, record.messageId, false);
			const unacknowledged = await deliveries.find({ ackedAt: { $exists: false } }).sort({ storedAt: 1 }).limit(1).toArray();
			for (const record of unacknowledged) try {
				await deliver(record.payload, key);
			} catch {
				options.log("vendos_delivery_ack_pending");
			}
			const poll = await rpc("briefing_poll", { project: PROJECT }, key);
			if (poll.thread_id !== VENDOS_THREAD || !Array.isArray(poll.deliveries)) throw new Error("vendos_invalid_poll");
			for (const delivery of poll.deliveries.slice(0, 2)) try {
				await deliver(delivery, key);
			} catch {
				options.log("vendos_delivery_pending");
			}
		} catch (error) {
			options.log(error instanceof Error && error.message.startsWith("vendos_") ? error.message : "vendos_delivery_unavailable");
		} finally {
			await unlock();
		}
	}
	async function handleDraft(request) {
		const { body } = request;
		const rejected = (error, statusCode = 409) => ({
			handled: true,
			decisionType: "draft",
			statusCode,
			error
		});
		let selection;
		try {
			selection = parseDraftApproval(body.text);
		} catch {
			return rejected("Jde o souhlas pouze s obsahem. Napište „Souhlasím se všemi body“ nebo zvolte obsahové body konkrétní verze. Pokyny k provedení neposílejte v téže zprávě.", 400);
		}
		if (request.protocolVersion < 2 || !UUID.test(body.messageId ?? "") || !UUID.test(body.parentMessageId ?? "") || body.messageId !== body.messageId?.toLowerCase() || body.parentMessageId !== body.parentMessageId?.toLowerCase() || body.isRegenerate || body.isEdited || body.isContinued || body.editedContent || body.overrideParentMessageId || body.overrideUserMessageId || body.overrideConvoId || body.responseMessageId || body.recoverySteerId || body.isTemporary || body.files?.length || body.quotes?.length) return rejected("Obsahový souhlas musí být nová zpráva pod aktuální strategií nebo jejími doručenými podrobnostmi.", 400);
		if (!await lock()) return rejected("Právě se aktualizuje souhrn. Vyčkejte na dokončení.");
		try {
			if (((await options.getOwner())?.tenantId ?? "") !== (request.tenantId ?? "")) return rejected("Souhlas nepatří tomuto účtu.", 403);
			const scope = await identity();
			if (!await conversations.findOne(scope) || await options.isBusy()) return rejected("Chat právě dokončuje jinou odpověď.");
			if (await approvals.findOne({ _id: body.messageId })) return rejected("Tuto zprávu nelze použít pro jiný druh souhlasu.");
			const prior = await draftDecisions.findOne({ _id: body.messageId });
			if (prior) {
				if (prior.ownerId !== VENDOS_OWNER || prior.threadId !== VENDOS_THREAD || prior.text !== body.text || prior.parentMessageId !== body.parentMessageId) return rejected("Uložený souhlas nelze změnit.");
				if (prior.state === "accepted") {
					await saveMessage(prior.responseMessageId, prior.resultText, prior.messageId, false);
					return {
						handled: true,
						decisionType: "draft",
						statusCode: 200
					};
				}
				return rejected("Obsahový souhlas už čeká na ověření. Neposílejte jej znovu; potvrzení dorazí do chatu.");
			}
			const [offer, latestMessage, existing] = await Promise.all([
				deliveries.findOne({
					kind: "briefing",
					ackedAt: { $exists: true }
				}, { sort: {
					storedAt: -1,
					_id: -1
				} }),
				messages.findOne(scope, { sort: {
					createdAt: -1,
					_id: -1
				} }),
				messages.findOne({ messageId: body.messageId })
			]);
			if (existing) return rejected("Uloženou nebo importovanou zprávu nelze použít jako nový souhlas.");
			if (!offer || offer.decision_type !== "draft") return rejected("Zde zatím není nový obsahový balík s přesnou verzí a posudkem. Starý souhrn se na obsahové schválení nepřevádí.");
			if (latestMessage?.messageId !== body.parentMessageId) return rejected("Tato větev není aktuální. Otevřete poslední doručenou strategii a její podrobnosti.");
			let targets;
			try {
				targets = resolveDraftTargets(draftBundle(offer), selection, draftPolicy, now().getTime());
			} catch {
				return rejected("Obsahový balík už není platný nebo neodpovídá vybrané verzi. Je potřeba nové zobrazení stejného či opraveného návrhu.");
			}
			const key = await options.getKey();
			if (!key || Buffer.byteLength(key, "utf8") < 32) return rejected("Připojení botů není připravené; obsahový souhlas nebyl potvrzen.", 503);
			const record = {
				_id: body.messageId,
				messageId: body.messageId,
				parentMessageId: body.parentMessageId,
				text: body.text,
				points: targets.map((target) => target.number),
				bundleId: offer.bundle_id,
				bundleHash: offer.bundle_hash,
				sourceMessageId: offer.message_id,
				decisionType: "draft",
				ownerId: VENDOS_OWNER,
				threadId: VENDOS_THREAD,
				state: "pending",
				responseMessageId: (0, node_crypto.randomUUID)(),
				resultText: "",
				createdAt: now(),
				attempts: 0
			};
			const hypothetical = {
				messageId: record.messageId,
				conversationId: VENDOS_THREAD,
				user: VENDOS_OWNER,
				parentMessageId: record.parentMessageId,
				text: record.text,
				content: [{
					type: "text",
					text: record.text
				}],
				isCreatedByUser: true,
				sender: "User",
				endpoint: preset.endpoint,
				model: preset.model,
				unfinished: false,
				isTemporary: false,
				createdAt: now(),
				updatedAt: now()
			};
			try {
				await draftContext(record, hypothetical);
			} catch {
				return rejected("Souhlas musí navazovat na přesně doručenou strategii nebo její nezměněné podrobnosti.");
			}
			await draftDecisions.insertOne(record);
			try {
				await submitDraftDecision(record, key);
			} catch {
				options.log("vendos_draft_decision_waiting_for_receipt");
				return rejected("Obsahový souhlas je zachycený, ale notebook jej zatím nepotvrdil. Neposílejte ho znovu; potvrzení dorazí sem. Žádná změna není tímto souhlasem povolená.", 503);
			}
			return {
				handled: true,
				decisionType: "draft",
				statusCode: 200
			};
		} finally {
			await unlock();
		}
	}
	async function handle(request) {
		const { body } = request;
		if (request.userId !== VENDOS_OWNER || body.conversationId !== VENDOS_THREAD || typeof body.text !== "string") return { handled: false };
		if (isDraftLanguage(body.text)) return handleDraft(request);
		if (isVendosDecisionText(body.text)) {
			const offer = await deliveries.findOne({
				kind: "briefing",
				ackedAt: { $exists: true }
			}, { sort: {
				storedAt: -1,
				_id: -1
			} });
			if (offer && (offer.decision_type === "draft" || offer.items.every((item) => !item.executable))) return handleDraft(request);
		}
		const normalized = body.text.normalize("NFD").replace(/[\u0300-\u036f]/g, "").trim().toLowerCase();
		if (!/^(?:schvaluji|souhlasim)\b/.test(normalized)) return { handled: false };
		const rejected = (error, statusCode = 409) => ({
			handled: true,
			statusCode,
			error
		});
		const points = parseApproval(body.text);
		if (!points) return rejected("Použijte jednoznačnou zprávu, například: „Schvaluji body 1 a 3, proveď je.“ Podmínky a úpravy nejdřív napište zvlášť.", 400);
		if (request.protocolVersion < 2 || !UUID.test(body.messageId ?? "") || !UUID.test(body.parentMessageId ?? "") || body.isRegenerate || body.isEdited || body.isContinued || body.editedContent || body.overrideParentMessageId || body.overrideUserMessageId || body.overrideConvoId || body.responseMessageId || body.recoverySteerId || body.isTemporary || body.files?.length || body.quotes?.length) return rejected("Schválení musí být nová zpráva přímo pod aktuálním souhrnem. Obnovte stránku a odešlete ji znovu.", 400);
		if (!await lock()) return rejected("Právě se aktualizuje souhrn. Vyčkejte chvíli, obnovte chat a zkuste schválení znovu.");
		try {
			if (((await options.getOwner())?.tenantId ?? "") !== (request.tenantId ?? "")) return rejected("Schválení nepatří tomuto účtu.", 403);
			const scope = await identity();
			if (!await conversations.findOne(scope) || await options.isBusy()) return rejected("Chat právě dokončuje jinou odpověď. Počkejte na její dokončení.");
			const prior = await approvals.findOne({ _id: body.messageId });
			if (await draftDecisions.findOne({ _id: body.messageId })) return rejected("Tuto zprávu nelze použít pro jiný druh souhlasu.");
			if (prior) {
				if (prior.text !== body.text || prior.parentMessageId !== body.parentMessageId) return rejected("Tuto zprávu již nelze změnit. Pro změněný návrh je potřeba nové schválení.");
				if (prior.state === "accepted") {
					await saveMessage(prior.responseMessageId, prior.resultText, prior.messageId, false);
					return {
						handled: true,
						statusCode: 200
					};
				}
				return rejected("Toto schválení už bylo přijato k ověření. Neposílejte ho znovu; výsledek dorazí do chatu.");
			}
			const latestBundle = await deliveries.findOne({
				kind: "briefing",
				ackedAt: { $exists: true }
			}, { sort: {
				storedAt: -1,
				_id: -1
			} });
			const source = await messages.findOne({
				...scope,
				messageId: body.parentMessageId,
				isCreatedByUser: false
			});
			const latestMessage = await messages.findOne(scope, { sort: {
				createdAt: -1,
				_id: -1
			} });
			if (!latestBundle || latestBundle.message_id !== body.parentMessageId || source?.text !== latestBundle.body || latestMessage?.messageId !== body.parentMessageId || !latestBundle.expires_at || Date.parse(latestBundle.expires_at) <= now().getTime() || !Number.isFinite(Date.parse(latestBundle.expires_at))) return rejected("Tento souhrn již není aktuální nebo není poslední zprávou. Otevřete nejnovější souhrn a schvalte jeho body.");
			if (points.some((point) => !latestBundle.items.some((item) => item.number === point && item.executable && item.plan_id && item.plan_hash && item.approval_summary))) return rejected("Některý vybraný bod není připravený k provedení. Zkontrolujte čísla a uvedené překážky.", 400);
			if (await messages.findOne({ messageId: body.messageId })) return rejected("Uloženou nebo importovanou zprávu nelze použít jako nové schválení.");
			const key = await options.getKey();
			if (!key || key.length < 24) return rejected("Připojení botů není připravené. Nic se neprovedlo.", 503);
			const record = {
				_id: body.messageId,
				messageId: body.messageId,
				parentMessageId: body.parentMessageId,
				text: body.text,
				points,
				bundleId: latestBundle.bundle_id,
				bundleHash: latestBundle.bundle_hash,
				sourceMessageId: latestBundle.message_id,
				state: "pending",
				responseMessageId: (0, node_crypto.randomUUID)(),
				resultText: "",
				createdAt: now(),
				attempts: 0
			};
			await approvals.insertOne(record);
			try {
				await submitApproval(record, key);
			} catch {
				options.log("vendos_approval_waiting_for_receipt");
			}
			return {
				handled: true,
				statusCode: 200
			};
		} finally {
			await unlock();
		}
	}
	function start() {
		if (timer) return;
		timer = setInterval(() => void tick(), 3e4);
		timer.unref();
		tick();
	}
	function stop() {
		if (timer) {
			clearInterval(timer);
			timer = void 0;
		}
	}
	return {
		start,
		stop,
		tick,
		handle
	};
}
//#endregion
exports.GOOGLE_EMAIL_EXCEPTION_ENV = GOOGLE_EMAIL_EXCEPTION_ENV;
exports.VENDOS_RESTRICTED_COLLECTION = VENDOS_RESTRICTED_COLLECTION;
exports.VENDOS_RESTRICTED_ENDPOINT = VENDOS_RESTRICTED_ENDPOINT;
exports.VENDOS_RESTRICTED_MODEL = VENDOS_RESTRICTED_MODEL;
exports.VENDOS_RESTRICTED_POLICY = VENDOS_RESTRICTED_POLICY;
exports.VENDOS_RESTRICTED_SPEC = VENDOS_RESTRICTED_SPEC;
exports.createVendosBriefing = createVendosBriefing;
exports.createVendosRestrictedChat = createVendosRestrictedChat;
exports.denyVendosRestrictedRemote = denyVendosRestrictedRemote;
exports.enforceVendosRestrictedBody = enforceVendosRestrictedBody;
exports.enforceVendosRestrictedConfig = enforceVendosRestrictedConfig;
exports.isSameGoogleExceptionIdentity = isSameGoogleExceptionIdentity;
exports.isVendosDecisionText = isVendosDecisionText;
exports.isVendosGenerationBusy = isVendosGenerationBusy;
exports.isVendosRestrictedIdentity = isVendosRestrictedIdentity;
exports.isVerifiedGoogleEmailException = isVerifiedGoogleEmailException;
exports.isVerifiedGoogleIdentity = isVerifiedGoogleIdentity;
exports.parseApproval = parseApproval;
exports.sha256 = sha256;
exports.signReceipt = signReceipt;
exports.vendosRestrictedDigest = vendosRestrictedDigest;
exports.vendosRestrictedOverrides = vendosRestrictedOverrides;
exports.verifyVendosRestrictedAccess = verifyVendosRestrictedAccess;

//# sourceMappingURL=vendos.cjs.map