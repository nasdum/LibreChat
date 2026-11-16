/** Content-only protocol; callers must supply authenticated, persisted message provenance. */
import { createHash, createHmac } from 'node:crypto';

export type Policy = { project: string; owner: string; thread_id: string };
export type Selection = { all: true } | { all: false; revision: number; points: number[] };
export type Bundle = {
  id: string;
  project: string;
  thread_id: string;
  owner: string;
  payload: string;
  bundle_hash: string;
  source_message_id: string;
  acknowledged_at_ms: number;
  expires_at: string;
};
export type Message = {
  message_id: string;
  thread_id: string;
  actor: string;
  is_created_by_user: boolean;
  message_text: string;
  parent_message_id: string;
  created_at_ms: number;
};
export type Ancestor = {
  message_id: string;
  thread_id: string;
  parent_message_id: string | null;
  is_created_by_user: boolean;
};
export type Target = {
  number: number;
  job_id: string;
  revision: number;
  item_key: string;
  draft_sha256: string;
  review_sha256: string;
};
export type TrustedContext = {
  policy: Policy;
  bundle: Bundle;
  message: Message;
  ancestors: Ancestor[];
  latest_briefing: { bundle_id: string; bundle_hash: string; source_message_id: string };
};
interface DraftItem extends Target {
  decision_type: 'draft';
  executable: false;
  plan_id: null;
  plan_hash: null;
  approval_summary: null;
  execution_action?: null;
}
interface DraftPayload {
  id: string;
  project: string;
  thread_id: string;
  owner: string;
  expires_at: string;
  decision_type: 'draft';
  items: DraftItem[];
}

const HASH = /^[0-9a-f]{64}$/;
const JOB_ID = /^vnd-[a-z0-9]{16}$/;
const ITEM_KEY = /^[a-z0-9-]{3,40}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
// The protocol deliberately rejects C0/DEL, without rejecting other Unicode characters.
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f\u007f]/;
const MAX_AGE_MS = 300_000;
export class DraftApprovalError extends Error {}
function fail(reason: string): never {
  throw new DraftApprovalError(reason);
}
function check(condition: boolean, reason: string): asserts condition {
  if (!condition) fail(reason);
}
function text(value: unknown, max = 200): value is string {
  return (
    typeof value === 'string' && value.length > 0 && value.length <= max && !CONTROL.test(value)
  );
}
function integer(value: unknown, min = 1, max = Number.MAX_SAFE_INTEGER): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= min && value <= max;
}
export function sha256(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

/** Only these two exact non-executing Czech sentences are recognized. */
export function parseDraftApproval(raw: unknown): Selection {
  check(text(raw, 500), 'Ambiguous content approval');
  const normalized = raw
    .normalize('NFC')
    .replace(/^ +| +$/g, '')
    .toLowerCase();
  if (/^souhlasím se všemi body\.?$/.test(normalized)) return { all: true };
  const match =
    /^souhlasím s obsahem strategie v([1-9][0-9]*), (?:body|bod) ([1-9][0-9]*(?:(?:, | a )[1-9][0-9]*)*)\.?$/.exec(
      normalized,
    );
  check(match !== null, 'Use an exact content-only approval sentence');
  const revision = Number(match[1]);
  const points = match[2].match(/[0-9]+/g)!.map(Number);
  check(
    integer(revision) &&
      points.length <= 50 &&
      points.every((p) => integer(p, 1, 50)) &&
      new Set(points).size === points.length,
    'Duplicate, unsafe or excessive selection',
  );
  return { all: false, revision, points: points.sort((a, b) => a - b) };
}

function checkPolicy(policy: Policy) {
  check(
    text(policy?.project) &&
      text(policy?.owner) &&
      typeof policy.thread_id === 'string' &&
      UUID.test(policy.thread_id),
    'Invalid trusted policy',
  );
}
function expires(value: unknown): number {
  check(
    typeof value === 'string' && /T.*(?:Z|[+-][0-9]{2}:[0-9]{2})$/.test(value),
    'Expiry requires explicit timezone',
  );
  const at = Date.parse(value);
  check(Number.isFinite(at), 'Invalid expiry');
  return at;
}

/** Resolve exclusively from the raw immutable payload received by authenticated notebook poll.
 * UI text, parsed Markdown, user-supplied metadata and reconstructed JSON are not sources.
 */
export function resolveDraftTargets(
  bundle: Bundle,
  selection: Selection,
  policy: Policy,
  nowMs: number,
): Target[] {
  checkPolicy(policy);
  check(integer(nowMs), 'Invalid server clock');
  check(
    bundle &&
      text(bundle.id) &&
      bundle.project === policy.project &&
      bundle.owner === policy.owner &&
      bundle.thread_id === policy.thread_id,
    'Wrong private bundle owner or conversation',
  );
  check(
    typeof bundle.payload === 'string' &&
      bundle.payload.length <= 2_000_000 &&
      typeof bundle.bundle_hash === 'string' &&
      HASH.test(bundle.bundle_hash) &&
      sha256(bundle.payload) === bundle.bundle_hash,
    'Immutable bundle hash mismatch',
  );
  let payload: DraftPayload;
  try {
    payload = JSON.parse(bundle.payload) as DraftPayload;
  } catch {
    return fail('Invalid immutable bundle JSON');
  }
  check(
    payload !== null && typeof payload === 'object' && !Array.isArray(payload),
    'Invalid immutable bundle object',
  );
  check(
    payload.id === bundle.id &&
      payload.project === policy.project &&
      payload.owner === policy.owner &&
      payload.thread_id === policy.thread_id &&
      payload.expires_at === bundle.expires_at &&
      payload.decision_type === 'draft',
    'Bundle is not an exact advisory draft offer',
  );
  check(expires(bundle.expires_at) > nowMs, 'Draft offer expired');
  check(
    typeof bundle.source_message_id === 'string' &&
      UUID.test(bundle.source_message_id) &&
      integer(bundle.acknowledged_at_ms) &&
      bundle.acknowledged_at_ms <= nowMs + 2_000,
    'The exact source has no valid delivery acknowledgement',
  );
  check(
    Array.isArray(payload.items) && payload.items.length > 0 && payload.items.length <= 50,
    'Invalid advisory manifest',
  );
  const identities = new Set<string>();
  const targets = payload.items.map((value, i): Target => {
    check(
      value !== null && typeof value === 'object' && !Array.isArray(value),
      'Invalid manifest item',
    );
    const item = value;
    check(
      item.number === i + 1 &&
        item.decision_type === 'draft' &&
        item.executable === false &&
        item.plan_id === null &&
        item.plan_hash === null &&
        item.approval_summary === null &&
        (item.execution_action === undefined || item.execution_action === null),
      'Mixed or executable bundle is not a draft decision',
    );
    check(
      typeof item.job_id === 'string' &&
        JOB_ID.test(item.job_id) &&
        integer(item.revision) &&
        typeof item.item_key === 'string' &&
        ITEM_KEY.test(item.item_key) &&
        typeof item.draft_sha256 === 'string' &&
        HASH.test(item.draft_sha256) &&
        typeof item.review_sha256 === 'string' &&
        HASH.test(item.review_sha256),
      'Missing exact draft/review metadata',
    );
    const identity = JSON.stringify([item.job_id, item.revision, item.item_key]);
    check(!identities.has(identity), 'Duplicate target identity');
    identities.add(identity);
    return Object.freeze({
      number: item.number,
      job_id: item.job_id,
      revision: item.revision,
      item_key: item.item_key,
      draft_sha256: item.draft_sha256,
      review_sha256: item.review_sha256,
    });
  });
  check(selection && (selection.all === true || selection.all === false), 'Invalid selection');
  if (selection.all) return targets;
  check(
    integer(selection.revision) &&
      Array.isArray(selection.points) &&
      selection.points.length > 0 &&
      selection.points.length <= 50 &&
      selection.points.every(
        (p, i) => integer(p, 1, targets.length) && (i === 0 || p > selection.points[i - 1]),
      ),
    'Selection must be sorted, unique and present',
  );
  const chosen = selection.points.map((p) => targets[p - 1]);
  check(
    chosen.every((target) => target.revision === selection.revision),
    'Explicit revision does not match every selected target',
  );
  return chosen;
}

function checkAncestry(context: TrustedContext) {
  const { policy, bundle, message, ancestors } = context;
  check(
    Array.isArray(ancestors) && ancestors.length > 0 && ancestors.length <= 100,
    'Missing trusted ancestry',
  );
  const nodes = new Map<string, Ancestor>();
  for (const node of ancestors) {
    check(
      node &&
        typeof node.message_id === 'string' &&
        UUID.test(node.message_id) &&
        node.thread_id === policy.thread_id &&
        typeof node.is_created_by_user === 'boolean' &&
        (node.parent_message_id === null ||
          (typeof node.parent_message_id === 'string' && UUID.test(node.parent_message_id))) &&
        !nodes.has(node.message_id) &&
        node.message_id !== message.message_id,
      'Invalid trusted ancestor',
    );
    nodes.set(node.message_id, node);
  }
  let cursor: string | null = message.parent_message_id;
  const seen = new Set<string>();
  while (cursor !== null) {
    check(!seen.has(cursor), 'Cyclic message ancestry');
    seen.add(cursor);
    const node = nodes.get(cursor);
    check(node !== undefined, 'Source is not on the persisted parent chain');
    if (node.message_id === bundle.source_message_id) {
      check(node.is_created_by_user === false, 'Source delivery cannot be a human message');
      return;
    }
    cursor = node.parent_message_id;
  }
  fail('No ancestor binds this owner message to the exact delivered bundle');
}

/** The adapter must supply reread persisted/authenticated records, never model or body fields.
 * This signs a CONTENT DECISION ONLY; no execution parser or executor is called.
 */
export function buildDraftDecision(context: TrustedContext, serverKey: string, nowMs: number) {
  check(
    !!(context && context.message && context.latest_briefing),
    'Missing trusted decision context',
  );
  const { policy, bundle, message, latest_briefing: latest } = context;
  checkPolicy(policy);
  check(
    integer(nowMs) && typeof serverKey === 'string' && Buffer.byteLength(serverKey, 'utf8') >= 32,
    'Invalid server clock or signing key',
  );
  check(
    message.actor === policy.owner &&
      message.thread_id === policy.thread_id &&
      message.is_created_by_user === true &&
      typeof message.message_id === 'string' &&
      UUID.test(message.message_id) &&
      typeof message.parent_message_id === 'string' &&
      UUID.test(message.parent_message_id),
    'Only the persisted authenticated owner message may authorize a content decision',
  );
  check(
    integer(message.created_at_ms) &&
      nowMs - message.created_at_ms >= -2_000 &&
      nowMs - message.created_at_ms <= MAX_AGE_MS,
    'Owner message is not fresh',
  );
  const selection = parseDraftApproval(message.message_text);
  const targets = resolveDraftTargets(bundle, selection, policy, nowMs);
  check(
    latest.bundle_id === bundle.id &&
      latest.bundle_hash === bundle.bundle_hash &&
      latest.source_message_id === bundle.source_message_id,
    'A newer or conflicting acknowledged briefing exists',
  );
  check(
    message.message_id !== bundle.source_message_id &&
      message.created_at_ms >= bundle.acknowledged_at_ms,
    'Owner message predates the acknowledged offer',
  );
  checkAncestry(context);
  const selected = targets.map((target) => target.number);
  // Insertion order is intentionally fixed for the shared Python/TypeScript golden fixture.
  // Python verifies HMAC over the ORIGINAL base64url body, without reserializing JSON.
  const receiptPayload = {
    v: 2,
    kind: 'vendos_draft_decision',
    actor: policy.owner,
    thread_id: policy.thread_id,
    bundle_id: bundle.id,
    bundle_hash: bundle.bundle_hash,
    message_id: message.message_id,
    source_message_id: bundle.source_message_id,
    selected_points: selected,
    message_sha256: sha256(message.message_text),
    nonce: 'draft-message:' + message.message_id,
    issued_at: nowMs,
  };
  const body = Buffer.from(JSON.stringify(receiptPayload), 'utf8').toString('base64url');
  const receipt = body + '.' + createHmac('sha256', serverKey).update(body, 'utf8').digest('hex');
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
      approval_receipt: receipt,
    },
  };
}
