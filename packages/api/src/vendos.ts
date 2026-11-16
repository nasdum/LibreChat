import { createHash, createHmac, randomUUID } from 'node:crypto';
import type { Db } from 'mongodb';
import type { Ancestor, Bundle, Selection, Target, TrustedContext } from './vendos/drafts';
import { buildDraftDecision, parseDraftApproval, resolveDraftTargets } from './vendos/drafts';

const PROJECT = 'vendos-cz';
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const HASH = /^[a-f0-9]{64}$/;
const NO_PARENT = '00000000-0000-0000-0000-000000000000';

interface BriefingItem {
  number: number;
  title: string;
  executable: boolean;
  plan_id: string | null;
  plan_hash: string | null;
  approval_summary: string | null;
  blocker: string | null;
}
export interface Delivery {
  delivery_id: string;
  kind: 'briefing' | 'result';
  bundle_id: string;
  bundle_hash: string;
  message_id: string;
  body: string;
  expires_at: string | null;
  items: BriefingItem[];
  decision_type?: 'draft' | 'execution' | 'legacy';
  payload?: string | null;
}
interface Poll {
  thread_id: string;
  deliveries: Delivery[];
}
interface DeliveryRecord extends Omit<Delivery, 'payload'> {
  _id: string;
  payloadHash: string;
  storedAt: Date;
  ackedAt?: Date;
  payload: Delivery;
}
interface ChatMessage {
  messageId: string;
  conversationId: string;
  user: string;
  tenantId?: string;
  parentMessageId: string;
  text: string;
  content?: { type: 'text'; text: string }[];
  isCreatedByUser: boolean;
  sender: string;
  endpoint: string;
  model: string;
  unfinished: boolean;
  isTemporary: boolean;
  createdAt: Date;
  updatedAt: Date;
}
interface Preset {
  endpoint: string;
  model: string;
  endpointType?: string;
  agent_id?: string;
  promptPrefix?: string;
}
interface Conversation extends Preset {
  conversationId: string;
  user: string;
  tenantId?: string;
  title: string;
  spec: string;
  createdAt: Date;
  updatedAt: Date;
  isArchived: boolean;
  isTemporary: boolean;
}
interface Owner {
  email?: string;
  tenantId?: string;
}
interface ApprovalRecord {
  _id: string;
  messageId: string;
  parentMessageId: string;
  text: string;
  points: number[];
  bundleId: string;
  bundleHash: string;
  sourceMessageId: string;
  state: 'pending' | 'accepted' | 'attention';
  responseMessageId: string;
  resultText: string;
  createdAt: Date;
  acceptedAt?: Date;
  approvalId?: string;
  attempts: number;
  lastAttemptAt?: Date;
}
interface DraftDecisionRecord extends ApprovalRecord {
  decisionType: 'draft';
  ownerId: string;
  threadId: string;
  decisionId?: string;
  approvalReceipt?: string;
  attestedAt?: Date;
}
interface Lease {
  _id: string;
  holder: string;
  until: Date;
}
type MCPArguments = {
  project: string;
  delivery_id?: string;
  message_id?: string;
  approval_receipt?: string;
  bundle_id?: string;
  bundle_hash?: string;
  message_text?: string;
  selected_points?: number[];
};
interface ApprovalResult {
  status: string;
  approval_id?: string;
  decision_id?: string;
  decision?: string;
  execution_allowed?: boolean;
}
interface MCPResult {
  error?: { code?: number; message?: string };
  result?: {
    isError?: boolean;
    content?: { type: string; text?: string }[];
    structuredContent?: Poll | ApprovalResult;
  };
}
export interface MessageRequest {
  userId: string;
  tenantId?: string;
  protocolVersion: number;
  body: {
    conversationId?: string;
    messageId?: string;
    parentMessageId?: string;
    text?: string;
    isRegenerate?: boolean;
    isEdited?: boolean;
    isContinued?: boolean;
    editedContent?: object | null;
    overrideParentMessageId?: string;
    overrideUserMessageId?: string;
    overrideConvoId?: string;
    responseMessageId?: string;
    recoverySteerId?: string;
    isTemporary?: boolean;
    files?: object[];
    quotes?: string[];
  };
}
export interface HandleResult {
  handled: boolean;
  statusCode?: number;
  error?: string;
  decisionType?: 'draft';
}
interface Options {
  db: Db;
  ownerId: string;
  threadId: string;
  ownerEmail: string;
  mcpUrl: string;
  preset: Preset;
  getKey: () => Promise<string | null>;
  getOwner: () => Promise<Owner | null>;
  isBusy: () => Promise<boolean>;
  log: (event: string) => void;
  rpc?: <T>(name: string, args: MCPArguments, key: string) => Promise<T>;
  now?: () => Date;
}

export function sha256(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

export function isVendosDecisionText(text?: string): boolean {
  return (
    typeof text === 'string' &&
    /^(?:schvaluji|souhlasim)\b/.test(
      text
        .normalize('NFD')
        .replace(/[\u0300-\u036f]/g, '')
        .trim()
        .toLowerCase(),
    )
  );
}

export function isVendosGenerationBusy(
  job: { status: string; metadata?: { terminalPersistencePending?: boolean } } | null | undefined,
): boolean {
  return (
    !!job &&
    (job.metadata?.terminalPersistencePending === true ||
      !['complete', 'error', 'aborted'].includes(job.status))
  );
}

function isDraftLanguage(text: string): boolean {
  const normalized = text
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .trim()
    .toLowerCase();
  return /^souhlasim (?:se|s obsahem)\b/.test(normalized);
}

export function parseApproval(text: string): number[] | null {
  if (text.length > 400 || /[\n\r"'`>[\]{}]/.test(text)) {
    return null;
  }
  const normalized = text
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .trim();
  const match =
    /^(?:schvaluji (?:body|bod)|souhlasim s (?:body|bodem)) ([1-9][0-9]?(?:\s*(?:,|a)\s*[1-9][0-9]?)*)\s*,?\s+(?:proved|implementuj)(?:\s+(?:je|to))?\.?$/.exec(
      normalized,
    );
  if (!match) {
    return null;
  }
  const points = match[1].split(/\s*(?:,|a)\s*/).map(Number);
  return points.length <= 20 && new Set(points).size === points.length
    ? points.sort((a, b) => a - b)
    : null;
}

export function signReceipt(payload: object, key: string): string {
  if (key.length < 24) {
    throw new Error('vendos_invalid_key');
  }
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `${body}.${createHmac('sha256', key).update(body).digest('hex')}`;
}

async function callMCP<T>(url: string, name: string, args: MCPArguments, key: string): Promise<T> {
  const headers = {
    'Content-Type': 'application/json',
    Accept: 'application/json, text/event-stream',
    'MCP-Protocol-Version': '2025-03-26',
    Authorization: `Bearer ${key}`,
  };
  const response = await fetch(url, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: randomUUID(),
      method: 'tools/call',
      params: { name, arguments: args },
    }),
    signal: AbortSignal.timeout(20000),
  });
  if (!response.ok) {
    throw new Error(`vendos_mcp_http_${response.status}`);
  }
  const body: MCPResult = await response.json();
  if (body.error || body.result?.isError) {
    throw new Error('vendos_mcp_rejected');
  }
  const result =
    body.result?.structuredContent ??
    body.result?.content?.find((part) => part.type === 'text')?.text;
  if (result == null) {
    throw new Error('vendos_mcp_empty_result');
  }
  return (typeof result === 'string' ? JSON.parse(result) : result) as T;
}

function validDelivery(delivery: Delivery): boolean {
  return (
    !!delivery &&
    typeof delivery.delivery_id === 'string' &&
    delivery.delivery_id.length <= 150 &&
    (delivery.kind === 'briefing' || delivery.kind === 'result') &&
    typeof delivery.bundle_id === 'string' &&
    delivery.bundle_id.length <= 150 &&
    HASH.test(delivery.bundle_hash) &&
    UUID.test(delivery.message_id) &&
    typeof delivery.body === 'string' &&
    delivery.body.length > 0 &&
    delivery.body.length <= 100000 &&
    Array.isArray(delivery.items) &&
    delivery.items.length <= 50 &&
    delivery.items.every(
      (item) =>
        Number.isInteger(item.number) &&
        item.number > 0 &&
        item.number <= 99 &&
        typeof item.executable === 'boolean' &&
        (!item.executable ||
          (typeof item.plan_id === 'string' &&
            /^act-[a-f0-9]{20}$/.test(item.plan_id) &&
            HASH.test(item.plan_hash ?? '') &&
            typeof item.approval_summary === 'string' &&
            item.approval_summary.length > 0 &&
            item.approval_summary.length <= 20000 &&
            delivery.body.includes(item.approval_summary))),
    ) &&
    new Set(delivery.items.map((item) => item.number)).size === delivery.items.length
  );
}

/** Only the authenticated request controller may call handle; no MCP/model hook exposes it. */
export function createVendosBriefing(options: Options) {
  const { db } = options;
  // The MongoDB driver otherwise serializes undefined optional preset fields as
  // null, which the browser's conversation schema rejects before sending a message.
  const preset = Object.fromEntries(
    Object.entries(options.preset).filter(([, value]) => value != null),
  ) as unknown as Preset;
  const { ownerId: VENDOS_OWNER, threadId: VENDOS_THREAD } = options;
  if (!/^[a-f0-9]{24}$/.test(VENDOS_OWNER) || !UUID.test(VENDOS_THREAD) || !options.ownerEmail) {
    throw new Error('vendos_invalid_configuration');
  }
  const messages = db.collection<ChatMessage>('messages');
  const conversations = db.collection<Conversation>('conversations');
  const deliveries = db.collection<DeliveryRecord>('vendos_briefing_deliveries');
  const approvals = db.collection<ApprovalRecord>('vendos_briefing_approvals');
  const draftDecisions = db.collection<DraftDecisionRecord>('vendos_briefing_draft_decisions');
  const leases = db.collection<Lease>('vendos_briefing_leases');
  const now = options.now ?? (() => new Date());
  const rpc =
    options.rpc ??
    (<T>(name: string, args: MCPArguments, key: string) =>
      callMCP<T>(options.mcpUrl, name, args, key));
  const holder = randomUUID();
  const draftPolicy = {
    project: PROJECT,
    owner: `librechat-${VENDOS_OWNER}`,
    thread_id: VENDOS_THREAD,
  };
  let timer: NodeJS.Timeout | undefined;
  let inFlight = false;

  async function identity() {
    const owner = await options.getOwner();
    if (!owner || owner.email?.toLowerCase() !== options.ownerEmail.toLowerCase()) {
      throw new Error('vendos_owner_not_verified');
    }
    return {
      user: VENDOS_OWNER,
      conversationId: VENDOS_THREAD,
      ...(owner.tenantId ? { tenantId: owner.tenantId } : { tenantId: { $exists: false } }),
    };
  }

  async function lock(): Promise<boolean> {
    if (inFlight) {
      return false;
    }
    inFlight = true;
    try {
      const claimed = await leases.findOneAndUpdate(
        { _id: VENDOS_THREAD, $or: [{ until: { $lt: now() } }, { holder }] },
        { $set: { holder, until: new Date(now().getTime() + 120000) } },
        { upsert: true, returnDocument: 'after' },
      );
      const acquired = claimed?.holder === holder;
      if (!acquired) {
        inFlight = false;
      }
      return acquired;
    } catch {
      inFlight = false;
      return false;
    }
  }

  async function unlock() {
    try {
      await leases.updateOne({ _id: VENDOS_THREAD, holder }, { $set: { until: new Date(0) } });
    } catch {
      options.log('vendos_lease_release_pending');
    } finally {
      inFlight = false;
    }
  }

  async function ensureConversation() {
    const scope = await identity();
    const existing = await conversations.findOne(scope);
    if (existing) {
      if (existing.spec !== 'vendos-pilot' || existing.endpoint !== preset.endpoint) {
        throw new Error('vendos_conversation_changed');
      }
      return scope;
    }
    const owner = await options.getOwner();
    await conversations.insertOne({
      conversationId: VENDOS_THREAD,
      user: VENDOS_OWNER,
      ...(owner?.tenantId ? { tenantId: owner.tenantId } : {}),
      title: 'VENDOS — marketing a schvalování',
      spec: 'vendos-pilot',
      ...preset,
      isArchived: false,
      isTemporary: false,
      createdAt: now(),
      updatedAt: now(),
    });
    return scope;
  }

  async function saveMessage(
    messageId: string,
    text: string,
    parentMessageId: string,
    fromUser: boolean,
  ) {
    const scope = await identity();
    const existing = await messages.findOne({ ...scope, messageId });
    if (existing) {
      if (
        existing.text !== text ||
        existing.parentMessageId !== parentMessageId ||
        existing.isCreatedByUser !== fromUser
      ) {
        throw new Error('vendos_message_conflict');
      }
      return;
    }
    if (await messages.findOne({ messageId })) {
      throw new Error('vendos_message_id_owned_elsewhere');
    }
    const owner = await options.getOwner();
    const createdAt = now();
    await messages.insertOne({
      messageId,
      conversationId: VENDOS_THREAD,
      user: VENDOS_OWNER,
      ...(owner?.tenantId ? { tenantId: owner.tenantId } : {}),
      parentMessageId,
      text,
      content: [{ type: 'text', text }],
      isCreatedByUser: fromUser,
      sender: fromUser ? 'User' : 'VENDOS koordinátor',
      endpoint: preset.endpoint,
      model: preset.model,
      unfinished: false,
      isTemporary: false,
      createdAt,
      updatedAt: createdAt,
    });
    await conversations.updateOne(scope, { $set: { updatedAt: now() } });
  }

  async function deliver(delivery: Delivery, key: string) {
    if (!validDelivery(delivery)) {
      throw new Error('vendos_invalid_delivery');
    }
    if (delivery.kind === 'briefing' && delivery.decision_type === 'draft') {
      if (typeof delivery.payload !== 'string' || !delivery.expires_at) {
        throw new Error('vendos_missing_draft_manifest');
      }
      resolveDraftTargets(
        {
          id: delivery.bundle_id,
          project: PROJECT,
          owner: draftPolicy.owner,
          thread_id: VENDOS_THREAD,
          payload: delivery.payload,
          bundle_hash: delivery.bundle_hash,
          source_message_id: delivery.message_id,
          acknowledged_at_ms: now().getTime(),
          expires_at: delivery.expires_at,
        },
        { all: true },
        draftPolicy,
        now().getTime(),
      );
    }
    const scope = await ensureConversation();
    const payloadHash = sha256(JSON.stringify(delivery));
    const existing = await deliveries.findOne({ _id: delivery.delivery_id });
    if (existing && existing.payloadHash !== payloadHash) {
      throw new Error('vendos_delivery_changed');
    }
    const savedMessage = await messages.findOne({
      ...scope,
      messageId: delivery.message_id,
    });
    const latest =
      savedMessage ?? (await messages.findOne(scope, { sort: { createdAt: -1, _id: -1 } }));
    const parent = savedMessage?.parentMessageId ?? latest?.messageId ?? NO_PARENT;
    await saveMessage(delivery.message_id, delivery.body, parent, false);
    await deliveries.updateOne(
      { _id: delivery.delivery_id },
      {
        $setOnInsert: {
          ...delivery,
          payload: delivery,
          payloadHash,
          storedAt: now(),
        },
      },
      { upsert: true },
    );
    const receipt = signReceipt(
      {
        v: 2,
        kind: 'vendos_delivery_ack',
        actor: `librechat-${VENDOS_OWNER}`,
        thread_id: VENDOS_THREAD,
        delivery_id: delivery.delivery_id,
        message_id: delivery.message_id,
        bundle_hash: delivery.bundle_hash,
        nonce: `delivery:${delivery.delivery_id}`,
        issued_at: now().getTime(),
      },
      key,
    );
    await rpc(
      'briefing_ack',
      {
        project: PROJECT,
        delivery_id: delivery.delivery_id,
        message_id: delivery.message_id,
        approval_receipt: receipt,
      },
      key,
    );
    await deliveries.updateOne({ _id: delivery.delivery_id }, { $set: { ackedAt: now() } });
  }

  async function submitApproval(record: ApprovalRecord, key: string) {
    if (await draftDecisions.findOne({ _id: record.messageId })) {
      throw new Error('vendos_cross_type_message_reuse');
    }
    await saveMessage(record.messageId, record.text, record.parentMessageId, true);
    await approvals.updateOne(
      { _id: record._id, state: 'pending' },
      { $inc: { attempts: 1 }, $set: { lastAttemptAt: now() } },
    );
    const receipt = signReceipt(
      {
        v: 2,
        kind: 'vendos_message_approval',
        actor: `librechat-${VENDOS_OWNER}`,
        thread_id: VENDOS_THREAD,
        bundle_id: record.bundleId,
        bundle_hash: record.bundleHash,
        message_id: record.messageId,
        source_message_id: record.sourceMessageId,
        selected_points: record.points,
        message_sha256: sha256(record.text),
        nonce: `message:${record.messageId}`,
        issued_at: now().getTime(),
      },
      key,
    );
    const result = await rpc<ApprovalResult>(
      'briefing_approve',
      {
        project: PROJECT,
        bundle_id: record.bundleId,
        bundle_hash: record.bundleHash,
        message_id: record.messageId,
        message_text: record.text,
        selected_points: record.points,
        approval_receipt: receipt,
      },
      key,
    );
    if (!['accepted', 'already_accepted'].includes(result.status) || !result.approval_id) {
      throw new Error('vendos_approval_not_accepted');
    }
    const resultText = `Přijal jsem schválení bodů ${record.points.join(' a ')}. Boti provedou pouze tyto body v zobrazené verzi. Výsledky jednotlivých kroků dorazí sem; toto potvrzení ještě neznamená dokončení změn.`;
    await approvals.updateOne(
      { _id: record._id, state: 'pending' },
      {
        $set: {
          state: 'accepted',
          approvalId: result.approval_id,
          acceptedAt: now(),
          resultText,
        },
      },
    );
    await saveMessage(record.responseMessageId, resultText, record.messageId, false);
  }

  function draftBundle(record: DeliveryRecord): Bundle {
    if (
      record.decision_type !== 'draft' ||
      typeof record.payload.payload !== 'string' ||
      !record.ackedAt ||
      !record.expires_at
    ) {
      throw new Error('vendos_not_a_draft_offer');
    }
    return {
      id: record.bundle_id,
      project: PROJECT,
      owner: draftPolicy.owner,
      thread_id: VENDOS_THREAD,
      payload: record.payload.payload,
      bundle_hash: record.bundle_hash,
      source_message_id: record.message_id,
      acknowledged_at_ms: record.ackedAt.getTime(),
      expires_at: record.expires_at,
    };
  }

  function exactStoredText(message: ChatMessage, text: string): boolean {
    return (
      message.text === text &&
      Array.isArray(message.content) &&
      message.content.length === 1 &&
      message.content[0].type === 'text' &&
      message.content[0].text === text &&
      message.updatedAt.getTime() === message.createdAt.getTime()
    );
  }

  async function draftContext(
    record: DraftDecisionRecord,
    stored: ChatMessage,
  ): Promise<TrustedContext> {
    const scope = await identity();
    const [offer, latest, source, attached, earlierDecisions] = await Promise.all([
      deliveries.findOne({
        kind: 'briefing',
        bundle_id: record.bundleId,
        message_id: record.sourceMessageId,
      }),
      deliveries.findOne(
        { kind: 'briefing', ackedAt: { $exists: true } },
        { sort: { storedAt: -1, _id: -1 } },
      ),
      messages.findOne({ ...scope, messageId: record.sourceMessageId, isCreatedByUser: false }),
      deliveries.find({ bundle_id: record.bundleId, bundle_hash: record.bundleHash }).toArray(),
      draftDecisions
        .find({
          ownerId: VENDOS_OWNER,
          threadId: VENDOS_THREAD,
          bundleId: record.bundleId,
          bundleHash: record.bundleHash,
          state: 'accepted',
        })
        .limit(100)
        .toArray(),
    ]);
    if (
      !offer ||
      !latest ||
      !source ||
      !exactStoredText(source, offer.body) ||
      offer.bundle_hash !== record.bundleHash
    ) {
      throw new Error('vendos_draft_source_changed');
    }
    const trusted = new Map(attached.map((item) => [item.message_id, item]));
    const earlierMessages = new Map<string, { text: string; parent: string; human: boolean }>(
      earlierDecisions.flatMap(
        (item) =>
          [
            [item.messageId, { text: item.text, parent: item.parentMessageId, human: true }],
            [
              item.responseMessageId,
              { text: item.resultText, parent: item.messageId, human: false },
            ],
          ] as const,
      ),
    );
    const ancestors: Ancestor[] = [];
    const seen = new Set<string>();
    let cursor = stored.parentMessageId;
    for (let depth = 0; depth < 100; depth++) {
      if (seen.has(cursor)) throw new Error('vendos_cyclic_draft_parent');
      seen.add(cursor);
      const journal = trusted.get(cursor);
      const earlier = earlierMessages.get(cursor);
      const ancestor = await messages.findOne({ ...scope, messageId: cursor });
      const trustedDelivery =
        !!journal?.ackedAt &&
        !!ancestor &&
        !ancestor.isCreatedByUser &&
        exactStoredText(ancestor, journal.body);
      const trustedDecision =
        !!earlier &&
        !!ancestor &&
        ancestor.isCreatedByUser === earlier.human &&
        ancestor.parentMessageId === earlier.parent &&
        exactStoredText(ancestor, earlier.text);
      if (!ancestor || (!trustedDelivery && !trustedDecision)) {
        throw new Error('vendos_untrusted_draft_parent');
      }
      ancestors.push({
        message_id: ancestor.messageId,
        thread_id: ancestor.conversationId,
        parent_message_id: ancestor.parentMessageId === NO_PARENT ? null : ancestor.parentMessageId,
        is_created_by_user: ancestor.isCreatedByUser,
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
        created_at_ms: stored.createdAt.getTime(),
      },
      latest_briefing: {
        bundle_id: latest.bundle_id,
        bundle_hash: latest.bundle_hash,
        source_message_id: latest.message_id,
      },
    };
  }

  async function submitDraftDecision(record: DraftDecisionRecord, key: string) {
    const age = now().getTime() - record.createdAt.getTime();
    if (
      record.ownerId !== VENDOS_OWNER ||
      record.threadId !== VENDOS_THREAD ||
      age < -2000 ||
      age > 300000 ||
      (await approvals.findOne({ _id: record.messageId }))
    ) {
      throw new Error('vendos_draft_message_not_fresh_or_reused');
    }
    await saveMessage(record.messageId, record.text, record.parentMessageId, true);
    const scope = await identity();
    const stored = await messages.findOne({
      ...scope,
      messageId: record.messageId,
      isCreatedByUser: true,
    });
    if (
      !stored ||
      !exactStoredText(stored, record.text) ||
      stored.parentMessageId !== record.parentMessageId
    ) {
      throw new Error('vendos_draft_owner_message_changed');
    }
    let receipt = record.approvalReceipt;
    if (!receipt) {
      const decision = buildDraftDecision(await draftContext(record, stored), key, now().getTime());
      if (
        JSON.stringify(decision.endpoint_args.selected_points) !== JSON.stringify(record.points)
      ) {
        throw new Error('vendos_draft_selection_changed');
      }
      receipt = decision.endpoint_args.approval_receipt;
      await draftDecisions.updateOne(
        { _id: record._id, state: 'pending' },
        { $set: { approvalReceipt: receipt, attestedAt: now() } },
      );
    }
    await draftDecisions.updateOne(
      { _id: record._id, state: 'pending' },
      { $inc: { attempts: 1 }, $set: { lastAttemptAt: now() } },
    );
    const result = await rpc<ApprovalResult>(
      'briefing_approve_draft',
      {
        project: PROJECT,
        bundle_id: record.bundleId,
        bundle_hash: record.bundleHash,
        message_id: record.messageId,
        message_text: record.text,
        selected_points: record.points,
        approval_receipt: receipt,
      },
      key,
    );
    if (
      result.status !== 'draft_decision_saved' ||
      result.decision !== 'approve_draft' ||
      typeof result.decision_id !== 'string' ||
      !result.decision_id ||
      result.decision_id.length > 150 ||
      result.execution_allowed !== false
    ) {
      throw new Error('vendos_draft_decision_not_confirmed');
    }
    const resultText = `Uložil jsem váš souhlas s obsahem bodů ${record.points.join(' a ')} této přesné verze strategie. Reklamy, rozesílky, publikování ani firemní úkoly se tím nemění. Případné provedení dostane samostatný konkrétní návrh ke schválení.`;
    await draftDecisions.updateOne(
      { _id: record._id, state: 'pending' },
      {
        $set: { state: 'accepted', decisionId: result.decision_id, acceptedAt: now(), resultText },
      },
    );
    await saveMessage(record.responseMessageId, resultText, record.messageId, false);
  }

  async function recoverDraftDecisions(key: string) {
    const pending = await draftDecisions
      .find({
        ownerId: VENDOS_OWNER,
        threadId: VENDOS_THREAD,
        state: 'pending',
        $or: [
          { lastAttemptAt: { $exists: false } },
          { lastAttemptAt: { $lt: new Date(now().getTime() - 60000) } },
        ],
      })
      .sort({ createdAt: 1 })
      .limit(1)
      .toArray();
    for (const record of pending) {
      if (record.attempts >= 3 || now().getTime() - record.createdAt.getTime() > 300000) {
        await draftDecisions.updateOne(
          { _id: record._id, state: 'pending' },
          { $set: { state: 'attention' } },
        );
        await saveMessage(
          record.responseMessageId,
          'Obsahový souhlas se nepodařilo spolehlivě potvrdit. Automatické opakování je zastavené; je třeba ověřit uložený stav. Žádné oprávnění k provedení změn tím nevzniklo.',
          record.messageId,
          false,
        );
        continue;
      }
      try {
        await submitDraftDecision(record, key);
      } catch {
        options.log('vendos_draft_decision_waiting_for_receipt');
      }
    }
    const accepted = await draftDecisions
      .find({ ownerId: VENDOS_OWNER, threadId: VENDOS_THREAD, state: 'accepted' })
      .sort({ createdAt: -1 })
      .limit(10)
      .toArray();
    for (const record of accepted)
      await saveMessage(record.responseMessageId, record.resultText, record.messageId, false);
  }

  async function tick() {
    if (!(await lock())) {
      return;
    }
    try {
      if (await options.isBusy()) {
        return;
      }
      const key = await options.getKey();
      if (!key || key.length < 24) {
        return;
      }
      await recoverDraftDecisions(key);
      const pending = await approvals
        .find({
          state: 'pending',
          $or: [
            { lastAttemptAt: { $exists: false } },
            { lastAttemptAt: { $lt: new Date(now().getTime() - 60000) } },
          ],
        })
        .sort({ createdAt: 1 })
        .limit(1)
        .toArray();
      for (const record of pending) {
        if (record.attempts >= 3) {
          await approvals.updateOne(
            { _id: record._id, state: 'pending' },
            { $set: { state: 'attention' } },
          );
          await saveMessage(
            record.responseMessageId,
            'Přijetí schválení se nepodařilo spolehlivě ověřit. Opakování je zastavené, aby nevznikly další nejasnosti. Případné výsledky už přijatých akcí se dál zobrazí zde; schválení zatím znovu neposílejte.',
            record.messageId,
            false,
          );
          continue;
        }
        try {
          await submitApproval(record, key);
        } catch {
          options.log('vendos_approval_waiting_for_receipt');
        }
      }
      const accepted = await approvals
        .find({ state: 'accepted' })
        .sort({ createdAt: -1 })
        .limit(10)
        .toArray();
      for (const record of accepted) {
        await saveMessage(record.responseMessageId, record.resultText, record.messageId, false);
      }
      const unacknowledged = await deliveries
        .find({ ackedAt: { $exists: false } })
        .sort({ storedAt: 1 })
        .limit(1)
        .toArray();
      for (const record of unacknowledged) {
        try {
          await deliver(record.payload, key);
        } catch {
          options.log('vendos_delivery_ack_pending');
        }
      }
      const poll = await rpc<Poll>('briefing_poll', { project: PROJECT }, key);
      if (poll.thread_id !== VENDOS_THREAD || !Array.isArray(poll.deliveries)) {
        throw new Error('vendos_invalid_poll');
      }
      for (const delivery of poll.deliveries.slice(0, 2)) {
        try {
          await deliver(delivery, key);
        } catch {
          options.log('vendos_delivery_pending');
        }
      }
    } catch (error) {
      options.log(
        error instanceof Error && error.message.startsWith('vendos_')
          ? error.message
          : 'vendos_delivery_unavailable',
      );
    } finally {
      await unlock();
    }
  }

  async function handleDraft(request: MessageRequest): Promise<HandleResult> {
    const { body } = request;
    const rejected = (error: string, statusCode = 409): HandleResult => ({
      handled: true,
      decisionType: 'draft',
      statusCode,
      error,
    });
    let selection: Selection;
    try {
      selection = parseDraftApproval(body.text);
    } catch {
      return rejected(
        'Jde o souhlas pouze s obsahem. Napište „Souhlasím se všemi body“ nebo zvolte obsahové body konkrétní verze. Pokyny k provedení neposílejte v téže zprávě.',
        400,
      );
    }
    if (
      request.protocolVersion < 2 ||
      !UUID.test(body.messageId ?? '') ||
      !UUID.test(body.parentMessageId ?? '') ||
      body.messageId !== body.messageId?.toLowerCase() ||
      body.parentMessageId !== body.parentMessageId?.toLowerCase() ||
      body.isRegenerate ||
      body.isEdited ||
      body.isContinued ||
      body.editedContent ||
      body.overrideParentMessageId ||
      body.overrideUserMessageId ||
      body.overrideConvoId ||
      body.responseMessageId ||
      body.recoverySteerId ||
      body.isTemporary ||
      body.files?.length ||
      body.quotes?.length
    ) {
      return rejected(
        'Obsahový souhlas musí být nová zpráva pod aktuální strategií nebo jejími doručenými podrobnostmi.',
        400,
      );
    }
    if (!(await lock())) return rejected('Právě se aktualizuje souhrn. Vyčkejte na dokončení.');
    try {
      const owner = await options.getOwner();
      if ((owner?.tenantId ?? '') !== (request.tenantId ?? ''))
        return rejected('Souhlas nepatří tomuto účtu.', 403);
      const scope = await identity();
      if (!(await conversations.findOne(scope)) || (await options.isBusy()))
        return rejected('Chat právě dokončuje jinou odpověď.');
      if (await approvals.findOne({ _id: body.messageId }))
        return rejected('Tuto zprávu nelze použít pro jiný druh souhlasu.');
      const prior = await draftDecisions.findOne({ _id: body.messageId });
      if (prior) {
        if (
          prior.ownerId !== VENDOS_OWNER ||
          prior.threadId !== VENDOS_THREAD ||
          prior.text !== body.text ||
          prior.parentMessageId !== body.parentMessageId
        )
          return rejected('Uložený souhlas nelze změnit.');
        if (prior.state === 'accepted') {
          await saveMessage(prior.responseMessageId, prior.resultText, prior.messageId, false);
          return { handled: true, decisionType: 'draft', statusCode: 200 };
        }
        return rejected(
          'Obsahový souhlas už čeká na ověření. Neposílejte jej znovu; potvrzení dorazí do chatu.',
        );
      }
      const [offer, latestMessage, existing] = await Promise.all([
        deliveries.findOne(
          { kind: 'briefing', ackedAt: { $exists: true } },
          { sort: { storedAt: -1, _id: -1 } },
        ),
        messages.findOne(scope, { sort: { createdAt: -1, _id: -1 } }),
        messages.findOne({ messageId: body.messageId }),
      ]);
      if (existing)
        return rejected('Uloženou nebo importovanou zprávu nelze použít jako nový souhlas.');
      if (!offer || offer.decision_type !== 'draft')
        return rejected(
          'Zde zatím není nový obsahový balík s přesnou verzí a posudkem. Starý souhrn se na obsahové schválení nepřevádí.',
        );
      if (latestMessage?.messageId !== body.parentMessageId)
        return rejected(
          'Tato větev není aktuální. Otevřete poslední doručenou strategii a její podrobnosti.',
        );
      let targets: Target[];
      try {
        targets = resolveDraftTargets(draftBundle(offer), selection, draftPolicy, now().getTime());
      } catch {
        return rejected(
          'Obsahový balík už není platný nebo neodpovídá vybrané verzi. Je potřeba nové zobrazení stejného či opraveného návrhu.',
        );
      }
      const key = await options.getKey();
      if (!key || Buffer.byteLength(key, 'utf8') < 32)
        return rejected('Připojení botů není připravené; obsahový souhlas nebyl potvrzen.', 503);
      const record: DraftDecisionRecord = {
        _id: body.messageId!,
        messageId: body.messageId!,
        parentMessageId: body.parentMessageId!,
        text: body.text!,
        points: targets.map((target) => target.number),
        bundleId: offer.bundle_id,
        bundleHash: offer.bundle_hash,
        sourceMessageId: offer.message_id,
        decisionType: 'draft',
        ownerId: VENDOS_OWNER,
        threadId: VENDOS_THREAD,
        state: 'pending',
        responseMessageId: randomUUID(),
        resultText: '',
        createdAt: now(),
        attempts: 0,
      };
      // Validate the trusted source chain before capturing any owner decision.
      const hypothetical: ChatMessage = {
        messageId: record.messageId,
        conversationId: VENDOS_THREAD,
        user: VENDOS_OWNER,
        parentMessageId: record.parentMessageId,
        text: record.text,
        content: [{ type: 'text', text: record.text }],
        isCreatedByUser: true,
        sender: 'User',
        endpoint: preset.endpoint,
        model: preset.model,
        unfinished: false,
        isTemporary: false,
        createdAt: now(),
        updatedAt: now(),
      };
      try {
        await draftContext(record, hypothetical);
      } catch {
        return rejected(
          'Souhlas musí navazovat na přesně doručenou strategii nebo její nezměněné podrobnosti.',
        );
      }
      await draftDecisions.insertOne(record);
      try {
        await submitDraftDecision(record, key);
      } catch {
        options.log('vendos_draft_decision_waiting_for_receipt');
        return rejected(
          'Obsahový souhlas je zachycený, ale notebook jej zatím nepotvrdil. Neposílejte ho znovu; potvrzení dorazí sem. Žádná změna není tímto souhlasem povolená.',
          503,
        );
      }
      return { handled: true, decisionType: 'draft', statusCode: 200 };
    } finally {
      await unlock();
    }
  }

  async function handle(request: MessageRequest): Promise<HandleResult> {
    const { body } = request;
    if (
      request.userId !== VENDOS_OWNER ||
      body.conversationId !== VENDOS_THREAD ||
      typeof body.text !== 'string'
    ) {
      return { handled: false };
    }
    if (isDraftLanguage(body.text)) return handleDraft(request);
    if (isVendosDecisionText(body.text)) {
      const offer = await deliveries.findOne(
        { kind: 'briefing', ackedAt: { $exists: true } },
        { sort: { storedAt: -1, _id: -1 } },
      );
      if (
        offer &&
        (offer.decision_type === 'draft' || offer.items.every((item) => !item.executable))
      ) {
        return handleDraft(request);
      }
    }
    const normalized = body.text
      .normalize('NFD')
      .replace(/[\u0300-\u036f]/g, '')
      .trim()
      .toLowerCase();
    if (!/^(?:schvaluji|souhlasim)\b/.test(normalized)) {
      return { handled: false };
    }
    const rejected = (error: string, statusCode = 409): HandleResult => ({
      handled: true,
      statusCode,
      error,
    });
    const points = parseApproval(body.text);
    if (!points) {
      return rejected(
        'Použijte jednoznačnou zprávu, například: „Schvaluji body 1 a 3, proveď je.“ Podmínky a úpravy nejdřív napište zvlášť.',
        400,
      );
    }
    if (
      request.protocolVersion < 2 ||
      !UUID.test(body.messageId ?? '') ||
      !UUID.test(body.parentMessageId ?? '') ||
      body.isRegenerate ||
      body.isEdited ||
      body.isContinued ||
      body.editedContent ||
      body.overrideParentMessageId ||
      body.overrideUserMessageId ||
      body.overrideConvoId ||
      body.responseMessageId ||
      body.recoverySteerId ||
      body.isTemporary ||
      body.files?.length ||
      body.quotes?.length
    ) {
      return rejected(
        'Schválení musí být nová zpráva přímo pod aktuálním souhrnem. Obnovte stránku a odešlete ji znovu.',
        400,
      );
    }
    if (!(await lock())) {
      return rejected(
        'Právě se aktualizuje souhrn. Vyčkejte chvíli, obnovte chat a zkuste schválení znovu.',
      );
    }
    try {
      const owner = await options.getOwner();
      if ((owner?.tenantId ?? '') !== (request.tenantId ?? '')) {
        return rejected('Schválení nepatří tomuto účtu.', 403);
      }
      const scope = await identity();
      if (!(await conversations.findOne(scope)) || (await options.isBusy())) {
        return rejected('Chat právě dokončuje jinou odpověď. Počkejte na její dokončení.');
      }
      const prior = await approvals.findOne({ _id: body.messageId });
      if (await draftDecisions.findOne({ _id: body.messageId })) {
        return rejected('Tuto zprávu nelze použít pro jiný druh souhlasu.');
      }
      if (prior) {
        if (prior.text !== body.text || prior.parentMessageId !== body.parentMessageId) {
          return rejected(
            'Tuto zprávu již nelze změnit. Pro změněný návrh je potřeba nové schválení.',
          );
        }
        if (prior.state === 'accepted') {
          await saveMessage(prior.responseMessageId, prior.resultText, prior.messageId, false);
          return { handled: true, statusCode: 200 };
        }
        return rejected(
          'Toto schválení už bylo přijato k ověření. Neposílejte ho znovu; výsledek dorazí do chatu.',
        );
      }
      const latestBundle = await deliveries.findOne(
        { kind: 'briefing', ackedAt: { $exists: true } },
        { sort: { storedAt: -1, _id: -1 } },
      );
      const source = await messages.findOne({
        ...scope,
        messageId: body.parentMessageId,
        isCreatedByUser: false,
      });
      const latestMessage = await messages.findOne(scope, {
        sort: { createdAt: -1, _id: -1 },
      });
      if (
        !latestBundle ||
        latestBundle.message_id !== body.parentMessageId ||
        source?.text !== latestBundle.body ||
        latestMessage?.messageId !== body.parentMessageId ||
        !latestBundle.expires_at ||
        Date.parse(latestBundle.expires_at) <= now().getTime() ||
        !Number.isFinite(Date.parse(latestBundle.expires_at))
      ) {
        return rejected(
          'Tento souhrn již není aktuální nebo není poslední zprávou. Otevřete nejnovější souhrn a schvalte jeho body.',
        );
      }
      if (
        points.some(
          (point) =>
            !latestBundle.items.some(
              (item) =>
                item.number === point &&
                item.executable &&
                item.plan_id &&
                item.plan_hash &&
                item.approval_summary,
            ),
        )
      ) {
        return rejected(
          'Některý vybraný bod není připravený k provedení. Zkontrolujte čísla a uvedené překážky.',
          400,
        );
      }
      if (await messages.findOne({ messageId: body.messageId })) {
        return rejected('Uloženou nebo importovanou zprávu nelze použít jako nové schválení.');
      }
      const key = await options.getKey();
      if (!key || key.length < 24) {
        return rejected('Připojení botů není připravené. Nic se neprovedlo.', 503);
      }
      const record: ApprovalRecord = {
        _id: body.messageId!,
        messageId: body.messageId!,
        parentMessageId: body.parentMessageId!,
        text: body.text,
        points,
        bundleId: latestBundle.bundle_id,
        bundleHash: latestBundle.bundle_hash,
        sourceMessageId: latestBundle.message_id,
        state: 'pending',
        responseMessageId: randomUUID(),
        resultText: '',
        createdAt: now(),
        attempts: 0,
      };
      await approvals.insertOne(record);
      try {
        await submitApproval(record, key);
      } catch {
        options.log('vendos_approval_waiting_for_receipt');
      }
      return { handled: true, statusCode: 200 };
    } finally {
      await unlock();
    }
  }

  function start() {
    if (timer) {
      return;
    }
    timer = setInterval(() => void tick(), 30000);
    timer.unref();
    void tick();
  }
  function stop() {
    if (timer) {
      clearInterval(timer);
      timer = undefined;
    }
  }
  return { start, stop, tick, handle };
}
