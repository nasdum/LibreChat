import { MongoClient } from 'mongodb';
import assert from 'node:assert/strict';
import { randomUUID, createHmac } from 'node:crypto';
import { MongoMemoryServer } from 'mongodb-memory-server';
import { after, before, beforeEach, test } from 'node:test';
import type { Delivery, MessageRequest } from './vendos';
import { createVendosBriefing, parseApproval, sha256, isVendosGenerationBusy } from './vendos';
import { buildDraftDecision, parseDraftApproval, resolveDraftTargets } from './vendos/drafts';
import golden from './vendos/golden.json';
const VENDOS_OWNER = '111111111111111111111111';
const VENDOS_THREAD = '11111111-1111-4111-8111-111111111111';

let mongo: MongoMemoryServer;
let client: MongoClient;
let clock = new Date('2026-11-16T10:00:00Z');
let queue: Delivery[] = [];
let calls: { name: string; args: object; receipt: object | null }[] = [];
let failApproval = false;
let failAck = false;
let failDraft = false;
let wrongDraftResult = false;
let advancingClock = false;
let clockIncrement = 0;
let jobStatus: string | undefined;
let terminalPersistencePending = false;
const key = 'local-test-key-with-no-production-permissions';
const preset = {
  endpoint: 'VENDOS pilot',
  model: 'claude-sonnet-5-5',
  agent_id: undefined,
  endpointType: undefined,
  promptPrefix: undefined,
};
let service: ReturnType<typeof createVendosBriefing>;

function delivery(): Delivery {
  return {
    delivery_id: `delivery-${randomUUID()}`,
    kind: 'briefing',
    bundle_id: `bundle-${randomUUID()}`,
    bundle_hash: sha256(randomUUID()),
    message_id: randomUUID(),
    body: '1. Místní test 1\n2. Místní test 2\n3. Místní test 3',
    expires_at: '2026-11-17T10:00:00Z',
    items: [1, 2, 3].map((number) => ({
      number,
      title: `Test ${number}`,
      executable: true,
      plan_id: `act-${sha256(String(number)).slice(0, 20)}`,
      plan_hash: sha256(String(number)),
      approval_summary: `Místní test ${number}`,
      blocker: null,
    })),
  };
}
function request(source: Delivery, text = 'Schvaluji body 1 a 3, proveď je.'): MessageRequest {
  return {
    userId: VENDOS_OWNER,
    protocolVersion: 2,
    body: {
      conversationId: VENDOS_THREAD,
      messageId: randomUUID(),
      parentMessageId: source.message_id,
      text,
    },
  };
}
function draftDelivery(): Delivery {
  const id = `brief-${sha256(randomUUID()).slice(0, 20)}`;
  const items = [1, 2, 3].map((number) => ({
    number,
    title: `Obsah ${number}`,
    decision_type: 'draft',
    executable: false,
    plan_id: null,
    plan_hash: null,
    approval_summary: null,
    blocker: 'Content only',
    job_id: 'vnd-0123456789abcdef',
    revision: 4,
    item_key: ['strategy-segment', 'strategy-budget', 'strategy-tests'][number - 1],
    draft_sha256: sha256('synthetic draft'),
    review_sha256: sha256('synthetic review'),
  }));
  const expires_at = '2026-11-17T10:00:00Z';
  const payload = JSON.stringify({
    id,
    project: 'vendos-cz',
    owner: `librechat-${VENDOS_OWNER}`,
    thread_id: VENDOS_THREAD,
    decision_type: 'draft',
    expires_at,
    items,
  });
  return {
    delivery_id: `delivery-${randomUUID()}`,
    kind: 'briefing',
    bundle_id: id,
    bundle_hash: sha256(payload),
    message_id: randomUUID(),
    body: 'Strategie v4. Pouze obsahový souhlas.',
    expires_at,
    decision_type: 'draft',
    payload,
    items,
  };
}
function makeService() {
  return createVendosBriefing({
    db: client.db('vendos_integration'),
    ownerId: VENDOS_OWNER,
    threadId: VENDOS_THREAD,
    ownerEmail: 'owner@example.test',
    mcpUrl: 'http://localhost.invalid/mcp',
    preset,
    getKey: async () => key,
    getOwner: async () => ({ email: 'owner@example.test' }),
    isBusy: async () =>
      isVendosGenerationBusy(
        jobStatus ? { status: jobStatus, metadata: { terminalPersistencePending } } : undefined,
      ),
    now: () => (advancingClock ? new Date(clock.getTime() + clockIncrement++) : clock),
    log: () => {},
    rpc: async <T>(name: string, args: object): Promise<T> => {
      const receipt = 'approval_receipt' in args ? String(args.approval_receipt) : null;
      let payload: object | null = null;
      if (receipt) {
        const [body, signature] = receipt.split('.');
        assert.equal(signature, createHmac('sha256', key).update(body).digest('hex'));
        payload = JSON.parse(Buffer.from(body, 'base64url').toString());
      }
      calls.push({ name, args, receipt: payload });
      if (name === 'briefing_poll') return { thread_id: VENDOS_THREAD, deliveries: queue } as T;
      if (name === 'briefing_ack') {
        if (failAck) throw Error('simulated network failure');
        queue = queue.filter(
          (item) => !('delivery_id' in args) || item.delivery_id !== args.delivery_id,
        );
        return { status: 'delivered' } as T;
      }
      if (name === 'briefing_approve') {
        assert.equal(
          await client
            .db('vendos_integration')
            .collection('messages')
            .countDocuments({
              messageId: 'message_id' in args ? args.message_id : '',
              isCreatedByUser: true,
            }),
          1,
          'a real saved user message must precede attestation',
        );
        if (failApproval) throw Error('ambiguous transport timeout');
        return { status: 'accepted', approval_id: 'test-approval' } as T;
      }
      if (name === 'briefing_approve_draft') {
        const message = await client
          .db('vendos_integration')
          .collection('messages')
          .findOne({
            messageId: 'message_id' in args ? args.message_id : '',
            user: VENDOS_OWNER,
            conversationId: VENDOS_THREAD,
            isCreatedByUser: true,
          });
        assert.ok(message, 'persisted authenticated owner message must precede draft attestation');
        assert.equal(message.text, 'message_text' in args ? args.message_text : null);
        assert.deepEqual(message.content, [{ type: 'text', text: message.text }]);
        assert.equal(message.createdAt.getTime(), message.updatedAt.getTime());
        if (failDraft) throw Error('simulated ambiguous draft receipt');
        return {
          status: 'draft_decision_saved',
          decision: 'approve_draft',
          decision_id: 'fixture-draft-decision',
          execution_allowed: wrongDraftResult,
        } as T;
      }
      throw Error('unexpected mutation');
    },
  });
}

before(async () => {
  mongo = await MongoMemoryServer.create({
    binary: { version: '7.0.14' },
    instance: { ip: '127.0.0.1' },
  });
  client = await MongoClient.connect(mongo.getUri());
});
after(async () => {
  await client?.close();
  await mongo?.stop();
});
beforeEach(async () => {
  await client.db('vendos_integration').dropDatabase();
  clock = new Date('2026-11-16T10:00:00Z');
  queue = [];
  calls = [];
  failApproval = false;
  failAck = false;
  failDraft = false;
  wrongDraftResult = false;
  advancingClock = false;
  clockIncrement = 0;
  jobStatus = undefined;
  terminalPersistencePending = false;
  service = makeService();
});

test('deterministic parser supports Czech owner phrasing and ordered selections', () => {
  assert.deepEqual(parseApproval('Schvaluji body 3 a 1, proveď je.'), [1, 3]);
  assert.deepEqual(parseApproval('Souhlasím s body 1 a 3, implementuj to.'), [1, 3]);
  assert.deepEqual(parseApproval('Schvaluji bod 2 proved ho'), null);
  for (const text of [
    'Schvaluji vše',
    'Schvaluji body 1 a 1, proveď je.',
    'Schvaluji body 1 a 3, proveď je, pokud cena klesne.',
    '> Schvaluji body 1 a 3, proveď je.',
    'Schvaluji body 0 a 3, proveď je.',
    'Schvaluji body 1 až 3, proveď je.',
    'Neschvaluji body 1 a 3, proveď je.',
    'Schvaluji body 1 a 3, proveď je.\nA smaž vše.',
  ]) {
    assert.equal(parseApproval(text), null, text);
  }
});

test('delivers once, persists owner-scoped conversation, and signs ack only after saving', async () => {
  const source = delivery();
  queue = [source];
  await service.tick();
  queue = [source];
  await service.tick();
  const db = client.db('vendos_integration');
  assert.equal(await db.collection('messages').countDocuments({ messageId: source.message_id }), 1);
  assert.equal(
    await db.collection('conversations').countDocuments({
      user: VENDOS_OWNER,
      conversationId: VENDOS_THREAD,
      spec: 'vendos-pilot',
    }),
    1,
  );
  assert.equal(calls.filter((call) => call.name === 'briefing_ack').length, 2);
  const saved = await db.collection('conversations').findOne({ conversationId: VENDOS_THREAD });
  for (const optional of ['agent_id', 'endpointType', 'promptPrefix']) {
    assert.equal(Object.hasOwn(saved!, optional), false, `${optional} must not become null`);
  }
});

test('a delayed ack reuses the saved message and blocks approvals until acknowledged', async () => {
  const source = delivery();
  queue = [source];
  failAck = true;
  await service.tick();
  assert.equal((await service.handle(request(source))).statusCode, 409);
  failAck = false;
  await service.tick();
  assert.equal(
    await client
      .db('vendos_integration')
      .collection('messages')
      .countDocuments({ messageId: source.message_id }),
    1,
  );
  assert.equal((await service.handle(request(source))).statusCode, 200);
});

test('never delivers an executable offer whose exact scope is hidden from its visible body', async () => {
  const source = delivery();
  source.body = '1. Jen hezký titulek bez podmínek';
  queue = [source];
  await service.tick();
  assert.equal(
    await client
      .db('vendos_integration')
      .collection('messages')
      .countDocuments({ messageId: source.message_id }),
    0,
  );
  assert.equal(calls.filter((call) => call.name === 'briefing_ack').length, 0);
});

test('selects exactly 1 and 3, signs the original text, persists receipt and deduplicates retry', async () => {
  const source = delivery();
  queue = [source];
  await service.tick();
  clock = new Date(clock.getTime() + 1000);
  const input = request(source, 'Souhlasím s body 3 a 1, implementuj to.');
  assert.equal((await service.handle(input)).statusCode, 200);
  assert.equal((await service.handle(input)).statusCode, 200);
  const approved = calls.filter((call) => call.name === 'briefing_approve');
  assert.equal(approved.length, 1);
  assert.deepEqual(approved[0].receipt, {
    v: 2,
    kind: 'vendos_message_approval',
    actor: `librechat-${VENDOS_OWNER}`,
    thread_id: VENDOS_THREAD,
    bundle_id: source.bundle_id,
    bundle_hash: source.bundle_hash,
    message_id: input.body.messageId,
    source_message_id: source.message_id,
    selected_points: [1, 3],
    message_sha256: sha256(input.body.text!),
    nonce: `message:${input.body.messageId}`,
    issued_at: clock.getTime(),
  });
  assert.equal(
    await client
      .db('vendos_integration')
      .collection('messages')
      .countDocuments({ isCreatedByUser: true }),
    1,
  );
});

test('other accounts, conversations, and tenant identities cannot authorize the owner plan', async () => {
  const source = delivery();
  queue = [source];
  await service.tick();
  assert.equal((await service.handle({ ...request(source), userId: 'other' })).handled, false);
  const otherChat = request(source);
  otherChat.body.conversationId = randomUUID();
  assert.equal((await service.handle(otherChat)).handled, false);
  assert.equal(
    (await service.handle({ ...request(source), tenantId: 'other-tenant' })).statusCode,
    403,
  );
  assert.equal(calls.filter((call) => call.name === 'briefing_approve').length, 0);
});

test('rejects expired, unavailable or nonexistent selected points without partial approval', async () => {
  const source = delivery();
  source.items[1].executable = false;
  queue = [source];
  await service.tick();
  assert.equal(
    (await service.handle(request(source, 'Schvaluji body 1 a 2, proveď je.'))).statusCode,
    400,
  );
  assert.equal(
    (await service.handle(request(source, 'Schvaluji body 1 a 9, proveď je.'))).statusCode,
    400,
  );
  clock = new Date('2026-11-18T10:00:00Z');
  assert.equal((await service.handle(request(source))).statusCode, 409);
  assert.equal(calls.filter((call) => call.name === 'briefing_approve').length, 0);
});

test('rejects modified assistant text, old bundle and forged parent', async () => {
  const old = delivery();
  queue = [old];
  await service.tick();
  clock = new Date(clock.getTime() + 1000);
  const current = delivery();
  queue = [current];
  await service.tick();
  assert.equal((await service.handle(request(old))).statusCode, 409);
  const forged = request(current);
  forged.body.parentMessageId = randomUUID();
  assert.equal((await service.handle(forged)).statusCode, 409);
  await client
    .db('vendos_integration')
    .collection('messages')
    .updateOne({ messageId: current.message_id }, { $set: { text: 'tampered offer' } });
  assert.equal((await service.handle(request(current))).statusCode, 409);
  assert.equal(calls.filter((call) => call.name === 'briefing_approve').length, 0);
});

test('rejects regeneration, edit, attachments, quote, protocol v1 and imported user messages', async () => {
  const source = delivery();
  queue = [source];
  await service.tick();
  for (const extra of [
    { isRegenerate: true },
    { isContinued: true },
    { editedContent: {} },
    { overrideParentMessageId: randomUUID() },
    { overrideUserMessageId: randomUUID() },
    { responseMessageId: randomUUID() },
    { files: [{}] },
    { quotes: ['approve'] },
  ]) {
    const input = request(source);
    Object.assign(input.body, extra);
    assert.equal((await service.handle(input)).statusCode, 400);
  }
  assert.equal((await service.handle({ ...request(source), protocolVersion: 1 })).statusCode, 400);
  const imported = request(source);
  await client.db('vendos_integration').collection('messages').insertOne({
    messageId: imported.body.messageId,
    user: VENDOS_OWNER,
    conversationId: 'imported-chat',
  });
  assert.equal((await service.handle(imported)).statusCode, 409);
  assert.equal(calls.filter((call) => call.name === 'briefing_approve').length, 0);
});

test('an uncertain acknowledgement is retried with the same authorization identity and bounded attempts', async () => {
  const source = delivery();
  queue = [source];
  await service.tick();
  clock = new Date(clock.getTime() + 1000);
  failApproval = true;
  const input = request(source);
  assert.equal((await service.handle(input)).statusCode, 200);
  for (let index = 0; index < 4; index++) {
    clock = new Date(clock.getTime() + 61000);
    await service.tick();
  }
  const attempts = calls.filter((call) => call.name === 'briefing_approve');
  assert.equal(attempts.length, 3);
  assert.deepEqual(
    attempts.map((item) => (item.receipt && 'nonce' in item.receipt ? item.receipt.nonce : null)),
    Array(3).fill(`message:${input.body.messageId}`),
  );
  assert.equal(
    (
      await client
        .db('vendos_integration')
        .collection('vendos_briefing_approvals')
        .findOne({ messageId: input.body.messageId })
    )?.state,
    'attention',
  );
  const result = { ...delivery(), kind: 'result' as const, items: [] };
  queue = [result];
  await service.tick();
  assert.equal(
    await client
      .db('vendos_integration')
      .collection('messages')
      .countDocuments({ messageId: result.message_id }),
    1,
  );
});

test('crash after remote ack but before local ack bookkeeping does not strand the offer', async () => {
  const source = delivery();
  queue = [source];
  await service.tick();
  await client
    .db('vendos_integration')
    .collection('vendos_briefing_deliveries')
    .updateOne({ delivery_id: source.delivery_id }, { $unset: { ackedAt: '' } });
  assert.equal(queue.length, 0);
  clock = new Date(clock.getTime() + 1000);
  service = makeService();
  await service.tick();
  assert.equal((await service.handle(request(source))).statusCode, 200);
});

test('independent server instances deduplicate simultaneous deliveries and approvals', async () => {
  const source = delivery();
  queue = [source];
  const second = makeService();
  await Promise.all([service.tick(), second.tick()]);
  assert.equal(
    await client
      .db('vendos_integration')
      .collection('messages')
      .countDocuments({ messageId: source.message_id }),
    1,
  );
  clock = new Date(clock.getTime() + 1000);
  const one = request(source);
  const two = request(source);
  const results = await Promise.all([service.handle(one), second.handle(two)]);
  assert.equal(results.filter((result) => result.statusCode === 200).length, 1);
  assert.equal(calls.filter((call) => call.name === 'briefing_approve').length, 1);
});

test('crash recovery finishes a trusted captured approval before signing and still delivers other work', async () => {
  const source = delivery();
  queue = [source];
  await service.tick();
  clock = new Date(clock.getTime() + 1000);
  const input = request(source);
  failApproval = true;
  await service.handle(input);
  const record = await client
    .db('vendos_integration')
    .collection('vendos_briefing_approvals')
    .findOne({ messageId: input.body.messageId });
  assert.ok(record);
  failApproval = false;
  clock = new Date(clock.getTime() + 61000);
  service = makeService();
  await service.tick();
  assert.equal(
    (
      await client
        .db('vendos_integration')
        .collection('vendos_briefing_approvals')
        .findOne({ messageId: input.body.messageId })
    )?.state,
    'accepted',
  );
  assert.equal(
    await client
      .db('vendos_integration')
      .collection('messages')
      .countDocuments({ messageId: record.responseMessageId }),
    1,
  );
});

test('shared Python fixture preserves exact content grammar, targets and receipt bytes', () => {
  const context = {
    policy: golden.policy,
    bundle: golden.bundle,
    message: golden.message,
    ancestors: golden.ancestors,
    latest_briefing: golden.latest_briefing,
  };
  const result = buildDraftDecision(context, golden.synthetic_key, golden.at_ms);
  assert.equal(result.endpoint_args.approval_receipt, golden.expected_receipt);
  assert.deepEqual(result.receipt_payload, golden.expected_receipt_payload);
  for (const text of golden.parser_reject) assert.throws(() => parseDraftApproval(text));
  for (const item of golden.parser_accept) {
    const selection = parseDraftApproval(item.text);
    const targets = resolveDraftTargets(golden.bundle, selection, golden.policy, golden.at_ms);
    assert.deepEqual(
      targets.map((target) => target.number),
      'points' in item ? item.points : [1, 2],
    );
  }
});

test('fresh all-content consent is persisted and sent only to the draft endpoint', async () => {
  const source = draftDelivery();
  queue = [source];
  await service.tick();
  clock = new Date(clock.getTime() + 1000);
  const input = request(source, 'Souhlasím se všemi body');
  assert.equal((await service.handle(input)).statusCode, 200);
  assert.equal((await service.handle(input)).statusCode, 200);
  const drafts = calls.filter((call) => call.name === 'briefing_approve_draft');
  assert.equal(drafts.length, 1);
  assert.deepEqual(drafts[0].receipt, {
    v: 2,
    kind: 'vendos_draft_decision',
    actor: `librechat-${VENDOS_OWNER}`,
    thread_id: VENDOS_THREAD,
    bundle_id: source.bundle_id,
    bundle_hash: source.bundle_hash,
    message_id: input.body.messageId,
    source_message_id: source.message_id,
    selected_points: [1, 2, 3],
    message_sha256: sha256(input.body.text!),
    nonce: `draft-message:${input.body.messageId}`,
    issued_at: clock.getTime(),
  });
  const db = client.db('vendos_integration');
  assert.equal(await db.collection('vendos_briefing_approvals').countDocuments(), 0);
  assert.equal(
    await db.collection('vendos_briefing_draft_decisions').countDocuments({ state: 'accepted' }),
    1,
  );
  assert.equal(calls.filter((call) => call.name === 'briefing_approve').length, 0);
  const response = await db
    .collection('messages')
    .findOne({ parentMessageId: input.body.messageId, isCreatedByUser: false });
  assert.match(response?.text, /souhlas s obsahem/);
  assert.doesNotMatch(response?.text, /Boti provedou|dokončení změn/);
});

test('real millisecond changes do not make server-written messages appear edited', async () => {
  advancingClock = true;
  const source = draftDelivery();
  queue = [source];
  await service.tick();
  const result = await service.handle(request(source, 'Souhlasím se všemi body'));
  assert.equal(result.statusCode, 200);
  assert.equal(calls.filter((call) => call.name === 'briefing_approve_draft').length, 1);
});

test('draft parent can be its acknowledged reviewer attachment, with exact source binding', async () => {
  const source = draftDelivery();
  const detail: Delivery = {
    ...source,
    delivery_id: `delivery-${randomUUID()}`,
    kind: 'result',
    message_id: randomUUID(),
    body: 'Plný posudek této strategie.',
    items: [],
    payload: null,
  };
  queue = [source, detail];
  await service.tick();
  clock = new Date(clock.getTime() + 1000);
  const input = request(detail, 'Souhlasím s obsahem strategie v4, body 3 a 1.');
  assert.equal((await service.handle(input)).statusCode, 200);
  const call = calls.find((item) => item.name === 'briefing_approve_draft');
  assert.ok(
    call?.receipt && 'source_message_id' in call.receipt && 'selected_points' in call.receipt,
  );
  assert.equal(call.receipt.source_message_id, source.message_id);
  assert.deepEqual(call.receipt.selected_points, [1, 3]);
});

test('different subsets can be accepted sequentially through trusted content confirmations', async () => {
  const source = draftDelivery();
  queue = [source];
  await service.tick();
  clock = new Date(clock.getTime() + 1000);
  const first = request(source, 'Souhlasím s obsahem strategie v4, bod 1');
  assert.equal((await service.handle(first)).statusCode, 200);
  const response = await client
    .db('vendos_integration')
    .collection('messages')
    .findOne({ parentMessageId: first.body.messageId });
  assert.ok(response);
  clock = new Date(clock.getTime() + 1000);
  const second = request(source, 'Souhlasím s obsahem strategie v4, bod 2');
  second.body.parentMessageId = response.messageId;
  assert.equal((await service.handle(second)).statusCode, 200);
  assert.equal(calls.filter((call) => call.name === 'briefing_approve_draft').length, 2);
  assert.equal(calls.filter((call) => call.name === 'briefing_approve').length, 0);
});

test('ambiguous advisory consent never recommends execution syntax or falls to a model', async () => {
  const source = draftDelivery();
  queue = [source];
  await service.tick();
  for (const text of [
    'Souhlasím',
    'Schvaluji všechny body',
    'Souhlasím se všemi body, proveď je',
    'Schvaluji body 1 a 3, proveď je',
    'Souhlasím s obsahem strategie v3, bod 1',
  ]) {
    const result = await service.handle(request(source, text));
    assert.equal(result.handled, true);
    assert.ok(result.error);
    assert.doesNotMatch(result.error, /proveď je|Schvaluji body/);
    assert.equal(result.decisionType, 'draft');
  }
  assert.equal(calls.filter((call) => call.name.startsWith('briefing_approve')).length, 0);
  assert.equal(
    await client
      .db('vendos_integration')
      .collection('vendos_briefing_draft_decisions')
      .countDocuments(),
    0,
  );
});

test('legacy advisory content is never retrofitted with an approval manifest', async () => {
  const source = delivery();
  source.items = source.items.map((item) => ({
    ...item,
    executable: false,
    plan_id: null,
    plan_hash: null,
    approval_summary: null,
  }));
  queue = [source];
  await service.tick();
  const result = await service.handle(request(source, 'Souhlasím se všemi body'));
  assert.equal(result.handled, true);
  assert.equal(result.statusCode, 409);
  assert.match(result.error!, /Starý souhrn/);
  assert.equal(calls.filter((call) => call.name.startsWith('briefing_approve')).length, 0);
});

test('mixed or altered draft manifest is not delivered or acknowledged', async () => {
  const source = draftDelivery();
  source.payload = source.payload!.replace('"review_sha256"', '"missing_review_sha256"');
  source.bundle_hash = sha256(source.payload);
  queue = [source];
  await service.tick();
  assert.equal(calls.filter((call) => call.name === 'briefing_ack').length, 0);
  assert.equal(await client.db('vendos_integration').collection('messages').countDocuments(), 0);
});

test('quoted, regenerated, foreign, imported and changed-source draft messages cannot be signed', async () => {
  const source = draftDelivery();
  queue = [source];
  await service.tick();
  for (const extra of [
    { isEdited: true },
    { isRegenerate: true },
    { isContinued: true },
    { quotes: ['approval'] },
    { files: [{}] },
  ]) {
    const input = request(source, 'Souhlasím se všemi body');
    Object.assign(input.body, extra);
    assert.equal((await service.handle(input)).statusCode, 400);
  }
  assert.equal(
    (await service.handle({ ...request(source, 'Souhlasím se všemi body'), userId: 'foreign' }))
      .handled,
    false,
  );
  assert.equal(
    (await service.handle({ ...request(source, 'Souhlasím se všemi body'), tenantId: 'foreign' }))
      .statusCode,
    403,
  );
  const imported = request(source, 'Souhlasím se všemi body');
  await client
    .db('vendos_integration')
    .collection('messages')
    .insertOne({ messageId: imported.body.messageId, user: 'foreign' });
  assert.equal((await service.handle(imported)).statusCode, 409);
  await client
    .db('vendos_integration')
    .collection('messages')
    .updateOne(
      { messageId: source.message_id },
      { $set: { content: [{ type: 'text', text: 'altered hidden content' }] } },
    );
  assert.equal((await service.handle(request(source, 'Souhlasím se všemi body'))).statusCode, 409);
  assert.equal(calls.filter((call) => call.name === 'briefing_approve_draft').length, 0);
});

test('an arbitrary assistant reply is not trusted ancestry for all-content consent', async () => {
  const source = draftDelivery();
  queue = [source];
  await service.tick();
  clock = new Date(clock.getTime() + 1000);
  const otherId = randomUUID();
  await client
    .db('vendos_integration')
    .collection('messages')
    .insertOne({
      messageId: otherId,
      user: VENDOS_OWNER,
      conversationId: VENDOS_THREAD,
      parentMessageId: source.message_id,
      text: 'Other model ideas',
      content: [{ type: 'text', text: 'Other model ideas' }],
      isCreatedByUser: false,
      createdAt: clock,
      updatedAt: clock,
    });
  const input = request(source, 'Souhlasím se všemi body');
  input.body.parentMessageId = otherId;
  assert.equal((await service.handle(input)).statusCode, 409);
  assert.equal(calls.filter((call) => call.name === 'briefing_approve_draft').length, 0);
});

test('lost draft response retries identical signed bytes after restart without execution or false confirmation', async () => {
  const source = draftDelivery();
  queue = [source];
  await service.tick();
  clock = new Date(clock.getTime() + 1000);
  failDraft = true;
  const input = request(source, 'Souhlasím se všemi body');
  const result = await service.handle(input);
  assert.equal(result.statusCode, 503);
  assert.match(result.error!, /zatím nepotvrdil/);
  const db = client.db('vendos_integration');
  assert.equal(
    await db
      .collection('messages')
      .countDocuments({ parentMessageId: input.body.messageId, isCreatedByUser: false }),
    0,
  );
  failDraft = false;
  clock = new Date(clock.getTime() + 61000);
  service = makeService();
  await service.tick();
  const attempts = calls.filter((call) => call.name === 'briefing_approve_draft');
  assert.equal(attempts.length, 2);
  assert.deepEqual(attempts[0].args, attempts[1].args);
  assert.equal(
    await db.collection('vendos_briefing_draft_decisions').countDocuments({ state: 'accepted' }),
    1,
  );
  assert.equal(
    await db
      .collection('messages')
      .countDocuments({ parentMessageId: input.body.messageId, isCreatedByUser: false }),
    1,
  );
  assert.equal(calls.filter((call) => call.name === 'briefing_approve').length, 0);
});

test('draft recovery stops on edited owner message and never refreshes its authority beyond five minutes', async () => {
  const source = draftDelivery();
  queue = [source];
  await service.tick();
  clock = new Date(clock.getTime() + 1000);
  failDraft = true;
  const input = request(source, 'Souhlasím se všemi body');
  await service.handle(input);
  await client
    .db('vendos_integration')
    .collection('messages')
    .updateOne({ messageId: input.body.messageId }, { $set: { text: 'changed owner message' } });
  clock = new Date(clock.getTime() + 61000);
  await service.tick();
  assert.equal(calls.filter((call) => call.name === 'briefing_approve_draft').length, 1);
  clock = new Date(clock.getTime() + 300000);
  await service.tick();
  assert.equal(calls.filter((call) => call.name === 'briefing_approve_draft').length, 1);
  assert.equal(
    await client
      .db('vendos_integration')
      .collection('vendos_briefing_draft_decisions')
      .countDocuments({ state: 'attention' }),
    1,
  );
});

test('only an explicit non-executing notebook result can produce a content confirmation', async () => {
  const source = draftDelivery();
  queue = [source];
  await service.tick();
  clock = new Date(clock.getTime() + 1000);
  wrongDraftResult = true;
  const input = request(source, 'Souhlasím se všemi body');
  assert.equal((await service.handle(input)).statusCode, 503);
  assert.equal(
    await client
      .db('vendos_integration')
      .collection('messages')
      .countDocuments({ parentMessageId: input.body.messageId }),
    0,
  );
  assert.equal(
    await client
      .db('vendos_integration')
      .collection('vendos_briefing_draft_decisions')
      .countDocuments({ state: 'accepted' }),
    0,
  );
});

test('concurrent draft requests are serialized and edited replay cannot change selected content', async () => {
  const source = draftDelivery();
  queue = [source];
  await service.tick();
  clock = new Date(clock.getTime() + 1000);
  const input = request(source, 'Souhlasím se všemi body');
  const results = await Promise.all([service.handle(input), makeService().handle(input)]);
  assert.equal(results.filter((result) => result.statusCode === 200).length, 1);
  assert.equal(calls.filter((call) => call.name === 'briefing_approve_draft').length, 1);
  input.body.text = 'Souhlasím s obsahem strategie v4, bod 1';
  assert.equal((await service.handle(input)).statusCode, 409);
});

test('an execution message ID cannot be reinterpreted for a new draft offer', async () => {
  const execution = delivery();
  queue = [execution];
  await service.tick();
  clock = new Date(clock.getTime() + 1000);
  const approved = request(execution);
  assert.equal((await service.handle(approved)).statusCode, 200);
  clock = new Date(clock.getTime() + 1000);
  const source = draftDelivery();
  queue = [source];
  await service.tick();
  const changed = request(source, 'Souhlasím se všemi body');
  changed.body.messageId = approved.body.messageId;
  assert.equal((await service.handle(changed)).statusCode, 409);
  assert.equal(calls.filter((call) => call.name === 'briefing_approve_draft').length, 0);
});

test('a content message ID cannot be reused later for an execution offer', async () => {
  const source = draftDelivery();
  queue = [source];
  await service.tick();
  clock = new Date(clock.getTime() + 1000);
  const approved = request(source, 'Souhlasím se všemi body');
  assert.equal((await service.handle(approved)).statusCode, 200);
  clock = new Date(clock.getTime() + 1000);
  const execution = delivery();
  queue = [execution];
  await service.tick();
  const changed = request(execution);
  changed.body.messageId = approved.body.messageId;
  assert.equal((await service.handle(changed)).statusCode, 409);
  assert.equal(calls.filter((call) => call.name === 'briefing_approve').length, 0);
});

test('a newer acknowledged draft and an expired draft cannot inherit old content consent', async () => {
  const old = draftDelivery();
  queue = [old];
  await service.tick();
  clock = new Date(clock.getTime() + 1000);
  const current = draftDelivery();
  queue = [current];
  await service.tick();
  assert.equal((await service.handle(request(old, 'Souhlasím se všemi body'))).statusCode, 409);
  clock = new Date('2026-11-18T10:00:00Z');
  assert.equal((await service.handle(request(current, 'Souhlasím se všemi body'))).statusCode, 409);
  assert.equal(calls.filter((call) => call.name === 'briefing_approve_draft').length, 0);
  assert.equal(
    await client
      .db('vendos_integration')
      .collection('vendos_briefing_draft_decisions')
      .countDocuments(),
    0,
  );
});

for (const status of ['complete', 'error', 'aborted']) {
  test(`retained ${status} generation blocks delivery and consent until terminal persistence completes`, async () => {
    const source = draftDelivery();
    queue = [source];
    await service.tick();
    jobStatus = status;
    terminalPersistencePending = true;
    const next = draftDelivery();
    queue = [next];
    await service.tick();
    assert.equal(
      await client
        .db('vendos_integration')
        .collection('messages')
        .countDocuments({ messageId: next.message_id }),
      0,
    );
    assert.equal(
      (await service.handle(request(source, 'Souhlasím se všemi body'))).statusCode,
      409,
    );
    assert.equal(calls.filter((call) => call.name === 'briefing_approve_draft').length, 0);
    assert.equal(
      await client
        .db('vendos_integration')
        .collection('vendos_briefing_draft_decisions')
        .countDocuments(),
      0,
    );
    terminalPersistencePending = false;
    clock = new Date(clock.getTime() + 1000);
    await service.tick();
    assert.equal(
      await client
        .db('vendos_integration')
        .collection('messages')
        .countDocuments({ messageId: next.message_id }),
      1,
    );
    assert.equal((await service.handle(request(next, 'Souhlasím se všemi body'))).statusCode, 200);
  });
  test(`retained ${status} generation permits draft delivery and content consent`, async () => {
    jobStatus = status;
    const source = draftDelivery();
    queue = [source];
    await service.tick();
    clock = new Date(clock.getTime() + 1000);
    assert.equal(
      (await service.handle(request(source, 'Souhlasím se všemi body'))).statusCode,
      200,
    );
    assert.equal(calls.filter((call) => call.name === 'briefing_approve_draft').length, 1);
  });
}
for (const status of ['running', 'requires_action', 'future-unrecognized-state']) {
  test(`active or unknown ${status} generation blocks draft capture`, async () => {
    const source = draftDelivery();
    queue = [source];
    await service.tick();
    jobStatus = status;
    assert.equal(
      (await service.handle(request(source, 'Souhlasím se všemi body'))).statusCode,
      409,
    );
    assert.equal(calls.filter((call) => call.name === 'briefing_approve_draft').length, 0);
    assert.equal(
      await client
        .db('vendos_integration')
        .collection('vendos_briefing_draft_decisions')
        .countDocuments(),
      0,
    );
  });
}
