import { MongoClient } from 'mongodb';
import assert from 'node:assert/strict';
import { randomUUID, createHmac } from 'node:crypto';
import { MongoMemoryServer } from 'mongodb-memory-server';
import { after, before, beforeEach, test } from 'node:test';
import type { Delivery, MessageRequest } from './vendos';
import { createVendosBriefing, parseApproval, sha256 } from './vendos';
const VENDOS_OWNER = '111111111111111111111111';
const VENDOS_THREAD = '11111111-1111-4111-8111-111111111111';

let mongo: MongoMemoryServer;
let client: MongoClient;
let clock = new Date('2026-11-16T10:00:00Z');
let queue: Delivery[] = [];
let calls: { name: string; args: object; receipt: object | null }[] = [];
let failApproval = false;
let failAck = false;
const key = 'local-test-key-with-no-production-permissions';
const preset = { endpoint: 'VENDOS pilot', model: 'claude-sonnet-5-5' };
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
    isBusy: async () => false,
    now: () => clock,
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
