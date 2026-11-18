'use strict';
/** Load only inside the existing LibreChat container. No model/HTTP calls or account bootstrap. */
const fs = require('node:fs');
const { createRequire } = require('node:module');
const core = require('./provision.cjs');
const { createStorage } = require('./mongo-storage.cjs');

function disableFileLogging() {
  // Must precede every application import: constructing Winston transports can create files.
  process.env.LOG_TO_FILE = 'false';
  process.env.DEBUG_LOGGING = 'false';
  process.env.DEBUG_CONSOLE = 'false';
}

async function connect(request) {
  if (process.cwd() !== '/app') throw new Error('EXPECTED_LIBRECHAT_APP_ROOT');
  disableFileLogging();
  const appRequire = createRequire('/app/package.json');
  const apiFile = appRequire.resolve('@librechat/api/vendos');
  if (fs.realpathSync(apiFile) !== apiFile || !apiFile.startsWith('/app/')) throw new Error('UNEXPECTED_BUNDLE_PATH');
  if (core.hash(fs.readFileSync(apiFile)) !== request.expected_vendos_bundle_sha256) throw new Error('RUNTIME_BUNDLE_DRIFT');
  const fence = appRequire('@librechat/api/vendos');
  const policy = require('./policy.cjs');
  if (fence.VENDOS_RESTRICTED_POLICY !== policy.POLICY || fence.VENDOS_RESTRICTED_COLLECTION !== core.COLLECTION || fence.vendosRestrictedDigest(core.consultationOverrides()) !== fence.vendosRestrictedDigest(fence.vendosRestrictedOverrides())) throw new Error('LIVE_CANONICAL_POLICY_MISMATCH');
  const schema = appRequire('@librechat/data-schemas');
  schema.logger.silent = true;
  const api = appRequire('@librechat/api');
  if (typeof api.encrypt !== 'function' || typeof api.decrypt !== 'function') throw new Error('ENCRYPTION_HELPERS_UNAVAILABLE');
  const { MongoClient, ObjectId } = appRequire('mongodb');
  const yaml = appRequire('js-yaml');
  if (!process.env.MONGO_URI) throw new Error('MONGO_CONNECTION_UNAVAILABLE');
  const configPath = process.env.CONFIG_PATH || '/app/librechat.yaml';
  if (configPath !== '/app/librechat.yaml' || fs.realpathSync(configPath) !== configPath) throw new Error('LOCAL_CONFIG_PATH_REQUIRES_REVIEW');
  const client = new MongoClient(process.env.MONGO_URI, { maxPoolSize: 2 });
  await client.connect();
  const db = client.db();
  const journal = db.collection(core.COLLECTION);
  const oldJournals = ['vendos_colleague_provisions', 'vendos_colleague_provisions_v2'].map((name) => db.collection(name));
  const users = db.collection('users');
  const projection = { email: 1, provider: 1, emailVerified: 1, googleId: 1, role: 1, tenantId: 1 };
  const storage = createStorage(db, ObjectId, api.encrypt, api.decrypt);
  return {
    ...storage,
    now: () => Date.now(),
    verifyAccess: (user, records) => fence.verifyVendosRestrictedAccess(user, records, Date.now()),
    ownerId: async () => process.env.VENDOS_BRIEFING_OWNER_ID,
    bundleHash: async () => core.hash(fs.readFileSync(apiFile)),
    user: (id) => users.findOne({ _id: new ObjectId(id) }, { projection }),
    usersByEmailHash: async (emailHash) => {
      const candidates = await users.find({ provider: 'google', emailVerified: true }, { projection }).limit(1001).toArray();
      if (candidates.length > 1000) throw new Error('USER_LOOKUP_REQUIRES_NARROWER_PRIVATE_QUERY');
      return candidates.filter((user) => core.normalizedEmailHash(user.email) === emailHash);
    },
    baseConfig: async () => {
      // Parse only the local approved YAML. No getAppConfig cache, seeding, index creation or URL loader.
      const value = yaml.load(fs.readFileSync(configPath, 'utf8'));
      if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('INVALID_LOCAL_CONFIGURATION');
      return value;
    },
    // A standalone process cannot invalidate the live server's forced in-memory config cache.
    // Public result explicitly waits for the 60s TTL plus margin and requires actual-user readback.
    invalidateCaches: async () => {},
    encrypt: api.encrypt,
    decrypt: api.decrypt,
    journal: async (id) => {
      for (const oldJournal of oldJournals) if (await oldJournal.findOne({ _id: id }, { projection: { _id: 1 } })) throw new Error('LEGACY_PROVISION_STATE_REQUIRES_REVIEW');
      return journal.findOne({ _id: id });
    },
    insertJournal: async (value) => {
      try { await journal.insertOne(value); } catch (error) { if (error.code !== 11000) throw error; }
    },
    acquire: async (id, lease, at) => Boolean(await journal.findOneAndUpdate(
      { _id: id, $or: [{ lease_id: { $exists: false } }, { lease_until: { $lte: at } }] },
      { $set: { lease_id: lease, lease_until: at + 120000 } }, { returnDocument: 'after' },
    )),
    renew: async (id, lease, at) => (await journal.updateOne(
      { _id: id, lease_id: lease, lease_until: { $gt: at } }, { $set: { lease_until: at + 120000 } },
    )).matchedCount === 1,
    complete: async (id, lease, at, fields) => {
      const result = await journal.updateOne({ _id: id, lease_id: lease, lease_until: { $gt: at } },
        { $set: { ...fields, state: 'prepared', verified_at: new Date(at).toISOString() } });
      if (result.matchedCount !== 1) throw new Error('PROVISION_LEASE_LOST');
    },
    release: async (id, lease) => { await journal.updateOne({ _id: id, lease_id: lease }, { $unset: { lease_id: '', lease_until: '' } }); },
    close: () => client.close(),
  };
}

module.exports = { connect, disableFileLogging };
