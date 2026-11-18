'use strict';
const { isDeepStrictEqual } = require('node:util');
const core = require('./provision.cjs');

async function rows(collection, query) {
  return collection.find(query).limit(2).toArray();
}

/** Never updates a credential/config row. A raced foreign insert is preserved. */
async function insertOnly(collection, query, document, matches) {
  const before = await rows(collection, query);
  if (before.length) {
    if (before.length === 1 && matches(before[0], document)) return;
    throw new Error('FOREIGN_RECORD_APPEARED_BEFORE_INSERT');
  }
  let inserted = false;
  try {
    await collection.insertOne(document);
    inserted = true;
  } catch (error) {
    if (error.code !== 11000) throw error;
  }
  const after = await rows(collection, query);
  if (after.length === 1 && matches(after[0], document)) return;
  if (inserted) {
    // Delete only this attempt's exact unchanged insert. If UI altered it, preserve it.
    await collection.deleteOne(document);
  }
  throw new Error('CONCURRENT_RECORD_CONFLICT_NOT_OVERWRITTEN');
}

function createStorage(db, ObjectId, encrypt, decrypt) {
  const keys = db.collection('keys');
  const plugins = db.collection('pluginauths');
  const configs = db.collection('configs');
  const keyQuery = (id) => ({ userId: { $in: [new ObjectId(id), id] }, name: core.ENDPOINT });
  const pluginQuery = (id) => ({ userId: id, authField: core.AUTH_FIELD, pluginKey: core.PLUGIN });
  const configQuery = (id) => ({ principalType: 'user', principalId: id });
  const recordId = (kind, id) => new ObjectId(core.hash(`vendos-provision-v3:${kind}:${id}`).slice(0, 24));
  async function one(collection, query, code) {
    const values = await rows(collection, query);
    if (values.length > 1) throw new Error(code);
    return values[0] || null;
  }
  const same = (left, right, fields) => String(left._id) === String(right._id) && fields.every((field) => isDeepStrictEqual(left[field], right[field]));
  return {
    activeConfigs: () => configs.find({ isActive: true }).limit(3).toArray(),
    accessRecords: async (id) => ({
      journal: await db.collection(core.COLLECTION).findOne({ _id: id }),
      activeConfigs: await configs.find({ isActive: true }).limit(3).toArray(),
      keys: await keys.find(keyQuery(id)).limit(3).toArray(),
      plugins: await plugins.find(pluginQuery(id)).limit(3).toArray(),
    }),
    verifyCredentialSnapshot: async (records, companyHash, tokenHash) => {
      try {
        if (records.keys.length !== 1 || records.plugins.length !== 1) throw new Error();
        const model = JSON.parse(await decrypt(records.keys[0].value));
        const token = await decrypt(records.plugins[0].value);
        if (typeof model.apiKey !== 'string' || core.hash(model.apiKey) !== companyHash ||
            typeof token !== 'string' || core.hash(token) !== tokenHash) throw new Error();
      } catch { throw new Error('FINAL_CREDENTIAL_SNAPSHOT_MISMATCH'); }
    },
    modelKey: async (id, optional = false) => {
      const doc = await one(keys, keyQuery(id), 'MODEL_KEY_AMBIGUOUS');
      if (!doc) {
        if (optional) return null;
        throw new Error('CORPORATE_KEY_NOT_CONFIGURED');
      }
      let values;
      try { values = JSON.parse(await decrypt(doc.value)); } catch { throw new Error('MODEL_KEY_FORMAT_INVALID'); }
      if (typeof values?.apiKey !== 'string') throw new Error('MODEL_KEY_FORMAT_INVALID');
      return values.apiKey;
    },
    modelKeyExpiry: async (id) => {
      const doc = await one(keys, keyQuery(id), 'MODEL_KEY_AMBIGUOUS');
      return doc?.expiresAt instanceof Date ? doc.expiresAt.getTime() / 1000 : null;
    },
    saveModelKey: async (id, value, expiresAt) => {
      const document = { _id: recordId('key', id), userId: new ObjectId(id), name: core.ENDPOINT,
        value: await encrypt(JSON.stringify({ apiKey: value })), expiresAt: new Date(expiresAt * 1000) };
      await insertOnly(keys, keyQuery(id), document, (left, right) => same(left, right, ['userId', 'name', 'value', 'expiresAt']));
    },
    pluginToken: async (id) => {
      const doc = await one(plugins, pluginQuery(id), 'PLUGIN_AUTH_AMBIGUOUS');
      return doc ? decrypt(doc.value) : null;
    },
    savePluginToken: async (id, value) => {
      const at = new Date();
      const document = { _id: recordId('plugin', id), userId: id, authField: core.AUTH_FIELD,
        pluginKey: core.PLUGIN, value: await encrypt(value), createdAt: at, updatedAt: at };
      await insertOnly(plugins, pluginQuery(id), document, (left, right) => same(left, right, ['userId', 'authField', 'pluginKey', 'value']));
    },
    userConfig: (id) => one(configs, configQuery(id), 'USER_CONFIG_AMBIGUOUS'),
    saveUserConfig: async (id, overrides) => {
      const at = new Date();
      const document = { _id: recordId('config', id), principalType: 'user', principalId: id,
        principalModel: 'User', priority: 1000, isActive: true, overrides, tombstones: [],
        configVersion: 1, createdAt: at, updatedAt: at };
      await insertOnly(configs, configQuery(id), document, (left, right) => same(left, right, ['principalType', 'principalId', 'principalModel', 'priority', 'isActive', 'overrides', 'tombstones']));
    },
  };
}

module.exports = { createStorage, insertOnly };
