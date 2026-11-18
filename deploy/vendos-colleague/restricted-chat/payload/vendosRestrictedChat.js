const mongoose = require('mongoose');
const { GenerationJobManager } = require('@librechat/api');
const { createVendosRestrictedChat, VENDOS_RESTRICTED_COLLECTION } = require('@librechat/api/vendos');
const optionalJwtAuth = require('./optionalJwtAuth');

const limited = (collection, query, projection) => mongoose.connection.db.collection(collection)
  .find(query, projection ? { projection } : {}).limit(3).toArray();

module.exports = createVendosRestrictedChat({
  authenticate: optionalJwtAuth,
  provision: async (id) => {
    const db = mongoose.connection.db;
    const [journal, activeConfigs, keys, plugins] = await Promise.all([
      db.collection(VENDOS_RESTRICTED_COLLECTION).findOne({ _id: id }, { projection: { token_ciphertext: 0 } }),
      limited('configs', { isActive: true }),
      limited('keys', { userId: { $in: [id, new mongoose.Types.ObjectId(id)] }, name: 'VENDOS pilot' }),
      limited('pluginauths', { userId: id, pluginKey: 'mcp_vendos_pilot', authField: 'VENDOS_PILOT_KEY' }),
    ]);
    return { journal, activeConfigs, keys, plugins };
  },
  conversation: (id) => mongoose.connection.db.collection('conversations').findOne({ conversationId: id }),
  conversations: (id) => mongoose.connection.db.collection('conversations').find({ user: id, endpoint: 'VENDOS pilot', model: 'claude-sonnet-5-5', spec: 'vendos-consultation', isTemporary: { $ne: true } }, { projection: { _id: 0, __v: 0 } }).sort({ updatedAt: -1 }).limit(100).toArray(),
  generation: (id) => GenerationJobManager.getJob(id),
  generations: async (id) => {
    const ids = await GenerationJobManager.getActiveJobIdsForUser(id);
    return (await Promise.all(ids.map((streamId) => GenerationJobManager.getJob(streamId))))
      .filter(Boolean);
  },
});
