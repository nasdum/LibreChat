'use strict';
const { createHash } = require('node:crypto');
const canonical = require('./policy.json');
const POLICY = 'vendos-chat-only-v1';
const overrides = () => structuredClone(canonical);
function digest(value) {
  const stable = (input) => Array.isArray(input) ? input.map(stable) :
    input != null && typeof input === 'object' ? Object.fromEntries(Object.entries(input)
      .sort(([a], [b]) => a.localeCompare(b)).map(([key, val]) => [key, stable(val)])) : input;
  return createHash('sha256').update(JSON.stringify(stable(value))).digest('hex');
}
module.exports = { POLICY, overrides, digest };
