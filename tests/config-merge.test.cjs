'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const ts = require('typescript');
const { test } = require('node:test');
const api = require('../payload/vendos.cjs');
const repo = path.resolve(__dirname, '../../../content-approval-20261116/librechat-current');

test('actual LibreChat merge implementation replaces spec list and preserves canonical required fields', () => {
  const configSource = fs.readFileSync(path.join(repo, 'packages/data-provider/src/config.ts'), 'utf8');
  assert.ok(configSource.includes('BASE_ONLY_CONFIG_SECTIONS = [] as const'));
  assert.ok(configSource.includes("BASE_PRINCIPAL_CONFIG_SECTIONS = ['langfuse'] as const"));
  const source = fs.readFileSync(path.join(repo, 'packages/data-schemas/src/app/resolution.ts'), 'utf8');
  const compiled = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText;
  const module = { exports: {} };
  vm.runInNewContext(`(function(require,module,exports){${compiled}\n})`, {})(
    (name) => {
      if (name === 'librechat-data-provider') return { BASE_ONLY_CONFIG_SECTIONS: [], BASE_PRINCIPAL_CONFIG_SECTIONS: ['langfuse'], INTERFACE_PERMISSION_FIELDS: new Set(), PERMISSION_SUB_KEYS: new Set() };
      if (name === '~/admin/capabilities') return { BASE_CONFIG_PRINCIPAL_ID: 'synthetic-base-unused' };
      throw new Error(`Unexpected runtime dependency ${name}`);
    }, module, module.exports,
  );
  const canonical = api.vendosRestrictedOverrides();
  const base = { modelSpecs: { enforce: false, prioritize: false, addedEndpoints: ['unrelated'], list: [{ name: 'old-base-spec', preset: { endpoint: 'other' } }] } };
  const merged = module.exports.mergeConfigOverrides(base, [{ principalId: 'synthetic-user', priority: 1000, tombstones: [], overrides: canonical }]);
  for (const [key, value] of Object.entries(canonical.modelSpecs)) assert.deepEqual(merged.modelSpecs[key], value);
  assert.deepEqual(merged.modelSpecs.addedEndpoints, ['unrelated']);
  assert.equal(merged.modelSpecs.list.length, 1);
  assert.equal(merged.modelSpecs.list[0].name, 'vendos-consultation');
  // The real service calls this exact pure merge after getApplicableConfigs, without parsing specs again.
  const service = fs.readFileSync(path.join(repo, 'packages/api/src/app/service.ts'), 'utf8');
  assert.ok(service.includes('const merged = mergeConfigOverrides(baseConfig, configs);'));
  assert.ok(service.includes('return merged;'));
});
