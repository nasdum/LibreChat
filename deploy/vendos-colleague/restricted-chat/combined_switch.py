"""Reviewed restricted-chat overlay and two OAuth env values in one controlled cutover."""
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal

ROOT = Path(__file__).resolve().parent
OAUTH_SHA = 'e4c009ab6b906545fe1305923b7ca130e0e3fc4516e1b17aea10c57bdf0ad031'
if hashlib.sha256((ROOT / 'oauth_switch.py').read_bytes()).hexdigest() != OAUTH_SHA:
    raise RuntimeError('OAUTH_HELPER_CHANGED')
spec = importlib.util.spec_from_file_location('combined_oauth', ROOT / 'oauth_switch.py')
oauth = importlib.util.module_from_spec(spec); spec.loader.exec_module(oauth)
base = oauth.base
validate_pause = oauth.validate_pause
BACKUP_ROOT = Path('/var/backups/librechat-vendos-restricted-chat')
TARGETS = {
    'socialLogin.js': '/app/api/strategies/socialLogin.js',
    'checkDomainAllowed.js': '/app/api/server/middleware/checkDomainAllowed.js',
    'server-index.js': '/app/api/server/index.js',
    'buildEndpointOption.js': '/app/api/server/middleware/buildEndpointOption.js',
    'config-app.js': '/app/api/server/middleware/config/app.js',
    'agents-middleware.js': '/app/api/server/routes/agents/middleware.js',
    'vendosRestrictedChat.js': '/app/api/server/middleware/vendosRestrictedChat.js',
    'vendos.cjs': '/app/packages/api/dist/vendos.cjs',
    'vendos.cjs.map': '/app/packages/api/dist/vendos.cjs.map',
}
PATHS = {path.removeprefix('/app/'): path for path in {*base.PATHS.values(), *TARGETS.values()}}
NEW_PATH = 'api/server/middleware/vendosRestrictedChat.js'

FILES_JS = r"""
const fs=require('node:fs'),crypto=require('node:crypto'),paths=JSON.parse(process.argv[1]),out={};
for(const [name,path] of Object.entries(paths)){
 try {const s=fs.lstatSync(path);
  if(!s.isFile()||s.isSymbolicLink()||s.size>16000000||fs.realpathSync(path)!==path)process.exit(31);
  out[name]={exists:true,sha256:crypto.createHash('sha256').update(fs.readFileSync(path)).digest('hex'),
   size:s.size,uid:s.uid,gid:s.gid,mode:s.mode&511};
 }catch(e){if(e.code==='ENOENT')out[name]={exists:false};else process.exit(31);}
}process.stdout.write(JSON.stringify(out));
"""
CONFIG_JS = r"""
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),mongoose=require('mongoose');
const client=new mongoose.mongo.MongoClient(process.env.MONGO_URI,{serverSelectionTimeoutMS:5000,connectTimeoutMS:5000,socketTimeoutMS:7000});
(async()=>{try{const p=process.env.CONFIG_PATH||'/app/librechat.yaml';if(/^https?:/i.test(p))throw Error();
 const raw=fs.readFileSync(path.resolve('/app',p));if(raw.length>2097152)throw Error();
 await client.connect();const db=client.db();if(db.databaseName!=='LibreChat')throw Error();
 const active=!!await db.collection('configs').findOne({isActive:true},{projection:{_id:1},maxTimeMS:5000});
 process.stdout.write(JSON.stringify({sha256:crypto.createHash('sha256').update(raw).digest('hex'),active,
  openai_moderation_disabled:String(process.env.OPENAI_MODERATION||'').trim().toLowerCase()!=='true'}));
}catch{process.exitCode=41;}finally{await client.close();}})();
"""
FENCE_PROBE_JS = r"""
const m=require('/app/packages/api/dist/vendos.cjs');
for(const name of ['createVendosRestrictedChat','vendosRestrictedOverrides','verifyVendosRestrictedAccess',
 'enforceVendosRestrictedConfig','enforceVendosRestrictedBody','denyVendosRestrictedRemote','isVerifiedGoogleIdentity']){
 if(typeof m[name]!=='function')process.exit(32);
}
const policy=m.vendosRestrictedOverrides();
if(policy.modelSpecs.enforce!==true||policy.modelSpecs.list.length!==1||
 policy.modelSpecs.list[0].name!=='vendos-consultation')process.exit(33);
if(m.isVerifiedGoogleIdentity({provider:'google',email:'synthetic@example.test',googleId:'123',emailVerified:false})!==false)process.exit(34);
"""


def validate_manifest(value):
    base.demand(isinstance(value, dict) and set(value) == {'schema', 'purpose', 'oauth', 'baseline_files',
        'base_config_sha256', 'payload_sha256', 'paths', 'source_proof_sha256'}, 'WRONG_COMBINED_MANIFEST')
    base.demand(value['schema'] == 1 and value['purpose'] == 'vendos-restricted-chat-and-dedicated-google',
                'WRONG_COMBINED_MANIFEST')
    oauth.validate_manifest(value['oauth'])
    base.demand(value['paths'] == TARGETS and set(value['payload_sha256']) == set(TARGETS), 'WRONG_OVERLAY_SCOPE')
    base.demand(all(isinstance(v, str) and re.fullmatch('[a-f0-9]{64}', v)
        for v in [*value['payload_sha256'].values(), value['source_proof_sha256'], value['base_config_sha256']]), 'INVALID_OVERLAY_PIN')
    files = value['baseline_files']
    base.demand(isinstance(files, dict) and set(files) == set(PATHS), 'INCOMPLETE_RUNTIME_BASELINE')
    for name, data in files.items():
        if name == NEW_PATH:
            base.demand(data == {'exists': False}, 'NEW_FENCE_ALREADY_PRESENT')
            continue
        base.demand(isinstance(data, dict) and set(data) == {'exists', 'sha256', 'size', 'uid', 'gid', 'mode'}
            and data['exists'] is True and re.fullmatch('[a-f0-9]{64}', data['sha256'])
            and all(type(data[k]) is int and data[k] >= 0 for k in ('size', 'uid', 'gid', 'mode'))
            and data['size'] <= 16000000 and data['mode'] <= 0o777, 'INVALID_RUNTIME_BASELINE')
    for name, path in base.PATHS.items():
        base.demand(files[path.removeprefix('/app/')]['sha256'] == oauth.BASELINE[name], 'PRIOR_AUTH_BASELINE_CHANGED')


def load_payload(manifest, directory):
    validate_manifest(manifest)
    output = {}
    for name, digest in manifest['payload_sha256'].items():
        path = directory / name
        base.demand(path.is_file() and not path.is_symlink() and path.stat().st_size <= 16000000, 'UNSAFE_OVERLAY_INPUT')
        raw = path.read_bytes()
        base.demand(base.digest(raw) == digest, 'OVERLAY_PAYLOAD_CHANGED')
        output[name] = raw
    base.demand(b'sourceMappingURL=vendos.cjs.map' in output['vendos.cjs'], 'SOURCE_MAP_REQUIRED')
    mapping = json.loads(output['vendos.cjs.map'])
    base.demand(mapping.get('version') == 3 and mapping.get('sourcesContent'), 'INVALID_SOURCE_MAP')
    return output


def expected_files(manifest, payload):
    output = {key: dict(value) for key, value in manifest['baseline_files'].items()}
    for name, path in TARGETS.items():
        key = path.removeprefix('/app/')
        attrs = output['api/server/middleware/buildEndpointOption.js'] if key == NEW_PATH else output[key]
        output[key] = {'exists': True, 'sha256': base.digest(payload[name]), 'size': len(payload[name]),
                       **{field: attrs[field] for field in ('uid', 'gid', 'mode')}}
    return output


def verify_files(commands, expected=None):
    actual = json.loads(commands.run(['docker', 'exec', base.CONTAINER, 'node', '-e', FILES_JS, base.stable(PATHS)]))
    if expected is not None: base.demand(actual == expected, 'RUNTIME_BASELINE_CHANGED')
    return actual


def verify_configuration(commands, manifest):
    value = json.loads(commands.run(['docker', 'exec', base.CONTAINER, 'node', '-e', CONFIG_JS], 20))
    base.demand(value.get('openai_moderation_disabled') is True, 'NON_CLAUDE_MODERATION_ENABLED_OR_UNKNOWN')
    base.demand(value == {'sha256': manifest['base_config_sha256'], 'active': False, 'openai_moderation_disabled': True}, 'APPLICATION_CONFIG_CHANGED')


def validate_runtime_baseline(before, manifest):
    validate_manifest(manifest)
    env = oauth.validate_runtime_baseline(before, manifest['oauth'])
    base.demand(env.get('OPENAI_MODERATION', '').strip().lower() != 'true', 'NON_CLAUDE_MODERATION_ENABLED_OR_UNKNOWN')
    return env


def execute(manifest, credentials, pause_proof):
    base.demand(os.name == 'posix' and os.geteuid() == 0, 'ROOT_LINUX_REQUIRED')
    os.umask(0o077)
    validate_manifest(manifest)
    validate_pause(pause_proof, dt.datetime.now(dt.timezone.utc))
    payload = load_payload(manifest, ROOT / 'payload')
    desired_files = expected_files(manifest, payload)
    def interrupted(_signal, _frame): raise base.Refusal('INTERRUPTED')
    signal.signal(signal.SIGTERM, interrupted)
    import fcntl
    base.secure_directory(BACKUP_ROOT)
    base.secure_directory(base.BACKUP_ROOT)
    lock = (base.BACKUP_ROOT / 'deployment.lock').open('a')
    try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError: raise base.Refusal('DEPLOYMENT_ALREADY_RUNNING') from None
    stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    backup = BACKUP_ROOT / stamp
    base.secure_directory(backup, new=True)
    commands = base.Commands(backup)
    base.demand(not os.environ.get('DOCKER_HOST') and os.environ.get('DOCKER_CONTEXT', 'default') == 'default', 'NONLOCAL_DOCKER_CONTEXT')
    base.demand(commands.run(['docker', 'context', 'show']).strip() == 'default', 'NONLOCAL_DOCKER_CONTEXT')
    context = json.loads(commands.run(['docker', 'context', 'inspect', 'default']))[0]
    base.demand(context['Endpoints']['docker']['Host'] == 'unix:///var/run/docker.sock', 'NONLOCAL_DOCKER_CONTEXT')
    before = commands.inspect()
    base.demand(before['Name'] == '/' + base.CONTAINER and before['State'].get('Running') is True
        and not before['State'].get('Paused') and not before['State'].get('Restarting'), 'UNEXPECTED_CONTAINER_STATE')
    labels = before['Config'].get('Labels') or {}
    base.demand(labels.get('com.docker.compose.project') == 'librechat' and labels.get('com.docker.compose.service') == 'api', 'UNEXPECTED_COMPOSE_PROJECT')
    base.demand(not base.mount_collision(before['Mounts'], list(PATHS.values())), 'OVERLAY_MOUNT_COLLISION')
    validate_runtime_baseline(before, manifest)
    expected = oauth.expected_runtime(before, credentials, manifest['oauth'])
    base.engine_create_payload(expected, before['Image'])
    (backup / 'before.json').write_text(base.stable(before), encoding='utf-8')
    (backup / 'manifest.json').write_text(base.stable(manifest), encoding='utf-8')
    (backup / 'pause-proof.json').write_text(base.stable(pause_proof), encoding='utf-8')
    verify_files(commands, manifest['baseline_files'])
    verify_configuration(commands, manifest)
    base.fresh_journal_counts(commands)
    base.verify_notebook_paused(commands)
    first_metrics = base.observe_metrics(commands, 'controlled-restart')
    snapshot_tag = 'librechat-restricted-snapshot:' + stamp.lower()
    commands.run(['docker', 'commit', '--pause=true', before['Id'], snapshot_tag], 120)
    snapshot = json.loads(commands.run(['docker', 'image', 'inspect', snapshot_tag]))[0]['Id']
    base.demand(re.fullmatch(r'sha256:[a-f0-9]{64}', snapshot), 'INVALID_SNAPSHOT')
    (backup / 'snapshot-id').write_text(snapshot)
    build = backup / 'build'; base.secure_directory(build, new=True)
    dockerfile = ['FROM ' + snapshot_tag]
    for name, destination in TARGETS.items():
        (build / name).write_bytes(payload[name])
        base.demand(base.digest((build / name).read_bytes()) == manifest['payload_sha256'][name], 'PAYLOAD_CHANGED_DURING_COPY')
        attrs = desired_files[destination.removeprefix('/app/')]
        dockerfile.append(f"COPY --chown={attrs['uid']}:{attrs['gid']} --chmod={attrs['mode']:04o} {name} {destination}")
    (build / 'Dockerfile').write_text('\n'.join(dockerfile) + '\n', encoding='ascii')
    overlay_tag = 'librechat-restricted-google:' + stamp.lower()
    commands.run(['docker', 'build', '--pull=false', '--network=none', '--tag', overlay_tag, str(build)], 180)
    image_id = json.loads(commands.run(['docker', 'image', 'inspect', overlay_tag]))[0]['Id']
    (backup / 'overlay-id').write_text(image_id)
    run = ['docker', 'run', '--rm', '--network', 'none', '--read-only', '--no-healthcheck', '--entrypoint', 'node', overlay_tag]
    built = json.loads(commands.run([*run, '-e', FILES_JS, base.stable(PATHS)]))
    base.demand(built == desired_files, 'BUILT_FILES_CHANGED')
    for name, destination in TARGETS.items():
        if not name.endswith('.map'): commands.run([*run, '--check', destination])
    commands.run([*run, '-e', base.AUTH_PROBE_JS])
    commands.run([*run, '-e', FENCE_PROBE_JS])
    current = commands.inspect()
    base.demand(current['Id'] == before['Id'] and current['Image'] == before['Image']
        and base.canonical_inspect(current) == base.canonical_inspect(before), 'CONFIGURATION_CHANGED')
    candidate_name = 'LibreChat-API-vendos-restricted-candidate-' + stamp.lower()
    retained_name = 'LibreChat-API-vendos-restricted-rollback-' + stamp.lower()
    candidate_id = base.create_stopped(commands, expected, image_id, candidate_name)
    (backup / 'candidate-id').write_text(candidate_id)
    (backup / 'retained-name').write_text(retained_name)
    try:
        after = commands.inspect(candidate_id)
        base.demand(not after['State'].get('Running'), 'CANDIDATE_STARTED_EARLY')
        base.assert_parity(expected, after, image_id, candidate_name)
        base.verify_networks(commands, before)
        base.verify_notebook_paused(commands)
        verify_files(commands, manifest['baseline_files'])
        verify_configuration(commands, manifest)
        current = commands.inspect()
        base.demand(current['Id'] == before['Id'] and current['Image'] == before['Image']
            and base.canonical_inspect(current) == base.canonical_inspect(before), 'CONFIGURATION_CHANGED')
        counts = base.fresh_journal_counts(commands)
        metrics = base.observe_metrics(commands, 'controlled-restart')
        validate_pause(pause_proof, dt.datetime.now(dt.timezone.utc))
        (backup / 'restart-evidence.json').write_text(base.stable({'counts': counts, 'first_metrics': first_metrics, 'last_metrics': metrics}))
    except BaseException:
        base.remove_owned_candidate(commands, candidate_id)
        raise
    def health_check(command):
        base.verify_health(command)
        verify_files(command, desired_files if command.inspect()['Image'] == image_id else manifest['baseline_files'])
        verify_configuration(command, manifest)
    oauth.activate(commands, before, expected, candidate_id, image_id, retained_name, health_check)
    (backup / 'complete').write_text('yes')
    return {'status': 'deployed', 'health_ok': True, 'only_two_oauth_env_replaced': True,
        'configuration_parity': True, 'owner_approval_preserved': True, 'restricted_payload_verified': True,
        'current_filesystem_snapshotted': True, 'original_container_retained': True, 'external_api_calls': False,
        'non_claude_moderation_disabled': True,
        'metrics_available': metrics['available'], 'running_jobs_observed': metrics['running']}
