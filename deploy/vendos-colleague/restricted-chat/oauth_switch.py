"""Dedicated Google login client: exact two-env runtime switch; no cloud/model calls."""
import argparse
import copy
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import sys

ROOT = Path(__file__).resolve().parent
BASE_SHA = '512e526483bb9f0e1850175fe916a5f8af7a61921bb586c9edc285e6e23d4f5b'
if hashlib.sha256((ROOT / 'engine_base.py').read_bytes()).hexdigest() != BASE_SHA:
    raise RuntimeError('ENGINE_HELPER_CHANGED')
spec = importlib.util.spec_from_file_location('verified_oauth_engine', ROOT / 'engine_base.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
BACKUP_ROOT = Path('/var/backups/librechat-vendos-google-oauth')
OLD_CLIENT = '851039774056-ai8alf50sv2r5p0hkuna314s8f194u28.apps.googleusercontent.com'
REDIRECT = 'https://chat.nasdum.cz/oauth/google/callback'
PROJECT = 'nasdum-librechat-login'
ENV_KEYS = {'GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET'}
PAUSE_PREFIX = 'vendos-google-oauth-stop:'
PAUSE_HELPER_SHA = 'dd66b453d37b98b865c7db485b341726cc4f871f7adcf565b8dc1bd97d627de8'
NOTEBOOK_CONFIG_SHA = '449e769617bdff8268d19f2361bc1b0abf8aeff926fa0611a7f74375b6cddaf6'
NOTEBOOK_SERVICE_SHA = '728efbe1ff7f66f217776c0fbc1dbe7bc1d0bdf64acd0030a8ebab8763135673'
NOTEBOOK_SOURCE_SHA = 'df384ea6d418d99344ab1b9175b45d4ec77be6fc4330867d04f76bfc4138b90c'
BASELINE = {
    'MCP.js': '1ea4a33ecbfff103fa6366f04c5e9f8da1b54bdad0d71bea1132e0dfb7fd35c4',
    'PluginService.js': '07997a0cd92545aa4b4823cdf47db9d5880fe2239c5f8ac12cabedc7e01d5f03',
    'VendosBriefing.js': 'ea1c4ae84323a993b33f419a872696aab9a17e590e038694238808d9637914b2',
    'request.js': 'b43d80081aa53b056ca84ef68651db963041d97aaa42a961b853689b7c066d74',
    'api-package.json': '04ef36bf22990b1003c88302df2e83e74b1d912a8705bfcf1e830f609dbbc94c',
    'socialLogin.js': '0aa083682a36c288a004ca81286ff258ba51740ed73f08e36a2144ea319f947f',
    'checkDomainAllowed.js': 'c2b67bb773844ae9559e338076498f31c311d2134f7498dcee56a879a3c4d073',
    'vendos.cjs': 'c4f3c4f5401fefa2246edf2780b335092ba524b80b3758faa8e1622db24a8502',
    'vendos.cjs.map': '2e039d3facf87d351809c23fb1c32726a27e6edae291fa4db463a6bd5fea14e2',
}


def validate_pause(proof, now):
    base.demand(isinstance(proof, dict) and set(proof) == {'schema', 'notebook_agents_paused',
        'marker', 'notebook_pause_marker', 'observed_at_utc', 'supervisor', 'pid_confirmed_stopped',
        'busy', 'config_sha256', 'live_service_sha256', 'service_sha256', 'source_sha256', 'helper_sha256'},
        'INVALID_PAUSE_PROOF')
    base.demand(proof['schema'] == 1 and proof['notebook_agents_paused'] is True
        and proof['pid_confirmed_stopped'] is True and proof['supervisor'] == 'stopped', 'NOTEBOOK_NOT_PAUSED')
    base.demand(isinstance(proof['marker'], str) and re.fullmatch(PAUSE_PREFIX + '[a-f0-9]{32}', proof['marker'])
        and proof['marker'] == proof['notebook_pause_marker'], 'WRONG_PAUSE_OWNER')
    base.demand(proof['config_sha256'] == NOTEBOOK_CONFIG_SHA and proof['live_service_sha256'] == NOTEBOOK_SERVICE_SHA
        and proof['service_sha256'] == NOTEBOOK_SERVICE_SHA and proof['source_sha256'] == NOTEBOOK_SOURCE_SHA
        and proof['helper_sha256'] == PAUSE_HELPER_SHA, 'NOTEBOOK_BASELINE_CHANGED')
    busy = proof['busy']
    base.demand(isinstance(busy, dict) and set(busy) == {'models', 'execution', 'cycles', 'legacy_generations',
        'legacy_reviews', 'digest_sending', 'delivery_preparing'}
        and all(type(value) is int and value == 0 for value in busy.values()), 'NOTEBOOK_BUSY_OR_UNKNOWN')
    try: age = (now - dt.datetime.fromisoformat(proof['observed_at_utc'].replace('Z', '+00:00'))).total_seconds()
    except (TypeError, ValueError, AttributeError): raise base.Refusal('INVALID_PAUSE_TIME') from None
    base.demand(0 <= age <= 1800, 'STALE_PAUSE_PROOF')


def validate_manifest(manifest):
    base.demand(set(manifest) == {'schema', 'purpose', 'project_id', 'client_id', 'redirect_uri',
                                 'previous_client_id', 'baseline_sha256', 'environment_keys'}, 'WRONG_OAUTH_MANIFEST')
    base.demand(manifest['schema'] == 1 and manifest['purpose'] == 'vendos-dedicated-google-login',
                'WRONG_OAUTH_MANIFEST')
    base.demand(manifest['project_id'] == PROJECT and manifest['redirect_uri'] == REDIRECT
                and manifest['previous_client_id'] == OLD_CLIENT, 'WRONG_OAUTH_TARGET')
    client = manifest['client_id']
    base.demand(isinstance(client, str) and re.fullmatch(r'[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com', client)
                and not client.startswith('851039774056-'), 'DEDICATED_CLIENT_REQUIRED')
    base.demand(manifest['baseline_sha256'] == BASELINE and set(manifest['environment_keys']) == ENV_KEYS
                and len(manifest['environment_keys']) == 2, 'WRONG_OAUTH_SCOPE')


def validate_runtime_baseline(before, manifest):
    validate_manifest(manifest)
    old = base.env_map(before['Config'].get('Env') or [])
    base.demand(old.get('GOOGLE_CLIENT_ID') == OLD_CLIENT and bool(old.get('GOOGLE_CLIENT_SECRET')),
                'OAUTH_BASELINE_CHANGED')
    base.demand(old.get('DOMAIN_SERVER', '') + old.get('GOOGLE_CALLBACK_URL', '') == REDIRECT,
                'OAUTH_REDIRECT_CHANGED')
    base.demand(all(old.get(k) == v for k, v in base.ENV_PATCH.items()), 'EMAIL_EXCEPTION_BASELINE_CHANGED')
    return old


def expected_runtime(before, credentials, manifest):
    old = validate_runtime_baseline(before, manifest)
    base.demand(isinstance(credentials, dict) and set(credentials) == {'client_id', 'client_secret'},
                'WRONG_CREDENTIAL_FIELDS')
    base.demand(credentials['client_id'] == manifest['client_id'], 'WRONG_NEW_CLIENT')
    secret = credentials['client_secret']
    base.demand(isinstance(secret, str) and re.fullmatch(r'[A-Za-z0-9_-]{16,256}', secret), 'INVALID_CLIENT_SECRET')
    patch = {'GOOGLE_CLIENT_ID': credentials['client_id'], 'GOOGLE_CLIENT_SECRET': secret}
    base.demand(patch['GOOGLE_CLIENT_SECRET'] != old['GOOGLE_CLIENT_SECRET'], 'NEW_SECRET_REQUIRED')
    expected = copy.deepcopy(before)
    expected['Config']['Env'] = [key + '=' + patch.get(key, value)
                                 for key, value in (entry.split('=', 1) for entry in before['Config']['Env'])]
    return expected


def verify_files(commands):
    actual = json.loads(commands.run(['docker', 'exec', base.CONTAINER, 'node', '-e', base.FILES_JS,
                                     base.stable(base.PATHS)]))
    base.demand({key: value['sha256'] for key, value in actual.items()} == BASELINE, 'RUNTIME_BASELINE_CHANGED')
    return actual


def activate(commands, before, expected, candidate_id, snapshot_id, retained_name, health_check):
    policy = base.restart_argument(before)
    (commands.backup / 'cutover-started').write_text('yes')
    try:
        commands.run(['docker', 'stop', '--time', '70', before['Id']], 90)
        commands.run(['docker', 'update', '--restart', 'no', before['Id']])
        commands.run(['docker', 'rename', before['Id'], retained_name])
        commands.run(['docker', 'rename', candidate_id, base.CONTAINER])
        commands.run(['docker', 'start', candidate_id])
        health_check(commands)
        base.assert_parity(expected, commands.inspect(candidate_id), snapshot_id)
    except BaseException:
        try:
            base.remove_owned_candidate(commands, candidate_id)
            old = commands.inspect(before['Id'])
            base.demand(old['Name'] in ('/' + base.CONTAINER, '/' + retained_name), 'ORIGINAL_CONTAINER_RENAMED')
            if old['Name'] != '/' + base.CONTAINER:
                commands.run(['docker', 'rename', before['Id'], base.CONTAINER])
            commands.run(['docker', 'update', '--restart', policy, before['Id']])
            commands.run(['docker', 'start', before['Id']])
            base.assert_parity(before, commands.inspect(before['Id']), before['Image'])
            health_check(commands)
            (commands.backup / 'rolled-back').write_text('yes')
        except BaseException:
            (commands.backup / 'rollback-needs-operator').write_text('yes')
            raise base.Refusal('ROLLBACK_NEEDS_OPERATOR') from None
        raise base.Refusal('DEPLOYMENT_FAILED_ROLLED_BACK') from None


def execute(manifest, credentials, pause_proof):
    base.demand(os.name == 'posix' and os.geteuid() == 0, 'ROOT_LINUX_REQUIRED')
    validate_manifest(manifest)
    validate_pause(pause_proof, dt.datetime.now(dt.timezone.utc))
    os.umask(0o077)
    def interrupted(_signal, _frame): raise base.Refusal('INTERRUPTED')
    signal.signal(signal.SIGTERM, interrupted)
    import fcntl
    base.secure_directory(BACKUP_ROOT)
    # Use the same deployment lock as the auth overlay, so the two cannot overlap.
    base.secure_directory(base.BACKUP_ROOT)
    lock = (base.BACKUP_ROOT / 'deployment.lock').open('a')
    try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError: raise base.Refusal('DEPLOYMENT_ALREADY_RUNNING') from None
    stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    backup = BACKUP_ROOT / stamp
    base.secure_directory(backup, new=True)
    commands = base.Commands(backup)
    base.demand(not os.environ.get('DOCKER_HOST') and os.environ.get('DOCKER_CONTEXT', 'default') == 'default',
                'NONLOCAL_DOCKER_CONTEXT')
    base.demand(commands.run(['docker', 'context', 'show']).strip() == 'default', 'NONLOCAL_DOCKER_CONTEXT')
    context = json.loads(commands.run(['docker', 'context', 'inspect', 'default']))[0]
    base.demand(context['Endpoints']['docker']['Host'] == 'unix:///var/run/docker.sock', 'NONLOCAL_DOCKER_CONTEXT')
    before = commands.inspect()
    base.demand(before['Name'] == '/' + base.CONTAINER and before['State'].get('Running') is True
                and not before['State'].get('Paused') and not before['State'].get('Restarting'), 'UNEXPECTED_CONTAINER_STATE')
    labels = before['Config'].get('Labels') or {}
    base.demand(labels.get('com.docker.compose.project') == 'librechat'
                and labels.get('com.docker.compose.service') == 'api', 'UNEXPECTED_COMPOSE_PROJECT')
    base.demand(not base.mount_collision(before['Mounts'], list(base.PATHS.values())), 'BASELINE_MOUNT_COLLISION')
    expected = expected_runtime(before, credentials, manifest)
    base.engine_create_payload(expected, before['Image'])
    (backup / 'before.json').write_text(base.stable(before), encoding='utf-8')
    (backup / 'manifest.json').write_text(base.stable(manifest), encoding='utf-8')
    (backup / 'pause-proof.json').write_text(base.stable(pause_proof), encoding='utf-8')
    verify_files(commands)
    initial_counts = base.fresh_journal_counts(commands)
    base.verify_notebook_paused(commands)
    initial_metrics = base.observe_metrics(commands, 'controlled-restart')
    tag = 'librechat-google-oauth-snapshot:' + stamp.lower()
    commands.run(['docker', 'commit', '--pause=true', before['Id'], tag], 120)
    snapshot = json.loads(commands.run(['docker', 'image', 'inspect', tag]))[0]['Id']
    base.demand(re.fullmatch(r'sha256:[a-f0-9]{64}', snapshot), 'INVALID_SNAPSHOT')
    (backup / 'snapshot-id').write_text(snapshot)
    # No image build, COPY or push. The current writable layer is preserved.
    current = commands.inspect()
    base.demand(current['Id'] == before['Id'] and current['Image'] == before['Image']
                and base.canonical_inspect(current) == base.canonical_inspect(before), 'CONFIGURATION_CHANGED')
    candidate_name = 'LibreChat-API-vendos-oauth-candidate-' + stamp.lower()
    retained_name = 'LibreChat-API-vendos-oauth-rollback-' + stamp.lower()
    candidate_id = base.create_stopped(commands, expected, snapshot, candidate_name)
    (backup / 'candidate-id').write_text(candidate_id)
    (backup / 'retained-name').write_text(retained_name)
    try:
        after = commands.inspect(candidate_id)
        base.demand(not after['State'].get('Running'), 'CANDIDATE_STARTED_EARLY')
        base.assert_parity(expected, after, snapshot, candidate_name)
        base.verify_networks(commands, before)
        base.verify_notebook_paused(commands)
        verify_files(commands)
        current = commands.inspect()
        base.demand(current['Id'] == before['Id'] and current['Image'] == before['Image']
                    and base.canonical_inspect(current) == base.canonical_inspect(before), 'CONFIGURATION_CHANGED')
        counts = base.fresh_journal_counts(commands)
        metrics = base.observe_metrics(commands, 'controlled-restart')
        validate_pause(pause_proof, dt.datetime.now(dt.timezone.utc))
        (backup / 'restart-evidence.json').write_text(base.stable({'first_counts': initial_counts,
            'last_counts': counts, 'first_metrics': initial_metrics, 'last_metrics': metrics}))
    except BaseException:
        base.remove_owned_candidate(commands, candidate_id)
        raise
    def health_check(command):
        base.verify_health(command)
        verify_files(command)
    activate(commands, before, expected, candidate_id, snapshot, retained_name, health_check)
    (backup / 'complete').write_text('yes')
    return {'status': 'deployed', 'health_ok': True, 'only_two_oauth_env_replaced': True,
            'configuration_parity': True, 'owner_approval_preserved': True, 'files_unchanged': True,
            'current_filesystem_snapshotted': True, 'original_container_retained': True,
            'external_api_calls': False, 'metrics_available': metrics['available'],
            'running_jobs_observed': metrics['running']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    args = parser.parse_args()
    try:
        validate_manifest(json.loads(args.manifest.read_bytes()))
        print(json.dumps({'status': 'manifest_verified_not_deployed', 'docker_called': False}))
        return 0
    except BaseException as error:
        code = getattr(error, 'code', 'INVALID_INPUT')
        if not re.fullmatch('[A-Z_]{1,100}', code): code = 'INVALID_INPUT'
        print(json.dumps({'status': 'stopped', 'error_code': code}))
        return 1


if __name__ == '__main__': sys.exit(main())
