"""Integrity-bound auth release launcher. Default is local input validation only."""
import argparse
import base64
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import io
import tarfile

PAYLOAD_NAMES = {'socialLogin.js', 'checkDomainAllowed.js', 'vendos.cjs', 'vendos.cjs.map'}
RELEASE_FILES = {'deploy.py', 'launch.py', 'manifest.json'} | {'payload/' + name for name in PAYLOAD_NAMES}
CONFIG_SHA = '449e769617bdff8268d19f2361bc1b0abf8aeff926fa0611a7f74375b6cddaf6'
SERVICE_SHA = '728efbe1ff7f66f217776c0fbc1dbe7bc1d0bdf64acd0030a8ebab8763135673'
SOURCE_SHA = 'df384ea6d418d99344ab1b9175b45d4ec77be6fc4330867d04f76bfc4138b90c'
PAUSE_HELPER_SHA = 'dd66b453d37b98b865c7db485b341726cc4f871f7adcf565b8dc1bd97d627de8'
REQUEST_PATH = '.github/vendos-colleague-auth-run.json'


def demand(value, code):
    if not value: raise RuntimeError(code)


def sha(value): return hashlib.sha256(value).hexdigest()


def validate_proof(proof, now):
    allowed = {'schema', 'notebook_agents_paused', 'notebook_pause_marker', 'observed_at_utc',
               'supervisor', 'busy', 'config_sha256', 'live_service_sha256', 'helper_sha256',
               'marker', 'pid_confirmed_stopped', 'source_sha256', 'service_sha256'}
    demand(isinstance(proof, dict) and set(proof) == allowed, 'UNEXPECTED_PAUSE_PROOF_FIELDS')
    demand(proof.get('schema') == 1 and proof.get('notebook_agents_paused') is True
           and proof.get('supervisor') == 'stopped' and proof.get('pid_confirmed_stopped') is True,
           'NOTEBOOK_NOT_PAUSED')
    demand(isinstance(proof.get('notebook_pause_marker'), str) and
           re.fullmatch(r'vendos-colleague-auth-stop:[a-f0-9]{32}', proof['notebook_pause_marker']),
           'WRONG_PAUSE_OWNER_MARKER')
    demand(proof['marker'] == proof['notebook_pause_marker'], 'WRONG_PAUSE_OWNER_MARKER')
    demand(proof.get('config_sha256') == CONFIG_SHA and proof.get('live_service_sha256') == SERVICE_SHA,
           'NOTEBOOK_BASELINE_CHANGED')
    demand(proof['service_sha256'] == SERVICE_SHA and proof['source_sha256'] == SOURCE_SHA,
           'NOTEBOOK_BASELINE_CHANGED')
    demand(proof['helper_sha256'] == PAUSE_HELPER_SHA, 'PAUSE_HELPER_CHANGED')
    busy = proof.get('busy', {})
    demand(isinstance(busy, dict) and set(busy) == {'models', 'execution', 'cycles', 'legacy_generations', 'legacy_reviews',
                        'digest_sending', 'delivery_preparing'} and
           all(type(v) is int and v == 0 for v in busy.values()), 'NOTEBOOK_BUSY_OR_UNKNOWN')
    try:
        age = (now - dt.datetime.fromisoformat(proof['observed_at_utc'].replace('Z', '+00:00'))).total_seconds()
    except (KeyError, TypeError, ValueError, AttributeError):
        raise RuntimeError('INVALID_PAUSE_PROOF_TIME') from None
    demand(0 <= age <= 1800, 'PAUSE_PROOF_EXPIRED')


def release_bytes(root, release_sha256):
    raw = (root / 'release-files.json').read_bytes()
    demand(sha(raw) == release_sha256, 'RELEASE_INTEGRITY_FAILURE')
    release = json.loads(raw)
    demand(release.get('schema') == 1 and set(release.get('file_sha256', {})) == RELEASE_FILES,
           'UNEXPECTED_RELEASE_FILE_SET')
    content = {'release-files.json': raw}
    for name, digest in release['file_sha256'].items():
        path = root / name
        value = path.read_bytes()
        demand(not path.is_symlink() and path.resolve().is_relative_to(root.resolve())
               and sha(value) == digest, 'RELEASE_FILE_CHANGED')
        content[name] = value
    return content


def load_release(root, release_sha256, proof_sha256, now):
    release_bytes(root, release_sha256)
    proof_raw = (root / 'notebook-pause-proof.json').read_bytes()
    demand(sha(proof_raw) == proof_sha256, 'PAUSE_PROOF_INTEGRITY_FAILURE')
    proof = json.loads(proof_raw)
    validate_proof(proof, now)
    return proof


def validate_request(request, now):
    expected = {'schema', 'execute', 'prepared_commit', 'release_sha256',
                'notebook_pause_proof_sha256', 'notebook_pause_proof_b64'}
    demand(isinstance(request, dict) and set(request) == expected and request['schema'] == 1
           and request['execute'] is True, 'EXPLICIT_RUN_REQUEST_REQUIRED')
    for key, size in [('prepared_commit', 40), ('release_sha256', 64), ('notebook_pause_proof_sha256', 64)]:
        demand(isinstance(request[key], str) and re.fullmatch('[a-f0-9]{' + str(size) + '}', request[key]),
               'INVALID_RUN_REQUEST_PIN')
    demand(isinstance(request['notebook_pause_proof_b64'], str)
           and len(request['notebook_pause_proof_b64']) <= 12000, 'INVALID_PAUSE_PROOF_SIZE')
    try:
        raw = base64.b64decode(request['notebook_pause_proof_b64'], validate=True)
        proof = json.loads(raw)
    except (ValueError, TypeError):
        raise RuntimeError('INVALID_PAUSE_PROOF_ENCODING') from None
    demand(sha(raw) == request['notebook_pause_proof_sha256'], 'PAUSE_PROOF_INTEGRITY_FAILURE')
    validate_proof(proof, now)
    return raw


def package_request(root, request, output, now):
    proof_raw = validate_request(request, now)
    content = release_bytes(root, request['release_sha256'])
    content['notebook-pause-proof.json'] = proof_raw
    # Fixed regular files only; never archive a directory, symlink or private local state.
    with output.open('xb') as stream, tarfile.open(fileobj=stream, mode='w') as archive:
        for name, raw in sorted(content.items()):
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(raw), 0o600, 0
            archive.addfile(info, io.BytesIO(raw))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--release-sha256', required=True)
    parser.add_argument('--pause-proof-sha256', required=True)
    args = parser.parse_args()
    os.umask(0o077)
    root = Path(__file__).resolve().parent
    try:
        proof = load_release(root, args.release_sha256, args.pause_proof_sha256, dt.datetime.now(dt.timezone.utc))
        # Import only after the fixed release file hashes have been checked.
        spec = importlib.util.spec_from_file_location('verified_auth_deploy', root / 'deploy.py')
        deploy = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(deploy)
        manifest = root / 'manifest.json'
        manifest_hash = sha(manifest.read_bytes())
        deploy.load_payload(json.loads(manifest.read_bytes()), root / 'payload')
        if not args.execute:
            print(json.dumps({'status': 'release_verified_not_deployed', 'docker_called': False}))
            return 0
        demand(os.name == 'posix' and os.geteuid() == 0, 'ROOT_LINUX_REQUIRED')
        deploy.read_private_json(root / 'release-files.json')
        deploy.read_private_json(root / 'notebook-pause-proof.json')
        commands = deploy.Commands(root)
        before = commands.inspect()
        counts = deploy.fresh_journal_counts(commands)
        deploy.verify_notebook_paused(commands)
        gate = {'schema': 1, 'policy': 'controlled-restart', 'container_id': before['Id'],
                'image_id': before['Image'], 'manifest_sha256': manifest_hash,
                'notebook_agents_paused': True, 'notebook_pause_marker': proof['notebook_pause_marker'],
                'notebook_pause_proof_sha256': args.pause_proof_sha256, 'journal_source': 'mongodb-metadata',
                'observed_at_utc': dt.datetime.now(dt.timezone.utc).isoformat(), **counts}
        (root / 'gate.json').write_text(json.dumps(gate), encoding='utf-8')
        deploy_args = argparse.Namespace(execute=True, policy='controlled-restart', manifest=str(manifest),
            manifest_sha256=manifest_hash, payload=str(root / 'payload'), gate=str(root / 'gate.json'))
        result = deploy.deploy(deploy_args)
        (root / 'result.json').write_text(json.dumps(result), encoding='utf-8')
        print(json.dumps(result))
        return 0
    except BaseException as error:
        code = getattr(error, 'code', None) or (str(error) if type(error) is RuntimeError else 'LAUNCH_FAILED')
        if not re.fullmatch(r'[A-Z_]{1,100}', code): code = 'LAUNCH_FAILED'
        print(json.dumps({'status': 'stopped', 'error_code': code}))
        return 1


if __name__ == '__main__': sys.exit(main())
