"""Integrity-bound dedicated OAuth switch launcher; default local validation only."""
import argparse
import base64
import datetime as dt
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import sys
import tarfile

PAYLOAD = {'socialLogin.js','checkDomainAllowed.js','server-index.js','buildEndpointOption.js','config-app.js','agents-middleware.js','vendosRestrictedChat.js','vendos.cjs','vendos.cjs.map'}
FILES = {'engine_base.py', 'oauth_switch.py', 'combined_switch.py', 'transport.py', 'launch.py', 'manifest.json'} | {'payload/' + name for name in PAYLOAD}
REQUEST_PATH = '.github/vendos-restricted-google-run.json'


def demand(value, code):
    if not value: raise RuntimeError(code)


def sha(raw): return hashlib.sha256(raw).hexdigest()


def release_bytes(root, expected_sha):
    raw = (root / 'release-files.json').read_bytes()
    demand(sha(raw) == expected_sha, 'RELEASE_INTEGRITY_FAILURE')
    value = json.loads(raw)
    demand(set(value) == {'schema', 'file_sha256'} and value['schema'] == 1
           and set(value['file_sha256']) == FILES, 'WRONG_RELEASE_FILES')
    result = {'release-files.json': raw}
    for name, digest in value['file_sha256'].items():
        path = root / name
        raw = path.read_bytes()
        demand(not path.is_symlink() and path.resolve().is_relative_to(root.resolve())
               and sha(raw) == digest, 'RELEASE_FILE_CHANGED')
        result[name] = raw
    return result


def request_content(request):
    demand(isinstance(request, dict) and set(request) == {'schema', 'execute', 'prepared_commit',
        'release_sha256', 'envelope_b64', 'envelope_sha256', 'pause_proof_b64', 'pause_proof_sha256'}
        and request['schema'] == 1 and request['execute'] is True, 'EXPLICIT_REQUEST_REQUIRED')
    for key, length in [('prepared_commit', 40), ('release_sha256', 64), ('envelope_sha256', 64), ('pause_proof_sha256', 64)]:
        demand(isinstance(request[key], str) and re.fullmatch('[a-f0-9]{' + str(length) + '}', request[key]), 'INVALID_REQUEST_PIN')
    result = {}
    for kind, filename in [('envelope', 'envelope.json'), ('pause_proof', 'notebook-pause-proof.json')]:
        value = request[kind + '_b64']
        demand(isinstance(value, str) and len(value) <= 12000, 'INVALID_REQUEST_SIZE')
        try: raw = base64.b64decode(value, validate=True)
        except (ValueError, TypeError): raise RuntimeError('INVALID_REQUEST_ENCODING') from None
        demand(sha(raw) == request[kind + '_sha256'], 'REQUEST_INTEGRITY_FAILURE')
        result[filename] = raw
    return result


def load_module(root, name):
    spec = importlib.util.spec_from_file_location('verified_oauth_' + name, root / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_inputs(root, content, now):
    switch = load_module(root, 'combined_switch')
    manifest = json.loads(content['manifest.json'])
    switch.validate_manifest(manifest)
    switch.load_payload(manifest, root / 'payload')
    proof = json.loads(content['notebook-pause-proof.json'])
    switch.validate_pause(proof, now)
    # Full cryptographic key metadata is checked by transport before decryption.
    envelope = json.loads(content['envelope.json'])
    demand(isinstance(envelope, dict) and set(envelope) == {'schema', 'algorithm', 'key_id',
        'public_key_sha256', 'ciphertext_b64', 'ciphertext_sha256'} and envelope['schema'] == 1
        and envelope['algorithm'] == 'RSA-OAEP-256', 'INVALID_ENVELOPE')
    for key, length in [('key_id', 32), ('public_key_sha256', 64), ('ciphertext_sha256', 64)]:
        demand(isinstance(envelope[key], str) and re.fullmatch('[a-f0-9]{' + str(length) + '}', envelope[key]), 'INVALID_ENVELOPE')
    ciphertext = base64.b64decode(envelope['ciphertext_b64'], validate=True)
    demand(len(ciphertext) == 384 and sha(ciphertext) == envelope['ciphertext_sha256'], 'INVALID_ENVELOPE')
    return switch, manifest, proof, envelope


def package_request(root, request, output, now):
    content = release_bytes(root, request['release_sha256'])
    content.update(request_content(request))
    validate_inputs(root, content, now)
    with output.open('xb') as stream, tarfile.open(fileobj=stream, mode='w') as archive:
        for name, raw in sorted(content.items()):
            info = tarfile.TarInfo(name); info.size = len(raw); info.mode = 0o600; info.mtime = 0
            archive.addfile(info, io.BytesIO(raw))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--release-sha256', required=True)
    parser.add_argument('--envelope-sha256', required=True)
    parser.add_argument('--pause-proof-sha256', required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    os.umask(0o077)
    credentials = None
    try:
        content = release_bytes(root, args.release_sha256)
        for name, digest in [('envelope.json', args.envelope_sha256), ('notebook-pause-proof.json', args.pause_proof_sha256)]:
            raw = (root / name).read_bytes()
            demand(sha(raw) == digest, 'REQUEST_INTEGRITY_FAILURE')
            content[name] = raw
        switch, manifest, proof, envelope = validate_inputs(root, content, dt.datetime.now(dt.timezone.utc))
        if not args.execute:
            print(json.dumps({'status': 'inputs_verified_not_deployed', 'docker_called': False, 'decrypted': False}))
            return 0
        demand(os.name == 'posix' and os.geteuid() == 0, 'ROOT_LINUX_REQUIRED')
        for name in ['release-files.json', 'manifest.json', 'envelope.json', 'notebook-pause-proof.json']:
            switch.base.read_private_json(root / name)
        commands = switch.base.Commands(root)
        switch.validate_runtime_baseline(commands.inspect(), manifest)
        switch.verify_files(commands, manifest['baseline_files'])
        switch.verify_configuration(commands, manifest)
        switch.base.fresh_journal_counts(commands)
        switch.base.verify_notebook_paused(commands)
        transport = load_module(root, 'transport')
        credentials = transport.decrypt(envelope, manifest['oauth']['client_id'])
        result = switch.execute(manifest, credentials, proof)
        (root / 'result.json').write_text(json.dumps(result), encoding='utf-8')
        print(json.dumps(result))
        return 0
    except BaseException as error:
        code = getattr(error, 'code', None) or (str(error) if type(error).__name__ in ('RuntimeError', 'TransportError') else 'OAUTH_SWITCH_FAILED')
        if not re.fullmatch('[A-Z_]{1,100}', code): code = 'OAUTH_SWITCH_FAILED'
        print(json.dumps({'status': 'stopped', 'error_code': code}))
        return 1
    finally:
        if isinstance(credentials, dict): credentials.clear()


if __name__ == '__main__': sys.exit(main())
