"""Pinned v3 provisioning runner. Default validates inputs locally; --execute is explicit."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent
SOURCE_MANIFEST_SHA = '739b9b48467c3352d024f5a110c2113be65395d998884fc780bc0157e5d3f6e9'
CORE_FILES = {'cli.cjs','mongo-storage.cjs','policy.cjs','policy.json','provision.cjs','server-runtime.cjs'}
FILES = {'runner.py', 'entry.cjs', 'source-manifest.json'} | {'core/' + name for name in CORE_FILES}
TARGET = '14322c63c114759593f4985f41d3ad3b9580dfd532dfcf125695ccd4b5eff11c'
BUNDLE = '5b2ea09578628adb479cc7235cbd42ed29ead9267ad16e9ecb93d70e94a622ed'
BACKUP = Path('/var/backups/librechat-vendos-provision-v3')
REQUEST_PATHS = {'check': '.github/vendos-colleague-v3-check.json', 'prepare': '.github/vendos-colleague-v3-prepare.json'}


def demand(value, code):
    if not value: raise RuntimeError(code)


def sha(raw): return hashlib.sha256(raw).hexdigest()
def encoded(value): return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
def is_hash(value): return isinstance(value, str) and re.fullmatch('[a-f0-9]{64}', value) is not None


def validate_request(value, now):
    demand(isinstance(value, dict) and set(value) == {'schema', 'mode', 'execute', 'prepared_commit', 'release_sha256',
        'request', 'check_id', 'check_receipt_sha256'} and value['schema'] == 1 and value['execute'] is True
        and value['mode'] in REQUEST_PATHS, 'EXPLICIT_REQUEST_REQUIRED')
    demand(isinstance(value['prepared_commit'], str) and re.fullmatch('[a-f0-9]{40}', value['prepared_commit'])
        and is_hash(value['release_sha256']), 'INVALID_RELEASE_PIN')
    request = value['request']
    demand(isinstance(request, dict) and set(request) == {'schema', 'request_id', 'target_email_sha256', 'expected_user_sha256',
        'expected_corporate_key_sha256', 'expected_vendos_bundle_sha256', 'expires_at'} and request['schema'] == 1, 'INVALID_CORE_REQUEST')
    demand(isinstance(request['request_id'], str) and re.fullmatch('[a-z0-9-]{8,80}', request['request_id']), 'INVALID_REQUEST_ID')
    demand(request['target_email_sha256'] == TARGET and request['expected_vendos_bundle_sha256'] == BUNDLE
        and is_hash(request['expected_corporate_key_sha256']), 'UNVERIFIED_TARGET_OR_CORPORATE_KEY_PIN')
    demand(request['expected_user_sha256'] is None or is_hash(request['expected_user_sha256']), 'INVALID_USER_PIN')
    demand(type(request['expires_at']) is int and now < request['expires_at'] <= now + 366 * 86400, 'INVALID_EXPIRY')
    if value['mode'] == 'check':
        demand(value['check_id'] is None and value['check_receipt_sha256'] is None, 'UNEXPECTED_CHECK_RECEIPT')
    else:
        demand(is_hash(request['expected_user_sha256']) and isinstance(value['check_id'], str)
            and re.fullmatch('[a-f0-9]{32}', value['check_id']) and is_hash(value['check_receipt_sha256']), 'FRESH_CHECK_REQUIRED')
    return request


def load_release(root, digest):
    raw = (root / 'release-files.json').read_bytes()
    demand(sha(raw) == digest, 'RELEASE_CHANGED')
    release = json.loads(raw)
    demand(release.get('schema') == 1 and set(release.get('file_sha256', {})) == FILES, 'WRONG_RELEASE_FILES')
    files = {'release-files.json': raw}
    for name, expected in release['file_sha256'].items():
        path = root / name; raw = path.read_bytes()
        demand(not path.is_symlink() and path.resolve().is_relative_to(root.resolve()) and sha(raw) == expected, 'RELEASE_FILE_CHANGED')
        files[name] = raw
    demand(sha(files['source-manifest.json']) == SOURCE_MANIFEST_SHA, 'FROZEN_V3_MANIFEST_CHANGED')
    source = json.loads(files['source-manifest.json'])
    for name in CORE_FILES:
        demand(sha(files['core/' + name]) == source['file_sha256'][name], 'FROZEN_V3_SOURCE_CHANGED')
    return files


def safe_result(value, request, mode):
    demand(isinstance(value, dict), 'INVALID_CORE_RESULT')
    if 'error_code' in value:
        demand(set(value) == {'schema','error_code','credentials_printed','automatic_rollback'}
            and value['schema'] == 1 and value['credentials_printed'] is False and value['automatic_rollback'] is False
            and isinstance(value['error_code'], str) and re.fullmatch('[A-Z0-9_]{1,100}', value['error_code']), 'INVALID_CORE_ERROR')
        return value
    demand(set(value) == {'schema','phase','request_id','user_sha256','subject','token_sha256','expires_at','token_manifest_entry',
        'notebook_registration_performed','owner_approval_granted','conversation_created_or_shared','financial_configuration_changed',
        'activation_not_before','live_login_and_mcp_readback_required'}, 'UNEXPECTED_CORE_RESULT_FIELDS')
    demand(value['schema'] == 1 and value['phase'] == ('prepared' if mode == 'prepare' else 'checked_no_writes')
        and value['request_id'] == request['request_id'] and value['expires_at'] == request['expires_at']
        and is_hash(value['user_sha256']) and value['subject'] == 'vendos-colleague:' + value['user_sha256'][:24], 'CORE_RESULT_PIN_MISMATCH')
    demand(request['expected_user_sha256'] is None or value['user_sha256'] == request['expected_user_sha256'], 'TARGET_USER_CHANGED')
    demand(all(value[key] is False for key in ['notebook_registration_performed','owner_approval_granted',
        'conversation_created_or_shared','financial_configuration_changed']) and value['live_login_and_mcp_readback_required'] is True,
        'UNEXPECTED_AUTHORITY_CHANGE')
    token = value['token_manifest_entry']
    if token is not None:
        demand(is_hash(value['token_sha256']) and token == {'sha256': value['token_sha256'], 'user': value['subject'],
            'scopes': ['project:read','coordinator:submit'], 'projects': ['vendos-cz'], 'expires_at': request['expires_at'], 'revoked': False},
            'UNEXPECTED_NOTEBOOK_GRANT')
    else: demand(value['token_sha256'] is None and mode == 'check', 'PREPARED_TOKEN_MANIFEST_REQUIRED')
    activation = value['activation_not_before']
    demand(activation is None if mode == 'check' else isinstance(activation, str)
        and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z', activation), 'INVALID_ACTIVATION_TIME')
    return value


def check_basis(request): return {key: value for key, value in request.items() if key != 'expected_user_sha256'}


def verify_check(receipt, raw, envelope, now):
    demand(sha(raw) == envelope['check_receipt_sha256'] and receipt.get('schema') == 1
        and receipt.get('check_id') == envelope['check_id'] and receipt.get('release_sha256') == envelope['release_sha256'], 'CHECK_RECEIPT_CHANGED')
    demand(type(receipt.get('observed_at')) is int and 0 <= now - receipt['observed_at'] <= 1800, 'CHECK_RECEIPT_EXPIRED')
    demand(check_basis(receipt['request']) == check_basis(envelope['request']), 'CHECK_REQUEST_CHANGED')
    checked = safe_result(receipt['result'], receipt['request'], 'check')
    demand(checked.get('phase') == 'checked_no_writes'
        and checked['user_sha256'] == envelope['request']['expected_user_sha256'], 'CHECKED_USER_CHANGED')


def private_directory(path):
    demand(path.is_absolute() and not path.is_symlink() and path.resolve() == path, 'UNSAFE_PRIVATE_DIRECTORY')
    path.mkdir(mode=0o700, exist_ok=True)
    stat = path.stat()
    demand(stat.st_uid == 0 and stat.st_mode & 0o077 == 0, 'PRIVATE_DIRECTORY_REQUIRED')


def execute(files, envelope, backup=BACKUP):
    demand(os.name == 'posix' and os.geteuid() == 0, 'ROOT_LINUX_REQUIRED')
    now = int(time.time()); request = validate_request(envelope, now)
    private_directory(backup)
    checks = backup / 'checks'; private_directory(checks)
    if envelope['mode'] == 'prepare':
        path = checks / (envelope['check_id'] + '.json')
        demand(path.is_file() and not path.is_symlink() and path.stat().st_uid == 0 and path.stat().st_mode & 0o077 == 0, 'PRIVATE_CHECK_RECEIPT_REQUIRED')
        raw = path.read_bytes(); verify_check(json.loads(raw), raw, envelope, now)
    packet = {'schema': 1, 'mode': envelope['mode'], 'request': request,
        'files': {name: {'text': files['core/' + name].decode('utf-8'), 'sha256': sha(files['core/' + name])} for name in CORE_FILES}}
    # Credentials remain inside the existing container environment/DB. Stdin contains only source and hash pins.
    result = subprocess.run(['docker','exec','--interactive','--workdir','/app','LibreChat-API','node','-e',files['entry.cjs'].decode('utf-8')],
        input=encoded(packet), capture_output=True, check=False, timeout=180)
    try: public = safe_result(json.loads(result.stdout), request, envelope['mode'])
    except BaseException: raise RuntimeError('PROVISION_RESPONSE_REQUIRES_INSPECTION') from None
    if result.returncode or 'error_code' in public: return public, 1
    output = {'schema': 1, 'mode': envelope['mode'], 'result': public, 'non_claude_moderation_disabled': True,
              'notebook_registration_performed': False}
    if envelope['mode'] == 'check':
        check_id = secrets.token_hex(16)
        receipt = {'schema': 1, 'check_id': check_id, 'observed_at': int(time.time()),
            'release_sha256': envelope['release_sha256'], 'request': request, 'result': public}
        raw = encoded(receipt)
        with (checks / (check_id + '.json')).open('xb') as stream: stream.write(raw)
        output.update(check_id=check_id, check_receipt_sha256=sha(raw), check_valid_seconds=1800)
    return output, 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--request-file', type=Path, required=True)
    parser.add_argument('--request-sha256', required=True)
    args = parser.parse_args(); os.umask(0o077)
    try:
        raw = args.request_file.read_bytes()
        demand(len(raw) <= 12000 and sha(raw) == args.request_sha256, 'RUN_REQUEST_CHANGED')
        envelope = json.loads(raw); validate_request(envelope, int(time.time()))
        files = load_release(ROOT, envelope['release_sha256'])
        if not args.execute:
            print(json.dumps({'status':'inputs_verified_not_executed','mode':envelope['mode'],'docker_called':False}))
            return 0
        output, code = execute(files, envelope)
        print(json.dumps(output, sort_keys=True)); return code
    except BaseException as error:
        code = str(error) if type(error) is RuntimeError and re.fullmatch('[A-Z0-9_]{1,100}', str(error)) else 'PROVISION_RUNNER_STOPPED_REQUIRES_INSPECTION'
        print(json.dumps({'schema':1,'error_code':code,'credentials_printed':False,'automatic_rollback':False})); return 1


if __name__ == '__main__': sys.exit(main())
