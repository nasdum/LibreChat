"""One-use OAuth credential transport. No plaintext CLI output or network calls."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import time

ROOT = Path('/root/.vendos-google-oauth-transport')
ALGORITHM = 'RSA-OAEP-256'
CALLBACK = 'https://chat.nasdum.cz/oauth/google/callback'
PROJECT = 'nasdum-librechat-login'
HEX = re.compile(r'[a-f0-9]{64}\Z')
KEY_ID = re.compile(r'[a-f0-9]{32}\Z')
CLIENT = re.compile(r'[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com\Z')
SECRET = re.compile(r'[A-Za-z0-9_-]{20,160}\Z')
MAX_PLAINTEXT = 318  # RSA3072 OAEP-SHA256: 384 - 2*32 - 2


class TransportError(Exception):
    pass


def require(condition, code):
    if not condition:
        raise TransportError(code)


def sha(value):
    return hashlib.sha256(value).hexdigest()


def decode_json(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            require(key not in result, 'DUPLICATE_JSON_FIELD')
            result[key] = value
        return result
    try:
        require(len(raw) <= 16384, 'JSON_TOO_LARGE')
        return json.loads(raw, object_pairs_hook=pairs)
    except TransportError:
        raise
    except Exception:
        raise TransportError('INVALID_JSON') from None


def compact(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def root_only():
    require(os.name == 'posix' and os.geteuid() == 0, 'ROOT_LINUX_REQUIRED')


def secured(path, directory=False):
    require(path.is_absolute() and path.resolve() == path, 'UNSAFE_PRIVATE_PATH')
    info = path.lstat()
    require(not stat.S_ISLNK(info.st_mode), 'SYMLINK_REJECTED')
    require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode), 'PRIVATE_PATH_TYPE')
    require(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o600), 'PRIVATE_PATH_PERMISSIONS')
    if not directory:
        require(info.st_nlink == 1, 'PRIVATE_HARDLINK_REJECTED')


def write_exclusive(path, data):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, 'wb') as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
    except Exception:
        raise TransportError('PRIVATE_WRITE_FAILED') from None


def openssl(args, data=None):
    try:
        result = subprocess.run(['openssl', *args], input=data, capture_output=True, check=False, timeout=60)
    except Exception:
        raise TransportError('OPENSSL_UNAVAILABLE') from None
    require(result.returncode == 0, 'OPENSSL_OPERATION_FAILED')
    return result.stdout


def validate_public(value, now=None):
    fields = {'schema', 'algorithm', 'key_id', 'public_key_pem', 'public_key_sha256', 'created_at', 'expires_at'}
    require(type(value) is dict and set(value) == fields, 'INVALID_PUBLIC_METADATA')
    require(type(value['schema']) is int and value['schema'] == 1 and value['algorithm'] == ALGORITHM, 'INVALID_PUBLIC_METADATA')
    require(type(value['key_id']) is str and KEY_ID.fullmatch(value['key_id']), 'INVALID_KEY_ID')
    pem = value['public_key_pem']
    require(type(pem) is str and len(pem) < 2048 and pem.startswith('-----BEGIN PUBLIC KEY-----\n') and pem.endswith('-----END PUBLIC KEY-----\n'), 'INVALID_PUBLIC_KEY')
    require(type(value['public_key_sha256']) is str and HEX.fullmatch(value['public_key_sha256']) and sha(pem.encode()) == value['public_key_sha256'], 'PUBLIC_KEY_HASH_MISMATCH')
    require(type(value['created_at']) is int and type(value['expires_at']) is int and value['expires_at'] == value['created_at'] + 3600, 'INVALID_KEY_LIFETIME')
    at = int(time.time()) if now is None else now
    require(value['created_at'] <= at + 60 and value['expires_at'] > at, 'KEY_EXPIRED_OR_FUTURE')
    return value


def generate(*, root=ROOT):
    root_only()
    require(root.is_absolute() and root.resolve() == root and not root.is_symlink(), 'UNSAFE_PRIVATE_PATH')
    root.mkdir(mode=0o700, exist_ok=True)
    secured(root, True)
    key_id = secrets.token_hex(16)
    directory = root / key_id
    directory.mkdir(mode=0o700)
    secured(directory, True)
    private = directory / 'private.pem'
    # Pre-create with the restrictive mode before OpenSSL opens its output.
    write_exclusive(private, b'')
    try:
        openssl(['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:3072', '-out', str(private)])
        secured(private)
        public = openssl(['pkey', '-in', str(private), '-pubout']).decode('ascii')
        at = int(time.time())
        result = {'schema': 1, 'algorithm': ALGORITHM, 'key_id': key_id, 'public_key_pem': public,
                  'public_key_sha256': sha(public.encode()), 'created_at': at, 'expires_at': at + 3600}
        validate_public(result, at)
        write_exclusive(directory / 'metadata.json', compact(result))
        return result
    except Exception:
        private.unlink(missing_ok=True)
        raise


def validate_credentials(value, expected_client_id):
    require(type(expected_client_id) is str and CLIENT.fullmatch(expected_client_id), 'INVALID_EXPECTED_CLIENT')
    require(type(value) is dict and set(value) == {'client_id', 'client_secret'}, 'INVALID_CREDENTIAL_FIELDS')
    require(value['client_id'] == expected_client_id, 'CLIENT_ID_MISMATCH')
    require(type(value['client_secret']) is str and SECRET.fullmatch(value['client_secret']), 'INVALID_CLIENT_SECRET')
    require(len(compact(value)) <= MAX_PLAINTEXT, 'CREDENTIAL_PAYLOAD_TOO_LARGE')
    return value


def credentials_from_download(download, expected_client_id, expected_project=PROJECT):
    require(expected_project == PROJECT, 'UNEXPECTED_PROJECT')
    require(type(download) is dict and set(download) == {'web'} and type(download['web']) is dict, 'EXPECTED_GOOGLE_WEB_CLIENT')
    web = download['web']
    require(web.get('project_id') == expected_project, 'PROJECT_MISMATCH')
    require(web.get('redirect_uris') == [CALLBACK], 'REDIRECT_MISMATCH')
    require(web.get('javascript_origins', []) in ([], ['https://chat.nasdum.cz']), 'ORIGIN_MISMATCH')
    require(web.get('auth_uri') == 'https://accounts.google.com/o/oauth2/auth' and web.get('token_uri') == 'https://oauth2.googleapis.com/token', 'GOOGLE_ENDPOINT_MISMATCH')
    require(web.get('auth_provider_x509_cert_url') == 'https://www.googleapis.com/oauth2/v1/certs', 'GOOGLE_CERT_ENDPOINT_MISMATCH')
    return validate_credentials({'client_id': web.get('client_id'), 'client_secret': web.get('client_secret')}, expected_client_id)


def seal(credentials, public_metadata, expected_client_id):
    # Notebook only: server generation/decryption needs Python stdlib and OpenSSL.
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    public_metadata = validate_public(public_metadata)
    value = validate_credentials(credentials, expected_client_id)
    try:
        key = serialization.load_pem_public_key(public_metadata['public_key_pem'].encode())
        require(isinstance(key, rsa.RSAPublicKey) and key.key_size == 3072 and key.public_numbers().e == 65537, 'UNEXPECTED_RSA_KEY')
        ciphertext = key.encrypt(compact(value), padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    except TransportError:
        raise
    except Exception:
        raise TransportError('PUBLIC_ENCRYPTION_FAILED') from None
    return {'schema': 1, 'algorithm': ALGORITHM, 'key_id': public_metadata['key_id'],
            'public_key_sha256': public_metadata['public_key_sha256'],
            'ciphertext_b64': base64.b64encode(ciphertext).decode('ascii'), 'ciphertext_sha256': sha(ciphertext)}


def validate_envelope(value):
    fields = {'schema', 'algorithm', 'key_id', 'public_key_sha256', 'ciphertext_b64', 'ciphertext_sha256'}
    require(type(value) is dict and set(value) == fields and type(value['schema']) is int and value['schema'] == 1 and value['algorithm'] == ALGORITHM, 'INVALID_ENVELOPE')
    require(type(value['key_id']) is str and KEY_ID.fullmatch(value['key_id']), 'INVALID_KEY_ID')
    for field in ('public_key_sha256', 'ciphertext_sha256'):
        require(type(value[field]) is str and HEX.fullmatch(value[field]), 'INVALID_FINGERPRINT')
    try:
        require(type(value['ciphertext_b64']) is str and len(value['ciphertext_b64']) == 512, 'INVALID_CIPHERTEXT')
        ciphertext = base64.b64decode(value['ciphertext_b64'], validate=True)
    except (ValueError, TypeError):
        raise TransportError('INVALID_CIPHERTEXT') from None
    require(len(ciphertext) == 384 and sha(ciphertext) == value['ciphertext_sha256'], 'CIPHERTEXT_HASH_MISMATCH')
    return ciphertext


def decrypt(envelope, expected_client_id, *, root=ROOT):
    root_only()
    ciphertext = validate_envelope(envelope)
    require(type(expected_client_id) is str and CLIENT.fullmatch(expected_client_id), 'INVALID_EXPECTED_CLIENT')
    secured(root, True)
    directory = root / envelope['key_id']
    secured(directory, True)
    metadata_path = directory / 'metadata.json'
    secured(metadata_path)
    metadata = validate_public(decode_json(metadata_path.read_bytes()))
    require(metadata['key_id'] == envelope['key_id'] and metadata['public_key_sha256'] == envelope['public_key_sha256'], 'KEY_METADATA_MISMATCH')
    private = directory / 'private.pem'
    require(not (directory / 'consumed.json').exists(), 'KEY_ALREADY_CONSUMED')
    secured(private)
    try:
        write_exclusive(directory / 'consumed.json', compact({'schema': 1, 'consumed_at': int(time.time()), 'ciphertext_sha256': envelope['ciphertext_sha256']}))
    except FileExistsError:
        raise TransportError('KEY_ALREADY_CONSUMED') from None
    try:
        raw = openssl(['pkeyutl', '-decrypt', '-inkey', str(private), '-pkeyopt', 'rsa_padding_mode:oaep',
                       '-pkeyopt', 'rsa_oaep_md:sha256', '-pkeyopt', 'rsa_mgf1_md:sha256'], ciphertext)
        require(len(raw) <= MAX_PLAINTEXT, 'CREDENTIAL_PAYLOAD_TOO_LARGE')
        return validate_credentials(decode_json(raw), expected_client_id)
    finally:
        private.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--generate', action='store_true')
    modes.add_argument('--seal', action='store_true')
    parser.add_argument('--client-file', type=Path)
    parser.add_argument('--public-file', type=Path)
    parser.add_argument('--expected-client-id')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    try:
        if args.generate:
            require(not any((args.client_file, args.public_file, args.expected_client_id, args.output)), 'UNEXPECTED_GENERATE_ARGUMENTS')
            print(json.dumps(generate(), sort_keys=True))
            return
        require(all((args.client_file, args.public_file, args.expected_client_id, args.output)), 'SEAL_ARGUMENTS_REQUIRED')
        value = credentials_from_download(decode_json(args.client_file.read_bytes()), args.expected_client_id)
        envelope = seal(value, decode_json(args.public_file.read_bytes()), args.expected_client_id)
        # Envelope contains no plaintext secret. Refuse replacing prior requests.
        write_exclusive(args.output, compact(envelope) + b'\n')
        print(json.dumps({'schema': 1, 'status': 'sealed', 'key_id': envelope['key_id'],
                          'envelope_sha256': sha(args.output.read_bytes()), 'ciphertext_sha256': envelope['ciphertext_sha256']}))
    except BaseException as error:
        code = str(error) if isinstance(error, TransportError) else 'TRANSPORT_OPERATION_FAILED'
        print(json.dumps({'schema': 1, 'status': 'stopped', 'error_code': code}))
        raise SystemExit(1) from None


if __name__ == '__main__':
    main()
