"""Run the reviewed two-file overlay with an explicit release and pause proof."""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent
FILES = {'engine_base.py', 'tunnel_switch.py', 'launch.py', 'manifest.json',
         'payload/vendos.cjs', 'payload/vendos.cjs.map'}


def read_pinned(path, digest):
    if not isinstance(digest, str) or not re.fullmatch('[a-f0-9]{64}', digest):
        raise RuntimeError('INVALID_RELEASE_PIN')
    if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(ROOT):
        raise RuntimeError('UNSAFE_RELEASE_PATH')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != digest:
        raise RuntimeError('RELEASE_BYTES_CHANGED')
    return raw


def inputs(release_hash, pause_hash):
    release = json.loads(read_pinned(ROOT / 'release-files.json', release_hash))
    if set(release) != {'schema', 'file_sha256'} or release['schema'] != 1 or set(release['file_sha256']) != FILES:
        raise RuntimeError('WRONG_RELEASE_FILES')
    files = {name: read_pinned(ROOT / name, digest) for name, digest in release['file_sha256'].items()}
    proof = json.loads(read_pinned(ROOT / 'notebook-pause-proof.json', pause_hash))
    return json.loads(files['manifest.json']), proof


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release-sha256', required=True)
    parser.add_argument('--pause-sha256', required=True)
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    try:
        manifest, proof = inputs(args.release_sha256, args.pause_sha256)
        import tunnel_switch
        tunnel_switch.load_payload(manifest, ROOT / 'payload')
        tunnel_switch.validate_pause(proof, dt.datetime.now(dt.timezone.utc))
        value = tunnel_switch.execute(manifest, proof) if args.execute else {'status': 'checked'}
        print(json.dumps(value, sort_keys=True))
        return 0
    except BaseException as error:
        code = str(error)
        if not isinstance(error, RuntimeError) or not re.fullmatch('[A-Z_]{1,100}', code):
            code = 'TUNNEL_SWITCH_FAILED_REQUIRES_INSPECTION'
        print(json.dumps({'status': 'stopped', 'error_code': code}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
