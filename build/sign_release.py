#!/usr/bin/env python3
"""Trusted signing and retention helpers. Never open a candidate archive here."""

import argparse
import base64
import datetime as dt
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from publisher import read_release, regular_bytes, release_names, validate
from schema_tools import canonical_json, fixture_bytes, load_json, sha256_hex


def verify_envelope(envelope, keys):
    validate('signed-manifest', envelope)
    raw = base64.b64decode(envelope['manifest'], validate=True)
    Ed25519PublicKey.from_public_bytes(keys[envelope['signingKeyId']]).verify(
        base64.b64decode(envelope['signature'], validate=True), raw)
    manifest = json.loads(raw)
    validate('manifest', manifest)
    if canonical_json(manifest) != raw or manifest['signingKeyId'] != envelope['signingKeyId']:
        raise ValueError('noncanonical manifest or key mismatch')
    return manifest


def sign(root, release_id, state, key_id, private_key, keys, issued_at, live=None, expected_base=None):
    """Call only under the shared sign/deploy lock, after loading the latest state.

    The caller commits returned state before making the manifest reachable. A failed
    deployment consumes a counter; retrying must never reuse that signed sequence.
    """
    now = dt.datetime.strptime(issued_at, '%Y-%m-%dT%H:%M:%SZ')
    # Only previously signed, retained releases may bypass source freshness for
    # renewal/rollback. A candidate can become stale while approval or queueing waits.
    is_retained = release_id in state.get('retained', []) and release_id in state.get('releaseDigests', {})
    release = read_release(root, release_id, None if is_retained else issued_at)
    for kind in ('series-bundle', 'baseline'):
        for _, document in release.files(kind):
            sources = [s['source'] for s in document['series']] if kind == 'series-bundle' else [document['source']]
            if any(source['retrievedAt'] > issued_at for source in sources):
                raise ValueError('source retrieval is later than signing time')
    if expected_base is not None and state.get('currentRelease') != expected_base:
        raise ValueError('candidate was superseded; rebuild against the latest release')
    if private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw) != keys[key_id]:
        raise ValueError('private key does not match configured public key')
    stored = state.get('sequenceByKey', {}).get(key_id, 0)
    live_sequence = 0
    if live is not None:
        live_manifest = verify_envelope(live, keys)
        if issued_at < live_manifest['issuedAt']:
            raise ValueError('issuedAt cannot precede the live signed manifest')
        if live_manifest['signingKeyId'] == key_id:
            live_sequence = live_manifest['sequence']
        if stored >= live_sequence + 1000:
            raise ValueError('stored sequence exceeds live counter by the client jump limit')
    elif state.get('lastManifest'):
        raise ValueError('live manifest is required after bootstrap')
    if state.get('lastManifest'):
        prior = verify_envelope(state['lastManifest'], keys)
        if issued_at < prior['issuedAt']:
            raise ValueError('issuedAt cannot go backwards')
    sequence = max(stored, live_sequence) + 1
    for entry in release.manifest['files']:
        data = regular_bytes(root, entry['path'])
        if entry['bytes'] != len(data) or entry['sha256'] != sha256_hex(data):
            raise ValueError('verified files changed during signing')
    payload = {'schemaVersion': 1, 'releaseId': release_id, 'sequence': sequence,
               'issuedAt': issued_at, 'validUntil': (now + dt.timedelta(days=45)).strftime('%Y-%m-%dT%H:%M:%SZ'),
               'signingKeyId': key_id, 'supersedesKeyId': None,
               'releaseManifest': {'path': release.path, 'sha256': sha256_hex(regular_bytes(root, release.path))}}
    validate('manifest', payload)
    raw = canonical_json(payload)
    envelope = {'schemaVersion': 1, 'signingKeyId': key_id,
                'manifest': base64.b64encode(raw).decode(),
                'signature': base64.b64encode(private_key.sign(raw)).decode()}
    validate('signed-manifest', envelope)
    counters = dict(state.get('sequenceByKey', {}))
    counters[key_id] = sequence
    retained = [release_id] + [r for r in state.get('retained', []) if r != release_id]
    # Keep every used ID pinned, even after its files leave the retention window:
    # clients can still have the old immutable URLs cached.
    digests = dict(state.get('releaseDigests', {}))
    pinned = payload['releaseManifest']['sha256']
    if release_id in digests and digests[release_id] != pinned:
        raise ValueError('attempt to overwrite an immutable release')
    digests[release_id] = pinned
    retained = retained[:3]
    return envelope, {'sequenceByKey': counters, 'currentRelease': release_id,
                      'retained': retained, 'releaseDigests': digests,
                      'lastManifest': envelope}


def build_site(root, state, destination):
    """Reconstruct the whole site from verified archives; retain referenced older paths."""
    if destination.exists():
        raise ValueError('site destination must not exist')
    names = set()
    for release_id in state['retained']:
        release = read_release(root, release_id)
        if sha256_hex(regular_bytes(root, release.path)) != state['releaseDigests'][release_id]:
            raise ValueError('retained release does not match trusted state')
        names |= release_names(release)
    for name in sorted(names):
        target = destination / 'v1' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(regular_bytes(root, name))
    # Manifest is written last. Hosts publish the resulting snapshot atomically.
    (destination / 'v1' / 'manifest.json').write_bytes(fixture_bytes(state['lastManifest']))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--release-id', required=True)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--keys', type=Path, required=True)
    parser.add_argument('--key-id', required=True)
    parser.add_argument('--live', type=Path)
    parser.add_argument('--issued-at', required=True)
    parser.add_argument('--expected-base')
    parser.add_argument('--site', type=Path, required=True)
    args = parser.parse_args()
    keys = {k['keyId']: base64.b64decode(k['publicKey'], validate=True) for k in load_json(args.keys)['keys']}
    # Existing production secret is a base64 raw 32-byte Ed25519 private key.
    private = Ed25519PrivateKey.from_private_bytes(base64.b64decode(os.environ['SIGNING_PRIVATE_KEY'], validate=True))
    state = load_json(args.state) if args.state.exists() else {}
    envelope, updated = sign(args.root, args.release_id, state, args.key_id, private, keys, args.issued_at,
                             load_json(args.live) if args.live else None, args.expected_base)
    build_site(args.root, updated, args.site)
    temporary = args.state.with_suffix('.tmp')
    temporary.write_bytes(fixture_bytes(updated))
    temporary.replace(args.state)


if __name__ == '__main__':
    main()
