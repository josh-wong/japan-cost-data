#!/usr/bin/env python3
"""Select a verified host manifest before signing, independently of host health."""

import argparse
import base64
import json
import urllib.error
import urllib.request
from http.client import HTTPException
from pathlib import Path

from cryptography.exceptions import InvalidSignature

from schema_tools import fixture_bytes, load_json
from sign_release import verify_envelope

HOSTS = ('https://www.080f53.com/japan-cost-data/v1/manifest.json',
         'https://japan-cost-data.web.app/v1/manifest.json')
MAX_ENVELOPE_BYTES = 65536


def fetch(url):
    with urllib.request.urlopen(url, timeout=15) as response:
        raw = response.read(MAX_ENVELOPE_BYTES + 1)
    if len(raw) > MAX_ENVELOPE_BYTES:
        raise ValueError('host manifest exceeds size limit')
    return raw


def select_live(state, keys, key_id, fetcher=fetch):
    if not state.get('lastManifest'):
        return None  # First publication; the protected state branch has no counter yet.
    valid, invalid = [], False
    for index, url in enumerate(HOSTS, 1):
        try:
            raw = fetcher(url)
        except urllib.error.HTTPError as error:
            if error.code >= 500:
                print(f'::warning::Host {index} is unavailable; checking the other sequence witnesses.')
            else:
                # A reachable host that lacks the manifest disagrees with the stored state.
                invalid = True
                print(f'::warning::Host {index} answered HTTP {error.code}; checking the other host.')
            continue
        except OSError:
            print(f'::warning::Host {index} is unavailable; checking the other sequence witnesses.')
            continue
        except (ValueError, HTTPException):
            # A malformed or truncated HTTP response is an invalid witness,
            # so it must not enable the both-hosts-offline recovery path.
            invalid = True
            print(f'::warning::Host {index} returned an invalid manifest; checking the other host.')
            continue
        try:
            envelope = json.loads(raw)
            manifest = verify_envelope(envelope, keys)
        except (ValueError, KeyError, TypeError, RecursionError, InvalidSignature):
            invalid = True
            print(f'::warning::Host {index} returned an invalid manifest; checking the other host.')
            continue
        valid.append((envelope, manifest))
    if valid:
        # Check both hosts, even if the primary verifies: a newer fallback counter
        # must not be hidden by a stale but correctly signed primary response.
        matching = [entry for entry in valid if entry[1]['signingKeyId'] == key_id]
        candidates = matching or valid
        return max(candidates, key=lambda entry: (entry[1]['sequence'], entry[1]['issuedAt']))[0]
    if invalid:
        raise ValueError('no host supplied a valid manifest; refusing to sign')
    # When both hosts are offline, repair remains possible from the protected,
    # previously signed state. An invalid reachable witness never takes this path.
    verify_envelope(state['lastManifest'], keys)
    print('::warning::Both hosts are unavailable; using the last signed state as the sequence witness.')
    return state['lastManifest']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--keys', type=Path, required=True)
    parser.add_argument('--key-id', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    keys = {key['keyId']: base64.b64decode(key['publicKey'], validate=True)
            for key in load_json(args.keys)['keys']}
    envelope = select_live(load_json(args.state), keys, args.key_id)
    if envelope is not None:
        args.output.write_bytes(fixture_bytes(envelope))


if __name__ == '__main__':
    main()
