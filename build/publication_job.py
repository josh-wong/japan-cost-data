#!/usr/bin/env python3
"""Public repository workflow orchestration. Only prepare extracts release archives."""

import argparse
import base64
import datetime as dt
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

from publisher import change_summary, read_release, regular_bytes, release_names, verify_candidate, write_archive
from schema_tools import fixture_bytes, load_json, sha256_hex
from sign_release import verify_envelope


def gh(*args):
    return subprocess.check_output(['gh', *args], text=True)


def candidate_info(tag):
    # REST created_at (also exposed by gh release view) is the target commit date.
    # GraphQL createdAt is the release object's creation time, including for drafts.
    owner, name = os.environ['GITHUB_REPOSITORY'].split('/')
    query = '''query($owner: String!, $name: String!, $tag: String!) {
        repository(owner: $owner, name: $name) {
            release(tagName: $tag) { isDraft createdAt body: description }
        }
    }'''
    response = json.loads(gh('api', 'graphql', '-f', f'query={query}',
                             '-f', f'owner={owner}', '-f', f'name={name}', '-f', f'tag={tag}'))
    info = response['data']['repository']['release']
    if info is None:
        raise ValueError('candidate release is missing or inaccessible')
    return info


def state_from_remote():
    # A missing state file is permitted only when the branch really has no state
    # yet; auth errors and all other API failures must fail closed.
    listing = json.loads(gh('api', f"repos/{os.environ['GITHUB_REPOSITORY']}/contents?ref=state"))
    if not any(e['name'] == 'state.json' for e in listing):
        return {}
    file = json.loads(gh('api', f"repos/{os.environ['GITHUB_REPOSITORY']}/contents/state.json?ref=state"))
    return json.loads(base64.b64decode(file['content']))


def merge(source, destination):
    for path in source.rglob('*'):
        if not path.is_file():
            continue
        name = path.relative_to(source).as_posix()
        file_bytes = regular_bytes(source, name)
        target = destination / name
        if target.exists() and target.read_bytes() != file_bytes:
            raise ValueError('conflicting immutable paths')
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(file_bytes)


def download(tag, directory):
    assets = json.loads(gh('release', 'view', tag, '--json', 'assets'))['assets']
    wanted = [a for a in assets if a['name'] in ('release.tar.gz', 'release-manifest.json')]
    if len(wanted) != 2 or any(a['size'] > 512 * 1024 * 1024 for a in wanted):
        raise ValueError('missing or oversized release assets')
    directory.mkdir(parents=True)
    gh('release', 'download', tag, '--pattern', 'release.tar.gz', '--pattern', 'release-manifest.json',
       '--dir', str(directory))


def prepare(mode, tag, output):
    if mode not in ('publish', 'resign', 'rollback'):
        raise ValueError('unknown mode')
    state = state_from_remote()
    keys = {k['keyId']: base64.b64decode(k['publicKey'], validate=True) for k in load_json(Path('keys/public-keys.json'))['keys']}
    if state:
        signed = verify_envelope(state['lastManifest'], keys)
        if signed['releaseId'] != state['currentRelease']:
            raise ValueError('state current release differs from its signed manifest')
    output.mkdir()
    root = output / 'verified'
    root.mkdir()
    now = dt.datetime.now(dt.timezone.utc)
    issued_at = now.strftime('%Y-%m-%dT%H:%M:%SZ')
    with tempfile.TemporaryDirectory() as temp:
        temp = Path(temp)
        for release_id in state.get('retained', []):
            release_temp = temp / 'retained' / release_id
            assets = release_temp / 'assets'
            download(release_id, assets)
            manifest = assets / 'release-manifest.json'
            if sha256_hex(manifest.read_bytes()) != state['releaseDigests'][release_id]:
                raise ValueError('archive manifest differs from trusted state')
            extracted = release_temp / 'files'
            verify_candidate(assets / 'release.tar.gz', manifest, extracted, None)
            merge(extracted, root)
        previous = read_release(root, state['currentRelease']) if state else None
        if mode == 'publish':
            if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,63}', tag):
                raise ValueError('invalid candidate tag')
            info = candidate_info(tag)
            if not info['isDraft'] or now - dt.datetime.fromisoformat(info['createdAt'].replace('Z', '+00:00')) > dt.timedelta(days=14):
                raise ValueError('candidate is published or expired')
            metadata = json.loads(info['body'])
            if metadata['baseRelease'] != state.get('currentRelease') or metadata['target'] != 'production':
                raise ValueError('candidate is superseded or is development data')
            assets = temp / 'candidate'
            download(tag, assets)
            candidate = verify_candidate(assets / 'release.tar.gz', assets / 'release-manifest.json',
                                         temp / 'candidate-files', issued_at, previous)
            if candidate.manifest['releaseId'] != tag or tag in state.get('releaseDigests', {}):
                raise ValueError('candidate ID is reused or mismatched')
            # Evicted paths may still be cached as immutable. Only retained,
            # trusted bytes can be reused outside the candidate's own release.
            for name in release_names(candidate):
                if not name.startswith(f'releases/{tag}/'):
                    if (not (root / name).is_file()
                            or regular_bytes(root, name) != regular_bytes(temp / 'candidate-files', name)):
                        raise ValueError(f'path outside candidate release must match a trusted retained file: {name}')
            merge(temp / 'candidate-files', root)
            summary = change_summary(candidate, previous)
            created_at = info['createdAt']
        else:
            tag = state.get('currentRelease') if mode == 'resign' else tag
            if tag not in state.get('retained', []):
                raise ValueError('requested release is not retained')
            candidate = read_release(root, tag)
            summary = {'requiresApproval': mode == 'rollback', 'reasons': [mode]}
            created_at = issued_at
    manifest_digest = sha256_hex(regular_bytes(root, candidate.path))
    metadata = {'mode': mode, 'releaseId': tag, 'baseRelease': state.get('currentRelease'),
                'createdAt': created_at, 'manifestDigest': manifest_digest}
    (output / 'request.json').write_bytes(fixture_bytes(metadata))
    (output / 'change-summary.json').write_bytes(fixture_bytes(summary))
    with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
        stream.write(f"approval={str(summary['requiresApproval']).lower()}\nmanifest_digest={manifest_digest}\n")
    with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as stream:
        stream.write('## Release change summary\n\n```json\n' + json.dumps(summary, indent=2) + '\n```\n')


def check_request(directory, expected_digest):
    request = load_json(directory / 'request.json')
    state = state_from_remote()
    if request['baseRelease'] != state.get('currentRelease'):
        raise ValueError('superseded candidate or stale re-sign preparation; run again')
    if dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(request['createdAt'].replace('Z', '+00:00')) > dt.timedelta(days=14):
        raise ValueError('request approval expired')
    manifest = directory / 'verified' / f"releases/{request['releaseId']}/release-manifest.json"
    if sha256_hex(manifest.read_bytes()) != expected_digest or request['manifestDigest'] != expected_digest:
        raise ValueError('verified manifest changed after approval')
    Path('state/state.json').write_bytes(fixture_bytes(state))
    with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
        stream.write(f"release_id={request['releaseId']}\nbase_release={request['baseRelease'] or ''}\nmode={request['mode']}\n")


def store_archive(directory, expected_digest):
    """Store and read back recovery assets before signing or advancing state.

    Rebuild only from verified regular files. The signing job never extracts the
    downloaded archive; comparing its bytes verifies durable storage independently.
    A failed or partial upload leaves the existing active release unchanged.
    """
    request = load_json(directory / 'request.json')
    root = directory / 'verified'
    release = read_release(root, request['releaseId'])
    manifest = regular_bytes(root, release.path)
    if sha256_hex(manifest) != expected_digest or request['manifestDigest'] != expected_digest:
        raise ValueError('verified manifest changed before archive storage')
    info = json.loads(gh('release', 'view', request['releaseId'], '--json', 'isDraft'))
    if not info['isDraft']:
        raise ValueError('cannot replace published recovery assets')
    with tempfile.TemporaryDirectory() as temp:
        temp = Path(temp)
        archive = temp / 'release.tar.gz'
        manifest_asset = temp / 'release-manifest.json'
        write_archive(root, release_names(release), archive)
        manifest_asset.write_bytes(manifest)
        gh('release', 'upload', request['releaseId'], str(archive), str(manifest_asset), '--clobber')
        restored = temp / 'readback'
        download(request['releaseId'], restored)
        for name in ('release.tar.gz', 'release-manifest.json'):
            if sha256_hex((temp / name).read_bytes()) != sha256_hex((restored / name).read_bytes()):
                raise ValueError('stored recovery asset differs from verified bytes')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['prepare', 'check', 'archive'])
    parser.add_argument('--mode', default='resign')
    parser.add_argument('--tag', default='')
    parser.add_argument('--directory', type=Path, default=Path('prepared'))
    parser.add_argument('--expected-digest')
    args = parser.parse_args()
    if args.operation == 'prepare':
        prepare(args.mode, args.tag, args.directory)
    elif args.operation == 'check':
        check_request(args.directory, args.expected_digest)
    else:
        store_archive(args.directory, args.expected_digest)


if __name__ == '__main__':
    main()
