#!/usr/bin/env python3
"""Deploy a complete static snapshot with Firebase Hosting's atomic version API.

Credential JSON comes from the environment, is never written to disk, and never
enters logs. The same command supports a local development preview deployment.
"""

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path

from google.auth.transport.requests import AuthorizedSession
from google.oauth2.service_account import Credentials


def deploy(site, project):
    if project not in ('japan-cost-data', 'japan-cost-data-dev'):
        raise ValueError('unknown Hosting project')
    files = {}
    for path in site.rglob('*'):
        if path.is_symlink():
            raise ValueError('site must not contain links')
        if path.is_file():
            name = '/' + path.relative_to(site).as_posix()
            if not name.startswith('/v1/') or not name.endswith('.json'):
                raise ValueError('unexpected site file')
            files[name] = gzip.compress(path.read_bytes(), mtime=0)
    if '/v1/manifest.json' not in files:
        raise ValueError('site has no signed manifest')
    credentials = Credentials.from_service_account_info(json.loads(os.environ['FIREBASE_SERVICE_ACCOUNT']),
                    scopes=['https://www.googleapis.com/auth/firebase.hosting'])
    session = AuthorizedSession(credentials)
    base = f'https://firebasehosting.googleapis.com/v1beta1/sites/{project}'

    def request(method, url, **kwargs):
        response = session.request(method, url, timeout=120, **kwargs)
        # Do not print responses or request headers: errors must not disclose credentials.
        if not response.ok:
            raise RuntimeError(f'Hosting API returned HTTP {response.status_code}')
        return response.json() if response.content and 'json' in response.headers.get('Content-Type', '') else {}

    version = request('POST', base + '/versions', json={'config': {'headers': [
        {'glob': '/v1/manifest.json', 'headers': {'Cache-Control': 'public,max-age=0,must-revalidate'}},
        {'glob': '/v1/releases/**', 'headers': {'Cache-Control': 'public,max-age=31536000,immutable'}}]}})
    hashes = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
    by_digest = {hashes[name]: data for name, data in files.items()}
    for offset in range(0, len(hashes), 1000):
        chunk = dict(list(hashes.items())[offset:offset + 1000])
        populated = request('POST', 'https://firebasehosting.googleapis.com/v1beta1/' + version['name'] + ':populateFiles', json={'files': chunk})
        upload_url = populated.get('uploadUrl', '')
        if populated.get('uploadRequiredHashes') and not upload_url.startswith('https://upload-firebasehosting.googleapis.com/'):
            raise ValueError('unexpected Hosting upload endpoint')
        for digest in populated.get('uploadRequiredHashes', []):
            request('POST', upload_url + '/' + digest, data=by_digest[digest], headers={'Content-Type': 'application/octet-stream'})
    request('PATCH', 'https://firebasehosting.googleapis.com/v1beta1/' + version['name'] + '?update_mask=status', json={'status': 'FINALIZED'})
    # The live release changes only after every file (including the manifest) is finalized.
    request('POST', base + '/releases?versionName=' + version['name'], json={})
    print(f'Deployed complete snapshot to {project}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--site', type=Path, required=True)
    parser.add_argument('--project', required=True)
    args = parser.parse_args()
    deploy(args.site, args.project)
