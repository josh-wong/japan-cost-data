#!/usr/bin/env python3
"""Build and independently verify unsigned release candidates (issue #12).

No network requests or private keys are used here. Paths are relative to /v1/.
"""

import argparse
import contextlib
import gzip
import io
import json
import re
import tarfile
from pathlib import Path, PurePosixPath

import validate_schemas as checks
from release_checks import Release, mover_pair, observed
from schema_tools import fixture_bytes, load_json, sha256_hex

MAX_FILE = 50 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024
MAX_FILES = 10000
RELEASE_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")


def validate(kind, document):
    errors = checks.errors_for(kind, document)
    if errors:
        raise ValueError(f"{kind}: {errors[0].message}")


def safe_path(name):
    path = PurePosixPath(name)
    if (not name or path.is_absolute() or any(p in ('', '.', '..') for p in name.split('/'))
            or '\\' in name or path.as_posix() != name):
        raise ValueError(f"unsafe path: {name!r}")
    return path


def regular_bytes(root, name):
    safe_path(name)
    path = root / name
    current = root
    for part in PurePosixPath(name).parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f'linked path: {name}')
    if root.is_symlink() or not path.is_file():
        raise ValueError(f'not a regular file: {name}')
    if path.stat().st_size > MAX_FILE:
        raise ValueError(f"file too large: {name}")
    return path.read_bytes()


def read_release(root, release_id, issued_at=None, previous=None):
    if not RELEASE_ID.fullmatch(release_id):
        raise ValueError('invalid release ID')
    name = f'releases/{release_id}/release-manifest.json'
    manifest = json.loads(regular_bytes(root, name))
    validate('release-manifest', manifest)
    documents = {}
    for entry in manifest['files']:
        path = entry['path']
        safe_path(path)
        file_bytes = regular_bytes(root, path)
        if len(file_bytes) != entry['bytes'] or sha256_hex(file_bytes) != entry['sha256']:
            raise ValueError(f'digest or size mismatch: {path}')
        if checks.kind_of(Path(path)) != entry['kind']:
            raise ValueError(f'kind does not match path: {path}')
        document = json.loads(file_bytes)
        validate(entry['kind'], document)
        documents[path] = document
    # Reuse the complete cross-file checks, including calendar periods, source dates,
    # mover arithmetic, geography, catalog coverage and stable IDs/revisions.
    output = io.StringIO()
    before = checks.failures
    try:
        with contextlib.redirect_stdout(output):
            checks.verify_release_files(root / name, manifest, documents, issued_at, previous, root=root)
        if checks.failures != before:
            raise ValueError(output.getvalue().strip())
    finally:
        checks.failures = before
    return Release(name, manifest, documents)


def extract_archive(archive, destination):
    """Extract only bounded JSON regular files, without tarfile extraction APIs."""
    if destination.exists():
        raise ValueError('extraction destination must not exist')
    total, seen = 0, set()
    with tarfile.open(archive, 'r:gz') as source:
        for member in source:
            safe_path(member.name)
            if (not member.isfile() or member.name in seen or member.size > MAX_FILE
                    or not member.name.endswith('.json')):
                raise ValueError(f'invalid archive member: {member.name}')
            seen.add(member.name)
            total += member.size
            if total > MAX_TOTAL or len(seen) > MAX_FILES:
                raise ValueError('archive exceeds size or file count limit')
            # Only published paths are accepted, including the release manifest.
            checks.kind_of(Path(member.name))
            target = destination / member.name
            target.parent.mkdir(parents=True, exist_ok=True)
            with source.extractfile(member) as stream:
                file_bytes = stream.read(member.size + 1)
            if len(file_bytes) != member.size:
                raise ValueError('truncated archive member')
            target.write_bytes(file_bytes)
    if not seen:
        raise ValueError('empty archive')


def write_archive(root, names, target):
    """Stable gzip/tar metadata makes identical inputs produce identical assets."""
    with target.open('wb') as raw, gzip.GzipFile(filename='', fileobj=raw, mode='wb', mtime=0) as compressed:
        # PAX carries schema-valid filenames beyond USTAR's 100-byte component limit.
        # TarInfo defaults and sorted paths keep its extended headers deterministic too.
        with tarfile.open(fileobj=compressed, mode='w', format=tarfile.PAX_FORMAT) as archive:
            for name in sorted(names):
                file_bytes = regular_bytes(root, name)
                entry = tarfile.TarInfo(name)
                entry.size, entry.mode = len(file_bytes), 0o644
                archive.addfile(entry, io.BytesIO(file_bytes))


def release_names(release):
    return {release.path, *(entry['path'] for entry in release.manifest['files'])}


def verify_candidate(archive, manifest_file, destination, issued_at, previous=None):
    manifest = load_json(manifest_file)
    validate('release-manifest', manifest)
    extract_archive(archive, destination)
    release = read_release(destination, manifest['releaseId'], issued_at, previous)
    if regular_bytes(destination, release.path) != manifest_file.read_bytes():
        raise ValueError('archive and asset release manifests differ')
    actual = {p.relative_to(destination).as_posix() for p in destination.rglob('*') if p.is_file()}
    if actual != release_names(release):
        raise ValueError('archive contains unlisted files')
    return release


def change_summary(current, previous, max_percent=25, max_series_changes=10):
    """Review revisions, newly valued periods and baseline category amounts."""
    if previous is None:
        return {'requiresApproval': True, 'reasons': ['first release'], 'added': [], 'removed': [], 'changes': []}
    old, new = previous.series(), current.series()
    added, removed = sorted(new.keys() - old.keys()), sorted(old.keys() - new.keys())
    changes = []
    for name in sorted(new.keys() & old.keys()):
        prior_rows = observed(old[name][1])
        prior = {r['period']: r['value'] for r in prior_rows}
        last_period = max((r['period'] for r in old[name][1]['observations']), default=None)
        for row in observed(new[name][1]):
            if row['period'] in prior:
                value = prior[row['period']]
                if row['value'] == value:
                    continue
            elif prior_rows and row['period'] > last_period:
                # Compare every appended value with the previous release's last value.
                value = prior_rows[-1]['value']
            else:
                # Historical gaps and series without values have no comparable prior value.
                value = None
            percent = None if value is None or value == 0 else abs((row['value'] / value - 1) * 100)
            changes.append({'seriesId': name, 'period': row['period'], 'percent': percent})
    # IDs stay stable across data years. New classifications/categories have no
    # comparable amount, so require review rather than silently skipping them.
    def baseline_amounts(release):
        return {(baseline['baselineId'], category['categoryId']): category['monthlyYen']
                for _, baseline in release.files('baseline') for category in baseline['categories']}

    old_amounts, new_amounts = baseline_amounts(previous), baseline_amounts(current)
    for key in sorted(old_amounts.keys() | new_amounts.keys()):
        before, after = old_amounts.get(key), new_amounts.get(key)
        if before != after:
            percent = None if before is None or after is None else abs((after / before - 1) * 100)
            changes.append({'baselineId': key[0], 'categoryId': key[1],
                            'previousMonthlyYen': before, 'monthlyYen': after, 'percent': percent})
    reasons = []
    if len(added) + len(removed) > max_series_changes:
        reasons.append('series count change exceeds limit')
    if any(c['percent'] is None for c in changes):
        reasons.append('change has no comparable prior value')
    if any(c['percent'] is not None and c['percent'] > max_percent for c in changes):
        reasons.append('value change exceeds limit')
    return {'requiresApproval': bool(reasons), 'reasons': reasons, 'added': added, 'removed': removed, 'changes': changes}


def assemble(input_dir, freshness_file, release_id, output, issued_at, previous_root=None, previous_id=None, keep_ids=(), target="development"):
    """Assemble normalized data with explicit per-series adapter freshness inputs.

    Input contains catalog.json, geography.json, series/ and optional baselines/.
    The publisher derives movers and the release manifest. It never includes raw inputs.
    """
    if target not in ('development', 'production'):
        raise ValueError('unknown release target')
    if not RELEASE_ID.fullmatch(release_id) or release_id in keep_ids or release_id == previous_id:
        raise ValueError('invalid or reused release ID')
    if output.exists():
        raise ValueError('output directory must not exist')
    previous = read_release(previous_root, previous_id) if previous_id else None
    if previous is not None and not keep_ids:
        raise ValueError('supply retained release IDs for safe path reuse')
    blobs = {}
    for path in sorted(input_dir.rglob('*')):
        if path.is_symlink():
            raise ValueError('input links are forbidden')
        if not path.is_file():
            continue
        relative = path.relative_to(input_dir).as_posix()
        full = f'releases/{release_id}/{relative}'
        kind = checks.kind_of(Path(full))
        if kind not in ('catalog', 'geography', 'series-bundle', 'baseline'):
            raise ValueError(f'input not allowed: {relative}')
        file_bytes = regular_bytes(input_dir, relative)
        document = json.loads(file_bytes)
        validate(kind, document)
        blobs[relative] = (kind, fixture_bytes(document), document)
    series = [s for kind, _, doc in blobs.values() if kind == 'series-bundle' for s in doc['series']]
    movers = []
    for s in sorted(series, key=lambda s: s['seriesId']):
        pair = mover_pair(s)
        if pair:
            latest, prior = pair
            movers.append({'seriesId': s['seriesId'], 'latestPeriod': latest['period'], 'latestValue': latest['value'],
                           'previousPeriod': prior['period'], 'previousValue': prior['value'],
                           'percentChange': (latest['value'] / prior['value'] - 1) * 100})
    doc = {'schemaVersion': 1, 'ruleVersion': 'period-change-v1', 'movers': movers}
    blobs['movers.json'] = ('movers', fixture_bytes(doc), doc)
    freshness = load_json(freshness_file)
    if set(freshness) != {s['seriesId'] for s in series}:
        raise ValueError('freshness inputs must name every series exactly once')
    entries, series_entries = [], []
    old_entries = previous.manifest['files'] if previous else []
    root = output / 'verified'
    for relative, (kind, file_bytes, _) in sorted(blobs.items()):
        name = f'releases/{release_id}/{relative}'
        digest = sha256_hex(file_bytes)
        for old in old_entries:
            # Only reuse paths inside the retention window. Republish older unchanged files.
            if (old['kind'] == kind and old['path'].split('/', 2)[2] == relative
                    and old['sha256'] == digest and old['path'].split('/')[1] in keep_ids):
                name = old['path']
                break
        destination = root / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(file_bytes)
        entries.append({'kind': kind, 'path': name, 'bytes': len(file_bytes), 'sha256': digest})
    for s in sorted(series, key=lambda s: s['seriesId']):
        rows = observed(s)
        policy = freshness[s['seriesId']]
        series_entries.append({'seriesId': s['seriesId'], 'frequency': s['frequency'],
                               'latestObservationPeriod': rows[-1]['period'] if rows else None,
                               'expectedNextRelease': policy['expectedNextRelease'], 'graceDays': policy['graceDays']})
    manifest = {'schemaVersion': 1, 'releaseId': release_id, 'files': entries, 'series': series_entries}
    name = f'releases/{release_id}/release-manifest.json'
    (root / name).parent.mkdir(parents=True, exist_ok=True)
    (root / name).write_bytes(fixture_bytes(manifest))
    release = read_release(root, release_id, issued_at, previous)
    write_archive(root, release_names(release), output / 'release.tar.gz')
    (output / 'release-manifest.json').write_bytes(regular_bytes(root, name))
    summary = change_summary(release, previous)
    (output / 'change-summary.json').write_bytes(fixture_bytes(summary))
    (output / 'build-info.json').write_bytes(fixture_bytes({'target': target, 'baseRelease': previous_id}))
    return release


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--freshness', type=Path, required=True)
    parser.add_argument('--release-id', required=True)
    parser.add_argument('--issued-at', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--previous-root', type=Path)
    parser.add_argument('--previous-id')
    parser.add_argument('--retain', nargs='*', default=[])
    parser.add_argument('--target', choices=['development', 'production'], default='development')
    args = parser.parse_args()
    assemble(args.input, args.freshness, args.release_id, args.output, args.issued_at,
             args.previous_root, args.previous_id, args.retain, args.target)
    print(f'Built unsigned candidate {args.release_id}')


if __name__ == '__main__':
    main()
