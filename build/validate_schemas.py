#!/usr/bin/env python3
"""Check the schema version 1 files and their fixtures.

1. Every schema is a valid Draft 2020-12 schema.
2. Every fixture file validates against the schema for its kind.
3. The fixtures agree with each other: every fixture sits at a published path and appears in a
   release manifest, file sizes and digests match each release manifest (not only the pinned
   one), the pinned release manifest matches the digest in the signed manifest, the signed
   manifest is canonical JSON with a valid Ed25519 signature and a validUntil later than issuedAt, the
   freshness list and the movers agree with the series, periods exist on the calendar, and every
   source was published before it was retrieved and retrieved before the release was issued.
4. Deliberately broken copies of the fixtures are rejected for the stated reason, so the
   schemas cannot quietly become permissive.

5. The release checks in release_checks.py (issue #11: references, duplicates, mover completeness,
   the validity window, source coverage and, against the previous release, stable series IDs and
   revisions) pass on the fixture releases and reject broken copies. They also run on the committed
   catalog and geography files.

Exits non-zero and prints GitHub Actions error annotations when a check fails.

Requires the packages in requirements.txt.
"""

import base64
import copy
import datetime
import contextlib
import functools
import io
import json
import math
import re
import sys
import urllib.parse
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator, FormatChecker

from release_checks import Release, check_release, following, observed, validity_window_problems, area_problems, duplicate_id_problems
from schema_tools import FIXTURE_DIR, ROOT, SCHEMA_DIR, SCHEMA_FILES, canonical_json, load_json, schema_registry, sha256_hex

failures = 0


def fail(path: Path, message: str) -> None:
    global failures
    failures += 1
    try:
        shown = path.relative_to(ROOT.parent)
    except ValueError:
        shown = path
    print(f"::error file={shown}::{message}")


def report(problems: list, root: Path = FIXTURE_DIR) -> None:
    """Reports the problems of a release check, which name a published path."""
    for problem in problems:
        fail(root / problem.path, problem.message)


def build_format_checker() -> FormatChecker:
    checker = FormatChecker()

    @checker.checks("date-time", raises=ValueError)
    def _date_time(value):
        if not isinstance(value, str):
            return True
        datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
        return True

    @checker.checks("uri", raises=ValueError)
    def _uri(value):
        # jsonschema registers no uri checker without an extra package, so assert it here. An
        # absolute URL needs a scheme and a host, and no whitespace, control or bracket errors.
        if not isinstance(value, str):
            return True
        parsed = urllib.parse.urlsplit(value)
        if not parsed.scheme or not parsed.hostname or re.search(r"[\x00-\x20\x7f<>\"\\^`{|}]", value):
            raise ValueError(f"{value!r} is not an absolute URI")
        parsed.port  # raises ValueError for a bad port
        return True

    return checker


KEY_FILE_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["note", "keyId", "algorithm", "publicKeyEncoding", "publicKey"],
    "properties": {
        "note": {"type": "string", "minLength": 1},
        "keyId": {"$ref": "common.schema.json#/$defs/keyId"},
        "algorithm": {"const": "Ed25519"},
        "publicKeyEncoding": {"const": "base64 of the raw 32-byte public key"},
        "publicKey": {"$ref": "common.schema.json#/$defs/base64", "pattern": "^[A-Za-z0-9+/]{43}=(?![\\s\\S])"},
    },
}


def key_file_errors(document) -> list:
    return sorted(Draft202012Validator(KEY_FILE_SCHEMA, registry=REGISTRY).iter_errors(document), key=lambda e: list(e.absolute_path))


REGISTRY = schema_registry()
FORMAT_CHECKER = build_format_checker()


@functools.cache
def validator_for(kind: str) -> Draft202012Validator:
    schema = load_json(SCHEMA_DIR / SCHEMA_FILES[kind])
    return Draft202012Validator(schema, registry=REGISTRY, format_checker=FORMAT_CHECKER)


def errors_for(kind: str, document) -> list:
    return sorted(validator_for(kind).iter_errors(document), key=lambda e: list(e.absolute_path))


LAYOUT = (
    (re.compile(r"manifest\.json"), "signed-manifest"),
    (re.compile(r"releases/[a-z0-9-]+/release-manifest\.json"), "release-manifest"),
    (re.compile(r"releases/[a-z0-9-]+/(catalog|geography|movers)\.json"), None),
    (re.compile(r"releases/[a-z0-9-]+/series/[a-z0-9._-]+\.json"), "series-bundle"),
    (re.compile(r"releases/[a-z0-9-]+/baselines/[a-z0-9._-]+\.json"), "baseline"),
)


def kind_of(relative: Path) -> str:
    """The schema kind of a fixture, from its exact published path. Raises ValueError for any other path."""
    posix = relative.as_posix()
    for pattern, kind in LAYOUT:
        match = pattern.fullmatch(posix)
        if match:
            return kind or match.group(1)
    raise ValueError(f"{posix} is not at a published path of any file kind")


def check_schemas_are_valid() -> None:
    for name in SCHEMA_FILES.values():
        schema = load_json(SCHEMA_DIR / name)
        try:
            Draft202012Validator.check_schema(schema)
        except Exception as exc:  # jsonschema raises SchemaError
            fail(SCHEMA_DIR / name, f"not a valid Draft 2020-12 schema: {exc}")


def check_fixtures_validate() -> dict:
    """Validates every published fixture file. Returns the parsed files by relative path."""
    documents = {}
    for path in sorted(FIXTURE_DIR.rglob("*.json")):
        relative = path.relative_to(FIXTURE_DIR)
        if relative.as_posix() == "test-public-key.json":
            for error in key_file_errors(load_json(path)):
                location = "/".join(str(part) for part in error.absolute_path) or "(root)"
                fail(path, f"does not match the test key file shape at {location}: {error.message}")
            continue
        try:
            kind = kind_of(relative)
        except ValueError as exc:
            fail(path, str(exc))
            continue
        document = load_json(path)
        documents[relative.as_posix()] = document
        for error in errors_for(kind, document):
            location = "/".join(str(part) for part in error.absolute_path) or "(root)"
            fail(path, f"does not match its schema at {location}: {error.message}")
    return documents


def b64(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


def check_signature_and_digests(documents: dict) -> None:
    """Runs the cross-file checks. A malformed fixture is reported, never raised."""
    try:
        verify_release(documents)
    except (KeyError, IndexError, TypeError, ValueError, OSError) as exc:
        fail(FIXTURE_DIR, f"could not check the release because a fixture is malformed ({type(exc).__name__}: {exc})")


def verify_release(documents: dict) -> None:
    envelope_path = FIXTURE_DIR / "manifest.json"
    envelope = documents.get("manifest.json")
    if envelope is None:
        fail(envelope_path, "missing")
        return

    key_file = load_json(FIXTURE_DIR / "test-public-key.json")
    if key_file["keyId"] != envelope["signingKeyId"]:
        fail(envelope_path, "signingKeyId does not name the test public key")
    manifest_bytes = b64(envelope["manifest"])
    try:
        public_key = Ed25519PublicKey.from_public_bytes(b64(key_file["publicKey"]))
    except ValueError as exc:
        fail(FIXTURE_DIR / "test-public-key.json", f"the test public key is not a valid Ed25519 public key ({exc})")
        return
    try:
        public_key.verify(b64(envelope["signature"]), manifest_bytes)
    except InvalidSignature:
        fail(envelope_path, "the signature does not verify against the test public key; run generate_schema_fixtures.py")
        return

    manifest = json.loads(manifest_bytes)
    for error in errors_for("manifest", manifest):
        fail(envelope_path, f"the signed manifest does not match manifest.schema.json: {error.message}")
    try:
        canonical = canonical_json(manifest) == manifest_bytes
    except ValueError as exc:
        fail(envelope_path, f"the signed manifest is not canonical JSON ({exc})")
    else:
        if not canonical:
            fail(envelope_path, "the signed manifest bytes are not canonical JSON")
    if manifest["signingKeyId"] != envelope["signingKeyId"]:
        fail(envelope_path, "the manifest and the envelope name different signing keys")
    check_manifest_times(envelope_path, manifest)

    pinned = manifest["releaseManifest"]
    release_manifest_path = FIXTURE_DIR / pinned["path"]
    if pinned["path"] not in documents:
        fail(envelope_path, f"pins a release manifest that does not exist: {pinned['path']}")
        return
    if sha256_hex(release_manifest_path.read_bytes()) != pinned["sha256"]:
        fail(release_manifest_path, "digest differs from the one pinned in the signed manifest")
    if documents[pinned["path"]]["releaseId"] != manifest["releaseId"]:
        fail(release_manifest_path, "releaseId differs from the signed manifest")
    if pinned["path"] != f"releases/{manifest['releaseId']}/release-manifest.json":
        fail(envelope_path, "the pinned release manifest path does not belong to the manifest's releaseId")

    # Every release in the fixtures is checked, not only the pinned one: a rollback manifest
    # can pin an earlier release. Only the pinned release has a signed issuedAt to compare with.
    # The fixture releases are named in order, so each one's predecessor is the release before it.
    listed = set()
    previous = None
    for name in sorted(documents):
        if kind_of(Path(name)) == "release-manifest":
            issued_at = manifest["issuedAt"] if name == pinned["path"] else None
            listed |= verify_release_files(FIXTURE_DIR / name, documents[name], documents, issued_at, previous)
            previous = Release(name, documents[name], documents)
    for name in sorted(documents):
        if kind_of(Path(name)) not in ("signed-manifest", "release-manifest") and name not in listed:
            fail(FIXTURE_DIR / name, "no release manifest lists this file")


def check_manifest_times(path: Path, manifest: dict) -> None:
    if manifest["validUntil"] <= manifest["issuedAt"]:
        fail(path, "validUntil must be later than issuedAt")
    else:
        for problem in validity_window_problems(path.name, manifest):
            fail(path, problem.message)


def verify_release_files(release_manifest_path: Path, release_manifest: dict, documents: dict, issued_at, previous=None, root=None) -> set:
    """Checks the files that one release manifest lists. Returns the paths it lists.

    previous is the Release before this one, when there is one, for the checks across releases.
    """
    root = FIXTURE_DIR if root is None else root
    series_by_id = {}
    movers_files = []
    catalogs = []
    sources = []
    listed = set()
    folder = release_manifest_path.parent.name
    if release_manifest["releaseId"] != folder:
        fail(release_manifest_path, f"releaseId {release_manifest['releaseId']!r} differs from its folder {folder!r}")
    paths = [entry["path"] for entry in release_manifest["files"]]
    if len(paths) != len(set(paths)):
        fail(release_manifest_path, "lists the same path more than once")
    kinds = [entry["kind"] for entry in release_manifest["files"]]
    for required in ("catalog", "geography", "movers"):
        if kinds.count(required) != 1:
            fail(release_manifest_path, f"must list exactly one {required} file")
    if "series-bundle" not in kinds:
        fail(release_manifest_path, "must list at least one series-bundle file")
    for entry in release_manifest["files"]:
        listed.add(entry["path"])
        file_path = root / entry["path"]
        if not file_path.is_file():
            fail(release_manifest_path, f"lists a file that does not exist: {entry['path']}")
            continue
        data = file_path.read_bytes()
        if len(data) != entry["bytes"] or sha256_hex(data) != entry["sha256"]:
            fail(file_path, "size or digest differs from the release manifest; run generate_schema_fixtures.py")
        if kind_of(Path(entry["path"])) != entry["kind"]:
            fail(release_manifest_path, f"kind {entry['kind']!r} does not match the file {entry['path']}")
        document = documents[entry["path"]]
        if entry["kind"] == "series-bundle":
            if document["bundleId"] != Path(entry["path"]).stem:
                fail(file_path, f"bundleId {document['bundleId']!r} differs from the file name")
            for series in document["series"]:
                if series["seriesId"] in series_by_id:
                    fail(file_path, f"{series['seriesId']}: the same seriesId appears twice in one release")
                series_by_id[series["seriesId"]] = series
                sources.append((file_path, series["seriesId"], series["source"]))
                check_series_periods(file_path, series)
        elif entry["kind"] == "baseline":
            if document["baselineId"] != Path(entry["path"]).stem:
                fail(file_path, f"baselineId {document['baselineId']!r} differs from the file name")
            category_ids = [row["categoryId"] for row in document["categories"]]
            if len(category_ids) != len(set(category_ids)):
                fail(file_path, "the same categoryId appears twice in one baseline")
            sources.append((file_path, document["baselineId"], document["source"]))
        elif entry["kind"] == "movers":
            movers_files.append((file_path, document))
        elif entry["kind"] == "catalog":
            catalogs.append((file_path, document))

    check_freshness(release_manifest_path, release_manifest, series_by_id)
    for file_path, document in catalogs:
        check_catalog_specifications(file_path, document, series_by_id)
    for file_path, document in movers_files:
        check_movers(file_path, document, series_by_id)
    for file_path, name, source in sources:
        if source["publishedAt"] > source["retrievedAt"] or (issued_at and source["retrievedAt"] > issued_at):
            fail(file_path, f"{name}: publishedAt, retrievedAt and the manifest issuedAt are out of order")
    if all(path in documents for path in paths):
        relative = release_manifest_path.relative_to(root).as_posix()
        report(check_release(Release(relative, release_manifest, documents), issued_at, previous), root=root)
    return listed


def period_problem(period: str):
    """A message when a period names a week or month that the calendar lacks, else None."""
    match = re.fullmatch(r"(\d{4})-W(\d{2})", period)
    if match:
        try:
            datetime.date.fromisocalendar(int(match[1]), int(match[2]), 1)
        except ValueError:
            return f"{period} is not an ISO 8601 week (the year does not have that week)"
    return None


def check_series_periods(path: Path, series: dict) -> None:
    periods = [row["period"] for row in series["observations"]]
    base = series["unit"]["indexBase"]
    if base:
        periods.append(base["period"])
    for period in periods:
        problem = period_problem(period)
        if problem:
            fail(path, f"{series['seriesId']}: {problem}")
    observed_periods = [row["period"] for row in series["observations"]]
    # Periods of one frequency have a fixed width, so a string sort is a chronological sort.
    if observed_periods != sorted(set(observed_periods)):
        fail(path, f"{series['seriesId']}: observations must be sorted by period with no duplicate period")


def check_freshness(path: Path, release_manifest: dict, series_by_id: dict) -> None:
    listed = [item["seriesId"] for item in release_manifest["series"]]
    if len(listed) != len(set(listed)) or set(listed) != set(series_by_id):
        fail(path, "the freshness list must name every series in the bundles exactly once")
    for item in release_manifest["series"]:
        series = series_by_id.get(item["seriesId"])
        if series is None:
            continue
        name = item["seriesId"]
        values = observed(series)
        if item["frequency"] != series["frequency"]:
            fail(path, f"{name}: freshness frequency differs from the series")
        if item["latestObservationPeriod"] != (values[-1]["period"] if values else None):
            fail(path, f"{name}: latestObservationPeriod is not the latest period with a value")
        if (item["expectedNextRelease"] is None) != (series["validTo"] is not None):
            fail(path, f"{name}: expectedNextRelease must be null exactly when the series is superseded")


def check_catalog_specifications(path: Path, catalog: dict, series_by_id: dict) -> None:
    """A supported item's current retail-price series must all measure one specification.

    The app's price check compares against one specification and refuses to choose between several, so a
    single series with a different specificationId would turn the item off for every area. A superseded
    series, a price index and a series the catalog does not list for the item are ignored, as in the app.
    """
    for item in catalog["items"]:
        if not item["supported"]:
            continue
        specifications = sorted({
            series["comparability"]["specificationId"]
            for series in (series_by_id.get(series_id) for series_id in item["seriesIds"])
            if series is not None and series["itemId"] == item["itemId"]
            and series["measureType"] == "retail_price" and series["validTo"] is None
        })
        if len(specifications) > 1:
            fail(path, f"{item['itemId']}: current retail-price series measure more than one specification "
                       f"({', '.join(specifications)}); supersede the old ones or split the item")


def check_movers(path: Path, movers: dict, series_by_id: dict) -> None:
    names = [mover["seriesId"] for mover in movers["movers"]]
    if len(names) != len(set(names)):
        fail(path, "a series appears more than once in the movers")
    for mover in movers["movers"]:
        name = mover["seriesId"]
        series = series_by_id.get(name)
        if series is None:
            fail(path, f"{name}: mover names a series that is not in the release")
            continue
        if series["validTo"] is not None:
            fail(path, f"{name}: a superseded series must not appear in the movers")
        rows = series["observations"]
        latest = max((i for i, row in enumerate(rows) if row["value"] is not None), default=None)
        if latest is None or latest == 0 or rows[latest - 1]["value"] is None:
            fail(path, f"{name}: mover has no latest and previous value in the series")
            continue
        latest_row, previous_row = rows[latest], rows[latest - 1]
        if following(previous_row["period"], series["frequency"]) != latest_row["period"]:
            fail(path, f"{name}: the mover's previous period is not the period just before the latest")
            continue
        expected = (latest_row["period"], latest_row["value"], previous_row["period"], previous_row["value"])
        found = (mover["latestPeriod"], mover["latestValue"], mover["previousPeriod"], mover["previousValue"])
        if found != expected:
            fail(path, f"{name}: mover periods or values differ from the series")
        elif not math.isclose(mover["percentChange"], (found[1] / found[3] - 1) * 100, rel_tol=1e-9, abs_tol=1e-9):
            fail(path, f"{name}: percentChange does not follow from the values")


def expect_check_failure(label: str, expected: str, run) -> None:
    """Runs a cross-file check on bad data. It must report a failure that mentions the expected text."""
    global failures
    before = failures
    output = io.StringIO()
    try:
        with contextlib.redirect_stdout(output):
            run()
    except Exception as exc:  # a check that crashes on bad data is a failure of the check
        output.write(f"raised {type(exc).__name__}: {exc}")
    finally:
        failures = before
    if expected not in output.getvalue():
        fail(Path(__file__), f"the cross-file check did not reject {label} for the expected reason ({expected!r}): {output.getvalue().strip() or 'accepted'}")


def mutated(document, change):
    copy_ = copy.deepcopy(document)
    change(copy_)
    return copy_


def series_of(doc, series_id):
    return next(item for item in doc["series"] if item["seriesId"] == series_id)


def observation_of(doc, series_id, period):
    return next(row for row in series_of(doc, series_id)["observations"] if row["period"] == period)


def file_of(doc, kind):
    return next(entry for entry in doc["files"] if entry["kind"] == kind)


def freshness_of(doc, series_id):
    return next(item for item in doc["series"] if item["seriesId"] == series_id)


def area_in(doc, area_id):
    return next(area for area in doc["areas"] if area["areaId"] == area_id)


def error_text(error) -> str:
    return "/".join(str(part) for part in error.absolute_path) + " " + error.message


ITEM_A = "example.rps.item-a.city"
OLD_B = "example.rps.item-b.city.old"
INDEX_A = "example.cpi.item-a.national"
EXPENDITURE_A = "example.fies.category-a.national"


def run_rejection_checks(documents: dict) -> None:
    r2 = "releases/example-release-2"
    r1 = "releases/example-release-1"
    bundle = documents[f"{r2}/series/example-food.json"]
    catalog = documents[f"{r1}/catalog.json"]
    baseline = documents[f"{r1}/baselines/example.household.single.json"]
    geography = documents[f"{r1}/geography.json"]
    movers = documents[f"{r2}/movers.json"]
    envelope = documents["manifest.json"]
    manifest = json.loads(b64(envelope["manifest"]))
    release_manifest = documents[f"{r2}/release-manifest.json"]

    def item_a(d):
        return series_of(d, ITEM_A)

    # Each case names the part of the error that shows the schema rejected it for the stated
    # reason (the property path or the message), so an unrelated error cannot satisfy it.
    cases = [
        # Series bundles
        ("series-bundle", "an observed value without a number", bundle, "observations/0/value",
         lambda d: item_a(d)["observations"][0].update(value=None)),
        ("series-bundle", "a missing period with a number (an invented zero)", bundle, "observations/2/value",
         lambda d: observation_of(d, ITEM_A, "2026-07").update(value=0)),
        ("series-bundle", "a negative value", bundle, "observations/0/value",
         lambda d: item_a(d)["observations"][0].update(value=-1)),
        ("series-bundle", "a retail price of zero", bundle, "observations/0/value",
         lambda d: item_a(d)["observations"][0].update(value=0)),
        ("series-bundle", "a price index of zero", bundle, "observations/0/value",
         lambda d: series_of(d, INDEX_A)["observations"][0].update(value=0)),
        ("series-bundle", "an unknown observation status", bundle, "observations/0/status",
         lambda d: item_a(d)["observations"][0].update(status="estimated")),
        ("series-bundle", "an unknown measure type", bundle, "measureType",
         lambda d: item_a(d).update(measureType="rate")),
        ("series-bundle", "an unknown quantity unit", bundle, "quantityUnit",
         lambda d: item_a(d)["unit"].update(quantityUnit="pack")),
        ("series-bundle", "a household unit on a retail price", bundle, "quantityUnit",
         lambda d: item_a(d)["unit"].update(quantityUnit="household")),
        ("series-bundle", "an index base on a retail price", bundle, "/unit/indexBase",
         lambda d: item_a(d)["unit"].update(indexBase={"period": "2020", "value": 100})),
        ("series-bundle", "a retail price without a currency", bundle, "/unit/currency",
         lambda d: item_a(d)["unit"].update(currency=None)),
        ("series-bundle", "a price index with a currency", bundle, "/unit/currency",
         lambda d: series_of(d, INDEX_A)["unit"].update(currency="JPY")),
        ("series-bundle", "a price index without an index base", bundle, "/unit/indexBase",
         lambda d: series_of(d, INDEX_A)["unit"].update(indexBase=None)),
        ("series-bundle", "a retail price with tax treatment not applicable", bundle, "taxTreatment",
         lambda d: item_a(d).update(taxTreatment="not_applicable")),
        ("series-bundle", "a price index with a tax treatment", bundle, "taxTreatment",
         lambda d: series_of(d, INDEX_A).update(taxTreatment="tax_included")),
        ("series-bundle", "an annual period in a monthly series", bundle, "observations/0/period",
         lambda d: item_a(d)["observations"][0].update(period="2026")),
        ("series-bundle", "a monthly period in an annual series", bundle, "observations/0/period",
         lambda d: series_of(d, EXPENDITURE_A)["observations"][0].update(period="2024-01")),
        ("series-bundle", "a monthly period in a weekly series", bundle, "observations/0/period",
         lambda d: item_a(d).update(frequency="weekly")),
        ("series-bundle", "a monthly period in a quarterly series", bundle, "observations/0/period",
         lambda d: item_a(d).update(frequency="quarterly")),
        ("series-bundle", "a weekly period in a monthly series", bundle, "observations/0/period",
         lambda d: item_a(d)["observations"][0].update(period="2026-W10")),
        ("series-bundle", "a quarterly period in a monthly series", bundle, "observations/0/period",
         lambda d: item_a(d)["observations"][0].update(period="2026-Q3")),
        ("series-bundle", "successors without a validTo", bundle, "/validTo",
         lambda d: series_of(d, OLD_B).update(validTo=None)),
        ("series-bundle", "a missing required field", bundle, "comparability",
         lambda d: item_a(d).pop("comparability")),
        ("series-bundle", "an extra field", bundle, "interpolated",
         lambda d: item_a(d).update(interpolated=True)),
        ("series-bundle", "an empty series list", bundle, "series [] should be non-empty",
         lambda d: d.update(series=[])),
        ("series-bundle", "an unsupported schema version", bundle, "schemaVersion",
         lambda d: d.update(schemaVersion=2)),
        ("series-bundle", "a source URL with an unclosed bracket", bundle, "source/url",
         lambda d: item_a(d)["source"].update(url="https://[")),
        ("series-bundle", "a source URL with a space in the host", bundle, "source/url",
         lambda d: item_a(d)["source"].update(url="https://a b/table")),
        ("series-bundle", "a source URL that is not HTTPS", bundle, "source/url",
         lambda d: item_a(d)["source"].update(url="http://example.invalid/table")),
        ("series-bundle", "a series ID with a slash", bundle, "/seriesId ",
         lambda d: item_a(d).update(seriesId="a/b")),
        ("series-bundle", "a series ID with a trailing newline", bundle, "/seriesId ",
         lambda d: item_a(d).update(seriesId="abc\n")),
        ("series-bundle", "a label with a trailing newline", bundle, "sourceItemLabelJa",
         lambda d: item_a(d).update(sourceItemLabelJa="label\n")),
        ("series-bundle", "an impossible calendar date", bundle, "/validTo ",
         lambda d: series_of(d, OLD_B).update(validTo="2026-02-30")),
        ("series-bundle", "a 31st day of a 30-day month", bundle, "/validTo ",
         lambda d: series_of(d, OLD_B).update(validTo="2026-04-31")),
        ("series-bundle", "a date with a trailing newline", bundle, "/validTo ",
         lambda d: series_of(d, OLD_B).update(validTo="2026-05-31\n")),
        ("series-bundle", "a timestamp with an offset", bundle, "retrievedAt",
         lambda d: item_a(d)["source"].update(retrievedAt="2026-09-20T03:00:00+09:00")),
        ("series-bundle", "a timestamp that is not a real instant", bundle, "retrievedAt",
         lambda d: item_a(d)["source"].update(retrievedAt="2026-02-30T03:00:00Z")),
        # Catalog
        ("catalog", "a household unit basis", catalog, "quantityUnit",
         lambda d: d["items"][0]["unitBasis"].update(quantityUnit="household")),
        ("catalog", "a missing supported flag", catalog, "'supported' is a required property",
         lambda d: d["items"][0].pop("supported")),
        ("catalog", "duplicate series IDs", catalog, "non-unique",
         lambda d: d["items"][0].update(seriesIds=["example.rps.item-a.city", "example.rps.item-a.city"])),
        # Baseline
        ("baseline", "a rounding rule other than nearest_yen", baseline, "rounding 'nearest_yen' was expected",
         lambda d: d.update(rounding="half_even")),
        ("baseline", "a fractional monthly amount", baseline, "monthlyYen",
         lambda d: d["categories"][0].update(monthlyYen=1000.5)),
        ("baseline", "a negative monthly amount", baseline, "monthlyYen",
         lambda d: d["categories"][0].update(monthlyYen=-1)),
        ("baseline", "a monthly amount of zero", baseline, "monthlyYen",
         lambda d: d["categories"][0].update(monthlyYen=0)),
        ("baseline", "an unknown household type", baseline, "householdType",
         lambda d: d.update(householdType="all")),
        # Geography
        ("geography", "no areas", geography, "areas [] should be non-empty",
         lambda d: d.update(areas=[])),
        ("geography", "a national area with a parent", geography, "parentAreaId",
         lambda d: area_in(d, "example-national").update(parentAreaId="example-region-a")),
        ("geography", "a region with a code", geography, "/code ",
         lambda d: area_in(d, "example-region-a").update(code="99")),
        ("geography", "a prefecture without a code", geography, "/code ",
         lambda d: area_in(d, "example-pref-a").update(code=None)),
        ("geography", "a prefecture with a municipality type", geography, "municipalityType",
         lambda d: area_in(d, "example-pref-a").update(municipalityType="city")),
        ("geography", "a municipality without a municipality type", geography, "municipalityType",
         lambda d: area_in(d, "example-city-a").update(municipalityType=None)),
        ("geography", "a selectable municipality without a centroid", geography, "/centroid ",
         lambda d: area_in(d, "example-city-a").update(centroid=None)),
        ("geography", "a selectable survey group", geography, "selectable",
         lambda d: area_in(d, "example-survey-group").update(selectable=True)),
        ("geography", "a survey group with a code", geography, "/code ",
         lambda d: area_in(d, "example-survey-group").update(code="99900")),
        ("geography", "an area that is not the national area and has no parent", geography, "parentAreaId",
         lambda d: area_in(d, "example-pref-a").update(parentAreaId=None)),
        ("geography", "successors without a validTo", geography, "/validTo",
         lambda d: area_in(d, "example-town-old").update(validTo=None)),
        ("geography", "a selectable area that no longer exists", geography, "selectable",
         lambda d: area_in(d, "example-town-old").update(selectable=True)),
        ("geography", "an out-of-range latitude", geography, "'lat': 91",
         lambda d: area_in(d, "example-city-a")["centroid"].update(lat=91)),
        ("geography", "no sources", geography, "sources [] should be non-empty",
         lambda d: d.update(sources=[])),
        # Movers
        ("movers", "a missing rule version", movers, "ruleVersion",
         lambda d: d.pop("ruleVersion")),
        ("movers", "a null latest value", movers, "latestValue",
         lambda d: d["movers"][0].update(latestValue=None)),
        ("movers", "a previous value of zero", movers, "previousValue",
         lambda d: d["movers"][0].update(previousValue=0)),
        # Signed manifest envelope
        ("signed-manifest", "a short signature", envelope, "is too short",
         lambda d: d.update(signature=d["signature"][:-4])),
        ("signed-manifest", "manifest bytes that are not base64", envelope, "manifest 'not base64!'",
         lambda d: d.update(manifest="not base64!")),
        ("signed-manifest", "a missing signing key ID", envelope, "signingKeyId",
         lambda d: d.pop("signingKeyId")),
        ("signed-manifest", "a key ID that names the app", envelope, "signingKeyId",
         lambda d: d.update(signingKeyId="colaide-2026")),
        ("signed-manifest", "a signature with a trailing newline", envelope, "does not match",
         lambda d: d.update(signature=d["signature"] + "\n")),
        # Manifest payload
        ("manifest", "a sequence of zero", manifest, "sequence 0 is less than the minimum",
         lambda d: d.update(sequence=0)),
        ("manifest", "a fractional sequence", manifest, "sequence 1.5 is not of type 'integer'",
         lambda d: d.update(sequence=1.5)),
        ("manifest", "a missing supersedesKeyId", manifest, "supersedesKeyId",
         lambda d: d.pop("supersedesKeyId")),
        ("manifest", "a timestamp with a fraction", manifest, "is not a 'date-time'",
         lambda d: d.update(issuedAt="2026-10-10T00:00:00.5Z")),
        ("manifest", "a timestamp that is not a real instant", manifest, "is not a 'date-time'",
         lambda d: d.update(issuedAt="2026-04-31T00:00:00Z")),
        ("manifest", "a path outside the release folder", manifest, "releaseManifest/path",
         lambda d: d["releaseManifest"].update(path="../release-manifest.json")),
        ("manifest", "an uppercase digest", manifest, "releaseManifest/sha256",
         lambda d: d["releaseManifest"].update(sha256=d["releaseManifest"]["sha256"].upper())),
        ("manifest", "a digest with a trailing newline", manifest, "releaseManifest/sha256",
         lambda d: d["releaseManifest"].update(sha256=d["releaseManifest"]["sha256"] + "\n")),
        # Release manifest
        ("release-manifest", "a path with a parent segment", release_manifest, "/path ",
         lambda d: file_of(d, "series-bundle").update(path="releases/example-release-1/series/../../x.json")),
        ("release-manifest", "a catalog kind on a series path", release_manifest, "/path ",
         lambda d: file_of(d, "catalog").update(path="releases/example-release-1/series/x.json")),
        ("release-manifest", "an absolute path", release_manifest, "/path ",
         lambda d: file_of(d, "catalog").update(path="/releases/example-release-1/catalog.json")),
        ("release-manifest", "a path with a trailing newline", release_manifest, "/path ",
         lambda d: file_of(d, "catalog").update(path="releases/example-release-1/catalog.json\n")),
        ("release-manifest", "a file without a digest", release_manifest, "'sha256' is a required property",
         lambda d: file_of(d, "catalog").pop("sha256")),
        ("release-manifest", "an unknown file kind", release_manifest, "/kind ",
         lambda d: file_of(d, "catalog").update(kind="other")),
        ("release-manifest", "a series without graceDays", release_manifest, "'graceDays' is a required property",
         lambda d: freshness_of(d, ITEM_A).pop("graceDays")),
        ("release-manifest", "a monthly series with an annual latest period", release_manifest, "latestObservationPeriod",
         lambda d: freshness_of(d, ITEM_A).update(latestObservationPeriod="2026")),
        ("release-manifest", "a weekly series with a monthly latest period", release_manifest, "latestObservationPeriod",
         lambda d: freshness_of(d, ITEM_A).update(frequency="weekly")),
        ("release-manifest", "a quarterly series with a monthly latest period", release_manifest, "latestObservationPeriod",
         lambda d: freshness_of(d, ITEM_A).update(frequency="quarterly")),
        ("release-manifest", "a series without an expectedNextRelease", release_manifest, "expectedNextRelease",
         lambda d: freshness_of(d, ITEM_A).pop("expectedNextRelease")),
    ]

    for kind, label, base, expected, change in cases:
        document = mutated(base, change)
        texts = [error_text(error) for error in errors_for(kind, document)]
        if not texts:
            fail(SCHEMA_DIR / SCHEMA_FILES[kind], f"accepted {label}")
        elif not any(expected in text for text in texts):
            fail(SCHEMA_DIR / SCHEMA_FILES[kind], f"rejected {label}, but not for the expected reason ({expected!r}): {texts[0]}")

    # The valid copies the cases start from must themselves pass.
    for kind, base in (("series-bundle", bundle), ("catalog", catalog), ("baseline", baseline),
                       ("geography", geography), ("movers", movers), ("signed-manifest", envelope),
                       ("manifest", manifest), ("release-manifest", release_manifest)):
        if errors_for(kind, base):
            fail(SCHEMA_DIR / SCHEMA_FILES[kind], "rejects the valid fixture used as the base of the rejection checks")

    # A signature must not verify for changed bytes.
    key_file = load_json(FIXTURE_DIR / "test-public-key.json")
    public_key = Ed25519PublicKey.from_public_bytes(b64(key_file["publicKey"]))
    changed = canonical_json({**manifest, "sequence": manifest["sequence"] + 1})
    try:
        public_key.verify(b64(envelope["signature"]), changed)
        fail(FIXTURE_DIR / "manifest.json", "a signature verified for changed manifest bytes")
    except InvalidSignature:
        pass

    run_check_tests(documents, bundle, movers, manifest)

    print(f"{len(cases)} rejection checks run")


def run_check_tests(documents: dict, bundle: dict, movers: dict, manifest: dict) -> None:
    """Runs the cross-file checks and the helpers on bad data, which the schemas cannot reject."""
    r1_manifest_name = "releases/example-release-1/release-manifest.json"
    stray = "releases/example-release-1/series/stray.json"
    mover = movers["movers"][0]
    series = copy.deepcopy(series_of(bundle, mover["seriesId"]))
    latest = max(i for i, row in enumerate(series["observations"]) if row["value"] is not None)
    series["observations"][latest - 1]["period"] = "1999" + series["observations"][latest - 1]["period"][4:]
    weekly = {"seriesId": "x", "observations": [{"period": "2025-W53"}], "unit": {"indexBase": None}}
    release_1 = mutated(documents[r1_manifest_name], lambda d: d["files"][0].update(sha256="0" * 64))

    key_file = load_json(FIXTURE_DIR / "test-public-key.json")
    for label, broken in (("a key file with the wrong algorithm", {**key_file, "algorithm": "RSA"}),
                          ("a key file with a short public key", {**key_file, "publicKey": "AAAA"}),
                          ("a key file with an extra field", {**key_file, "extra": 1}),
                          ("a key file without an algorithm", {k: v for k, v in key_file.items() if k != "algorithm"})):
        if not key_file_errors(broken):
            fail(FIXTURE_DIR / "test-public-key.json", f"the key file check accepted {label}")

    expect_check_failure("a mover whose previous period is not adjacent", "just before the latest",
                         lambda: check_movers(Path("movers.json"), movers, {mover["seriesId"]: series}))
    expect_check_failure("a week the year does not have", "not an ISO 8601 week",
                         lambda: check_series_periods(Path("series.json"), weekly))
    unsorted = copy.deepcopy(series)
    unsorted["observations"] = [series["observations"][1], series["observations"][0], *series["observations"][2:]]
    duplicated = copy.deepcopy(series)
    duplicated["observations"] = [series["observations"][0], *series["observations"]]
    expect_check_failure("observations out of order", "sorted by period",
                         lambda: check_series_periods(Path("series.json"), unsorted))
    expect_check_failure("a duplicate period", "no duplicate period",
                         lambda: check_series_periods(Path("series.json"), duplicated))
    expect_check_failure("a release manifest that lists a path twice", "lists the same path more than once",
                         lambda: verify_release_files(FIXTURE_DIR / r1_manifest_name,
                                                      mutated(documents[r1_manifest_name], lambda d: d["files"].append(dict(d["files"][0]))),
                                                      documents, None))
    expect_check_failure("a release manifest without a movers file", "exactly one movers file",
                         lambda: verify_release_files(FIXTURE_DIR / r1_manifest_name,
                                                      mutated(documents[r1_manifest_name], lambda d: d.update(files=[f for f in d["files"] if f["kind"] != "movers"])),
                                                      documents, None))
    r1_bundle = "releases/example-release-1/series/example-food.json"
    # Listing a bundle twice gives the release two copies of every series in it.
    expect_check_failure("a seriesId that two bundles share", "the same seriesId appears twice",
                         lambda: verify_release_files(
                             FIXTURE_DIR / r1_manifest_name,
                             mutated(documents[r1_manifest_name], lambda d: d["files"].append(dict(file_of(d, "series-bundle")))),
                             documents, None))
    expect_check_failure("a bundleId that differs from the file name", "differs from the file name",
                         lambda: verify_release_files(FIXTURE_DIR / r1_manifest_name, documents[r1_manifest_name],
                                                      {**documents, r1_bundle: {**documents[r1_bundle], "bundleId": "other"}}, None))
    baseline_path = "releases/example-release-1/baselines/example.household.single.json"
    expect_check_failure("a baselineId that differs from the file name", "differs from the file name",
                         lambda: verify_release_files(FIXTURE_DIR / r1_manifest_name, documents[r1_manifest_name],
                                                      {**documents, baseline_path: {**documents[baseline_path], "baselineId": "other"}}, None))
    expect_check_failure("a duplicate categoryId in a baseline", "same categoryId appears twice",
                         lambda: verify_release_files(FIXTURE_DIR / r1_manifest_name, documents[r1_manifest_name],
                                                      {**documents, baseline_path: mutated(documents[baseline_path], lambda d: d["categories"].append(dict(d["categories"][0])))}, None))
    expect_check_failure("a percentChange that does not follow from the values", "percentChange does not follow",
                         lambda: check_movers(Path("movers.json"), mutated(movers, lambda d: d["movers"][0].update(percentChange=d["movers"][0]["percentChange"] + 0.01)),
                                              {m["seriesId"]: series_of(bundle, m["seriesId"]) for m in movers["movers"]}))
    catalog = documents["releases/example-release-1/catalog.json"]
    r1_series = {s["seriesId"]: s for s in documents[r1_bundle]["series"]}
    expect_check_failure("a supported item with two current specifications", "more than one specification",
                         lambda: check_catalog_specifications(
                             Path("catalog.json"), catalog,
                             {**r1_series, OLD_B: {**r1_series[OLD_B], "validTo": None}}))
    expect_check_failure("a release whose catalog item has two current specifications", "more than one specification",
                         lambda: verify_release_files(
                             FIXTURE_DIR / r1_manifest_name, documents[r1_manifest_name],
                             {**documents, r1_bundle: mutated(documents[r1_bundle],
                                                              lambda d: series_of(d, OLD_B).update(validTo=None, successorSeriesIds=[]))},
                             None))
    expect_check_failure("a series listed twice in the movers", "more than once in the movers",
                         lambda: check_movers(Path("movers.json"), mutated(movers, lambda d: d["movers"].append(dict(d["movers"][0]))),
                                              {m["seriesId"]: series_of(bundle, m["seriesId"]) for m in movers["movers"]}))
    expect_check_failure("a file no release manifest lists", "no release manifest lists this file",
                         lambda: verify_release({**documents, stray: {}}))
    expect_check_failure("a stale digest in an earlier release", "differs from the release manifest",
                         lambda: verify_release({**documents, r1_manifest_name: release_1}))
    expect_check_failure("a manifest that expires before it is issued", "validUntil must be later",
                         lambda: check_manifest_times(Path("manifest.json"), {**manifest, "validUntil": manifest["issuedAt"]}))

    run_release_check_tests(documents, manifest)

    for label, change in (("a float", {"sequence": 2.0}), ("a non-ASCII key", {"\u00e9": 1}), ("an integer beyond 2**53", {"n": 2**60})):
        try:
            canonical_json(change)
            fail(Path(__file__), f"canonical_json accepted {label}")
        except ValueError:
            pass
    try:
        kind_of(Path("stray.json"))
        fail(Path(__file__), "kind_of accepted a path outside the layout")
    except ValueError:
        pass
    for path, kind in (("releases/series/baselines/x.json", "baseline"), ("releases/r/series/catalog.json", "series-bundle")):
        if kind_of(Path(path)) != kind:
            fail(Path(__file__), f"kind_of classified {path} as something other than {kind}")
    if period_problem("2026-W53") or not period_problem("2025-W53"):
        fail(Path(__file__), "period_problem gets the 53-week years wrong")
    for period, frequency, after in (("2026-12", "monthly", "2027-01"), ("2026-Q4", "quarterly", "2027-Q1"),
                                     ("2026", "annual", "2027"), ("2026-W53", "weekly", "2027-W01"),
                                     ("2025-W52", "weekly", "2026-W01")):
        if following(period, frequency) != after:
            fail(Path(__file__), f"following({period}, {frequency}) is not {after}")


def run_release_check_tests(documents: dict, manifest: dict) -> None:
    """Runs the release checks of release_checks.py on broken copies of the fixture releases."""
    r1_name = "releases/example-release-1/release-manifest.json"
    r2_name = "releases/example-release-2/release-manifest.json"
    r1_catalog = "releases/example-release-1/catalog.json"
    r1_geography = "releases/example-release-1/geography.json"
    r1_bundle = "releases/example-release-1/series/example-food.json"
    r2_bundle = "releases/example-release-2/series/example-food.json"
    r2_movers = "releases/example-release-2/movers.json"

    def edit(path: str, change) -> dict:
        return {**documents, path: mutated(documents[path], change)}

    def run(docs: dict, name: str = r2_name, issued_at=None, previous: bool = False):
        before = Release(r1_name, docs[r1_name], docs) if previous else None
        return lambda: report(check_release(Release(name, docs[name], docs), issued_at, before))

    def reject(label: str, expected: str, docs: dict, **options) -> None:
        expect_check_failure(label, expected, run(docs, **options))

    def with_series(series_id: str, change, path: str = r2_bundle) -> dict:
        return edit(path, lambda d: change(series_of(d, series_id)))

    def item_of(d, item_id):
        return next(item for item in d["items"] if item["itemId"] == item_id)

    reject("a repeated itemId", "itemId 'example.item-a' appears more than once", edit(r1_catalog, lambda d: d["items"].append(dict(d["items"][0]))))
    reject("a repeated areaId", "areaId 'example-city-a' appears more than once", edit(r1_geography, lambda d: d["areas"].append(dict(area_in(d, "example-city-a")))))
    reject("a series repeated across bundles", "appears more than once in the release",
           edit(r2_bundle, lambda d: d["series"].append(copy.deepcopy(series_of(d, ITEM_A)))))
    reject("a catalog item that lists a missing series", "which is not in the release", edit(r1_catalog, lambda d: item_of(d, "example.item-a")["seriesIds"].append("example.missing")))
    reject("a catalog item that lists another item's series", "which belongs to item", edit(r1_catalog, lambda d: item_of(d, "example.item-a")["seriesIds"].append(OLD_B)))
    reject("a series of an unknown item", "is not in the catalog", with_series(ITEM_A, lambda s: s.update(itemId="example.unknown")))
    reject("a series that no item lists", "does not list the series", edit(r1_catalog, lambda d: item_of(d, "example.item-a")["seriesIds"].remove(INDEX_A)))
    reject("a series of an unknown area", "is not in the geography file", with_series(ITEM_A, lambda s: s["geography"].update(areaId="example-nowhere")))
    reject("a successor series that is missing", "which is not in the release", with_series(OLD_B, lambda s: s.update(successorSeriesIds=["example.missing"])))
    reject("a successor series of another item", "another series of the same item", with_series(OLD_B, lambda s: s.update(successorSeriesIds=[ITEM_A])))
    reject("a parent area that is missing", "is not an area", edit(r1_geography, lambda d: area_in(d, "example-city-a").update(parentAreaId="example-nowhere")))
    reject("a successor area that is missing", "which is not an area", edit(r1_geography, lambda d: area_in(d, "example-city-a").update(successorAreaIds=["example-nowhere"])))
    reject("a parent chain that loops", "the parent chain loops", edit(r1_geography, lambda d: area_in(d, "example-pref-a").update(parentAreaId="example-city-a")))
    reject("a series left out of the movers", "missing from the movers", edit(r2_movers, lambda d: d["movers"].pop()))
    reject("a supported item with no current series", "has no current series", edit(r1_catalog, lambda d: item_of(d, "example.item-b").update(seriesIds=[OLD_B])))
    reject("a price series in the wrong unit family", "does not fit the item's unitBasis", with_series(ITEM_A, lambda s: s["unit"].update(quantityUnit="L")))
    reject("a supported item whose series have no value", "no compatible series has a value",
           with_series("example.rps.item-b.city", lambda s: s.update(observations=[{"period": row["period"], "value": None, "status": "missing"} for row in s["observations"]])))
    reject("a supported item whose series are stale", "is stale", documents, issued_at="2027-06-01T00:00:00Z")

    for label, until in (("a validity window that is too short", "2026-10-20T00:00:00Z"), ("a validity window that is too long", "2027-03-10T00:00:00Z")):
        expect_check_failure(label, "the window must be", lambda until=until: check_manifest_times(Path("manifest.json"), {**manifest, "validUntil": until}))

    reject("a release that reuses the previous release ID", "reuses the release ID", edit(r2_name, lambda d: d.update(releaseId="example-release-1")), previous=True)
    reject("a series dropped from the next release", "was removed; supersede it",
           edit(r2_bundle, lambda d: d.update(series=[s for s in d["series"] if s["seriesId"] != INDEX_A])), previous=True)
    reject("a unit that changes under a stable series ID", "unit changed under a stable series ID", with_series(ITEM_A, lambda s: s["unit"].update(quantity=2)), previous=True)
    reject("a specification that changes under a stable series ID", "specificationId changed under a stable series ID",
           with_series(ITEM_A, lambda s: s["comparability"].update(specificationId="example-spec-z")), previous=True)
    reject("a superseded series that comes back", "must keep its validTo", with_series(OLD_B, lambda s: s.update(validTo=None, successorSeriesIds=[])), previous=True)
    reject("a value that changes without the status revised", "without the status revised",
           with_series(ITEM_A, lambda s: next(row for row in s["observations"] if row["status"] == "observed" and row["value"] is not None).update(value=1)), previous=True)
    reject("a published period that disappears", "of the previous release is missing", with_series(ITEM_A, lambda s: s["observations"].pop(0)), previous=True)
    # The geography file is shared, so a drop is tested with a second geography file in the next release.
    dropped = "releases/example-release-2/geography.json"
    next_release = mutated(documents[r2_name], lambda d: file_of(d, "geography").update(path=dropped))
    expect_check_failure("an area dropped from the next release", "the file is append-only",
                         run({**documents, r2_name: next_release, dropped: mutated(documents[r1_geography], lambda d: d["areas"].pop())}, previous=True))


def check_reference_files() -> None:
    """Runs the checks that need no release on the committed catalog and geography files."""
    catalog_path, geography_path = ROOT / "reference" / "catalog.json", ROOT / "reference" / "geography.json"
    catalog, geography = load_json(catalog_path), load_json(geography_path)
    for path, kind, document in ((catalog_path, "catalog", catalog), (geography_path, "geography", geography)):
        for error in errors_for(kind, document):
            fail(path, f"does not match its schema at {'/'.join(str(part) for part in error.absolute_path) or '(root)'}: {error.message}")
    if failures:
        return
    for problem in duplicate_id_problems(catalog_path.name, catalog, geography_path.name, geography) + area_problems(geography_path.name, geography):
        fail(ROOT / "reference" / problem.path, problem.message)


def main() -> int:
    check_schemas_are_valid()
    if failures:
        print(f"{failures} problem(s) found in the schemas")
        return 1
    check_reference_files()
    documents = check_fixtures_validate()
    if not failures:
        check_signature_and_digests(documents)
    if not failures:
        run_rejection_checks(documents)
    if failures:
        print(f"{failures} problem(s) found in the schemas or fixtures")
        return 1
    print("schema and fixture checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
