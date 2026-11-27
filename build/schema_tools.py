"""Shared helpers for the schema validator and the fixture generator.

Loads the version 1 schemas into one registry so their relative references resolve,
and implements the canonical JSON and digest rules that the signed manifest uses.
"""

import hashlib
import json
from pathlib import Path

from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DIR = ROOT / "schema" / "v1"
FIXTURE_DIR = ROOT / "fixtures" / "schema-v1"

MAX_SAFE_INTEGER = 2**53 - 1

# Maps a file kind to its schema file name.
SCHEMA_FILES = {
    "common": "common.schema.json",
    "series-bundle": "series-bundle.schema.json",
    "catalog": "catalog.schema.json",
    "baseline": "baseline.schema.json",
    "geography": "geography.schema.json",
    "movers": "movers.schema.json",
    "signed-manifest": "signed-manifest.schema.json",
    "manifest": "manifest.schema.json",
    "release-manifest": "release-manifest.schema.json",
}


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def schema_registry() -> Registry:
    """Registers every schema file under its file name, which is how the files reference each other."""
    registry = Registry()
    for name in SCHEMA_FILES.values():
        resource = Resource.from_contents(load_json(SCHEMA_DIR / name), default_specification=DRAFT202012)
        registry = registry.with_resource(name, resource)
    return registry


def _check_canonical(value) -> None:
    """Raises ValueError for anything where Python's output would differ from RFC 8785."""
    if isinstance(value, dict):
        for key, item in value.items():
            if not (isinstance(key, str) and key.isascii()):
                raise ValueError(f"a canonical JSON key must be ASCII text, got {key!r}")
            _check_canonical(item)
    elif isinstance(value, list):
        for item in value:
            _check_canonical(item)
    elif isinstance(value, float):
        raise ValueError(f"a canonical JSON number must be an integer, got the float {value!r}")
    elif isinstance(value, int) and not isinstance(value, bool) and abs(value) > MAX_SAFE_INTEGER:
        raise ValueError(f"an integer beyond 2**53 - 1 is not exact in RFC 8785: {value}")


def canonical_json(value) -> bytes:
    """RFC 8785 canonical JSON, restricted to what manifests contain.

    A manifest holds ASCII keys, strings, integers and null, so sorting keys by code point,
    removing whitespace and leaving non-ASCII text unescaped gives the RFC 8785 bytes. Floats and
    non-ASCII keys, where Python's output differs from RFC 8785, raise ValueError.
    """
    _check_canonical(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fixture_bytes(value) -> bytes:
    """The bytes a published file has: two-space indentation, UTF-8 and a final newline."""
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
