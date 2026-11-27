"""Release checks that JSON Schema cannot express (issue #11).

The functions take parsed files and return a list of Problem values, so the fixture validator, the
tests and the release publisher (issue #12) can all run them and decide how to report. A release
that returns any problem must not be published. Nothing here reads a file or the network.

The checks cover references between files, duplicate IDs, completeness of the movers, source coverage for supported catalog items, and, given the previous release,
stable series IDs, append-only areas and explicit revisions. The validity window belongs to the signed
manifest, which a Release does not hold, so the caller runs validity_window_problems on it separately.
"""

import datetime
from typing import NamedTuple

# The design document sets a validUntil of about 45 days and a re-sign at least every 14 days. The
# window must outlast two missed re-signs, and a much longer one defeats the point of expiry.
MIN_VALIDITY_DAYS = 28
MAX_VALIDITY_DAYS = 60

# Units convert only inside their own family (schema README, enum families).
UNIT_FAMILY = {"g": "mass", "kg": "mass", "mL": "volume", "L": "volume", "piece": "piece", "household": "household"}

# A series keeps its ID only while these fields keep their meaning (schema README, series versions).
DEFINITION_FIELDS = (
    ("measureType", lambda s: s["measureType"]),
    ("itemId", lambda s: s["itemId"]),
    ("areaId", lambda s: s["geography"]["areaId"]),
    ("unit", lambda s: s["unit"]),
    ("frequency", lambda s: s["frequency"]),
    ("taxTreatment", lambda s: s["taxTreatment"]),
    ("specificationId", lambda s: s["comparability"]["specificationId"]),
)


class Problem(NamedTuple):
    path: str
    message: str


class Release(NamedTuple):
    """One release: the path and content of its release manifest, and the files it lists by path."""
    path: str
    manifest: dict
    documents: dict

    def files(self, kind: str) -> list:
        """(path, document) for every listed file of the kind."""
        return [(entry["path"], self.documents[entry["path"]]) for entry in self.manifest["files"] if entry["kind"] == kind]

    def series(self) -> dict:
        """seriesId -> (path, series) across every series bundle. The first of a repeated ID wins."""
        found = {}
        for path, bundle in self.files("series-bundle"):
            for series in bundle["series"]:
                found.setdefault(series["seriesId"], (path, series))
        return found

    def single(self, kind: str):
        """(path, document) of the one file of the kind, or None when the release lacks it or repeats it."""
        files = self.files(kind)
        return files[0] if len(files) == 1 else None


def following(period: str, frequency: str) -> str:
    """The period after this one at the given frequency."""
    if frequency == "annual":
        return f"{int(period) + 1:04d}"
    if frequency == "quarterly":
        year, quarter = int(period[:4]), int(period[6])
        return f"{year + quarter // 4:04d}-Q{quarter % 4 + 1}"
    if frequency == "monthly":
        year, month = int(period[:4]), int(period[5:])
        return f"{year + month // 12:04d}-{month % 12 + 1:02d}"
    year, week = int(period[:4]), int(period[6:])
    iso = (datetime.date.fromisocalendar(year, week, 1) + datetime.timedelta(days=7)).isocalendar()
    return f"{iso.year:04d}-W{iso.week:02d}"


def observed(series: dict) -> list:
    """The observations that carry a value."""
    return [row for row in series["observations"] if row["value"] is not None]


def latest_pair(series: dict):
    """(latest, previous) observations when the latest value has a value in the period just before it, else None."""
    rows = series["observations"]
    latest = max((i for i, row in enumerate(rows) if row["value"] is not None), default=None)
    if latest is None or latest == 0 or rows[latest - 1]["value"] is None:
        return None
    if following(rows[latest - 1]["period"], series["frequency"]) != rows[latest]["period"]:
        return None
    return rows[latest], rows[latest - 1]


def mover_pair(series: dict):
    """(latest, previous) for a current series that belongs in the movers, else None.

    A previous value of 0 has no percent change, so the movers schema excludes it.
    """
    pair = latest_pair(series)
    if series["validTo"] is not None or pair is None or pair[1]["value"] <= 0:
        return None
    return pair


def validity_window_problems(path: str, manifest: dict) -> list:
    """The signed manifest's validUntil must follow issuedAt by a policy window."""
    parse = lambda value: datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    days = (parse(manifest["validUntil"]) - parse(manifest["issuedAt"])).total_seconds() / 86400
    if MIN_VALIDITY_DAYS <= days <= MAX_VALIDITY_DAYS:
        return []
    return [Problem(path, f"validUntil is {days:g} days after issuedAt; the window must be "
                          f"{MIN_VALIDITY_DAYS} to {MAX_VALIDITY_DAYS} days (the design document uses about 45)")]


def duplicate_id_problems(catalog_path: str, catalog: dict, geography_path: str, geography: dict) -> list:
    problems = []
    for path, label, ids in ((catalog_path, "itemId", [item["itemId"] for item in catalog["items"]]),
                             (geography_path, "areaId", [area["areaId"] for area in geography["areas"]])):
        for value in sorted({value for value in ids if ids.count(value) > 1}):
            problems.append(Problem(path, f"{label} {value!r} appears more than once"))
    return problems


def series_duplicate_problems(release: Release) -> list:
    """A seriesId is defined once across the series bundles, so no later copy goes unchecked."""
    seen, problems = set(), []
    for path, bundle in release.files("series-bundle"):
        for series in bundle["series"]:
            if series["seriesId"] in seen:
                problems.append(Problem(path, f"seriesId {series['seriesId']!r} appears more than once in the release"))
            seen.add(series["seriesId"])
    return problems


def area_problems(path: str, geography: dict) -> list:
    """Parent and successor links resolve, and every parent chain ends at the national area without a loop."""
    areas = {area["areaId"]: area for area in geography["areas"]}
    problems = []
    for area_id, area in areas.items():
        for successor in area["successorAreaIds"]:
            if successor not in areas:
                problems.append(Problem(path, f"{area_id}: successorAreaIds names {successor}, which is not an area"))
        seen = {area_id}
        current = area
        while current["parentAreaId"] is not None:
            parent = current["parentAreaId"]
            if parent not in areas:
                problems.append(Problem(path, f"{area_id}: parentAreaId {parent} is not an area"))
                break
            if parent in seen:
                problems.append(Problem(path, f"{area_id}: the parent chain loops through {parent}"))
                break
            seen.add(parent)
            current = areas[parent]
    return problems


def reference_problems(release: Release) -> list:
    """Every ID that a catalog item, series or area names resolves to a record in the release."""
    catalog = release.single("catalog")
    geography = release.single("geography")
    if catalog is None or geography is None:
        return []  # The release manifest check already reports a missing or repeated file.
    catalog_path, catalog_doc = catalog
    items = {item["itemId"]: item for item in catalog_doc["items"]}
    areas = {area["areaId"] for area in geography[1]["areas"]}
    series = release.series()
    problems = []
    for item in catalog_doc["items"]:
        for series_id in item["seriesIds"]:
            if series_id not in series:
                problems.append(Problem(catalog_path, f"{item['itemId']}: seriesIds names {series_id}, which is not in the release"))
            elif series[series_id][1]["itemId"] != item["itemId"]:
                problems.append(Problem(catalog_path, f"{item['itemId']}: lists {series_id}, which belongs to item {series[series_id][1]['itemId']}"))
    for series_id, (path, entry) in series.items():
        if entry["itemId"] not in items:
            problems.append(Problem(path, f"{series_id}: itemId {entry['itemId']} is not in the catalog"))
        elif series_id not in items[entry["itemId"]]["seriesIds"]:
            problems.append(Problem(path, f"{series_id}: item {entry['itemId']} does not list the series, so nothing would use it"))
        if entry["geography"]["areaId"] not in areas:
            problems.append(Problem(path, f"{series_id}: areaId {entry['geography']['areaId']} is not in the geography file"))
        for successor in entry["successorSeriesIds"]:
            if successor not in series:
                problems.append(Problem(path, f"{series_id}: successorSeriesIds names {successor}, which is not in the release"))
            elif successor == series_id or series[successor][1]["itemId"] != entry["itemId"]:
                problems.append(Problem(path, f"{series_id}: successor {successor} must be another series of the same item"))
    problems += area_problems(*release.single("geography"))
    return problems


def mover_problems(release: Release) -> list:
    """Every current series with a latest and a previous value appears in the movers."""
    movers = release.single("movers")
    if movers is None:
        return []
    path, document = movers
    listed = {mover["seriesId"] for mover in document["movers"]}
    return [Problem(path, f"{series_id}: has a latest and a previous value but is missing from the movers")
            for series_id, (_, series) in release.series().items()
            if mover_pair(series) and series_id not in listed]


def coverage_problems(release: Release, issued_at) -> list:
    """Every supported catalog item has a compatible series with a value, and one of them is fresh.

    Fresh means the release is issued no later than expectedNextRelease plus graceDays (design document,
    section 5.2). Without an issuedAt only the value is checked.
    """
    catalog = release.single("catalog")
    if catalog is None:
        return []
    path, document = catalog
    series = release.series()
    freshness = {entry["seriesId"]: entry for entry in release.manifest["series"]}
    problems = []
    for item in document["items"]:
        if not item["supported"]:
            continue
        name = item["itemId"]
        basis = item["unitBasis"]
        current = [series[i][1] for i in item["seriesIds"] if i in series and series[i][1]["validTo"] is None]
        if not current:
            problems.append(Problem(path, f"{name}: is supported but has no current series"))
            continue
        compatible = []
        for entry in current:
            unit = entry["unit"]
            if entry["measureType"] == "retail_price":
                ok = basis is not None and UNIT_FAMILY[unit["quantityUnit"]] == UNIT_FAMILY[basis["quantityUnit"]]
            elif entry["measureType"] == "household_expenditure":
                ok = basis is None
            else:
                ok = True  # A price index has no quantity unit and sits beside the prices.
            if ok:
                compatible.append(entry)
            else:
                problems.append(Problem(path, f"{name}: {entry['seriesId']} has a unit or measure that does not fit the item's unitBasis"))
        usable = [entry for entry in compatible if observed(entry)]
        if compatible and not usable:
            problems.append(Problem(path, f"{name}: no compatible series has a value"))
        elif issued_at and usable and not any(is_fresh(freshness.get(entry["seriesId"]), issued_at) for entry in usable):
            problems.append(Problem(path, f"{name}: every compatible series is stale at the release's issuedAt"))
    return problems


def is_fresh(entry, issued_at: str) -> bool:
    """True when the release is issued by the end of the series' grace period. A missing entry is not fresh."""
    if entry is None or entry["expectedNextRelease"] is None:
        return False
    deadline = datetime.date.fromisoformat(entry["expectedNextRelease"]) + datetime.timedelta(days=entry["graceDays"])
    return datetime.date.fromisoformat(issued_at[:10]) <= deadline


def previous_problems(release: Release, previous: Release) -> list:
    """What the previous release published stays published, and a changed value says it was revised."""
    problems = []
    if release.manifest["releaseId"] == previous.manifest["releaseId"]:
        problems.append(Problem(release.path, "reuses the release ID of the previous release"))
    now_geography, before_geography = release.single("geography"), previous.single("geography")
    if now_geography and before_geography:
        now_areas = {area["areaId"] for area in now_geography[1]["areas"]}
        for area in before_geography[1]["areas"]:
            if area["areaId"] not in now_areas:
                problems.append(Problem(now_geography[0], f"{area['areaId']}: an area of the previous release was removed; the file is append-only"))
    now_series = release.series()
    for series_id, (_, before) in previous.series().items():
        if series_id not in now_series:
            problems.append(Problem(release.path, f"{series_id}: a series of the previous release was removed; supersede it instead"))
            continue
        path, now = now_series[series_id]
        for label, read in DEFINITION_FIELDS:
            if read(before) != read(now):
                problems.append(Problem(path, f"{series_id}: {label} changed under a stable series ID; publish a new series and supersede this one"))
        if before["validTo"] is not None and (now["validTo"], now["successorSeriesIds"]) != (before["validTo"], before["successorSeriesIds"]):
            problems.append(Problem(path, f"{series_id}: a superseded series must keep its validTo and successors"))
        now_rows = {row["period"]: row for row in now["observations"]}
        for row in before["observations"]:
            changed = now_rows.get(row["period"])
            if changed is None:
                problems.append(Problem(path, f"{series_id}: the period {row['period']} of the previous release is missing"))
            elif row["value"] is not None and changed["value"] != row["value"] and (changed["value"] is None or changed["status"] != "revised"):
                problems.append(Problem(path, f"{series_id}: the value for {row['period']} changed from {row['value']} to "
                                              f"{changed['value']} without the status revised"))
    return problems


def check_release(release: Release, issued_at=None, previous=None) -> list:
    """Runs every release check. issued_at is the signed manifest's issuedAt when the release has one."""
    problems = series_duplicate_problems(release) + reference_problems(release) + mover_problems(release) + coverage_problems(release, issued_at)
    catalog, geography = release.single("catalog"), release.single("geography")
    if catalog and geography:
        problems += duplicate_id_problems(catalog[0], catalog[1], geography[0], geography[1])
    if previous is not None:
        problems += previous_problems(release, previous)
    return problems
