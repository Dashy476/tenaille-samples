"""Load a checked-in CVE fixture. No HTTP."""

from __future__ import annotations

import json
from pathlib import Path

from tenaille.intel.models import AffectedSpan, CveRecord, EpssScore, KevStatus, OsvHit
from tenaille.paths import INTEL_FIXTURES


class IntelError(FileNotFoundError):
    """The sample has no fixture for this id, and it will not call the network."""


def load_record(path: Path) -> CveRecord:
    data = json.loads(path.read_text(encoding="utf-8"))
    epss = data.get("epss") or {}
    kev = data.get("kev") or {}
    osv = data.get("osv") or {}
    spans = []
    for item in data.get("affected") or []:
        spans.append(
            AffectedSpan(
                cpe=item["cpe"],
                version_start_including=item.get("version_start_including"),
                version_start_excluding=item.get("version_start_excluding"),
                version_end_including=item.get("version_end_including"),
                version_end_excluding=item.get("version_end_excluding"),
                note=item.get("note", ""),
            )
        )
    return CveRecord(
        cve_id=data["cve_id"],
        title=data["title"],
        description=data["description"],
        published=data.get("published", ""),
        cvss_score=data.get("cvss_score"),
        cvss_vector=data.get("cvss_vector", ""),
        epss=EpssScore(
            score=epss.get("score"),
            percentile=epss.get("percentile"),
            source=epss.get("source", "fixture"),
            note=epss.get("note", ""),
        ),
        kev=KevStatus(
            listed=bool(kev.get("listed")),
            source=kev.get("source", "fixture"),
            note=kev.get("note", ""),
        ),
        osv=OsvHit(
            queried=bool(osv.get("queried")),
            ids=list(osv.get("ids") or []),
            note=osv.get("note", ""),
        ),
        affected=spans,
        references=list(data.get("references") or []),
        fixture_snapshot=data.get("fixture_snapshot", ""),
        snapshot_note=data.get("snapshot_note", ""),
    )


def lookup_cve(cve_id: str) -> CveRecord:
    """Return the checked-in fixture for cve_id.

    TODO: NVD client — GET the CVE 2.0 API for this id only, with an API key
          in the environment, and cache the JSON locally. Sleep between calls.
          Do not page the whole catalog from a student laptop.
    TODO: EPSS client — GET https://api.first.org/data/v1/epss?cve=ID
          One id per call in this sample. No bulk pulls.
    TODO: KEV client — read CISA's published KEV catalog and match the id.
          A daily local copy is enough. Do not poll it in a loop.
    TODO: OSV client — POST https://api.osv.dev/v1/query for a package name
          the inventory already recorded. Do not fuzz package names.
    """
    safe = cve_id.strip().upper()
    path = INTEL_FIXTURES / f"{safe}.json"
    if not path.is_file():
        known = sorted(item.stem for item in INTEL_FIXTURES.glob("CVE-*.json"))
        raise IntelError(
            f"No local fixture for {safe}. This sample does not call NVD, OSV, "
            f"KEV, or EPSS. Checked-in ids: {', '.join(known) or '(none)'}."
        )
    return load_record(path)


def refuse_live_intel() -> None:
    """Live clients stay unimplemented on purpose."""
    raise IntelError(
        "Live intel is not enabled. Rate limits: NVD asks clients to space "
        "requests and will reject bursts; EPSS and OSV are public but still "
        "not a scraping target. Use `tenaille lookup CVE-...` for a fixture."
    )
