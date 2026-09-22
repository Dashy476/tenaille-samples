"""Types for a CVE record and the public intel sources Tenaille will read later."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class EpssScore:
    """FIRST.org EPSS. None means this fixture did not invent a live score."""

    score: float | None
    percentile: float | None
    source: str
    note: str


@dataclass(frozen=True)
class KevStatus:
    """CISA Known Exploited Vulnerabilities flag. A fixture flag is not a live query."""

    listed: bool
    source: str
    note: str


@dataclass(frozen=True)
class OsvHit:
    """OSV.dev hit. queried=False means no HTTP call was made."""

    queried: bool
    ids: list[str] = field(default_factory=list)
    note: str = ""


@dataclass(frozen=True)
class AffectedSpan:
    cpe: str
    version_start_including: str | None = None
    version_start_excluding: str | None = None
    version_end_including: str | None = None
    version_end_excluding: str | None = None
    note: str = ""


@dataclass(frozen=True)
class CveRecord:
    cve_id: str
    title: str
    description: str
    published: str
    cvss_score: float | None
    cvss_vector: str
    epss: EpssScore
    kev: KevStatus
    osv: OsvHit
    affected: list[AffectedSpan]
    references: list[str]
    fixture_snapshot: str
    snapshot_note: str

    def summary_lines(self) -> list[str]:
        epss = "not in this fixture" if self.epss.score is None else f"{self.epss.score:.3f}"
        kev = "listed" if self.kev.listed else "not listed in this fixture"
        lines = [
            f"{self.cve_id} — {self.title}",
            f"Snapshot: {self.fixture_snapshot} (not a live lookup)",
            f"CVSS: {self.cvss_score if self.cvss_score is not None else 'n/a'}  {self.cvss_vector}",
            f"KEV: {kev}",
            f"EPSS: {epss}",
            f"OSV queried: {self.osv.queried}",
            "",
            self.description,
            "",
            "Affected ranges in this fixture:",
        ]
        if not self.affected:
            lines.append("  (none recorded)")
        for span in self.affected:
            lines.append(
                "  "
                + " ".join(
                    part
                    for part in (
                        span.cpe,
                        f"from {span.version_start_including} (incl.)" if span.version_start_including else "",
                        f"after {span.version_start_excluding}" if span.version_start_excluding else "",
                        f"through {span.version_end_including} (incl.)" if span.version_end_including else "",
                        f"before {span.version_end_excluding}" if span.version_end_excluding else "",
                    )
                    if part
                )
            )
            if span.note:
                lines.append(f"    {span.note}")
        lines.append("")
        lines.append(self.snapshot_note)
        if self.references:
            lines.append("References:")
            lines.extend(f"  {item}" for item in self.references)
        return lines
