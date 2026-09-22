"""Label findings with a confirmation ceiling and reject over-claims.

This sample stops at version / CPE match. Active verification and
template verification are named so a later pack can use them. They are
not performed here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from tenaille.intel.models import CveRecord


class Ceiling(str, Enum):
    VERSION_MATCH = "version_match"
    ACTIVE_VERIFY = "active_verify"
    TEMPLATE_VERIFIED = "template_verified"


class ConfirmationError(ValueError):
    """A brief claimed more than its confirmation ceiling allows."""


# A version_match brief may discuss a CVE. It may not claim the host was compromised.
_FORBIDDEN_AT_VERSION_MATCH = (
    re.compile(r"\bexploited\b", re.IGNORECASE),
    re.compile(r"\bexploit succeeded\b", re.IGNORECASE),
    re.compile(r"\bproof of compromise\b", re.IGNORECASE),
    re.compile(r"\bshell obtained\b", re.IGNORECASE),
    re.compile(r"\bweaponized\b", re.IGNORECASE),
)


@dataclass(frozen=True)
class Finding:
    cve_id: str
    title: str
    role: str
    ceiling: Ceiling
    priority: str
    version_match: bool
    evidence: str
    why_it_matters: str
    not_claimed: str
    blue_control: str
    detection: str
    remediation: str
    done_means: str


def context_priority(
    *,
    kev_listed: bool,
    epss_score: float | None,
    exposure: str,
    ceiling: Ceiling,
) -> str:
    """Context-aware priority. KEV, EPSS, and exposure outrank raw CVSS.

    A lab-only fixture can never be P1. Version match adds no extra weight:
    it is the floor of this sample, not proof the issue is reachable.
    """
    score = 0
    if kev_listed:
        score += 2
    if epss_score is not None and epss_score >= 0.1:
        score += 1
    if exposure == "internet-facing":
        score += 2
    if ceiling is Ceiling.ACTIVE_VERIFY:
        score += 1
    elif ceiling is Ceiling.TEMPLATE_VERIFIED:
        score += 1

    if exposure == "lab-only":
        return "P2" if score >= 2 else "P3"
    if score >= 4:
        return "P1"
    if score >= 2:
        return "P2"
    return "P3"


def validate_brief(text: str, ceiling: Ceiling) -> None:
    """Raise ConfirmationError if text claims compromise past the ceiling."""
    if ceiling is not Ceiling.VERSION_MATCH:
        return
    for pattern in _FORBIDDEN_AT_VERSION_MATCH:
        match = pattern.search(text)
        if match:
            raise ConfirmationError(
                f"Brief claims {match.group(0)!r} but the confirmation "
                f"ceiling is {ceiling.value}. Version match is not compromise."
            )


def _openssh_tuple(version: str) -> tuple[int, int, int] | None:
    """Parse an upstream OpenSSH version like 8.9p1. Debian revisions are ignored."""
    match = re.search(r"(\d+)\.(\d+)p(\d+)", version or "")
    if not match:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def _in_range(version: str, start: str | None, end: str | None, start_inclusive: bool, end_inclusive: bool) -> bool:
    got = _openssh_tuple(version)
    if got is None:
        return False
    if start:
        bound = _openssh_tuple(start)
        if bound is None:
            return False
        if got < bound or (got == bound and not start_inclusive):
            return False
    if end:
        bound = _openssh_tuple(end)
        if bound is None:
            return False
        if got > bound or (got == bound and not end_inclusive):
            return False
    return True


def version_matches_record(version: str, record: CveRecord) -> bool:
    """True when the upstream version sits in a published affected range.

    This does not decide whether a distro backport already fixed the package.
    """
    if not record.affected:
        return False
    for span in record.affected:
        if _in_range(
            version,
            span.version_start_including or span.version_start_excluding,
            span.version_end_including or span.version_end_excluding,
            start_inclusive=bool(span.version_start_including or not span.version_start_excluding),
            end_inclusive=bool(span.version_end_including or not span.version_end_excluding),
        ):
            return True
    return False


def _sshd(inventory: dict) -> dict | None:
    for service in inventory.get("services") or []:
        if service.get("name") == "sshd":
            return service
    return None


def _openssh_version(inventory: dict) -> str:
    service = _sshd(inventory)
    if service and service.get("version"):
        return str(service["version"])
    for package in inventory.get("packages") or []:
        if "openssh" in str(package.get("name", "")).lower():
            return str(package.get("version", ""))
    return ""


def evaluate_inventory(inventory: dict, records: dict[str, CveRecord]) -> list[Finding]:
    """Build the starter finding list. Ceiling is always version_match."""
    exposure = str((inventory.get("host") or {}).get("exposure") or "lab-only")
    version = _openssh_version(inventory)
    service = _sshd(inventory) or {}
    config = service.get("config") or {}
    agent = str(config.get("allow_agent_forwarding", "")).lower()
    findings: list[Finding] = []

    regre = records.get("CVE-2024-6387")
    if regre and version and version_matches_record(version, regre):
        findings.append(
            Finding(
                cve_id="CVE-2024-6387",
                title="OpenSSH sshd signal-handler race (regreSSHion), upstream range",
                role="Path A — version match on the recorded sshd",
                ceiling=Ceiling.VERSION_MATCH,
                priority=context_priority(
                    kev_listed=regre.kev.listed,
                    epss_score=regre.epss.score,
                    exposure=exposure,
                    ceiling=Ceiling.VERSION_MATCH,
                ),
                version_match=True,
                evidence=(
                    f"Recorded sshd version {version} falls in the published upstream "
                    "range 8.5p1 through 9.7p1. The Debian package revision was not compared "
                    "to a vendor advisory, so a backport would not show up here."
                ),
                why_it_matters=(
                    "Public description: a race in sshd signal handling may let an "
                    "unauthenticated remote client reach an unsafe state. Attack complexity "
                    "in the published CVSS vector is High, and the attempts are described "
                    "as noisy. This sample does not describe how to trigger it."
                ),
                not_claimed=(
                    "Not claimed: that this lab host is reachable, that the race is "
                    "present in this build, that a distro patch is absent, or that "
                    "anything was compromised. Ceiling is version_match."
                ),
                blue_control="Patch sshd to a vendor build outside the upstream range, then re-record the version.",
                detection=(
                    "Inventory drift on the openssh-server package, plus authentication "
                    "failures that pile up inside LoginGraceTime. Review the vendor note "
                    "before treating volume alone as this issue."
                ),
                remediation=(
                    "Install the distribution's openssh security update and record the new "
                    "package version. Vendor write-ups also discuss setting LoginGraceTime "
                    "to 0 as a temporary mitigation; that setting has a denial-of-service "
                    "tradeoff (MaxStartups exhaustion). This sample does not change a host."
                ),
                done_means=(
                    "The recorded upstream version is outside 8.5p1–9.7p1, or a human has "
                    "attached a vendor advisory showing this package revision is fixed. "
                    "The ceiling is still not higher than the new evidence."
                ),
            )
        )

    agent_cve = records.get("CVE-2023-38408")
    agent_match = bool(agent_cve and version and version_matches_record(version, agent_cve))
    if agent_cve and (agent_match or agent == "yes"):
        findings.append(
            Finding(
                cve_id="CVE-2023-38408",
                title="OpenSSH agent-forwarding class, config observation",
                role="Path B — post-foothold, config-driven",
                ceiling=Ceiling.VERSION_MATCH,
                priority=context_priority(
                    kev_listed=agent_cve.kev.listed,
                    epss_score=agent_cve.epss.score,
                    exposure=exposure,
                    ceiling=Ceiling.VERSION_MATCH,
                ),
                version_match=agent_match,
                evidence=(
                    f"Recorded AllowAgentForwarding is {config.get('allow_agent_forwarding', 'absent')}. "
                    f"Upstream version {version or 'unknown'} "
                    + (
                        "is before 9.3p2, so the published range matches. "
                        if agent_match
                        else "is not inside the published 'before 9.3p2' range, so this is config context only. "
                    )
                    + "No forwarded-agent session is recorded."
                ),
                why_it_matters=(
                    "Public description: the PKCS#11 feature in ssh-agent before 9.3p2 "
                    "could be a problem if an agent was forwarded to a system the agent "
                    "should not trust. That is a post-foothold, configuration-driven class "
                    "of issue. This sample does not describe how."
                ),
                not_claimed=(
                    "Not claimed: that an agent was forwarded, that a library was loaded, "
                    "or that the lab host was compromised. Ceiling stays version_match "
                    "even where the upstream number matches, because the running config "
                    "was not re-checked."
                ),
                blue_control="Turn agent forwarding off unless a named workflow needs it, and record the exception.",
                detection=(
                    "Alert when sshd_config AllowAgentForwarding changes, and when SSH "
                    "client configs set ForwardAgent. A forwarded agent is an identity "
                    "decision, not just a package version."
                ),
                remediation=(
                    "Set AllowAgentForwarding to no on lab images that do not need it. "
                    "Upgrade OpenSSH to a build at or after 9.3p2 when the version match "
                    "is true. Re-collect the inventory afterward."
                ),
                done_means=(
                    "AllowAgentForwarding is no, or an exception names the user and the "
                    "purpose. If the upstream version was in range, the recorded build is "
                    "9.3p2 or later, or a vendor advisory covers this package revision."
                ),
            )
        )

    return findings
