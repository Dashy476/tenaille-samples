"""Fingerprint models, package-manager hints, and the starter check runner.

Week-1 behavior is local. `collect` reads inventory JSON that a human already
authorized. A later HARBNGR can fill that JSON over SSH. This file will not.
"""

from __future__ import annotations

import json
from pathlib import Path

from tenaille.paths import STARTER_CHECKS


class ReconError(ValueError):
    """The sample cannot collect this target."""


_FAMILY_MANAGERS = {
    "linux": ("apt", "dnf", "rpm", "pacman"),
    "windows": ("winget", "dism"),
    "macos": ("brew", "pkgutil"),
}


def load_inventory(path: Path) -> dict:
    """Read one inventory document. Refuse anything that is not a lab fixture."""
    if not path.is_file():
        raise ReconError(
            f"No inventory file at {path}. Live SSH is not implemented. "
            "Pass a synthetic fixture such as examples/lab-web-01.json."
        )
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ReconError(f"{path} is not JSON: {exc}") from exc
    if data.get("fixture") is not True or data.get("authorization") != "synthetic-lab":
        raise ReconError(
            "This sample only accepts synthetic lab fixtures "
            "(fixture: true and authorization: synthetic-lab)."
        )
    host = data.get("host") or {}
    if not host.get("id"):
        raise ReconError("Inventory is missing host.id.")
    return data


def detect_package_managers(inventory: dict) -> list[str]:
    """Stub. Trusts managers the fixture already recorded.

    A future collector would run the distro's own query (`dpkg -l`, `rpm -qa`,
    a Windows uninstall listing) on a host the operator can already log into.
    It would not guess across the network.
    """
    recorded = [str(item) for item in (inventory.get("package_managers") or [])]
    family = str(((inventory.get("host") or {}).get("os") or {}).get("family", "")).lower()
    known = _FAMILY_MANAGERS.get(family, ())
    ordered: list[str] = []
    for name in recorded + [item for item in known if item in recorded]:
        if name not in ordered:
            ordered.append(name)
    return ordered


def fingerprint_summary(inventory: dict) -> list[str]:
    """Short, non-secret description of a fixture. Safe to print."""
    host = inventory["host"]
    os_info = host.get("os") or {}
    addresses = ", ".join(host.get("addresses") or []) or "(none)"
    managers = ", ".join(detect_package_managers(inventory)) or "(none recorded)"
    services = inventory.get("services") or []
    return [
        f"Host: {host.get('id')}  hostname: {host.get('hostname', '')}",
        f"OS: {os_info.get('family', '?')} {os_info.get('distro', '')} {os_info.get('version', '')}".rstrip(),
        f"Exposure: {host.get('exposure', 'unspecified')}  addresses: {addresses}",
        f"Package managers: {managers}",
        f"Services recorded: {len(services)}  packages recorded: {len(inventory.get('packages') or [])}",
        "Collector: HARBNGR sample (fixture read, no SSH)",
    ]


def _dig(inventory: dict, path: str):
    """Tiny selector: 'host.os.family' or 'services[name=sshd].version'."""
    current: object = inventory
    for part in path.split("."):
        if current is None:
            return None
        if "[" in part and part.endswith("]"):
            name, predicate = part[:-1].split("[", 1)
            if name:
                if not isinstance(current, dict):
                    return None
                current = current.get(name)
            if not isinstance(current, list):
                return None
            key, _, expected = predicate.partition("=")
            found = None
            for item in current:
                if isinstance(item, dict) and str(item.get(key)) == expected:
                    found = item
                    break
            current = found
        else:
            if not isinstance(current, dict):
                return None
            current = current.get(part)
    return current


def _rule_passes(value, rule: str) -> bool:
    if rule == "nonempty":
        if value is None:
            return False
        if isinstance(value, str):
            return bool(value.strip())
        if isinstance(value, (list, dict)):
            return len(value) > 0
        return True
    if rule == "list":
        return isinstance(value, list)
    if rule == "synthetic-lab":
        return value == "synthetic-lab"
    return False


def run_starter_checks(inventory: dict, checks_dir: Path | None = None) -> list[dict]:
    """Run the public starter pack against an in-memory inventory.

    Every check is a read of a field the fixture already holds. None of them
    open a socket, change a config, or try a credential.
    """
    folder = checks_dir or STARTER_CHECKS
    results = []
    for path in sorted(folder.glob("*.json")):
        spec = json.loads(path.read_text(encoding="utf-8"))
        if spec.get("destructive") is not False:
            results.append(
                {
                    "id": spec.get("id", path.stem),
                    "title": spec.get("title", path.stem),
                    "status": "refused",
                    "detail": "Starter pack refused a check that is not marked non-destructive.",
                }
            )
            continue
        value = _dig(inventory, spec["reads"])
        ok = _rule_passes(value, spec.get("rule", "nonempty"))
        results.append(
            {
                "id": spec["id"],
                "title": spec["title"],
                "status": "pass" if ok else "not-recorded",
                "detail": spec.get("pass_note" if ok else "fail_note", ""),
            }
        )
    return results


def collect(path: Path) -> tuple[dict, list[dict]]:
    """Public sample entry: load a fixture and run starter checks. No SSH."""
    inventory = load_inventory(path)
    return inventory, run_starter_checks(inventory)


def refuse_live_ssh() -> None:
    raise ReconError(
        "Live SSH recon is not implemented in this sample. "
        "HARBNGR here only reads an inventory file you already have. "
        "It will not connect to a host, scan a range, or try credentials."
    )
