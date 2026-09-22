"""Locations inside this sample tree. No network paths."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
INTEL_FIXTURES = EXAMPLES / "intel"
DEFAULT_INVENTORY = EXAMPLES / "lab-web-01.json"
STARTER_CHECKS = ROOT / "packs" / "public-starter" / "checks"


def resolve_user_path(value: str) -> Path:
    """Prefer the path as given, then the same path under this sample tree."""
    raw = Path(value)
    if raw.is_file():
        return raw
    rooted = ROOT / value
    if rooted.is_file():
        return rooted
    return raw
