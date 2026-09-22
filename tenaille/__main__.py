"""Tenaille CLI. Fixtures only.

    python -m tenaille demo
    python -m tenaille lookup CVE-2024-6387
    python -m tenaille recon --inventory examples/lab-web-01.json
    python -m tenaille assess --inventory examples/lab-web-01.json --mode red
    python -m tenaille assess --mode blue
    python -m tenaille assess --mode both
"""

from __future__ import annotations

import argparse
import sys

from tenaille import PRODUCT, TAGLINE, __version__
from tenaille.confirmation import Ceiling, validate_brief
from tenaille.cvinferno import render_red_brief
from tenaille.cvbastion import render_blue_brief
from tenaille.harbngr import ReconError, collect, fingerprint_summary, refuse_live_ssh
from tenaille.intel import IntelError, lookup_cve
from tenaille.intel.lookup import refuse_live_intel
from tenaille.paths import DEFAULT_INVENTORY, resolve_user_path


def _inventory_or_default(value: str | None):
    if value is None:
        return DEFAULT_INVENTORY
    return resolve_user_path(value)


def render_demo() -> str:
    inventory, _checks = collect(DEFAULT_INVENTORY)
    host_id = inventory["host"]["id"]
    parts = [
        f"{PRODUCT} {__version__}",
        TAGLINE,
        "Pronounced ten-AY.",
        f"Demo host: {host_id} (synthetic lab fixture).",
        "Same inventory. Red face, then Blue face.",
        "",
        render_red_brief(inventory).rstrip(),
        "",
        render_blue_brief(inventory).rstrip(),
        "",
    ]
    text = "\n".join(parts) + "\n"
    validate_brief(text, Ceiling.VERSION_MATCH)
    return text


def _cmd_demo(_args: argparse.Namespace) -> int:
    sys.stdout.write(render_demo())
    return 0


def _cmd_lookup(args: argparse.Namespace) -> int:
    if args.live:
        refuse_live_intel()
    record = lookup_cve(args.cve_id)
    sys.stdout.write("\n".join(record.summary_lines()) + "\n")
    return 0


def _cmd_recon(args: argparse.Namespace) -> int:
    if args.live:
        refuse_live_ssh()
    inventory, checks = collect(resolve_user_path(args.inventory))
    lines = ["HARBNGR sample — fixture read", *fingerprint_summary(inventory), "", "Starter checks:"]
    for item in checks:
        lines.append(f"  [{item['status']}] {item['id']} — {item['title']}")
        if item.get("detail"):
            lines.append(f"           {item['detail']}")
    lines.append("")
    lines.append("No SSH session was opened.")
    sys.stdout.write("\n".join(lines) + "\n")
    return 0


def _cmd_assess(args: argparse.Namespace) -> int:
    if args.live:
        refuse_live_ssh()
    inventory, _checks = collect(_inventory_or_default(args.inventory))
    chunks = []
    if args.mode in ("red", "both"):
        chunks.append(render_red_brief(inventory).rstrip())
    if args.mode in ("blue", "both"):
        chunks.append(render_blue_brief(inventory).rstrip())
    sys.stdout.write("\n\n".join(chunks) + "\n")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tenaille",
        description=f"{PRODUCT} — {TAGLINE} Local lab sample. Fixtures only.",
    )
    parser.add_argument("--version", action="version", version=f"{PRODUCT} {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    demo = sub.add_parser("demo", help="Print the product name and both sample briefs.")
    demo.set_defaults(func=_cmd_demo)

    lookup = sub.add_parser("lookup", help="Print a checked-in CVE fixture.")
    lookup.add_argument("cve_id", help="For example CVE-2024-6387")
    lookup.add_argument(
        "--live",
        action="store_true",
        help="Refuses. Live NVD/OSV/KEV/EPSS clients are not in this sample.",
    )
    lookup.set_defaults(func=_cmd_lookup)

    recon = sub.add_parser("recon", help="Read an inventory fixture and run starter checks.")
    recon.add_argument("--inventory", required=True, help="Path to a synthetic inventory JSON file.")
    recon.add_argument(
        "--live",
        action="store_true",
        help="Refuses. This sample does not open SSH.",
    )
    recon.set_defaults(func=_cmd_recon)

    assess = sub.add_parser("assess", help="Write a Red brief, a Blue brief, or both.")
    assess.add_argument(
        "--inventory",
        default=None,
        help="Synthetic inventory JSON. Defaults to examples/lab-web-01.json.",
    )
    assess.add_argument(
        "--mode",
        choices=("red", "blue", "both"),
        default="both",
        help="red = CVINFERNO, blue = CVBASTION, both = the two faces.",
    )
    assess.add_argument(
        "--live",
        action="store_true",
        help="Refuses. Assessment reads the fixture only.",
    )
    assess.set_defaults(func=_cmd_assess)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (ReconError, IntelError) as exc:
        sys.stderr.write(f"{exc}\n")
        return 2


if __name__ == "__main__":
    sys.exit(main())
