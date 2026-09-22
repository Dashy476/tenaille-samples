# Tenaille

Pronounced **ten-AY**.

**Two faces. One host.**

Tenaille is local-first CVE intelligence for a lab. HARBNGR turns an authorized host into inventory JSON. CVINFERNO writes the Red Team attack-path brief. CVBASTION writes the Blue Team detection and remediation brief. Same inventory. Two opposing faces.

This folder is a standalone sample a newcomer can run. It is not a production scanner. It does not open SSH, does not call NVD, and does not ship exploit content. Every host in `examples/` is a synthetic lab fixture.

## Ten minutes

Python 3.10 or newer.

Windows PowerShell, from `D:\Python\tenaille-samples`:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m tenaille demo
```

If PowerShell says the script is not digitally signed, allow it for this window only and try again:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

Linux and macOS:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m tenaille demo
```

The requirements file is intentionally empty: the sample uses the standard library. Do not use `source .venv/bin/activate` in PowerShell. The Windows virtualenv has no `bin` directory.

`python -m tenaille demo` prints the product name and both briefs, then exits 0.

Other commands, still from fixtures:

```bash
python -m tenaille lookup CVE-2024-6387
python -m tenaille recon --inventory examples/lab-web-01.json
python -m tenaille assess --inventory examples/lab-web-01.json --mode red
python -m tenaille assess --mode blue
python -m tenaille assess --mode both
python -m unittest discover -s tests
```

`--live` on lookup, recon, or assess exits with an error. Live APIs and live SSH are stubs.

## What the demo is saying

`lab-web-01` records OpenSSH 8.9p1 and agent forwarding enabled. That is enough for two hypotheses:

- **Path A, CVE-2024-6387.** The upstream version sits in the published 8.5p1–9.7p1 range. Ceiling: `version_match`.
- **Path B, CVE-2023-38408.** Agent-forwarding class, post-foothold, and the upstream version is before 9.3p2. Ceiling: `version_match`.

Neither path claims the host was compromised. A lab-only exposure cannot become P1 just because a CVSS score is high. Details: `docs/sample-red-brief.md`, `docs/sample-blue-brief.md`, `docs/confirmation-tiers.md`.

## Layout

| Path | Role |
| --- | --- |
| `tenaille/` | The `tenaille` package. CLI: `python -m tenaille`. |
| `tenaille/harbngr/` | Inventory read and starter checks. |
| `tenaille/cvinferno/` | Red brief. |
| `tenaille/cvbastion/` | Blue brief. |
| `tenaille/intel/` | Fixture CVE records. Live clients are TODOs. |
| `tenaille/confirmation/` | Ceilings and the "do not claim exploited" check. |
| `tenaille/mcp/` | Tool list only. No listener. |
| `examples/` | Lab inventories and intel snapshots. |
| `packs/public-starter/` | Twelve non-destructive checks. |
| `packs/paid-reserved/` | A README. No paid data. |
| `docs/` | Schema, tiers, briefs, packaging, branch checklist. |

## Safety

Authorized systems only. Read `SECURITY.md`. Do not point this sample at a network. The fixture addresses are TEST-NET-3 (`203.0.113.0/24`).

## Names

The product, the package, and the CLI are Tenaille. CVINFERNO and CVBASTION are modules.
