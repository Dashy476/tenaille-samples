# Tenaille

Pronounced **ten-AY**.

**Two faces. One host.**

Tenaille is local-first CVE intelligence. HARBNGR fingerprints an authorized Linux or Windows host. CVINFERNO writes the Red Team attack-path brief. CVBASTION writes the Blue Team detection and remediation brief from the same inventory. Same host. Two opposing faces.

This folder is a standalone sample a newcomer can run in about ten minutes. It is not the production collector. It does not open SSH, does not call NVD, and does not ship exploit content. Every host in `examples/` is a synthetic lab fixture. Live SSH and live APIs are named below so the sample matches the platform design. In this tree they are stubs.

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

The requirements file in this sample is intentionally empty. The demo uses the standard library. Do not use `source .venv/bin/activate` in PowerShell. A Windows virtualenv has no `bin` directory.

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

`--live` on lookup, recon, or assess exits with an error.

## What the demo is saying

`lab-web-01` records OpenSSH 8.9p1 and agent forwarding enabled. That is enough for two hypotheses:

- **Path A, CVE-2024-6387.** The upstream version sits in the published 8.5p1–9.7p1 range. Ceiling: `version_match`.
- **Path B, CVE-2023-38408.** Agent-forwarding class, post-foothold, and the upstream version is before 9.3p2. Ceiling: `version_match`.

Neither path claims the host was compromised. A lab-only exposure cannot become P1 just because a CVSS score is high. Details: `docs/sample-red-brief.md`, `docs/sample-blue-brief.md`, `docs/confirmation-tiers.md`.

## Tools

### HARBNGR

The collector. On a host you already have credentials for, it detects Linux or Windows, reads installed packages, running services, open ports, and processes, and writes that as inventory. Target input in the full design is a single IP, a CIDR range, an IP range, or a file of addresses, scanned in parallel. It is not a credential-guessing tool. SSH to Windows requires OpenSSH Server already installed on that host.

This sample does not connect anywhere. `python -m tenaille recon` reads a fixture JSON file and runs the twelve public starter checks against fields that file already contains.

### CVINFERNO

The Red face. It takes HARBNGR's inventory, or a natural-language question in the full design, finds CVEs that apply, and writes a difficulty-scaled attack path: what the version suggests, what is still unproven, and what the brief refuses to claim. MITRE ATT&CK names belong on the path only when they were derived from the CVE text, so the write-up cannot invent technique IDs.

In this sample the difficulties are Easy, Medium, and Hard, and they change how much uncertainty the paragraph admits. They are not procedures. `python -m tenaille assess --mode red` prints that brief. It does not include exploit code.

### CVBASTION

The Blue face. Same inventory, same findings, opposite job: detection, containment, and remediation scaled to the lab and to the evidence in hand. Each Red path has a paired control. `python -m tenaille assess --mode blue` prints that brief. `--mode both` prints the two faces together.

## Data sources

The full platform looks these up in order. This sample ships frozen JSON in `examples/intel/` instead of calling them. Snapshot dates are on those files. A null EPSS score means "not fetched," not "zero."

| Source | Used for | Notes |
| --- | --- | --- |
| NIST NVD | Primary keyword and CPE search | Free API key. `virtualMatchString` when the product is in the CPE map, `keywordSearch` otherwise. A known installed version is pinned in the CPE so older CVEs that match that version are kept. Unversioned searches drop CVEs from before 2019. Results cached 24 hours; a stale cache is used if NVD is down. |
| OSV.dev | Debian, Ubuntu, PyPI, and npm packages | No key. Ecosystem chosen from the package type. |
| VulnCheck | Exact CVE-ID lookups, and the CISA KEV flag | Free tier is reliable for a direct CVE id, not for keyword search. |
| Vulners | Last resort | Paid key. Used only when NVD and OSV returned nothing for that product. Skipped if `VULNERS_API_KEY` is unset. |
| CISA KEV | "Known exploited" catalog flag | Raises priority. It does not prove this host was compromised. |
| FIRST.org EPSS | Exploitation probability | Free, no key. Used with KEV and exposure so raw CVSS does not set priority alone. |
| Exploit-DB | Public proof-of-concept references | Full platform only, via a local database. Fabricated snippets are suppressed. This sample does not ship or execute that code. |

`tenaille/intel/lookup.py` lists where those clients will go, including the rate-limit rules: one CVE id at a time, cache the body, do not page a whole catalog from a laptop. No API keys are in this tree.

NVD keys are UUID-shaped. Register at [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key). VulnCheck registration is at [vulncheck.com](https://vulncheck.com). Those keys are for a later live client, not for `python -m tenaille demo`.

## Confirmation

An NVD hit is not proof. The ceiling is the strongest claim a brief may make.

| Ceiling | Meaning | This sample |
| --- | --- | --- |
| `version_match` | Recorded upstream version sits in a published affected range. Distro backports are not checked. | Used. |
| `active_verify` | The service is reachable and the banner or recorded config agrees. | Named only. Not run. |
| `template_verified` | A non-destructive check template agrees. | Named only. Not run. |

The full platform also keeps an unconfirmed "potential" row when a source returned a CVE that the version does not place on this host, and it asks before any active check. Template checks there run only when the template's service matches a package, a running service, or a banner. An open HTTP port is not enough, and a status code alone is not a confirmation.

Priority is context-aware. KEV, EPSS, and exposure outrank raw CVSS. A lab-only fixture in this sample cannot be P1.

## Inventory

HARBNGR's package read, by family:

- Debian and Ubuntu: `dpkg -l`
- RPM distros: `rpm -qa`, parsed as name-version-release so the version is available for the range check
- Windows: the Uninstall registry (`DisplayName` and `DisplayVersion`). `Win32_Product` is a slow fallback only

Names sent to NVD come from a CPE map. A Windows display name is not split on the first space and searched as-is. The sample schema for that document is `docs/inventory-schema.md`.

## What the full platform adds

Not runnable from this folder. Listed so the sample's stubs have a place to grow.

- Local Ollama for the long-form briefs. Small model for pulling entities out of a question (`qwen2.5:3b`). Larger model for the narrative (`deepseek-r1:14b`). `ollama serve` has to be running. Inference stays on the machine.
- Python packages for that stack: `ollama`, `requests`, `rich`, `paramiko`, `pyexploitdb`, `python-dotenv`, `PyYAML`, `packaging`. `packaging` is what makes version-range checks exact. Without it, version confirmation should stay silent instead of guessing.
- Difficulty levels Novice, Easy, Medium, Hard, and Master, which change assumed attacker skill and assumed defender tooling. They do not add exploit steps.
- A local SQLite file (`recon.db`, WAL mode) of hosts, CVEs, findings, version ranges, and the NVD cache. The collector writes. The two brief tools read. A later write that does not know a CVSS score must not erase one already stored.
- Logs: collector, red brief, and blue brief in separate files.
- Interactive prompts for target mode, SSH port (default 22), username, password or key, one key for every host or a key per host, then Red or Blue analysis. After the read, the operator picks one host or all of them.

## Features the design is aiming at

- Multi-target input and parallel collection, with a key per host when needed
- OS detection for Linux distro/version and Windows version
- One shared CVE client for NVD, OSV, KEV, and EPSS, so the Red and Blue tools cannot drift
- CPE-aware search, then a relevance filter (CPE, description, denylist, version range)
- Generic OS services dropped before lookup, so `systemd` and friends do not dominate the brief
- KEV and EPSS used to order findings, not to declare that this host was compromised
- Red and Blue prompts kept separate, with ATT&CK ids restricted to the set derived from the CVE text

## Layout

| Path | Role |
| --- | --- |
| `tenaille/` | The `tenaille` package. CLI: `python -m tenaille`. |
| `tenaille/harbngr/` | Inventory read and starter checks. |
| `tenaille/cvinferno/` | Red brief. |
| `tenaille/cvbastion/` | Blue brief. |
| `tenaille/intel/` | Fixture CVE records. Live clients are TODOs. |
| `tenaille/confirmation/` | Ceilings and the check that rejects an "exploited" claim at `version_match`. |
| `tenaille/mcp/` | Tool list only. No listener. |
| `examples/` | Lab inventories and intel snapshots. |
| `packs/public-starter/` | Twelve non-destructive checks. |
| `packs/paid-reserved/` | A README. No paid data. |
| `docs/` | Schema, tiers, briefs, packaging, branch checklist. |

## Safety

Authorized systems only. Read `SECURITY.md`. Do not point this sample at a network. The fixture addresses are TEST-NET-3 (`203.0.113.0/24`).

HARBNGR, when it is a real collector, is for hosts where you already have a valid login. It is not a brute-force tool. This sample never gets that far: `--live` refuses.

## Names

The product, the package, and the CLI are Tenaille. CVINFERNO and CVBASTION are modules.
