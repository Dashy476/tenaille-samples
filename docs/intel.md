# Intel

Tenaille's intel layer is read-only public data, later. This sample returns checked-in JSON.

```bash
python -m tenaille lookup CVE-2024-6387
python -m tenaille lookup CVE-2023-38408
```

Fixtures live in `examples/intel/`. Each file is a `CveRecord`:

- Identity and a short public description
- CVSS base score and vector, labeled with a snapshot date
- `EpssScore` — `score` is null here. A null score is not zero and not "current"
- `KevStatus` — a frozen `listed` flag, not a live CISA download
- `OsvHit` — `queried: false`
- Affected CPE spans used by the version matcher
- Links to the CVE record and a vendor advisory. No exploit code, no proof-of-concept links

## Where live clients will go

`tenaille/intel/lookup.py` documents the four clients and then does not call them. `lookup_cve(..., )` has no network path. `--live` is an explicit error.

When someone adds a client:

| Source | Politeness |
| --- | --- |
| NIST NVD | One CVE id per call. Space requests. Cache the body on disk. An API key stays in the environment, never in the repo. |
| FIRST EPSS | One id per call to the public EPSS endpoint. Do not bulk-pull the catalog from a classroom laptop. |
| CISA KEV | Download the catalog at most once a day and match locally. |
| OSV.dev | Query a package name that is already in the inventory. Do not guess names. |

No API keys ship with this tree.
