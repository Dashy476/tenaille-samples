# Contributing

Tenaille (pronounced ten-AY) is a teaching sample. Two faces. One host.

## Ground rules

- Authorized lab use only. Read `SECURITY.md` before adding behavior.
- HARBNGR in this tree reads inventory JSON. Do not add an internet scanner, a subnet walk, or a credential loop.
- Starter checks stay non-destructive reads of fields the inventory already has. The public pack is 8 to 12 checks. Do not import a large template corpus.
- CVINFERNO writes hypotheses and limits. It does not ship exploit steps, payloads, or proof-of-concept code.
- CVBASTION writes detection and remediation for the same findings. Do not let the two faces disagree about the confirmation ceiling.
- Intel fixtures are frozen snapshots. A live NVD, OSV, KEV, or EPSS client must be polite: one query at a time, local cache, no key committed to the tree.
- Confirmation ceiling in sample output stays `version_match` until a real check exists and is labeled.

## Tests

From this folder, with Python 3.10 or newer:

```bash
python -m unittest discover -s tests
```

`tests/test_confirmation.py` must keep failing any brief that claims a host was exploited while the ceiling is `version_match`.

## Names

The product, the folder, and the CLI are Tenaille. CVINFERNO and CVBASTION are modules, not the product name.
