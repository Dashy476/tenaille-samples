# Security

Tenaille is a local lab sample for students and junior red and blue teams.
It is not a scanner, an exploit kit, or a service you point at networks you do not own.

## Authorized systems only

- Run it on synthetic fixtures in this tree, or on inventory you collected from a host you are allowed to administer.
- Do not add live scanning, credential attacks, password spraying, or exploit payloads to this sample.
- The addresses in the fixtures (`203.0.113.0/24`) are the documentation range TEST-NET-3. They are not targets.

## What "confirmed" means here

A version or CPE match means the recorded version sits in a published range.
It does not mean the lab host was compromised. Briefs that say otherwise are a defect. See `docs/confirmation-tiers.md`.

## Reporting a problem in this sample

If the sample generates a brief that claims compromise from a version match, or if a starter check does anything other than read a fixture, open an issue against the repository you publish this tree to. Do not include exploit proof-of-concept code in the report.

This tree has no deployed service and no API keys.
