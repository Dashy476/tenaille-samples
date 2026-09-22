# HARBNGR

HARBNGR is the collector face of Tenaille. It turns an authorized host into inventory JSON. In this sample that JSON already exists, and HARBNGR reads it.

```bash
python -m tenaille recon --inventory examples/lab-web-01.json
```

What the command does:

1. Refuse the file unless `fixture` is true and `authorization` is `synthetic-lab`.
2. Print a fingerprint summary: OS, exposure, package managers, counts.
3. Run the public starter pack in `packs/public-starter/checks/`.
4. Stop. No SSH client is imported.

`--live` exits with an error. A future collector, on a host the operator can already log into, would:

- Detect the OS family, then the package manager (`apt`, `dnf`, `rpm`, `winget`).
- Record installed packages and running services into this schema.
- Leave CVE judgment to intel and the two briefs.

Package-manager detection in `tenaille/harbngr/recon.py` is a stub. It returns managers the fixture already named and checks them against a short family list. It does not shell out.

The starter pack is twelve reads. See `packs/public-starter/README.md`. A check marked destructive is refused. There is no exploit template in the pack.
