# Branches the creator may add later

This file is a checklist. Tenaille-samples is delivered as files on disk. Nothing in the sample run creates a git repository, a remote, or a branch.

When you are ready, you create the GitHub repo yourself, `git init` yourself, and push yourself. `scripts/create-github-branches.sh` only prints `git branch` lines unless you pass `--apply` after that. Do not run it as part of generating this tree.

Suggested branch names, and what from this folder belongs on each:

| Branch they may create later | What from this folder goes on it |
| --- | --- |
| main | Working 10-minute demo, README, SECURITY, LICENSE |
| feat/fixtures | examples/ + docs/inventory-schema.md |
| feat/harbngr | tenaille/harbngr + packs/public-starter + docs/harbngr.md |
| feat/intel | tenaille/intel + examples/intel + docs/intel.md |
| feat/cvinferno-red | tenaille/cvinferno + docs/sample-red-brief.md |
| feat/cvbastion-blue | tenaille/cvbastion + docs/sample-blue-brief.md |
| feat/confirmation | tenaille/confirmation + tests/test_confirmation.py |
| feat/cli | tenaille/__main__.py polish |
| feat/mcp | tenaille/mcp + docs/mcp.md |
| feat/packaging | packs/ + docs/public-vs-paid.md + docs/digital-product-outline.md |

`main` should already run `python -m tenaille demo` before any feature branch is cut. Feature branches are a packaging choice for review, not a requirement of the sample.
