#!/usr/bin/env bash
# Do not run this during Grok Build. Creator only.
# After you have run `git init` and made your own first commit, this file
# prints branch names you may want. It does not create them unless you pass
# --apply. Even then it only runs `git branch <name>` in a repo you already own.

set -euo pipefail

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  echo "Usage: ./scripts/create-github-branches.sh [--apply]"
  echo "Default: print git commands. --apply runs them. Creator only."
  exit 0
fi

APPLY=0
if [[ "${1:-}" == "--apply" ]]; then
  APPLY=1
elif [[ -n "${1:-}" ]]; then
  echo "Unknown argument: $1" >&2
  exit 2
fi

branches=(
  "feat/fixtures"
  "feat/harbngr"
  "feat/intel"
  "feat/cvinferno-red"
  "feat/cvbastion-blue"
  "feat/confirmation"
  "feat/cli"
  "feat/mcp"
  "feat/packaging"
)

for branch in "${branches[@]}"; do
  if [[ "$APPLY" -eq 1 ]]; then
    git branch "$branch"
  else
    echo "git branch $branch"
  fi
done
