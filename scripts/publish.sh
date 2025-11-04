#!/usr/bin/env bash
set -euo pipefail

# Helper script to publish the local repository to GitHub using the gh CLI.
# Usage:
#   ./scripts/publish.sh <github-username> [<repository-name>]
# Example:
#   ./scripts/publish.sh KrisRichensUK ZKPAuth

if ! command -v gh >/dev/null 2>&1; then
  echo "The GitHub CLI (gh) is required to run this script." >&2
  exit 1
fi

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo "Usage: $0 <github-username> [<repository-name>]" >&2
  exit 1
fi

GITHUB_USER="$1"
REPO_NAME="${2:-ZKPAuth}"

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "This script must be executed from within a Git repository." >&2
  exit 1
fi

if [ -z "$(git status --porcelain)" ]; then
  echo "Working tree clean." >&2
else
  echo "Working tree has uncommitted changes. Commit or stash them before publishing." >&2
  exit 1
fi

REMOTE_URL="git@github.com:${GITHUB_USER}/${REPO_NAME}.git"

if git remote get-url origin >/dev/null 2>&1; then
  echo "Remote 'origin' already configured. Skipping remote creation." >&2
else
  echo "Configuring remote 'origin' -> ${REMOTE_URL}" >&2
  git remote add origin "${REMOTE_URL}"
fi

echo "Ensuring repository exists on GitHub..." >&2
if ! gh repo view "${GITHUB_USER}/${REPO_NAME}" >/dev/null 2>&1; then
  gh repo create "${GITHUB_USER}/${REPO_NAME}" --private --source=. --push
  exit 0
fi

echo "Pushing current branch to GitHub..." >&2
CURRENT_BRANCH="$(git symbolic-ref --short HEAD)"
git push -u origin "${CURRENT_BRANCH}"
