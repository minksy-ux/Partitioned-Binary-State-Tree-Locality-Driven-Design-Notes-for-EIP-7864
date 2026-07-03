#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

restore_if_tracked() {
	local path="$1"
	if git ls-files --error-unmatch "$path" >/dev/null 2>&1 || [[ -n "$(git ls-files "$path")" ]]; then
		git restore --worktree -- "$path"
	fi
}

# Restore tracked generated artifacts to repository state.
restore_if_tracked "dist"
restore_if_tracked "requirements.lock"
restore_if_tracked "pbt-rs/target"
restore_if_tracked "pbt/__pycache__"
restore_if_tracked "tests/__pycache__"
restore_if_tracked "scripts/__pycache__"

# Remove untracked cache directories only.
git clean -fd -- \
	.pytest_cache \
	.hypothesis \
	.mypy_cache \
	.ruff_cache \
	pbt/__pycache__ \
	tests/__pycache__ \
	scripts/__pycache__ \
	pbt-rs/target

echo "clean-generated: removed caches and restored generated artifacts"
