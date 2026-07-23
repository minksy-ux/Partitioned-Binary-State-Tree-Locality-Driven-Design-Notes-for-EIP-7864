#!/usr/bin/env bash
set -euo pipefail

git config core.hooksPath .githooks
echo "Configured core.hooksPath=.githooks"
