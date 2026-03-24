#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
src="$repo_root/netgear_hack"
dst="$repo_root/netgear-hack-addon/netgear_hack"

rm -rf "$dst"
mkdir -p "$dst"
cp -R "$src"/. "$dst"/
