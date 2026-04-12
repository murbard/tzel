#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root/ocaml"

exec dune exec -- ./test/test_main.exe
