#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
node "$repository_root/scripts/validate-release.mjs" "$repository_root/fixtures/valid"
node --test "$repository_root"/test/*.test.mjs
