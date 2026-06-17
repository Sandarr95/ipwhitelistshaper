#!/bin/sh
#
# Run the test suite under yaegi, the Go interpreter Traefik uses to load
# plugins. yaegi resolves a plugin's own import path from a GOPATH-style tree,
# so build a throwaway GOPATH that symlinks this repo at its module path, run
# the tests from there, and clean the GOPATH up on exit (including Ctrl-C).
#
# Run from the repository root (e.g. via `make yaegi_test`).
set -eu

module=$(go list -m)
gopath=$(mktemp -d)
trap 'rm -rf "$gopath"' EXIT INT TERM

mkdir -p "$gopath/src/$(dirname "$module")"
ln -s "$(pwd)" "$gopath/src/$module"

cd "$gopath/src/$module"
GOPATH="$gopath" yaegi test -v .
