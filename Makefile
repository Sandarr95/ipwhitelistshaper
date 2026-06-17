.PHONY: lint test vendor clean

export GO111MODULE=on

default: lint test

lint:
	golangci-lint run

test:
	go test -v -cover ./...

# yaegi resolves a plugin's own import path from a GOPATH-style tree, so run the
# tests against a throwaway GOPATH that symlinks this repo at its module path.
# The module path is read from go.mod (go list -m), not hard-coded.
yaegi_test:
	sh scripts/yaegi-test.sh

vendor:
	go mod vendor

clean:
	rm -rf ./vendor
