.PHONY: build test vet lint deb clean smoke

BINARY := dist/sysh

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o $(BINARY) ./cmd/sysh

test:
	go test ./...

vet:
	go vet ./...

lint:
	go vet ./...
	@command -v staticcheck >/dev/null && staticcheck ./... || echo "(staticcheck not installed; skipped)"

deb:
	./build.sh

# Local smoke: exercises dispatch, containment selfcheck, and the
# fail-closed path against the real (missing) /etc/sysh policy.
smoke: build
	$(BINARY) version
	$(BINARY) selfcheck
	@echo "--- gateway without policy (expect fail-closed 125):"
	-$(BINARY) -c '/bin/echo hi' 2>&1 | tail -1
	@echo "--- non-root control command (expect refusal):"
	-$(BINARY) auth list 2>&1 | tail -1; true

clean:
	rm -rf dist
