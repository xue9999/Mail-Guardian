GO ?= go
export GO
GOVULNCHECK_VERSION ?= v1.9.0
VERSION ?= $(shell tr -d '[:space:]' < VERSION)
LDFLAGS ?= -s -w -X main.version=$(VERSION)

.PHONY: build build-recovery build-swift test test-swift vuln package package-linux check check-linux check-maintenance check-docs

build:
	mkdir -p bin
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/guardian ./cmd/guardian

build-recovery:
	mkdir -p bin
	$(GO) build -trimpath -o bin/guardian-recovery ./cmd/guardian-recovery

test:
	$(GO) test ./...

build-swift:
	bash -c 'source scripts/swift-common.sh; guardian_swift build --package-path macos'

test-swift:
	bash scripts/test-swift.sh

vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...
	$(GO) list -deps ./... | python3 scripts/reject-openpgp.py

package:
	bash scripts/package-release.sh

package-linux:
	bash scripts/package-linux.sh

check-maintenance:
	python3 scripts/test-maintenance.py
	python3 -I -m unittest discover -s tools/migration -p 'test_*.py'
	python3 -I -m unittest discover -s tools/remote-control -p 'test_*.py'

check-docs:
	python3 scripts/check-doc-links.py

check-linux:
	$(GO) test -race ./...
	$(GO) vet ./...
	bash scripts/test-linux-package.sh
	$(MAKE) check-maintenance check-docs
	bash -n scripts/package-linux.sh scripts/test-linux-package.sh deploy/linux/install.sh deploy/linux/test_install_in_container.sh

check:
	$(GO) test -race ./...
	$(GO) vet ./...
	$(MAKE) vuln GO="$(GO)"
	bash scripts/test-build-tools.sh
	bash scripts/test-storage-health.sh
	bash scripts/test-swift.sh
	bash scripts/test-gui-mock-onboarding.sh
	bash scripts/test-installer-wrapper.sh
	bash scripts/test-installer-rollback.sh
	bash scripts/test-deploy-config.sh
	bash scripts/test-linux-package.sh
	$(MAKE) check-maintenance check-docs
	bash scripts/test-release-package.sh
	bash -n Install.command Guardian.command Uruchom-teraz.command Sprawdz-stan.command scripts/*.command scripts/*.sh
