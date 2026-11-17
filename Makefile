.PHONY: build test test-race test-ui vet static clean check-tools check-source format-check test-scripts verify rpm

BUILD_DIR ?= build
RPM_OUTPUT_DIR ?= dist/rpm

build:
	mkdir -p "$(BUILD_DIR)"
	go build -buildvcs=false -trimpath -o "$(BUILD_DIR)/sentinel-central" ./cmd/sentinel-central

test:
	go test ./...

test-race:
	go test -race ./...

test-ui:
	@set -- internal/console/assets/*.test.mjs; [ -f "$$1" ] || { echo 'Browser-script tests are missing.' >&2; exit 1; }
	node --test internal/console/assets/*.test.mjs

vet:
	go vet ./...

static:
	mkdir -p "$(BUILD_DIR)"
	CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags='-s -w' -o "$(BUILD_DIR)/sentinel-central" ./cmd/sentinel-central

check-tools:
	@for tool in go gofmt git python3 node; do \
		command -v "$$tool" >/dev/null 2>&1 || { echo "Required verification tool is missing: $$tool" >&2; exit 1; }; \
	done
	@python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))' || { echo 'Python 3.9 or newer is required.' >&2; exit 1; }
	@node -e 'if (Number(process.versions.node.split(".")[0]) < 22) process.exit(1)' || { echo 'Node.js 22 or newer is required.' >&2; exit 1; }

check-source:
	@if [ -f .local/private-source-patterns.txt ]; then \
		python3 scripts/check-source.py --private-patterns-file .local/private-source-patterns.txt; \
	else \
		python3 scripts/check-source.py; \
	fi

format-check:
	@files=$$(gofmt -l cmd internal) || exit 1; \
		if [ -n "$$files" ]; then printf 'Run gofmt on:\n%s\n' "$$files" >&2; exit 1; fi

test-scripts:
	@for script in install.sh packaging/install_test.sh scripts/*.sh; do bash -n "$$script" || exit 1; done
	bash packaging/install_test.sh
	bash scripts/build_rpm_test.sh
	PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts -p check_source_test.py

verify:
	$(MAKE) check-tools
	$(MAKE) check-source
	$(MAKE) format-check
	$(MAKE) test-scripts
	$(MAKE) test-ui
	$(MAKE) vet
	$(MAKE) test-race
	$(MAKE) static

rpm:
	./scripts/build-rpm.sh --output-dir "$(RPM_OUTPUT_DIR)"

clean:
	go clean
