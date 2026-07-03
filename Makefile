.PHONY: test all build sync-vap

# default task invoked while running make
all: build

export CGO_ENABLED=0

build:
	go build -v .

test:
	go test -v ./...

# cel-admission-library bundle vendored under the cel package so //go:embed can
# bake it into the binary. sync-vap refreshes that copy from a pinned release so
# it stays reproducible instead of hand-maintained. Bump CEL_LIBRARY_VERSION to
# vendor a newer bundle.
CEL_VAPDATA_DIR := core/pkg/opaprocessor/cel/vapdata
CEL_LIBRARY_VERSION := v0.11
CEL_LIBRARY_BASE_URL := https://github.com/kubescape/cel-admission-library/releases/download/$(CEL_LIBRARY_VERSION)
CEL_VAP_FILES := \
	kubescape-validating-admission-policies.yaml \
	basic-control-configuration.yaml \
	policy-configuration-definition.yaml

sync-vap:
	@for f in $(CEL_VAP_FILES); do \
		echo "syncing $$f"; \
		curl -fsSL "$(CEL_LIBRARY_BASE_URL)/$$f" -o "$(CEL_VAPDATA_DIR)/$$f"; \
	done
