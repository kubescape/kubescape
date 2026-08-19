.PHONY: test all build sync-vap sync-vap-digests

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
CEL_LIBRARY_VERSION := v0.13
CEL_LIBRARY_BASE_URL := https://github.com/kubescape/cel-admission-library/releases/download/$(CEL_LIBRARY_VERSION)
CEL_VAP_FILES := \
	kubescape-validating-admission-policies.yaml \
	basic-control-configuration.yaml \
	policy-configuration-definition.yaml

# SHA256 of each $(CEL_LIBRARY_VERSION) asset. The bundle is //go:embed-ed into
# the binary, so an unverified download bakes whatever the release serves into
# every build: a compromised release asset, a CDN, or an on-path attacker would
# silently replace the admission policies a security scanner enforces. The
# release publishes no checksum manifest or signature to verify against, so the
# digests are pinned here and sync-vap refuses to install a file that does not
# match. Refresh deliberately when bumping CEL_LIBRARY_VERSION: run
# `make sync-vap-digests`, check the values against the upstream release, then
# paste them below in the same commit as the version bump.
CEL_VAP_DIGESTS := \
	kubescape-validating-admission-policies.yaml=848f99c52370b768383e7bec4c6799dca1745d9684ad665ba8be1ea99908f5ac \
	basic-control-configuration.yaml=e309eac48242573cb9814c62367a675f09c06f9288d8fb1f7bdd421db82e51c9 \
	policy-configuration-definition.yaml=f1e1d0bda1e82ef880223a429fc5ecf99c957b5069b1ec759a9b65ab8620c7ef

# sha256sum on GNU coreutils, shasum on macOS; both print "<digest>  <file>".
# Each branch pipes its own command into awk so a missing tool surfaces as a
# non-zero return instead of an empty digest: piping the whole if/else into awk
# would let awk's zero exit status mask "command not found".
CEL_SHA256_FN := sha256() { \
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$$1" | awk '{ print $$1 }'; \
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$$1" | awk '{ print $$1 }'; \
  else echo "sync-vap: neither sha256sum nor shasum is available; cannot verify downloads" >&2; return 1; fi; \
}

# Every file is downloaded and verified before any of them is installed, so a
# mismatch on the last asset cannot leave vapdata/ holding a half-updated
# bundle.
sync-vap:
	@set -eu; \
	$(CEL_SHA256_FN); \
	tmp="$$(mktemp -d)"; \
	trap 'rm -rf "$$tmp"' EXIT INT TERM; \
	for pair in $(CEL_VAP_DIGESTS); do \
		f="$${pair%%=*}"; want="$${pair#*=}"; \
		echo "fetching $$f"; \
		curl -fsSL "$(CEL_LIBRARY_BASE_URL)/$$f" -o "$$tmp/$$f"; \
		got="$$(sha256 "$$tmp/$$f")"; \
		if [ "$$got" != "$$want" ]; then \
			printf 'sync-vap: SHA256 mismatch for %s\n  expected: %s\n  actual:   %s\nrefusing to update %s\n' \
				"$$f" "$$want" "$$got" "$(CEL_VAPDATA_DIR)" >&2; \
			exit 1; \
		fi; \
	done; \
	for pair in $(CEL_VAP_DIGESTS); do \
		f="$${pair%%=*}"; \
		mv "$$tmp/$$f" "$(CEL_VAPDATA_DIR)/$$f"; \
		echo "installed $$f"; \
	done; \
	echo "sync-vap: $(CEL_LIBRARY_VERSION) bundle verified against pinned SHA256 digests"

# Prints a CEL_VAP_DIGESTS block for the current CEL_LIBRARY_VERSION. Review the
# digests against the upstream release before pasting them in above.
sync-vap-digests:
	@set -eu; \
	$(CEL_SHA256_FN); \
	tmp="$$(mktemp -d)"; \
	trap 'rm -rf "$$tmp"' EXIT INT TERM; \
	last=""; \
	for f in $(CEL_VAP_FILES); do last="$$f"; done; \
	echo "CEL_VAP_DIGESTS := \\"; \
	for f in $(CEL_VAP_FILES); do \
		curl -fsSL "$(CEL_LIBRARY_BASE_URL)/$$f" -o "$$tmp/$$f"; \
		d="$$(sha256 "$$tmp/$$f")"; \
		if [ "$$f" = "$$last" ]; then \
			printf '\t%s=%s\n' "$$f" "$$d"; \
		else \
			printf '\t%s=%s \\\n' "$$f" "$$d"; \
		fi; \
	done
