.PHONY: test all build libgit2

# default task invoked while running make
all: libgit2 build

export CGO_ENABLED=1

# build and install libgit2
libgit2:
	git submodule update --init --recursive
	cd git2go; make install-static

# go build tags
TAGS = "static"

build:
	go build -v -tags=$(TAGS) .

test:
	go test -v -tags=$(TAGS) ./...
