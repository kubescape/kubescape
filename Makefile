.PHONY: test all build

# default task invoked while running make
all: build

export CGO_ENABLED=1

# go build tags
TAGS = ""

build:
	go build -v -tags=$(TAGS) .

test:
	go test -v -tags=$(TAGS) ./...
