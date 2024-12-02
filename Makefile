.PHONY: test all build

# default task invoked while running make
all: build

export CGO_ENABLED=0

build:
	go build -v .

test:
	go test -v ./...
