.PHONY: test all build libgit2

# default task invoked while running make
all: libgit2 build


export CGO_ENABLED=1
REPO := kubescape
TAG := $(shell git rev-parse  --short=8 HEAD)


# build and install libgit2
libgit2:
	-git submodule update --init --recursive
	cd git2go; make install-static

# go build tags
TAGS = "static"

build:
	go build -v -tags=$(TAGS) .

test:
	go test -v -tags=$(TAGS) ./...

docker-build:
	#docker buildx build --platform linux/arm64,linux/amd64 -f build/Dockerfile -t ${REPO}:${TAG} . --push
	#docker buildx build --platform linux/arm64 -f build/Dockerfile -t ${REPO}:${TAG} . -o type=docker
	 docker build -t ${REPO}:${TAG} -f build/Dockerfile .