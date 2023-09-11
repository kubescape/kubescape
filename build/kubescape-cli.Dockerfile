FROM --platform=$BUILDPLATFORM golang:1.20-bookworm as builder

ENV GO111MODULE=on CGO_ENABLED=1
WORKDIR /work
ARG TARGETOS TARGETARCH

RUN dpkg --add-architecture arm64 && apt update && apt install -y gcc-aarch64-linux-gnu libgit2-dev:arm64
RUN --mount=target=. \
    --mount=type=cache,target=/go/pkg \
    PKG_CONFIG_PATH=/usr/lib/aarch64-linux-gnu/pkgconfig/ \
    CGO_LDFLAGS="-static -tags nocgo -L/usr/lib/aarch64-linux-gnu -lgit2 -L/usr/lib/aarch64-linux-gnu -lmbedtls -lmbedx509 -lmbedcrypto -lhttp_parser -L/usr/lib/aarch64-linux-gnu -lssh2 -lrt -L/usr/lib/aarch64-linux-gnu -lpcre2-8 -lz" \
    CC=aarch64-linux-gnu-gcc \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go build -tags=gitenabled -o /out/kubescape .

FROM debian:bookworm

COPY --from=builder /out/kubescape /usr/bin/kubescape

ARG image_version client
ENV RELEASE=$image_version CLIENT=$client

ENTRYPOINT ["sleep", "infinity"]
