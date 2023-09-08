FROM --platform=$BUILDPLATFORM golang:1.20-bookworm as builder

ENV GO111MODULE=on CGO_ENABLED=1
WORKDIR /work
ARG TARGETOS TARGETARCH

RUN dpkg --add-architecture arm64 && apt update && apt install -y gcc-aarch64-linux-gnu libgit2-dev:arm64
RUN --mount=target=. \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    PKG_CONFIG_PATH=/usr/lib/aarch64-linux-gnu/pkgconfig/ \
    CC=aarch64-linux-gnu-gcc \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go build -tags=static,system_libgit2,gitenabled -o /out/kubescape .

FROM gcr.io/distroless/static-debian11:nonroot

USER nonroot
WORKDIR /home/nonroot/

COPY --from=builder /out/kubescape /usr/bin/kubescape

ARG image_version client
ENV RELEASE=$image_version CLIENT=$client

ENTRYPOINT ["kubescape"]
