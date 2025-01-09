FROM --platform=$BUILDPLATFORM golang:1.23-bookworm AS builder

ENV GO111MODULE=on CGO_ENABLED=0
WORKDIR /work
ARG TARGETOS TARGETARCH

RUN --mount=target=. \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    cd httphandler && GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o /out/ksserver .
RUN --mount=target=. \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    go run downloader/main.go

FROM gcr.io/distroless/static-debian12:nonroot

USER nonroot
WORKDIR /home/nonroot/

COPY --from=builder /out/ksserver /usr/bin/ksserver
COPY --from=builder /root/.kubescape /home/nonroot/.kubescape

ARG image_version client
ENV RELEASE=$image_version CLIENT=$client

ENTRYPOINT ["ksserver"]
