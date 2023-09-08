FROM golang:1.20-bookworm as builder

ENV GO111MODULE=on CGO_ENABLED=1
WORKDIR /work
ARG TARGETOS TARGETARCH

RUN apt update && apt install -y golang-github-libgit2-git2go-v34-dev
RUN --mount=target=. \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go build -tags=static,system_libgit2,gitenabled -o /out/kubescape .

FROM gcr.io/distroless/static-debian11:nonroot

USER nonroot
WORKDIR /home/nonroot/

COPY --from=builder /out/kubescape /usr/bin/kubescape

ARG image_version client
ENV RELEASE=$image_version CLIENT=$client

ENTRYPOINT ["kubescape"]
