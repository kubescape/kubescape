FROM golang:1.20-bullseye as builder
ARG image_version client
ENV GO111MODULE=on CGO_ENABLED=1 PYTHONUNBUFFERED=1 RELEASE=$image_version CLIENT=$client

# Install required python/pip
RUN apt update
RUN apt install -y cmake python3-pip
RUN pip3 install --no-cache --upgrade pip setuptools

WORKDIR /work
ADD . .

# install libgit2
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    make libgit2

# build kubescape server
WORKDIR /work/httphandler
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    python3 build.py
RUN ls -ltr build/

# build kubescape cmd
WORKDIR /work
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    python3 build.py

RUN /work/build/kubescape-ubuntu-latest download artifacts -o /work/artifacts

FROM gcr.io/distroless/base-debian11:nonroot

COPY --from=builder /work/artifacts/ /home/nonroot/.kubescape
COPY --from=builder /work/httphandler/build/kubescape-ubuntu-latest /usr/bin/ksserver
COPY --from=builder /work/build/kubescape-ubuntu-latest /usr/bin/kubescape

ENTRYPOINT ["ksserver"]
