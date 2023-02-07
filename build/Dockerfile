FROM golang:1.19-alpine as builder

ARG image_version
ARG client

ENV RELEASE=$image_version
ENV CLIENT=$client

ENV GO111MODULE=

ENV CGO_ENABLED=1

# Install required python/pip
ENV PYTHONUNBUFFERED=1
RUN apk add --update --no-cache python3 gcc make git libc-dev binutils-gold cmake pkgconfig && ln -sf python3 /usr/bin/python
RUN python3 -m ensurepip
RUN pip3 install --no-cache --upgrade pip setuptools

WORKDIR /work
ADD . .

# install libgit2
RUN rm -rf git2go && make libgit2

# build kubescape server
WORKDIR /work/httphandler
RUN python build.py
RUN ls -ltr build/

# build kubescape cmd
WORKDIR /work
RUN python build.py

RUN /work/build/kubescape-ubuntu-latest download artifacts -o /work/artifacts

FROM alpine:3.16.2

RUN addgroup -S ks && adduser -S ks -G ks

COPY --from=builder /work/artifacts/ /home/ks/.kubescape

RUN chown -R ks:ks /home/ks/.kubescape

USER ks

WORKDIR /home/ks

COPY --from=builder /work/httphandler/build/kubescape-ubuntu-latest /usr/bin/ksserver
COPY --from=builder /work/build/kubescape-ubuntu-latest /usr/bin/kubescape

ENTRYPOINT ["ksserver"]
