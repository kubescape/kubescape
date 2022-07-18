FROM golang:1.18-alpine as builder

ARG image_version
ARG client

ENV RELEASE=$image_version
ENV CLIENT=$client

ENV GO111MODULE=

ENV CGO_ENABLED=1

# Install required python/pip
ENV PYTHONUNBUFFERED=1
RUN apk add --update --no-cache python3 git openssl-dev musl-dev gcc make cmake pkgconfig && ln -sf python3 /usr/bin/python
RUN python3 -m ensurepip
RUN pip3 install --no-cache --upgrade pip setuptools

WORKDIR /work
ADD . .

# install libgit2
WORKDIR /work
RUN rm -rf git2go && make libgit2

# build kubescape server
WORKDIR /work/httphandler
RUN python build.py
RUN ls -ltr build/ubuntu-latest

# build kubescape cmd
WORKDIR /work
RUN python build.py

RUN /work/build/ubuntu-latest/kubescape download artifacts -o /work/artifacts

FROM alpine

RUN addgroup -S armo && adduser -S armo -G armo

RUN mkdir /home/armo/.kubescape
COPY --from=builder /work/artifacts/ /home/armo/.kubescape

RUN chown -R armo:armo /home/armo/.kubescape

USER armo
WORKDIR /home/armo

COPY --from=builder /work/httphandler/build/ubuntu-latest/kubescape /usr/bin/ksserver
COPY --from=builder /work/build/ubuntu-latest/kubescape /usr/bin/kubescape

ENTRYPOINT ["ksserver"]
