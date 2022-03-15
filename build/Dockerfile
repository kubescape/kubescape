FROM golang:1.17-alpine as builder
#ENV GOPROXY=https://goproxy.io,direct

ARG image_version

ENV RELEASE=$image_version

ENV GO111MODULE=

ENV CGO_ENABLED=0

# Install required python/pip
ENV PYTHONUNBUFFERED=1
RUN apk add --update --no-cache python3 && ln -sf python3 /usr/bin/python
RUN python3 -m ensurepip
RUN pip3 install --no-cache --upgrade pip setuptools

WORKDIR /work
ADD . .

# build kubescape server
WORKDIR /work/httphandler
RUN python build.py
RUN ls -ltr build/ubuntu-latest

# build kubescape cmd
WORKDIR /work/cmd
RUN python build.py

RUN /work/build/ubuntu-latest/kubescape download artifacts -o /work/artifacts

FROM alpine

RUN addgroup -S ks && adduser -S ks -G ks
USER ks

COPY --from=builder /work/httphandler/build/ubuntu-latest/kubescape /usr/bin/kubescape
COPY --from=builder /work/build/ubuntu-latest/kubescape /usr/bin/kscli

RUN mkdir /home/ks/.kubescape && chmod 777 -R /home/ks/.kubescape 
COPY --from=builder /work/artifacts/ /home/ks/.kubescape

ENTRYPOINT ["kubescape"]
