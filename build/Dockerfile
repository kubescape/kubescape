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
WORKDIR /work/httphandler

RUN python build.py

RUN ls -ltr build/ubuntu-latest

FROM alpine
COPY --from=builder /work/httphandler/build/ubuntu-latest/kubescape /usr/bin/kubescape

# # Download the frameworks. Use the "--use-default" flag when running kubescape
# RUN kubescape download framework nsa && kubescape download framework mitre

ENTRYPOINT ["kubescape"]
