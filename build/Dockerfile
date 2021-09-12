FROM golang:1.16-alpine as builder
ENV GOPROXY=https://goproxy.io,direct
ENV GO111MODULE=on

WORKDIR /work
ADD . .
RUN go mod download
RUN GOOS=linux CGO_ENABLED=0 go build -ldflags="-s -w " -installsuffix cgo  -o kubescape .

FROM alpine
COPY --from=builder /work/kubescape /usr/bin/kubescape

CMD ["kubescape"]
