FROM golang:alpine AS builder

LABEL stage=gobuilder

ENV CGO_ENABLED 0
ENV GOPROXY https://goproxy.cn,direct
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories

RUN apk update --no-cache && apk add --no-cache tzdata

WORKDIR /build

COPY .kubescape  /home/ks/.kubescape
COPY . .
RUN go mod download
RUN go build -ldflags="-s -w" -o kubescape
WORKDIR httphandler
RUN go mod download
RUN go build -ldflags="-s -w" -o ksserver main.go


FROM alpine

COPY --from=builder /usr/share/zoneinfo/Asia/Shanghai /usr/share/zoneinfo/Asia/Shanghai
ENV TZ Asia/Shanghai

CMD ["/bin/sh"]
RUN addgroup -S ks && adduser -S ks -G ks
COPY --from=builder  /home/ks/.kubescape /home/ks/.kubescape

RUN chown -R ks:ks /home/ks/.kubescape
USER ks
COPY --from=builder /build/httphandler/ksserver /usr/bin/ksserver
COPY --from=builder /build/kubescape /usr/bin/kubescape
WORKDIR /home/ks

ENTRYPOINT ["ksserver"]
