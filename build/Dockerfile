FROM golang:1.17-alpine as builder
ENV GOPROXY=https://goproxy.io,direct
ENV GO111MODULE=on

WORKDIR /work
ADD . .
RUN go mod tidy
RUN GOOS=linux CGO_ENABLED=0 go build -ldflags="-s -w " -installsuffix cgo  -o kubescape .

FROM alpine
COPY --from=builder /work/kubescape /usr/bin/kubescape

# # Download the frameworks. Use the "--use-default" flag when running kubescape 
# RUN kubescape download framework nsa && kubescape download framework mitre

CMD ["kubescape"]
