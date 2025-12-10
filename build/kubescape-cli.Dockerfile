FROM gcr.io/distroless/static-debian13:debug-nonroot

USER nonroot
WORKDIR /home/nonroot/

ARG image_version client TARGETARCH
ENV RELEASE=$image_version CLIENT=$client

ARG TARGETPLATFORM
COPY $TARGETPLATFORM/kubescape /usr/bin/kubescape
RUN ["kubescape", "download", "artifacts"]

ENTRYPOINT ["kubescape"]
