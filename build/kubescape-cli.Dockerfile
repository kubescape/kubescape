FROM gcr.io/distroless/base-debian11:debug-nonroot

USER nonroot
WORKDIR /home/nonroot/

ARG image_version client TARGETARCH
ENV RELEASE=$image_version CLIENT=$client

COPY kubescape-${TARGETARCH}-ubuntu-latest /usr/bin/kubescape
RUN ["kubescape", "download", "artifacts"]

ENTRYPOINT ["kubescape"]
