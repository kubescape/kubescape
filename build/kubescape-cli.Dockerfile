FROM gcr.io/distroless/base-debian11:nonroot

USER nonroot
WORKDIR /home/nonroot/

ARG image_version client ks_binary
ENV RELEASE=$image_version CLIENT=$client

COPY $ks_binary /usr/bin/kubescape
RUN ["kubescape", "download", "artifacts"]

ENTRYPOINT ["kubescape"]
