FROM gcr.io/distroless/static-debian13:nonroot

USER nonroot
WORKDIR /home/nonroot/

ARG TARGETPLATFORM
COPY $TARGETPLATFORM/downloader /usr/bin/downloader
RUN ["downloader"]
COPY $TARGETPLATFORM/ksserver /usr/bin/ksserver

ARG image_version client
ENV RELEASE=$image_version CLIENT=$client

ENTRYPOINT ["ksserver"]
