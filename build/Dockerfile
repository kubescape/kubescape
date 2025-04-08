FROM gcr.io/distroless/static-debian12:nonroot

USER nonroot
WORKDIR /home/nonroot/

COPY downloader /usr/bin/downloader
RUN ["downloader"]
COPY ksserver /usr/bin/ksserver

ARG image_version client
ENV RELEASE=$image_version CLIENT=$client

ENTRYPOINT ["ksserver"]
