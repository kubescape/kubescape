FROM ubuntu:22.10

RUN apt-get update && apt-get install -y curl \
    && curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash

ENTRYPOINT [ "kubescape" ]
