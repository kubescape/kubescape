#!/bin/bash
set -e

echo "Installing Kubescape..."
echo
 
BASE_DIR=~/.kubescape
KUBESCAPE_EXEC=kubescape

RELEASE=v0.0.34

DOWNLOAD_URL="https://github.com/armosec/kubescape/releases/download/$RELEASE/kubescape"

mkdir -p $BASE_DIR 

OUTPUT=$BASE_DIR/$KUBESCAPE_EXEC

curl --progress-bar -L $DOWNLOAD_URL -o $OUTPUT
echo -e "\033[32m[V] Downloaded Kubescape"

sudo chmod +x $OUTPUT
sudo rm -f /usr/local/bin/$KUBESCAPE_EXEC
sudo cp $OUTPUT /usr/local/bin
rm -rf $BASE_DIR

echo -e "[V] Finished Installation"
echo

echo -e "\033[35m Usage: $ $KUBESCAPE_EXEC scan framework nsa --exclude-namespaces kube-system,kube-public"
echo
