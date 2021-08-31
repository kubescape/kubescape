#!/bin/bash
set -e

echo "Installing Kubescape..."
echo
 
BASE_DIR=~/.kubescape
KUBESCAPE_EXEC=kubescape

osName=$(uname -s)
if [[ $osName == *"MINGW"* ]]; then
    osName=windows-latest
elif [[ $osName == *"Darwin"* ]]; then
    osName=macos-latest
else
    osName=ubuntu-latest
fi

GITHUB_OWNER=armosec

DOWNLOAD_URL=$(curl --silent "https://api.github.com/repos/$GITHUB_OWNER/kubescape/releases/latest" | grep -o "browser_download_url.*${osName}.*")
DOWNLOAD_URL=${DOWNLOAD_URL//\"}
DOWNLOAD_URL=${DOWNLOAD_URL/browser_download_url: /}

mkdir -p $BASE_DIR 

OUTPUT=$BASE_DIR/$KUBESCAPE_EXEC

curl --progress-bar -L $DOWNLOAD_URL -o $OUTPUT
echo -e "\033[32m[V] Downloaded Kubescape"

chmod +x $OUTPUT || sudo chmod +x $OUTPUT
rm -f /usr/local/bin/$KUBESCAPE_EXEC || sudo rm -f /usr/local/bin/$KUBESCAPE_EXEC
cp $OUTPUT /usr/local/bin || sudo cp $OUTPUT /usr/local/bin
rm -rf $BASE_DIR

echo -e "[V] Finished Installation"
echo

echo -e "\033[35m Usage: $ $KUBESCAPE_EXEC scan framework nsa --exclude-namespaces kube-system,kube-public"
echo
