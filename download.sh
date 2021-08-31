#!/bin/bash
set -e

echo "Downloading Kubescape..."
echo

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

KUBESCAPE_EXEC=kubescape

curl --progress-bar -L $DOWNLOAD_URL -o $KUBESCAPE_EXEC
echo -e "\033[32m[V] Downloaded Kubescape"

chmod +x $KUBESCAPE_EXEC || sudo chmod +x $KUBESCAPE_EXEC
