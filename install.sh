#!/bin/bash
set -e

echo -e "\033[0;36mInstalling Kubescape..."
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

# Ping download counter
curl --silent https://us-central1-elated-pottery-310110.cloudfunctions.net/kubescape-download-counter -o /dev/null
 
chmod +x $OUTPUT 2>/dev/null || sudo chmod +x $OUTPUT
sudo rm -f /usr/local/bin/$KUBESCAPE_EXEC 2>/dev/null || sudo rm -f /usr/local/bin/$KUBESCAPE_EXEC
sudo cp $OUTPUT /usr/local/bin 2>/dev/null || sudo cp $OUTPUT /usr/local/bin
rm -rf $OUTPUT

echo
echo -e "\033[32mFinished Installation."

echo -e "\033[0m"
$KUBESCAPE_EXEC version
echo

echo -e "\033[35mUsage: $ $KUBESCAPE_EXEC scan framework nsa --exclude-namespaces kube-system,kube-public"

echo -e "\033[0m"
