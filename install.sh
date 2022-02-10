#!/bin/bash
set -e

echo -e "\033[0;36mInstalling Kubescape..."
echo
 
BASE_DIR=~/.kubescape
KUBESCAPE_EXEC=kubescape
KUBESCAPE_ZIP=kubescape.zip

osName=$(uname -s)
if [[ $osName == *"MINGW"* ]]; then
    osName=windows
elif [[ $osName == *"Darwin"* ]]; then
    osName=macos
else
    osName=ubuntu
fi

mkdir -p $BASE_DIR 

OUTPUT=$BASE_DIR/$KUBESCAPE_EXEC
DOWNLOAD_URL="https://github.com/armosec/kubescape/releases/latest/download/kubescape-${osName}-latest"
curl --progress-bar -L $DOWNLOAD_URL -o $OUTPUT

# Checking if SUDO needed/exists 
SUDO=
if [ "$(id -u)" -ne 0 ] && [ -n "$(which sudo)" ]; then
    SUDO=sudo
fi


# Find install dir
install_dir=/usr/local/bin #default
for pdir in ${PATH//:/ }; do
    edir="${pdir/#\~/$HOME}"
    if [[ $edir == $HOME/* ]]; then
        install_dir=$edir
        mkdir -p $install_dir 2>/dev/null || true
        SUDO=
        break
    fi
done

chmod +x $OUTPUT 2>/dev/null 
$SUDO rm -f /usr/local/bin/$KUBESCAPE_EXEC 2>/dev/null || true # clearning up old install
$SUDO cp $OUTPUT $install_dir/$KUBESCAPE_EXEC 
rm -rf $OUTPUT

echo
echo -e "\033[32mFinished Installation."

echo -e "\033[0m"
$KUBESCAPE_EXEC version
echo

echo -e "\033[35mUsage: $ $KUBESCAPE_EXEC scan --submit --enable-host-scan"

echo -e "\033[0m"
