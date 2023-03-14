#!/bin/bash
set -e

while getopts v: option
do
    case ${option} in
        v) RELEASE="download/${OPTARG}";;
    esac
done

if [ -z ${RELEASE} ]; then
    RELEASE="latest/download"
fi

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
DOWNLOAD_URL="https://github.com/kubescape/kubescape/releases/${RELEASE}/kubescape-${osName}-latest"

curl --progress-bar -L $DOWNLOAD_URL -o $OUTPUT

# Find install dir
install_dir=/usr/local/bin # default if running as root
if [ "$(id -u)" -ne 0 ]; then
  install_dir=$BASE_DIR/bin # if not running as root, install to user dir
  export PATH=$PATH:$BASE_DIR/bin
fi

# Create install dir if it does not exist
if [ ! -d "$install_dir" ]; then
  mkdir -p $install_dir
fi

chmod +x $OUTPUT 2>/dev/null

# cleaning up old install
SUDO=
if [ "$(id -u)" -ne 0 ] && [ -n "$(which sudo)" ] && [ -f /usr/local/bin/$KUBESCAPE_EXEC ]; then
    SUDO=sudo
    echo -e "\n\033[33mOld installation as root found. We need the root access to uninstall the old kubescape CLI."
fi
$SUDO rm -f /usr/local/bin/$KUBESCAPE_EXEC 2>/dev/null || true
rm -f /home/${SUDO_USER:-$USER}/.kubescape/bin/$KUBESCAPE_EXEC 2>/dev/null || true

cp $OUTPUT $install_dir/$KUBESCAPE_EXEC 
rm -rf $OUTPUT

echo
echo -e "\033[32mFinished Installation."

echo -e "\033[0m"
$KUBESCAPE_EXEC version
echo

echo -e "\033[35mUsage: $ $KUBESCAPE_EXEC scan --enable-host-scan"

if [ "$(id -u)" -ne 0 ]; then
  echo -e "\nRemember to add the Kubescape CLI to your path with:"
  echo -e "  export PATH=\$PATH:$BASE_DIR/bin"
fi

echo -e "\033[0m"
