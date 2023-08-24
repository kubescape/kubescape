#!/bin/bash
set -e

while getopts v: option
do
    case ${option} in
        v) RELEASE="download/${OPTARG}";;
        *) ;;
    esac
done

if [ -z "${RELEASE}" ]; then
    RELEASE="latest/download"
fi

echo -e "\033[0;36mInstalling Kubescape..."
echo

BASE_DIR=~/.kubescape
KUBESCAPE_EXEC=kubescape

osName=$(uname -s)
if [[ $osName == *"MINGW"* ]]; then
    osName=windows
elif [[ $osName == *"Darwin"* ]]; then
    osName=macos
else
    osName=ubuntu
fi

arch=$(uname -m)
if [[ $arch == *"aarch64"* || $arch == *"arm64"* ]]; then
    arch="-arm64"
else
    if [[ $arch != *"x86_64"* ]]; then
        echo -e "\033[33mArchitecture $arch may be unsupported, will try to install the amd64 one anyway."
    fi
    arch=""
fi

mkdir -p $BASE_DIR 

OUTPUT=$BASE_DIR/$KUBESCAPE_EXEC
DOWNLOAD_URL="https://github.com/kubescape/kubescape/releases/${RELEASE}/kubescape${arch}-${osName}-latest"

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
if [ "$(id -u)" -ne 0 ] && [ -n "$(which sudo)" ] && [ "$KUBESCAPE_EXEC" != "" ] && [ -f /usr/local/bin/$KUBESCAPE_EXEC ]; then
    SUDO=sudo
    echo -e "\n\033[33mOld installation as root found, do you want to remove it? [\033[0my\033[33m/n]:"
    read -n 1 -r
    if [[ ! $REPLY =~ ^[Yy]$ ]] && [[ "$REPLY" != "" ]]; then
        echo -e "\n\033[0mSkipping old installation as root removal."
    else
        echo -e "\n\033[0mWe will need the root access to uninstall the old kubescape CLI."
        if $SUDO rm -f /usr/local/bin/$KUBESCAPE_EXEC 2>/dev/null; then
            echo -e "\033[32mRemoved old installation as root at /usr/local/bin/$KUBESCAPE_EXEC"
        else
            echo -e "\033[31mFailed to remove old installation as root at /usr/local/bin/$KUBESCAPE_EXEC, please remove it manually."
        fi
    fi
fi

if [ "$KUBESCAPE_EXEC" != "" ]; then
    if [ "${SUDO_USER:-$USER}" != "" ]; then
        rm -f /home/"${SUDO_USER:-$USER}"/.kubescape/bin/$KUBESCAPE_EXEC 2>/dev/null || true
    fi
    if [ "$BASE_DIR" != "" ]; then
        rm -f $BASE_DIR/bin/$KUBESCAPE_EXEC 2>/dev/null || true
    fi
fi

# Old install location, clean all those things up
for pdir in ${PATH//:/ }; do
    edir="${pdir/#\~/$HOME}"
    if [[ $edir == $HOME/* ]] && [[ -f $edir/$KUBESCAPE_EXEC ]]; then
        echo -e "\n\033[33mOld installation found at $edir/$KUBESCAPE_EXEC, do you want to remove it? [\033[0my\033[33m/n]:"
        read -n 1 -r
        if [[ ! $REPLY =~ ^[Yy]$ ]] && [[ "$REPLY" != "" ]]; then
            continue
        fi
        if rm -f "$edir"/$KUBESCAPE_EXEC 2>/dev/null; then
            echo -e "\n\033[32mRemoved old installation at $edir/$KUBESCAPE_EXEC"
        else
            echo -e "\n\033[31mFailed to remove old installation as root at $edir/$KUBESCAPE_EXEC, please remove it manually."
        fi
    fi
done

cp $OUTPUT $install_dir/$KUBESCAPE_EXEC
rm -f $OUTPUT

echo
echo -e "\033[32mFinished Installation."

if [ "$(id -u)" -ne 0 ]; then
  echo -e "\nRemember to add the Kubescape CLI to your path with:"
  echo -e "  export PATH=\$PATH:$BASE_DIR/bin"
  export PATH=\$PATH:$BASE_DIR/bin
fi

# Check cluster access by getting nodes
if ! kubectl get nodes &> /dev/null; then
    echo -e "  $KUBESCAPE_EXEC scan --create-account"
    exit 0
fi

echo -e "\033[0m"
echo -e "\033[32mExecuting Kubescape."
echo
$KUBESCAPE_EXEC scan --create-account
