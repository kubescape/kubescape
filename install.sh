#!/bin/bash
set -e

BASE_DIR=~/.kubescape
KUBESCAPE_EXEC=kubescape

# Function to determine OS and architecture
determine_os_and_arch() {
    osName=$(uname -s)
    case $osName in
        *MINGW*) osName=windows ;;
        Darwin*) osName=macos ;;
        *) osName=ubuntu ;;
    esac

    arch=$(uname -m)
    case $arch in
        *aarch64*|*arm64*) arch="-arm64" ;;
        *x86_64*) arch="" ;;
        *)
            echo -e "\033[33mArchitecture $arch may be unsupported, will try to install the amd64 one anyway."
            arch=""
            ;;
    esac
}

# Function to remove old installations
remove_old_install() {
    local exec_path=$1
    if [ -f "$exec_path" ]; then
        $SUDO rm -f "$exec_path" && echo -e "\033[32mRemoved old installation at $exec_path" || echo -e "\033[31mFailed to remove old installation at $exec_path"
    fi
}

# Parse command-line arguments
while getopts v: option; do
    case ${option} in
        v) RELEASE="download/${OPTARG}";;
        *) ;;
    esac
done

[ -z "${RELEASE}" ] && RELEASE="latest/download"

echo -e "\033[0;36mInstalling Kubescape..."

determine_os_and_arch

mkdir -p $BASE_DIR

OUTPUT=$BASE_DIR/$KUBESCAPE_EXEC
DOWNLOAD_URL="https://github.com/kubescape/kubescape/releases/${RELEASE}/kubescape${arch}-${osName}-latest"

curl --progress-bar -L $DOWNLOAD_URL -o $OUTPUT

# Determine install directory
install_dir=/usr/local/bin
[ "$(id -u)" -ne 0 ] && install_dir=$BASE_DIR/bin && export PATH=$PATH:$BASE_DIR/bin

# Create install dir if it does not exist
mkdir -p $install_dir

chmod +x $OUTPUT

# Remove old installations
SUDO=""
[ "$(id -u)" -ne 0 ] && [ -n "$(which sudo)" ] && [ -f /usr/local/bin/$KUBESCAPE_EXEC ] && SUDO=sudo

remove_old_install "/usr/local/bin/$KUBESCAPE_EXEC"
remove_old_install "$BASE_DIR/bin/$KUBESCAPE_EXEC"

# Remove any old installations in user's PATH
IFS=':' read -ra ADDR <<< "$PATH"
for pdir in "${ADDR[@]}"; do
  if [ "$pdir/$KUBESCAPE_EXEC" != "$OUTPUT" ]; then
    remove_old_install "$pdir/$KUBESCAPE_EXEC"
  fi
done

# Move the new executable to the install directory
mv $OUTPUT $install_dir/$KUBESCAPE_EXEC

echo -e "\033[32mFinished Installation."

if [ "$(id -u)" -ne 0 ]; then
  echo -e "\033[1;35;32m\nRemember to add the Kubescape CLI to your path with:"
  echo -e "\033[1;35;40m$ export PATH=\$PATH:$BASE_DIR/bin"
fi

# Check cluster access by getting nodes
if ! kubectl get nodes &> /dev/null; then
    echo -e "\033[0;37;32m\nRun:"
    echo -e "\033[1;35;40m$ $KUBESCAPE_EXEC scan"
    echo
    exit 0
fi

echo -e "\033[0;37;40m"
echo -e "\033[0;37;32mExecuting Kubescape."
$KUBESCAPE_EXEC scan
