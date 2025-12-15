#!/bin/bash
set -e

BASE_DIR=~/.kubescape
KUBESCAPE_EXEC=kubescape

# Function to determine OS and architecture
determine_os_and_arch() {
    osName=$(uname -s)
    case $osName in
        Linux*) osName=linux ;;
        Darwin*) osName=darwin ;;
        *MINGW*|*CYGWIN*|*MSYS*)
            echo -e "\033[31mError: Windows is not supported by this script. Please use the PowerShell installer or download manually from:"
            echo -e "\033[1;35;40mhttps://github.com/kubescape/kubescape/releases"
            exit 1
            ;;
        *)
            echo -e "\033[31mError: Unsupported operating system: $osName"
            exit 1
            ;;
    esac

    arch=$(uname -m)
    case $arch in
        x86_64|amd64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *)
            echo -e "\033[31mError: Unsupported architecture: $arch"
            exit 1
            ;;
    esac
}

# Function to get the latest release version from GitHub API
get_latest_version() {
    local latest_release
    latest_release=$(curl -s "https://api.github.com/repos/kubescape/kubescape/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    if [ -z "$latest_release" ]; then
        echo -e "\033[31mError: Failed to fetch latest release version"
        exit 1
    fi
    echo "$latest_release"
}

# Function to remove old installations
remove_old_install() {
    local exec_path=$1
    if [ -f "$exec_path" ]; then
        $SUDO rm -f "$exec_path" && echo -e "\033[32mRemoved old installation at $exec_path" || echo -e "\033[31mFailed to remove old installation at $exec_path"
    fi
}

# Parse command-line arguments
VERSION=""
while getopts v: option; do
    case ${option} in
        v) VERSION="${OPTARG}";;
        *) ;;
    esac
done

echo -e "\033[0;36mInstalling Kubescape..."

determine_os_and_arch

# Get version (use provided or fetch latest)
if [ -z "${VERSION}" ]; then
    VERSION=$(get_latest_version)
    echo -e "\033[0;36mLatest version: $VERSION"
fi

# Remove 'v' prefix if present for the filename
VERSION_NUM="${VERSION#v}"

mkdir -p $BASE_DIR

OUTPUT=$BASE_DIR/$KUBESCAPE_EXEC
# New URL pattern: kubescape_{version}_{os}_{arch}
DOWNLOAD_URL="https://github.com/kubescape/kubescape/releases/download/${VERSION}/kubescape_${VERSION_NUM}_${osName}_${arch}"

echo -e "\033[0;36mDownloading from: $DOWNLOAD_URL"
curl --progress-bar -L $DOWNLOAD_URL -o $OUTPUT

# Verify download was successful
if [ ! -s "$OUTPUT" ]; then
    echo -e "\033[31mError: Download failed or file is empty"
    rm -f "$OUTPUT"
    exit 1
fi

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
echo -e "\033[0;37;32mFinished Installation.\n"
$KUBESCAPE_EXEC version
echo -e "\033[0;37;35m\nUsage: $ kubescape scan"
