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

# Compute the SHA256 of a file. sha256sum ships with GNU coreutils, shasum with
# macOS; both print "<digest>  <file>". Each branch pipes its own command into
# awk so a missing tool surfaces as a non-zero return instead of an empty
# digest: piping the whole if/else into awk would let awk's zero exit status
# mask "command not found".
sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{ print $1 }'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{ print $1 }'
    else
        return 1
    fi
}

# Every release published under this asset naming also publishes a
# checksums.sha256 manifest covering each asset. Verify the download against it
# before the file is made executable: curl -f rejects HTTP errors, not a 200
# carrying different bytes, so without this a tampered release asset, a poisoned
# CDN object, or an on-path attacker is installed and executed unnoticed.
#
# This binds the binary to the manifest, not to the project's signing identity:
# both are fetched from the same release over the same channel, so it does not
# defend against a compromised release or GitHub account. It does close the case
# where only the binary object is substituted or corrupted in transit.
#
# Two stronger checks defend against a compromised release, and both are
# deliberately left manual: each needs a tool that is not present on a stock
# machine, so running them here would either hard-fail every install or degrade
# to a check that reports success without having verified anything.
#
#   1. Signing identity - cosign signature over the same manifest this function
#      uses, keyless, so the certificate names the workflow that produced it:
#
#        cosign verify-blob checksums.sha256 \
#          --signature checksums.sha256.sig \
#          --certificate checksums.sha256.pem \
#          --certificate-oidc-issuer https://token.actions.githubusercontent.com \
#          --certificate-identity-regexp '^https://github\.com/kubescape/kubescape/\.github/workflows/02-release\.yaml@refs/tags/'
#
#   2. Build provenance - SLSA attestation over the binary itself, stored in
#      GitHub's attestation index rather than as a release asset:
#
#        gh attestation verify kubescape --repo kubescape/kubescape
#
# Fail closed. A missing manifest or a missing entry means something is wrong
# with the release, not that verification can be skipped.
verify_checksum() {
    local file=$1 asset=$2 checksums_url=$3
    local expected actual manifest

    if ! actual=$(sha256_of "$file") || [ -z "$actual" ]; then
        echo -e "\033[31mError: neither sha256sum nor shasum is available; cannot verify the download"
        return 1
    fi

    if ! manifest=$(curl -fsSL "$checksums_url"); then
        echo -e "\033[31mError: failed to download the checksum manifest from $checksums_url"
        return 1
    fi

    # Manifest lines are "<digest>  <asset>"; match the asset exactly so a
    # substring such as kubescape_X_linux_amd64.tar.gz cannot satisfy the check.
    expected=$(printf '%s\n' "$manifest" | awk -v a="$asset" '$2 == a { print $1; exit }')
    if [ -z "$expected" ]; then
        echo -e "\033[31mError: $asset has no entry in the checksum manifest"
        return 1
    fi

    if [ "$expected" != "$actual" ]; then
        echo -e "\033[31mError: checksum mismatch for $asset"
        echo -e "\033[31m  expected: $expected"
        echo -e "\033[31m  actual:   $actual"
        return 1
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
ASSET="kubescape_${VERSION_NUM}_${osName}_${arch}"
RELEASE_URL="https://github.com/kubescape/kubescape/releases/download/${VERSION}"
DOWNLOAD_URL="${RELEASE_URL}/${ASSET}"

echo -e "\033[0;36mDownloading from: $DOWNLOAD_URL"
# -f so an HTTP error page is not saved as the binary: without it curl writes
# the 404 body to $OUTPUT and exits 0, and a 9-byte "Not Found" then passes the
# non-empty check below and gets installed as kubescape.
if ! curl --progress-bar -fL "$DOWNLOAD_URL" -o "$OUTPUT"; then
    echo -e "\033[31mError: Failed to download $DOWNLOAD_URL"
    rm -f "$OUTPUT"
    exit 1
fi

# Verify download was successful
if [ ! -s "$OUTPUT" ]; then
    echo -e "\033[31mError: Download failed or file is empty"
    rm -f "$OUTPUT"
    exit 1
fi

# Verify integrity before the binary is made executable or moved into place
echo -e "\033[0;36mVerifying checksum..."
if ! verify_checksum "$OUTPUT" "$ASSET" "${RELEASE_URL}/checksums.sha256"; then
    rm -f "$OUTPUT"
    exit 1
fi
echo -e "\033[32mChecksum verified."

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
