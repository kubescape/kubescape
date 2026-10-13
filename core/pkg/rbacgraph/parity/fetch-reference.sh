#!/usr/bin/env bash
# Downloads the kube-apiserver and etcd binaries pinned in reference.env into
# a directory envtest can use as KUBEBUILDER_ASSETS, verifying each against
# the checksum recorded there. A binary already present with the right
# checksum is kept, so the directory can be cached.
#
# Usage: fetch-reference.sh <directory>
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=reference.env
. "${here}/reference.env"

dest="${1:?usage: fetch-reference.sh <directory>}"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "Kubernetes publishes kube-apiserver for Linux only; see README.md for running the reference tests elsewhere." >&2
  exit 1
fi
case "$(uname -m)" in
  x86_64 | amd64) arch=amd64; apiserver_sha="${KUBE_APISERVER_SHA256_LINUX_AMD64}"; etcd_sha="${ETCD_SHA256_LINUX_AMD64}" ;;
  aarch64 | arm64) arch=arm64; apiserver_sha="${KUBE_APISERVER_SHA256_LINUX_ARM64}"; etcd_sha="${ETCD_SHA256_LINUX_ARM64}" ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

mkdir -p "${dest}"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

matches() { [[ -f "$1" ]] && echo "$2  $1" | sha256sum --check --status; }
download() { curl --fail --silent --show-error --location --retry 5 --retry-all-errors --retry-delay 2 --output "$2" "$1"; }

apiserver="${dest}/kube-apiserver"
if ! matches "${apiserver}" "${apiserver_sha}"; then
  download "https://dl.k8s.io/${KUBE_APISERVER_VERSION}/bin/linux/${arch}/kube-apiserver" "${work}/kube-apiserver"
  echo "${apiserver_sha}  ${work}/kube-apiserver" | sha256sum --check
  install -m 0755 "${work}/kube-apiserver" "${apiserver}"
fi

# The etcd checksum covers the release archive, so the archive is kept next to
# the binary: its checksum is what says the extracted binary can be reused.
etcd_archive="${dest}/etcd-${ETCD_VERSION}-linux-${arch}.tar.gz"
if ! matches "${etcd_archive}" "${etcd_sha}" || [[ ! -x "${dest}/etcd" ]]; then
  download "https://github.com/etcd-io/etcd/releases/download/${ETCD_VERSION}/etcd-${ETCD_VERSION}-linux-${arch}.tar.gz" "${work}/etcd.tar.gz"
  echo "${etcd_sha}  ${work}/etcd.tar.gz" | sha256sum --check
  tar --extract --gzip --file "${work}/etcd.tar.gz" --directory "${work}" --strip-components=1 "etcd-${ETCD_VERSION}-linux-${arch}/etcd"
  install -m 0755 "${work}/etcd" "${dest}/etcd"
  install -m 0644 "${work}/etcd.tar.gz" "${etcd_archive}"
fi

echo "kube-apiserver ${KUBE_APISERVER_VERSION} and etcd ${ETCD_VERSION} are in ${dest}"
