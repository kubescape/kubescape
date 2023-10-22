import os
import sys
import hashlib
import platform
import subprocess
import tarfile

BASE_GETTER_CONST = "github.com/kubescape/kubescape/v3/core/cautils/getter"
CURRENT_PLATFORM = platform.system()

platformSuffixes = {
    "Windows": "windows-latest",
    "Linux": "ubuntu-latest",
    "Darwin": "macos-latest",
}

def check_status(status, msg):
    if status != 0:
        sys.stderr.write(msg)
        exit(status)


def get_build_dir():
    return "build"


def get_package_name():
    if CURRENT_PLATFORM not in platformSuffixes: raise OSError("Platform %s is not supported!" % (CURRENT_PLATFORM))

    # # TODO: kubescape-windows-latest is deprecated and should be removed
    # if CURRENT_PLATFORM == "Windows": return "kubescape.exe"

    package_name = "kubescape-"
    if os.getenv("GOARCH"):
        package_name += os.getenv("GOARCH") + "-"
    return package_name + platformSuffixes[CURRENT_PLATFORM]


def main():
    print("Building Kubescape")

    # Set some variables
    package_name = get_package_name()
    build_url = "github.com/kubescape/kubescape/v3/core/cautils.BuildNumber"
    release_version = os.getenv("RELEASE")

    client_var = "github.com/kubescape/kubescape/v3/core/cautils.Client"
    client_name = os.getenv("CLIENT")

    # Create build directory
    build_dir = get_build_dir()

    ks_file = os.path.join(build_dir, package_name)
    hash_file = ks_file + ".sha256"
    tar_file = ks_file + ".tar.gz"

    if not os.path.isdir(build_dir):
        os.makedirs(build_dir)

    # Build kubescape
    ldflags = "-w -s"
    if release_version:
        ldflags += " -X {}={}".format(build_url, release_version)
    if client_name:
        ldflags += " -X {}={}".format(client_var, client_name)

    build_command = ["go", "build", "-buildmode=pie", "-tags=static,gitenabled", "-o", ks_file, "-ldflags" ,ldflags]
    if CURRENT_PLATFORM == "Windows":
        os.putenv("CGO_ENABLED", "0")
        build_command = ["go", "build", "-o", ks_file, "-ldflags", ldflags]

    print("Building kubescape and saving here: {}".format(ks_file))
    print("Build command: {}".format(" ".join(build_command)))

    status = subprocess.call(build_command)
    check_status(status, "Failed to build kubescape")

    sha256 = hashlib.sha256()
    with open(ks_file, "rb") as kube:
        sha256.update(kube.read())
        with open(hash_file, "w") as kube_sha:
            hash = sha256.hexdigest()
            print("kubescape hash: {}, file: {}".format(hash, hash_file))
            kube_sha.write(sha256.hexdigest())

    with tarfile.open(tar_file, 'w:gz') as archive:
        name = "kubescape"
        if CURRENT_PLATFORM == "Windows":
            name += ".exe"
        archive.add(ks_file, name)
        archive.add("LICENSE", "LICENSE")

    print("Build Done")


if __name__ == "__main__":
    main()
