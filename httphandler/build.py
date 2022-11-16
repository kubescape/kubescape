import os
import sys
import hashlib
import platform
import subprocess

BASE_GETTER_CONST = "github.com/kubescape/kubescape/v2/core/cautils/getter"

def check_status(status, msg):
    if status != 0:
        sys.stderr.write(msg)
        exit(status)


def get_build_dir():
    current_platform = platform.system()
    build_dir = ""

    if current_platform == "Windows": build_dir = "windows-latest"
    elif current_platform == "Linux": build_dir = "ubuntu-latest"
    elif current_platform == "Darwin": build_dir = "macos-latest"
    else: raise OSError("Platform %s is not supported!" % (current_platform))

    return os.path.join("build", build_dir)

def get_package_name():
    package_name = "kubescape"
    # TODO: if platform.system() == "Windows": packageName += ".exe" - we should find all places were we access the windows executable before changing the extension 
    return package_name


def main():
    print("Building Kubescape")

    # Set some variables
    package_name = get_package_name()
    build_url = "github.com/kubescape/kubescape/v2/core/cautils.BuildNumber"
    release_version = os.getenv("RELEASE")

    client_var = "github.com/kubescape/kubescape/v2/core/cautils.Client"
    client_name = os.getenv("CLIENT")
    
    # Create build directory
    build_dir = get_build_dir()

    ks_file = os.path.join(build_dir, package_name)
    hash_file = ks_file + ".sha256"

    if not os.path.isdir(build_dir):
        os.makedirs(build_dir)

    # Build kubescape
    ldflags = "-w -s"
    if release_version:
        ldflags += " -X {}={}".format(build_url, release_version)
    if client_name:
        ldflags += " -X {}={}".format(client_var, client_name)
 
    build_command = ["go", "build", "-buildmode=pie", "-tags=static", "-o", ks_file, "-ldflags" ,ldflags]

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

    print("Build Done")
 
 
if __name__ == "__main__":
    main()
