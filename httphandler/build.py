import os
import sys
import hashlib
import platform
import subprocess

BASE_GETTER_CONST = "github.com/armosec/kubescape/v2/core/cautils/getter"

def checkStatus(status, msg):
    if status != 0:
        sys.stderr.write(msg)
        exit(status)


def getBuildDir():
    currentPlatform = platform.system()
    buildDir = "build/"

    if currentPlatform == "Windows": return os.path.join(buildDir, "windows-latest") 
    if currentPlatform == "Linux": return os.path.join(buildDir, "ubuntu-latest")  
    if currentPlatform == "Darwin": return os.path.join(buildDir, "macos-latest")  
    raise OSError("Platform %s is not supported!" % (currentPlatform))

def getPackageName():
    packageName = "kubescape"
    # if platform.system() == "Windows": packageName += ".exe"

    return packageName


def main():
    print("Building Kubescape")

    # print environment variables
    # print(os.environ)

    # Set some variables
    packageName = getPackageName()
    buildUrl = "github.com/armosec/kubescape/v2/core/cautils.BuildNumber"
    releaseVersion = os.getenv("RELEASE")

    # Create build directory
    buildDir = getBuildDir()

    ks_file = os.path.join(buildDir, packageName)
    hash_file = ks_file + ".sha256"

    if not os.path.isdir(buildDir):
        os.makedirs(buildDir)

    # Build kubescape
    ldflags = "-w -s"
    if releaseVersion:
        ldflags += " -X {}={}".format(buildUrl, releaseVersion)

    build_command = ["go", "build", "-tags=static", "-o", ks_file, "-ldflags" ,ldflags]

    print("Building kubescape and saving here: {}".format(ks_file))
    print("Build command: {}".format(" ".join(build_command)))

    status = subprocess.call(build_command)
    checkStatus(status, "Failed to build kubescape")
    
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
