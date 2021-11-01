import os
import sys
import hashlib
import platform
import subprocess

BASE_GETTER_CONST = "github.com/armosec/kubescape/cautils/getter"
BE_SERVER_CONST   = BASE_GETTER_CONST + ".ArmoBEURL"
ER_SERVER_CONST   = BASE_GETTER_CONST + ".ArmoERURL"
WEBSITE_CONST     = BASE_GETTER_CONST + ".ArmoFEURL"

def checkStatus(status, msg):
    if status != 0:
        sys.stderr.write(msg)
        exit(status)


def getBuildDir():
    currentPlatform = platform.system()
    buildDir = "build/"

    if currentPlatform == "Windows": buildDir += "windows-latest"
    elif currentPlatform == "Linux": buildDir += "ubuntu-latest"
    elif currentPlatform == "Darwin": buildDir += "macos-latest"
    else: raise OSError("Platform %s is not supported!" % (currentPlatform))

    return buildDir

def getPackageName():
    packageName = "kubescape"
    # if platform.system() == "Windows": packageName += ".exe"

    return packageName


def main():
    print("Building Kubescape")

    # print environment variables
    print(os.environ)

    # Set some variables
    packageName = getPackageName()
    buildUrl = "github.com/armosec/kubescape/clihandler/cmd.BuildNumber"
    releaseVersion = os.getenv("RELEASE")
    ArmoBEServer = os.getenv("ArmoBEServer")
    ArmoERServer = os.getenv("ArmoERServer")
    ArmoWebsite = os.getenv("ArmoWebsite")

    # Create build directory
    buildDir = getBuildDir()

    if not os.path.isdir(buildDir):
        os.makedirs(buildDir)

    # Build kubescape
    ldflags = "-w -s -X %s=%s -X %s=%s -X %s=%s -X %s=%s" \
        % (buildUrl, releaseVersion, BE_SERVER_CONST, ArmoBEServer,
           ER_SERVER_CONST, ArmoERServer, WEBSITE_CONST, ArmoWebsite)
    status = subprocess.call(["go", "build", "-o", "%s/%s" % (buildDir, packageName), "-ldflags" ,ldflags])
    checkStatus(status, "Failed to build kubescape")
    
    test_cli_prints(buildDir,packageName)


    sha1 = hashlib.sha1()
    with open(buildDir + "/" + packageName, "rb") as kube:
        sha1.update(kube.read())
        with open(buildDir + "/" + packageName + ".sha1", "w") as kube_sha:
            kube_sha.write(sha1.hexdigest())

    print("Build Done")

def test_cli_prints(buildDir,packageName):
    bin_cli = os.path.abspath(os.path.join(buildDir,packageName))

    print(f"testing CLI prints on {bin_cli}")
    status = str(subprocess.check_output([bin_cli, "-h"]))
    assert "download" in status, "download is missing: " + status    

if __name__ == "__main__":
    main()
