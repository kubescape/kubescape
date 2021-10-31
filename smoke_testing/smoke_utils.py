import platform
from os import path
from sys import stderr


def get_build_dir():
    current_platform = platform.system()
    build_dir = "build/"

    if current_platform == "Windows": build_dir += "windows-latest"
    elif current_platform == "Linux": build_dir += "ubuntu-latest"
    elif current_platform == "Darwin": build_dir += "macos-latest"
    else: raise OSError(f"Platform {current_platform} is not supported!")

    return build_dir


def get_package_name():
    return "kubescape"


def get_bin_cli():
    return path.abspath(path.join(get_build_dir(), get_package_name()))


def check_status(status, msg):
    if status != 0:
        stderr.write(msg)
        exit(status)

