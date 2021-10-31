import os
import subprocess
import smoke_utils


def run():
    print("Testing version")

    ver = os.getenv("RELEASE")
    msg = str(subprocess.check_output([smoke_utils.get_bin_cli(), "version"]))
    assert ver in msg, f"expected version: {ver}, found: {msg}"

    print("Done testing version")


if __name__ == "__main__":
    run()
