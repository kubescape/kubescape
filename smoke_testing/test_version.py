import os
import smoke_utils
import sys


def run(kubescape_exec: str):
    print("Testing version")

    ver = os.getenv("RELEASE")
    msg = smoke_utils.run_command(command=[kubescape_exec, "version"])
    if isinstance(msg, bytes):
        msg = msg.decode('utf-8')
    assert (ver and ver in msg) or (ver and ver.lstrip('v') in msg), f"expected version: {ver}, found: {msg}"

    print("Done testing version")


if __name__ == "__main__":
    run(kubescape_exec=smoke_utils.get_exec_from_args(sys.argv))
