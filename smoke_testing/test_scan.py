import os
import smoke_utils
import sys


def full_scan(kubescape_exec: str):
    return smoke_utils.run_command(command=[kubescape_exec, "scan", "framework", "nsa", os.path.join("..", "*.yaml")])


def run(kubescape_exec: str):
    # return
    print("Testing E2E yaml files")
    msg = full_scan(kubescape_exec=kubescape_exec)
    assert "exit status 1" not in msg, msg
    print("Done E2E yaml files")


if __name__ == "__main__":
    run(kubescape_exec=smoke_utils.get_exec_from_args(sys.argv))
