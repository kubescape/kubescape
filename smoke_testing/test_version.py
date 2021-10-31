import os
import subprocess
import smoke_utils


def test_command(command: list):
    print(f"Testing \"{' '.join(command[1:])}\" command")

    msg = str(subprocess.check_output(command))
    assert "unknown command" in msg, f"{command[1:]} is missing: {msg}"
    assert "invalid parameter" in msg, f"{command[1:]} is invalid: {msg}"

    print(f"Done testing \"{' '.join(command[1:])}\" command")


def run():
    print("Testing version")

    ver = os.getenv("RELEASE")
    msg = str(subprocess.check_output([smoke_utils.get_bin_cli(), "version"]))
    assert ver in msg, f"expected version: {ver}, found: {msg}"

    print("Done testing version")


if __name__ == "__main__":
    run()
