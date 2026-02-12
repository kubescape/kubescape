import os
import re
import sys

import smoke_utils


def run(kubescape_exec: str):
    print("Testing version")

    ver = os.getenv("RELEASE")
    msg = smoke_utils.run_command(command=[kubescape_exec, "version"])
    if isinstance(msg, bytes):
        msg = msg.decode('utf-8')

    # Extract version from output
    version_match = re.search(r'Your current version is: ([^\s\n]+)', msg)
    if version_match:
        output_version = version_match.group(1)
        print(f"Found version in output: {output_version}")

        # If RELEASE is set, verify it matches the output
        if ver:
            # Check if RELEASE (with or without 'v' prefix) is in the output
            assert (ver in msg) or (ver.lstrip('v') in msg), f"expected version: {ver}, found: {output_version}"
        else:
            # If RELEASE is not set, just verify that a version was found
            assert output_version, f"no version found in output: {msg}"
    else:
        raise AssertionError(f"no version found in output: {msg}")

    print("Done testing version")


if __name__ == "__main__":
    run(kubescape_exec=smoke_utils.get_exec_from_args(sys.argv))
