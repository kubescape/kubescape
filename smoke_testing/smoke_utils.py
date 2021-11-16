import subprocess


def get_exec_from_args(args: list):
    return args[1]


def run_command(command):
    try:
        return f"{subprocess.check_output(command, stdin=subprocess.PIPE, stderr=subprocess.STDOUT)}"
    except Exception as e:
        return f"{e}"


def assertion(msg):
    errors = ["Error: invalid parameter", "exit status 1"]
    for e in errors:
        assert e not in msg, msg

