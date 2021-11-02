import subprocess


def get_exec_from_args(args: list):
    return args[1]


def run_command(command):
    try:
        return f"{subprocess.check_output(command, stderr=subprocess.STDOUT)}"
    except Exception as e:
        return f"{e}"

