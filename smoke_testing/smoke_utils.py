import subprocess


def get_exec_from_args(args: list):
    return args[1]

def run_command(command, stdin=subprocess.PIPE, stderr=subprocess.STDOUT):
    try:
        return f"{subprocess.check_output(command, stdin=stdin, stderr=stderr)}"
    except subprocess.CalledProcessError as e:
        print(f">>>>> Failed Command: {e.cmd}")
        print(f">>>>>>> Output: {e.output}")
        print(f">>>>>>> Stderr: {e.stderr}")
        print(f">>>>>>> Stdout: {e.stdout}")
        print(f">>>>>>> Exit status: {e.returncode}")
        return f"{e}"
    except Exception as e:
        return f"{e}"


def assertion(msg):
    errors = ["Error: invalid parameter", "exit status 1"]
    for e in errors:
        assert e not in msg, msg

