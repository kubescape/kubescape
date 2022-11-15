import smoke_utils
import sys


def test_command(command: list):
    print(f"Testing \"{' '.join(command[1:])}\" command")

    msg = smoke_utils.run_command(command)
    assert "unknown command" not in msg, f"{command[1:]} is missing: {msg}"
    assert "invalid parameter" not in msg, f"{command[1:]} is invalid: {msg}"

    print(f"Done testing \"{' '.join(command[1:])}\" command")


def run(kubescape_exec:str):
    print("Testing supported commands")

    test_command(command=[kubescape_exec, "version"])
    test_command(command=[kubescape_exec, "download"])
    test_command(command=[kubescape_exec, "config"])
    test_command(command=[kubescape_exec, "help"])
    test_command(command=[kubescape_exec, "scan", "framework"])
    test_command(command=[kubescape_exec, "scan", "control"])
    test_command(command=[kubescape_exec, "submit", "results"])

    print("Done testing commands")


if __name__ == "__main__":
    run(kubescape_exec=smoke_utils.get_exec_from_args(sys.argv))
