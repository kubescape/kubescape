import subprocess
import smoke_utils


def test_command(command: list):
    print(f"Testing \"{' '.join(command[1:])}\" command")

    msg = str(subprocess.check_output(command))
    assert "unknown command" not in msg, f"{command[1:]} is missing: {msg}"
    assert "invalid parameter" not in msg, f"{command[1:]} is invalid: {msg}"

    print(f"Done testing \"{' '.join(command[1:])}\" command")


def run():
    print("Testing supported commands")

    bin_cli = smoke_utils.get_bin_cli()
    test_command(command=[bin_cli, "version"])
    test_command(command=[bin_cli, "download"])
    test_command(command=[bin_cli, "config"])
    test_command(command=[bin_cli, "help"])
    test_command(command=[bin_cli, "scan"])
    test_command(command=[bin_cli, "scan", "framework"])
    test_command(command=[bin_cli, "scan", "control"])
    
    print("Done testing commands")


if __name__ == "__main__":
    run()
