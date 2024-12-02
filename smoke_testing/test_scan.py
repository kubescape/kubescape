import os
import smoke_utils
import sys


all_files = os.path.join("..", "*.yaml")
# all_files = os.path.join("..", "examples", "online-boutique", "*.yaml")
single_file = os.path.join("..", "examples", "online-boutique", "frontend.yaml")


def scan_all(kubescape_exec: str):
    return smoke_utils.run_command(command=[kubescape_exec, "scan", all_files])


def scan_control_name(kubescape_exec: str):
    return smoke_utils.run_command(command=[kubescape_exec, "scan", "control", 'HostPath mount', all_files])


def scan_control_id(kubescape_exec: str):
    return smoke_utils.run_command(command=[kubescape_exec, "scan", "control", 'C-0048', all_files])


def scan_controls(kubescape_exec: str):
    return smoke_utils.run_command(command=[kubescape_exec, "scan", "control", 'C-0048,C-0016', all_files])


def scan_framework(kubescape_exec: str):
    return smoke_utils.run_command(command=[kubescape_exec, "scan", "framework", "nsa", all_files])


def scan_frameworks(kubescape_exec: str):
    return smoke_utils.run_command(command=[kubescape_exec, "scan", "framework", "nsa,mitre", all_files])


def scan_all(kubescape_exec: str):
    return smoke_utils.run_command(command=[kubescape_exec, "scan", all_files])


def scan_all_format_sarif(kubescape_exec: str):
    return smoke_utils.run_command(command=[kubescape_exec, "scan", all_files, "--format", "sarif", "--output", "results"])


def scan_all_format_json(kubescape_exec: str):
    return smoke_utils.run_command(command=[kubescape_exec, "scan", all_files, "--format", "json", "--output", "results"])


def scan_all_format_junit(kubescape_exec: str):
    return smoke_utils.run_command(command=[kubescape_exec, "scan", all_files, "--format", "junit", "--output", "results"])


def scan_all_format_pretty_printer(kubescape_exec: str):
    return smoke_utils.run_command(command=[kubescape_exec, "scan", all_files, "--format", "pretty-printer", "--output", "results"])


def scan_all_format_html(kubescape_exec: str):
    return smoke_utils.run_command(command=[kubescape_exec, "scan", all_files, "--format", "html", "--output", "results"])


def scan_all_format_pdf(kubescape_exec: str):
    return smoke_utils.run_command(command=[kubescape_exec, "scan", all_files, "--format", "pdf", "--output", "results"])


def scan_from_stdin(kubescape_exec: str):
    return smoke_utils.run_command(command=["cat", single_file, "|", kubescape_exec, "scan", "framework", "nsa", "-"])


def run(kubescape_exec: str):
    print("Testing E2E on yaml files")

    # TODO - fix support
    # print("Testing scan all yaml files")
    # msg = scan_all(kubescape_exec=kubescape_exec)
    # smoke_utils.assertion(msg)

    print("Testing scan control id")
    msg = scan_control_id(kubescape_exec=kubescape_exec)
    print(f"scan_control_id message: {msg}")
    smoke_utils.assertion(msg)

    print("Testing scan controls")
    msg = scan_controls(kubescape_exec=kubescape_exec)
    smoke_utils.assertion(msg)

    print("Testing scan framework")
    msg = scan_framework(kubescape_exec=kubescape_exec)
    smoke_utils.assertion(msg)

    print("Testing scan frameworks")
    msg = scan_frameworks(kubescape_exec=kubescape_exec)
    smoke_utils.assertion(msg)

    print("Testing scan all")
    msg = scan_all(kubescape_exec=kubescape_exec)
    smoke_utils.assertion(msg)


    print("Testing scan_all_format_json")
    msg = scan_all_format_json(kubescape_exec=kubescape_exec)
    smoke_utils.assertion(msg)

    print("Testing scan_all_format_sarif")
    msg = scan_all_format_sarif(kubescape_exec=kubescape_exec)
    smoke_utils.assertion(msg)

    print("Testing scan_all_format_junit")
    msg = scan_all_format_junit(kubescape_exec=kubescape_exec)
    smoke_utils.assertion(msg)

    print("Testing scan_all_format_pretty_printer")
    msg = scan_all_format_pretty_printer(kubescape_exec=kubescape_exec)
    smoke_utils.assertion(msg)


    print("Testing scan_all_format_html")
    msg = scan_all_format_html(kubescape_exec=kubescape_exec)
    smoke_utils.assertion(msg)


    print("Testing scan_all_format_pdf")
    msg = scan_all_format_pdf(kubescape_exec=kubescape_exec)
    smoke_utils.assertion(msg)

    # TODO - fix test
    # print("Testing scan from stdin")
    # msg = scan_from_stdin(kubescape_exec=kubescape_exec)
    # smoke_utils.assertion(msg)

    print("Done E2E yaml files")


if __name__ == "__main__":
    run(kubescape_exec=smoke_utils.get_exec_from_args(sys.argv))
