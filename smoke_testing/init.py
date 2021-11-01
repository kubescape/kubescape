import sys
import smoke_utils


tests_pkg = [
    "test_command"
    , "test_version"
]


def run(**kwargs):
    for i in tests_pkg:
        m = __import__(i)
        m.run(**kwargs)


if __name__ == "__main__":
    run(kubescape_exec=smoke_utils.get_exec_from_args(sys.argv))
