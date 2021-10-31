
tests_pkg = [
    "test_command"
    , "test_version"
]


def run():
    for i in tests_pkg:
        m = __import__(i)
        m.run()


if __name__ == "__main__":
    run()
