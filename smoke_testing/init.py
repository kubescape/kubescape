"""
Kubescape smoke testing

Execute all tests:
python init.py path/the/bin/kubescape

Execute single test:
python test_<name>.py path/the/bin/kubescape

Add a new test:
1. Create a python file with test_ prefix
2. Implement a function named run()

"""

import sys
import smoke_utils
import glob
import os

# get all python files in dir that begin with test_
tests_pkg = list(map(lambda x: os.path.splitext(os.path.basename(x))[0], glob.glob(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'test_*.py'))))


def run(**kwargs):
    for i in tests_pkg:
        m = __import__(i)
        m.run(**kwargs)


if __name__ == "__main__":
    # the first argument should be the kubescape binary path
    run(kubescape_exec=smoke_utils.get_exec_from_args(sys.argv))

'''
Supported tests:
1. Commands
2. Version number
3. E2E yaml scanning

TODO:
1. Test formats + output
2. Test --fail-threshold
3. Test known supported FW
4. Test FW list
5. Test Controls list
'''