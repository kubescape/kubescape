import os
import platform


def main():
    current_platform = platform.system()
    if current_platform == "Windows":
        pass
    elif current_platform == "Linux" or current_platform == "Darwin":      
        os.system(f"git submodule update --init --recursive --init && cd git2go && make install-static")
    else: 
        raise OSError("Platform %s is not supported!" % (current_platform))

if __name__ == '__main__':
    main()
