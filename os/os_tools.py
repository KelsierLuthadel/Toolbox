import os


def is_sudo():
    """Return a flag indicating whether this process is running under sudo"""
    return 'SUDO_UID' in os.environ.keys()
