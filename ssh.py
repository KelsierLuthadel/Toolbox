#!/usr/bin/python3

import argparse
import sys

from network.socket.ssh import ConnectSSH

TARGET_HELP = """IP address for the target to connect to."""

USER_HELP = """Username to use for connection."""

PASSWORD_HELP = """Password to use to connect."""

TIMEOUT_HELP = """Timeout in seconds before giving up."""

VERBOSE_HELP = """Show debug output."""

FILE_HELP = """File containing passwords to iterate through."""


def parse_args():
    parser = argparse.ArgumentParser(description="ssh connect", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('target', nargs='?', default=None, help=TARGET_HELP)
    parser.add_argument('-u', '--username', action='store', dest='username', help=USER_HELP)
    parser.add_argument('-p', '--password', action='store', dest='password', help=PASSWORD_HELP)
    parser.add_argument('-f', '--file', action='store', dest='file', help=FILE_HELP)
    parser.add_argument('-t', '--timeout', action='store', dest='timeout', type=float, default=5, help=TIMEOUT_HELP)
    parser.add_argument('-v', '--verbose', action='store_true', dest='verbose', default=False, help=VERBOSE_HELP)

    return parser


def main():
    parser = parse_args()
    args = parser.parse_args()

    if args.target is None or args.username is None and (args.password is None or args.file is None):
        parser.print_help(sys.stderr)
        sys.exit(1)

    password_list = []

    if args.password is not None:
        password_list.append(args.password)
    else:
        password_list = read_passwords(args.file)

    ssh = ConnectSSH(args.target, username=args.username, verbose=args.verbose,
                     wait_time=args.timeout, passwords=password_list)
    ssh.run()


def read_passwords(filename):
    passwords_list = []
    with open(filename) as passwords:
        for password in passwords:
            passwords_list.append(password.strip('\n').strip('\r'))

    return passwords_list


if __name__ == '__main__':
    main()
