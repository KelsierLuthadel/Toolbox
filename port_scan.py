#!/usr/bin/python3

import argparse
import os
from errno import ECONNREFUSED

from network.inet.inet_tools import get_local_ip, cidr_from_ip
from network.inet.model.port import PortStatus
from network.socket.scan import Scan

TARGET_HELP = """Target IP to scan, if this is not provided it will default to the local IP address. Can be one of: 
Single IP: 192.168.0.1 
Multiple IPs as a comma separated list and enclosed in []: [192.168.0.1,192.168.0.55] 
CIDR range: 192.168.0/24"""

PORT_HELP = """A range of ports, if this is not provided it will default to 22,23,80,443. Can be one of: 
Single port: 80 
Multiple ports: 80,443 
Range of ports: 8080-8010 
Combination of ports: 22,80-90,8080"""

THREAD_HELP = """maximum number of threads, default is 500, with a maximum of 4096."""

SHOW_FAILED_HELP = """Show connection failures."""

SHOW_BANNER = """Show connection banner."""

TIMEOUT_HELP = """Maximum time in fractional seconds to wait for a response."""

RESOLVE_HELP = """Attempt to resolve hostnames"""


def parse_args():
    parser = argparse.ArgumentParser(description="Port scanner", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('target', nargs='?', default=None, help=TARGET_HELP)
    parser.add_argument('-p', '--port', action='store', dest='port', help=PORT_HELP)
    parser.add_argument('-t', '--threads', action='store', dest='max_threads', default=500, type=int, help=THREAD_HELP)
    parser.add_argument('-e', '--show_refused', action='store_true', dest='show_refused', default=False,
                        help=SHOW_FAILED_HELP)
    parser.add_argument('-b', '--show_banner', action='store_true', dest='show_banner', default=False, help=SHOW_BANNER)
    parser.add_argument('-w', '--wait', action='store', dest='wait_time', default=3, type=float, help=TIMEOUT_HELP)
    parser.add_argument('-r', '--resolve', action='store_true', dest='resolve', default=True, help=RESOLVE_HELP)

    return parser.parse_args()


def main():
    args = parse_args()

    if args.target is None:
        ip = get_local_ip()
        args.target = cidr_from_ip(ip)
        print(f"[+] scanning: {args.target}")

    scanner = Scan(address=args.target, port=args.port,
                   max_threads=args.max_threads, show_refused=args.show_refused, show_banner=args.show_banner,
                   wait_time=args.wait_time, resolve_hostnames=args.resolve)

    scanner.run()

    verbose = args.show_refused

    for host in scanner.get_ordered_results():
        ip = host.address
        for port in host.ports:
            status = port.status
            details = port.details
            port_number = port.port_number

            if status == PortStatus.OPEN:
                port_status = "Open"
            else:
                port_status = "Closed"

            if status != 0 and verbose is False:
                continue
            print_status(details, ip, port_number, port_status, status)

    if args.resolve is True:
        resolve_hostnames(scanner)

    print("\nEnd")


def resolve_hostnames(scanner):
    print("\nResolving hosts:")
    for value in scanner.get_ordered_results():
        if value.hostname is not None:
            print(f"   [+] {value.address} resolves to {value.hostname}")


def print_status(details, ip, port_number, port_status, status):
    if details is None:
        if status != 0:
            if status == ECONNREFUSED:
                print(f"[-] {ip}:{port_number} is {port_status}: {os.strerror(status)}")
        else:
            print(f"[+] {ip}:{port_number} is {port_status}")
    else:
        print(f"[+] {ip}:{port_number} is {port_status}: {details}:")


if __name__ == '__main__':
    main()
