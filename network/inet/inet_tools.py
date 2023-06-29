import _socket
import subprocess
from socket import socket, error, AF_INET, SOCK_DGRAM
import re

SINGLE_IP = r'^(?:\d{1,3}\.){3}\d{1,3}$'
CIDR = r'^(?:\d{1,3}\.){3}0\/24$'
GROUPED_IP = r'^\[.*\]$'

SINGLE_PORT = r'^\d+$'
PORT_RANGE = r'^\d+-\d+$'


# Get the local IP address
# This will connect to an arbitrary IP address to get the local address
def get_local_ip():
    s = socket(AF_INET, SOCK_DGRAM)
    try:
        s.connect(('1.1.1.1', 1))
        ip = s.getsockname()[0]
    except error:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip


def get_hostname(host_ip):
    try:
        target_ip = _socket.gethostbyname(host_ip)
    except OSError:
        raise OSError(f"Invalid target {host_ip}")

    try:
        target_host = _socket.gethostbyaddr(target_ip)
        return target_host[0]
    except OSError:
        return target_ip


# Translate an IPv4 address into a Classless Inter-Domain Routing (CIDR) range
# 192.168.0.12 => 192.168.0.0/24
def cidr_from_ip(ip_address):
    segments = ip_address.split('.')
    segments[-1] = '0/24'
    return '.'.join(segments)


def is_single_ip(address):
    return re.match(SINGLE_IP, address)


def is_cidr(address):
    return re.match(CIDR, address)


# Convert IP addresses as a string into an array of addresses
#
# The input can be one of:
#    Single IP: 192.168.0.1
#    Multiple IPs as a comma separated list and enclosed in []: [192.168.0.1,192.168.0.55]
#    CIDR range: 192.168.0/24
def read_ip(address):
    # Single IP address
    if is_single_ip(address):
        if all([node < 256 for node in map(int, address.split('.'))]):
            return [address]
        raise ValueError('invalid IP Address')

    # Block 24 IP address.
    if is_cidr(address):
        network = list(map(int, address.split('.')[:3]))
        if all([node < 256 for node in network]):
            ip_address = '.'.join(map(str, network))
            return [ip_address + '.' + str(host_id) for host_id in range(1, 255)]
        raise ValueError('invalid IP Address')

    # List of IP Address
    if re.match(GROUPED_IP, address):
        addresses = address[1:-1]
        elements = [e.strip() for e in addresses.split(',')]
        ip_list = []
        for element in elements:
            try:
                ip_list.extend(read_ip(element))
            except ValueError:
                print(f"{element} is invalid")
        return ip_list

    raise ValueError('invalid address')


# Convert ports as a string into an array of ports
#
# The input can be one of:
#    Single port: 80
#    Multiple ports: 80,443
#    Range of ports: 8080-8010
#    Combination of ports: 22,80-90,8080
def read_ports(port_str):
    ports = port_str.split(',')
    port_list = []

    for port in ports:
        if re.match(SINGLE_PORT, port):
            port_list.append(int(port))
        elif re.match(PORT_RANGE, port):
            p_start = int(port.split('-')[0])
            p_end = int(port.split('-')[1])
            p_range = list(range(p_start, p_end + 1))
            port_list.extend(p_range)
        else:
            raise ValueError('invalid ports')
    return port_list


def get_ip_forward():
    response = subprocess.run(["sysctl", "net.ipv4.ip_forward"], capture_output=True)
    current = response.stdout.decode('ascii').strip('\n')

    match = re.match(r'\w.+= (\d)', current)
    if match:
        return bool(match.group(1))

    return False


def set_ip_forward(allow):
    if allow:
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    else:
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=0"])

    # Read values from the /etc/sysctl.conf file.
    subprocess.run(["sysctl", "-p", "/etc/sysctl.conf"])