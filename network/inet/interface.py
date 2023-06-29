from dataclasses import dataclass, field
import socket

import netifaces
import psutil
from psutil import net_if_addrs

from network.inet.inet_tools import get_hostname
from network.inet.model.address import NetAddress, IPFamily


class Interface:
    def __init__(self, name):
        self.name = name
        self.address = []
        self.mac = None

    def add_address(self, net_address: NetAddress):
        self.address.append(net_address)

    def resolve_hostnames(self):
        for address in (address for address in self.address if address.family == IPFamily.IP4):
            address.hostname = get_hostname(address.address)

    def set_mac(self, mac):
        self.mac = mac

    def get_ip4(self):
        return list(filter(lambda s: s.family == IPFamily.IP4, self.address))

    def get_ip6(self):
        return list(filter(lambda s: s.family == IPFamily.IP6, self.address))


def get_interfaces():
    interfaces = []
    for name, addresses in psutil.net_if_addrs().items():
        interface = Interface(name)
        for address in addresses:
            # If the family is AF_LINK, the address represents the MAC Address
            if address.family == psutil.AF_LINK:
                interface.mac = address.address
            else:
                if address.family == socket.AF_INET:
                    family = IPFamily.IP4
                else:
                    family = IPFamily.IP6

                net_address = NetAddress(address=address.address, netmask=address.netmask, family=family,
                                         gateway=get_default_gateway(address.family), broadcast=address.broadcast)
                interface.add_address(net_address)
        interfaces.append(interface)

    return interfaces


def get_default_gateway(family):
    gateways = netifaces.gateways()
    return gateways["default"][family][0]


def get_physical_addresses(interfaces):
    return list(filter(lambda s: s.name != 'lo', interfaces))

