import _socket
import socket
from collections import namedtuple

import netifaces
import psutil
from unittest import TestCase, mock
from unittest.mock import patch

from network.inet import inet_tools
from network.inet.inet_tools import get_hostname
from network.inet.interface import Interface, get_interfaces
from network.inet.model.address import NetAddress, IPFamily


class TestTools(TestCase):
    nic = namedtuple('snicaddr', ['family', 'address', 'netmask', 'broadcast', 'ptp'])

    mock_nics = {'lo': [nic(family=socket.AF_INET, address='loopback', broadcast=None, netmask=None, ptp=None)],
                 'eth0': [nic(family=socket.AF_INET, address='ip4', broadcast=None, netmask=None, ptp=None),
                          nic(family=socket.AF_INET6, address='ip6', broadcast=None, netmask=None, ptp=None),
                          nic(family=psutil.AF_LINK, address='mac', broadcast=None, netmask=None, ptp=None)]}

    gateway = {"default": {
        socket.AF_INET: ("gateway4", 'eth0'),
        socket.AF_INET6: ("gateway6", 'eth0')
    }}

    def test_add_address(self):
        get_hostname("")
        interface = Interface(name="name")

        interface.add_address(NetAddress(family=IPFamily.IP4, address="address"))
        self.assertEqual(1, len(interface.address))

        interface.add_address(NetAddress(family=IPFamily.IP4, address="address"))
        self.assertEqual(2, len(interface.address))

        interface.add_address(NetAddress(family=IPFamily.IP4, address="address", mac_address="mac", hostname="host"))
        self.assertEqual(3, len(interface.address))

    @patch("_socket.gethostbyname")
    @patch("_socket.gethostbyaddr")
    def test_resolve_hostnames(self, mockaddr, mockname):
        mockaddr.return_value = ["name"]
        mockname.return_value = "0"
        interface = Interface(name="iface")
        interface.add_address(NetAddress(family=IPFamily.IP4, address="0"))
        interface.resolve_hostnames()

        for host in interface.address:
            self.assertEqual('name', host.hostname)
            self.assertEqual('0', host.address)

    def test_set_mac(self):
        with mock.patch('psutil.net_if_addrs', return_value=TestTools.mock_nics):
            with mock.patch('netifaces.gateways', return_value=TestTools.gateway):
                interfaces = get_interfaces()

        self.assertEqual(2, len(interfaces))

        for interface in interfaces:
            for address in interface.address:
                self.assertIsNotNone(address.gateway)

    def test_get_ip4(self):
        interface = Interface(name="iface")
        interface.add_address(NetAddress(family=IPFamily.IP4, address="ip4"))
        interface.add_address(NetAddress(family=IPFamily.IP4, address="ip4-2"))
        interface.add_address(NetAddress(family=IPFamily.IP4, address="ip4-3"))
        interface.add_address(NetAddress(family=IPFamily.IP6, address="ip6"))

        address = interface.get_ip4()
        self.assertEqual(3, len(address))

    def test_get_ip6(self):
        interface = Interface(name="iface")
        interface.add_address(NetAddress(family=IPFamily.IP4, address="ip4"))
        interface.add_address(NetAddress(family=IPFamily.IP6, address="ip6"))
        interface.add_address(NetAddress(family=IPFamily.IP6, address="ip6-2"))
        interface.add_address(NetAddress(family=IPFamily.IP4, address="ip4-2"))
        interface.add_address(NetAddress(family=IPFamily.IP6, address="ip6-3"))

        address = interface.get_ip6()
        self.assertEqual(3, len(address))
