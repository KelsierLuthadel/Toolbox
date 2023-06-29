import _socket
import socket
from unittest import TestCase, mock
from unittest.mock import patch

from network.inet import inet_tools
from network.inet.inet_tools import get_hostname
from network.inet.interface import Interface
from network.inet.model.address import NetAddress, IPFamily


class TestTools(TestCase):

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

