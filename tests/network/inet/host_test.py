from unittest import TestCase

from network.inet.host import Host
from network.inet.model.address import NetAddress, IPFamily
from network.inet.model.port import Port, PortType, PortStatus


class TestHost(TestCase):
    open_port = Port(port_number=1,
                     port_type=PortType.TCP,
                     status=PortStatus.OPEN,
                     status_code=0,
                     details="details")

    closed_port = Port(port_number=2,
                       port_type=PortType.UDP,
                       status=PortStatus.CLOSED,
                       status_code=11,
                       details="rejected")

    minimal_address = NetAddress(family=IPFamily.IP4,
                                 address="ip_address_0")

    basic_address = NetAddress(family=IPFamily.IP4,
                               address="ip_address_1",
                               gateway="gateway",
                               netmask="netmask",
                               mac_address="mac_address")

    address_with_ports = NetAddress(family=IPFamily.IP4,
                                    address="ip_address_2",
                                    gateway="gateway",
                                    netmask="netmask",
                                    mac_address="mac_address",
                                    broadcast="broadcast",
                                    ports=[open_port, closed_port])

    def test_empty_hosts(self):
        host = Host()
        self.assertEqual(0, len(host.address))

    def test_adding_address(self):
        host = Host()

        host.add_address(TestHost.minimal_address)
        self.assertEqual(1, len(host.address))

        host.add_address(TestHost.basic_address)
        self.assertEqual(2, len(host.address))

        host.add_address(TestHost.address_with_ports)
        self.assertEqual(3, len(host.address))

    def test_simple_host(self):
        host = Host()
        host.add_address(TestHost.basic_address)
        self.assertEqual(1, len(host.address))
        host_details = host.address.pop()
        self.assertIsNone(host_details.broadcast)
        self.assertIsNone(host_details.hostname)
        self.assertEqual(0, len(host_details.ports))

    def test_multiple_host(self):
        host = Host()
        host.add_address(TestHost.basic_address)
        host.add_address(TestHost.address_with_ports)

        self.assertEqual(2, len(host.address))
        first_host = host.address.pop(0)
        second_host = host.address.pop(0)

        self.assertIsNone(first_host.broadcast)
        self.assertIsNone(first_host.hostname)
        self.assertEqual(0, len(first_host.ports))

        self.assertIsNotNone(second_host.broadcast)
        self.assertIsNone(second_host.hostname)
        self.assertEqual(2, len(second_host.ports))

    def test_ports(self):
        host = Host()
        host.add_address(TestHost.address_with_ports)

        host = host.address.pop(0)
        first_port = host.ports.pop(0)
        second_port = host.ports.pop(0)

        self.assertEqual(1, first_port.port_number)
        self.assertEqual(PortType.TCP, first_port.port_type)
        self.assertEqual(PortStatus.OPEN, first_port.status)
        self.assertEqual(0, first_port.status_code)
        self.assertEqual("details", first_port.details)

        self.assertEqual(2, second_port.port_number)
        self.assertEqual(PortType.UDP, second_port.port_type)
        self.assertEqual(PortStatus.CLOSED, second_port.status)
        self.assertEqual(11, second_port.status_code)
        self.assertEqual("rejected", second_port.details)

    def test_adding_duplicate(self):
        host = Host()

        # Add the first host
        host.add_address(TestHost.basic_address)
        self.assertEqual(1, len(host.address))

        # Add the first host again, there should still be 1 host
        host.add_address(TestHost.basic_address)
        self.assertEqual(1, len(host.address))

        # Add the first host
        host.add_address(TestHost.address_with_ports)
        self.assertEqual(2, len(host.address))

        # Add the second host again, there should still be 2 hosts
        host.add_address(TestHost.address_with_ports)
        self.assertEqual(2, len(host.address))

    def test_lookup_address(self):
        host = Host()
        host.add_address(TestHost.basic_address)
        host.add_address(TestHost.address_with_ports)

        self.assertTrue(host.has_ip_address("ip_address_1"))
        self.assertTrue(host.has_ip_address("ip_address_2"))
        self.assertFalse(host.has_ip_address("unknown"))

    def test_getting_ip(self):
        host = Host()
        host.add_address(TestHost.basic_address)
        host.add_address(TestHost.address_with_ports)

        first_host = host.get_host_from_ip_address("ip_address_1")
        second_host = host.get_host_from_ip_address("ip_address_2")

        self.assertEqual("ip_address_1", first_host.address)
        self.assertEqual("ip_address_2", second_host.address)

    def test_getting_hostname(self):
        host = Host()
        host.add_address(NetAddress(family=IPFamily.IP4, address="1", gateway="gw",
                                    netmask="mask", mac_address="mac", hostname="hostname"))
        host.add_address(NetAddress(family=IPFamily.IP4, address="2", gateway="gw",
                                    netmask="mask", mac_address="mac", hostname="hostname"))

        hosts = host.get_hosts_from_hostname("hostname")
        self.assertEqual(2, len(hosts))

    def test_add_ports(self):
        host = Host()
        host.add_address(TestHost.basic_address)

        host.add_port_to_host("ip_address_1", TestHost.open_port)
        host.add_port_to_host("ip_address_1", TestHost.closed_port)

        host_details = host.get_host_from_ip_address("ip_address_1")
        self.assertEqual(2, len(host_details.ports))

        first_port = host_details.ports.pop(0)
        second_port = host_details.ports.pop(0)

        self.assertEqual(1, first_port.port_number)
        self.assertEqual(2, second_port.port_number)

    def test_resolve_no_resolution(self):
        host = Host(resolve=True)
        host.add_address(NetAddress(family=IPFamily.IP4,
                                    address="0",
                                    gateway="gateway",
                                    netmask="netmask",
                                    mac_address="mac_address"))

        host_details = host.get_host_from_ip_address("0")
        self.assertEqual("0.0.0.0", host_details.hostname)

    def test_resolve(self):
        host = Host(resolve=True)
        host.add_address(NetAddress(family=IPFamily.IP4,
                                    address="127.0.0.1",
                                    gateway="gateway",
                                    netmask="netmask",
                                    mac_address="mac_address"))

        host_details = host.get_host_from_ip_address("127.0.0.1")
        self.assertEqual("localhost", host_details.hostname)