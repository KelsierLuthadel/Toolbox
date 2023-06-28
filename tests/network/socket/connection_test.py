import argparse
from errno import ECONNREFUSED
from unittest import TestCase
from unittest.mock import patch

import mock

from network.inet.model.port import PortType, PortStatus
from network.socket.scan import Scan
from port_scan import main


def get_port(port_list, port_number):
    return next(port for port in port_list.ports if port.port_number == port_number)


class TestScan(TestCase):
    dummy_address = "1.1.1.1"
    dummy_address2 = "1.1.1.2"
    dummy_address_group = "[1.1.1.1,1.1.1.2]"
    dummy_unordered_address = "[10.1.1.20,1.1.1.2]"

    @patch.object(Scan, 'create_socket')
    def test_default_port(self, mock_method):
        mock_method.return_value.connect_ex.return_value = 0
        connection = Scan(address=TestScan.dummy_address_group)
        connection.run()

        self.assertEqual(8, connection.connections)

    @patch.object(Scan, 'create_socket')
    def test_scan_port_open(self, mock_method):
        mock_method.return_value.connect_ex.return_value = 0
        connection = Scan(address=TestScan.dummy_address, port="1")
        connection.scan(TestScan.dummy_address, 1)

        self.assert_connection(expected_address=TestScan.dummy_address,
                               expected_port=1,
                               expected_status=PortStatus.OPEN,
                               expected_status_code=0,
                               expected_port_type=PortType.TCP,
                               results=connection.results)

    @patch.object(Scan, 'create_socket')
    def test_scan_banner(self, mock_method):
        mock_method.return_value.connect_ex.return_value = 0
        mock_method.return_value.recv.return_value = b'banner'
        connection = Scan(address=TestScan.dummy_address, port="1", show_banner=True)
        connection.scan(TestScan.dummy_address, 1)

        self.assert_connection(expected_address=TestScan.dummy_address,
                               expected_port=1,
                               expected_status=PortStatus.OPEN,
                               expected_status_code=0,
                               expected_port_type=PortType.TCP,
                               results=connection.results,
                               banner='banner')

    @patch.object(Scan, 'create_socket')
    def test_scan_port_closed(self, mock_method):
        mock_method.return_value.connect_ex.return_value = ECONNREFUSED
        connection = Scan(address=TestScan.dummy_address, port="1")
        connection.scan(TestScan.dummy_address, 1)

        self.assert_connection(expected_address=TestScan.dummy_address,
                               expected_port=1,
                               expected_status=PortStatus.CLOSED,
                               expected_status_code=ECONNREFUSED,
                               expected_port_type=PortType.TCP,
                               results=connection.results)

    @patch.object(Scan, 'create_socket')
    def test_scan_udp(self, mock_method):
        mock_method.return_value.connect_ex.return_value = 0
        connection = Scan(address=TestScan.dummy_address, port="1", tcp=False)
        connection.scan(TestScan.dummy_address, 1)

        self.assert_connection(expected_address=TestScan.dummy_address,
                               expected_port=1,
                               expected_status=PortStatus.OPEN,
                               expected_status_code=0,
                               expected_port_type=PortType.UDP,
                               results=connection.results)

    @patch.object(Scan, 'create_socket')
    def test_single_ip_port(self, mock_method):
        mock_method.return_value.connect_ex.return_value = ECONNREFUSED
        connection = Scan(address=TestScan.dummy_address, port="1")
        connection.run()

        self.assert_connection(expected_address=TestScan.dummy_address,
                               expected_port=1,
                               expected_status=PortStatus.CLOSED,
                               expected_status_code=ECONNREFUSED,
                               expected_port_type=PortType.TCP,
                               results=connection.results)

    @patch.object(Scan, 'create_socket')
    def test_ips_single_port(self, mock_method):
        mock_method.return_value.connect_ex.return_value = 0
        connection = Scan(address=TestScan.dummy_address_group, port="1")
        connection.run()

        self.assert_connection(expected_address=TestScan.dummy_address,
                               expected_port=1,
                               expected_status=PortStatus.OPEN,
                               expected_status_code=0,
                               expected_port_type=PortType.TCP,
                               results=connection.results)
        self.assert_connection(expected_address=TestScan.dummy_address2,
                               expected_port=1,
                               expected_status=PortStatus.OPEN,
                               expected_status_code=0,
                               expected_port_type=PortType.TCP,
                               results=connection.results)

    def assert_connection(self, expected_address, expected_port,
                          expected_status, expected_status_code,
                          expected_port_type, results, banner=None):
        result = results.get_host_from_ip_address(expected_address)
        port = next(port for port in result.ports if port.port_number == expected_port)

        self.assertEqual(expected_address, result.address)
        self.assertEqual(expected_port, port.port_number)
        self.assertEqual(expected_status, port.status)
        self.assertEqual(expected_status_code, port.status_code)
        self.assertEqual(expected_port_type, port.port_type)
        self.assertEqual(banner, port.details)

    @patch.object(Scan, 'create_socket')
    def test_cidr_single_port(self, mock_method):
        mock_method.return_value.connect_ex.return_value = 0
        connection = Scan(address="1.1.1.0/24", port="1")
        connection.run()

        self.assertEqual(254, connection.connections)

    @patch.object(Scan, 'create_socket')
    def test_single_ip_multiple_ports(self, mock_method):
        mock_method.return_value.connect_ex.return_value = 0
        connection = Scan(address=TestScan.dummy_address, port="1,2,3")
        connection.run()

        self.assert_connection(expected_address=TestScan.dummy_address,
                               expected_port=1,
                               expected_status=PortStatus.OPEN,
                               expected_status_code=0,
                               expected_port_type=PortType.TCP,
                               results=connection.results)
        self.assert_connection(expected_address=TestScan.dummy_address,
                               expected_port=2,
                               expected_status=PortStatus.OPEN,
                               expected_status_code=0,
                               expected_port_type=PortType.TCP,
                               results=connection.results)
        self.assert_connection(expected_address=TestScan.dummy_address,
                               expected_port=3,
                               expected_status=PortStatus.OPEN,
                               expected_status_code=0,
                               expected_port_type=PortType.TCP,
                               results=connection.results)

    @patch.object(Scan, 'create_socket')
    def test_single_ip_port_range(self, mock_method):
        mock_method.return_value.connect_ex.return_value = 0
        connection = Scan(address=TestScan.dummy_address, port="1-3")
        connection.run()

        self.assert_connection(expected_address=TestScan.dummy_address,
                               expected_port=1,
                               expected_status=PortStatus.OPEN,
                               expected_status_code=0,
                               expected_port_type=PortType.TCP,
                               results=connection.results)
        self.assert_connection(expected_address=TestScan.dummy_address,
                               expected_port=2,
                               expected_status=PortStatus.OPEN,
                               expected_status_code=0,
                               expected_port_type=PortType.TCP,
                               results=connection.results)
        self.assert_connection(expected_address=TestScan.dummy_address,
                               expected_port=3,
                               expected_status=PortStatus.OPEN,
                               expected_status_code=0,
                               expected_port_type=PortType.TCP,
                               results=connection.results)

    @patch.object(Scan, 'create_socket')
    def test_udp(self, mock_method):
        mock_method.return_value.connect_ex.return_value = 0
        connection = Scan(address=TestScan.dummy_address, port="1-3", tcp=False)
        connection.run()

        self.assert_connection(expected_address=TestScan.dummy_address,
                               expected_port=1,
                               expected_status=PortStatus.OPEN,
                               expected_status_code=0,
                               expected_port_type=PortType.UDP,
                               results=connection.results)
        self.assert_connection(expected_address=TestScan.dummy_address,
                               expected_port=2,
                               expected_status=PortStatus.OPEN,
                               expected_status_code=0,
                               expected_port_type=PortType.UDP,
                               results=connection.results)
        self.assert_connection(expected_address=TestScan.dummy_address,
                               expected_port=3,
                               expected_status=PortStatus.OPEN,
                               expected_status_code=0,
                               expected_port_type=PortType.UDP,
                               results=connection.results)

    @patch.object(Scan, 'create_socket')
    def test_resolve(self, mock_method):
        mock_method.return_value.connect_ex.return_value = 0
        connection = Scan(address="127.0.0.1", port="1", resolve_hostnames=True, show_progress=True,
                          show_refused=True)
        connection.run()

        self.assertEqual("localhost", connection.results.get_host_from_ip_address("127.0.0.1").hostname)

    @patch.object(Scan, 'create_socket')
    def test_single_ip_port_ranges(self, mock_method):
        mock_method.return_value.connect_ex.return_value = 0
        connection = Scan(address=TestScan.dummy_address, port="1-3,4,9-10,80")
        connection.run()

        self.assert_connection(expected_address=TestScan.dummy_address,
                               expected_port=1,
                               expected_status=PortStatus.OPEN,
                               expected_status_code=0,
                               expected_port_type=PortType.TCP,
                               results=connection.results)
        self.assert_connection(expected_address=TestScan.dummy_address,
                               expected_port=2,
                               expected_status=PortStatus.OPEN,
                               expected_status_code=0,
                               expected_port_type=PortType.TCP,
                               results=connection.results)
        self.assert_connection(expected_address=TestScan.dummy_address,
                               expected_port=3,
                               expected_status=PortStatus.OPEN,
                               expected_status_code=0,
                               expected_port_type=PortType.TCP,
                               results=connection.results)
        self.assert_connection(expected_address=TestScan.dummy_address,
                               expected_port=4,
                               expected_status=PortStatus.OPEN,
                               expected_status_code=0,
                               expected_port_type=PortType.TCP,
                               results=connection.results)
        self.assert_connection(expected_address=TestScan.dummy_address,
                               expected_port=9,
                               expected_status=PortStatus.OPEN,
                               expected_status_code=0,
                               expected_port_type=PortType.TCP,
                               results=connection.results)
        self.assert_connection(expected_address=TestScan.dummy_address,
                               expected_port=10,
                               expected_status=PortStatus.OPEN,
                               expected_status_code=0,
                               expected_port_type=PortType.TCP,
                               results=connection.results)
        self.assert_connection(expected_address=TestScan.dummy_address,
                               expected_port=80,
                               expected_status=PortStatus.OPEN,
                               expected_status_code=0,
                               expected_port_type=PortType.TCP,
                               results=connection.results)

    @patch.object(Scan, 'create_socket')
    def test_ip_range_port_ranges(self, mock_method):
        mock_method.return_value.connect_ex.return_value = 0
        connection = Scan(address=TestScan.dummy_address_group, port="1-3,4,9-10,80")
        connection.run()

        self.assertEqual(14, connection.connections)

    @patch.object(Scan, 'create_socket')
    def test_zero_wait(self, mock_method):
        mock_method.return_value.connect_ex.return_value = 0
        self.assertRaises(ValueError, Scan, address=TestScan.dummy_address_group, wait_time=0)

    def test_max_threads(self):
        connection = Scan("0.0.0.0", max_threads=Scan.thread_limit + 1)
        self.assertEqual(Scan.thread_limit, connection.max_threads)

    @patch.object(Scan, 'create_socket')
    def test_pass_fail(self, mock_method):
        mock_method.return_value.connect_ex.side_effect = [0, 0,
                                                           0, 34,
                                                           0, 0,
                                                           0, 11,
                                                           0, 11]
        mock_method.return_value.recv.side_effect = [b"hello", b"bye",
                                                     b"hello",
                                                     b"hello", b"hello",
                                                     b"bye",
                                                     b"bye"]
        connection = Scan(address=TestScan.dummy_unordered_address, port="443,80", show_banner=True,
                          show_refused=True, show_progress=True)
        connection.run()

        results = connection.get_ordered_results()
        self.assertTrue(2 == len(results))

        first = connection.results.get_host_from_ip_address("1.1.1.2")
        second = connection.results.get_host_from_ip_address("10.1.1.20")

        self.assertEqual("1.1.1.2", first.address)
        self.assertEqual("10.1.1.20", second.address)

        self.assertEqual(2, len(first.ports))
        self.assertEqual(2, len(second.ports))

        port = get_port(first, 443)

        self.assertEqual("hello", port.details)
        self.assertEqual(443, port.port_number)
        self.assertEqual(PortStatus.OPEN, port.status)
        self.assertEqual(0, port.status_code)
        self.assertEqual(0, port.port_type)

        port = get_port(first, 80)
        self.assertEqual(None, port.details)
        self.assertEqual(80, port.port_number)
        self.assertEqual(PortStatus.CLOSED, port.status)
        self.assertEqual(34, port.status_code)
        self.assertEqual(0, port.port_type)

        port = get_port(second, 443)
        self.assertEqual("hello", port.details)
        self.assertEqual(443, port.port_number)
        self.assertEqual(PortStatus.OPEN, port.status)
        self.assertEqual(0, port.status_code)
        self.assertEqual(0, port.port_type)

        port = get_port(second, 80)
        self.assertEqual("bye", port.details)
        self.assertEqual(80, port.port_number)
        self.assertEqual(PortStatus.OPEN, port.status)
        self.assertEqual(0, port.status_code)
        self.assertEqual(0, port.port_type)

    @mock.patch('argparse.ArgumentParser.parse_args',
                return_value=argparse.Namespace(target="0.0.0.0", port="1,2", max_threads=255, show_refused=True,
                                                show_banner=True, wait_time=0.01, resolve=True, ))
    def test_scanner(self, mock_method):
        with mock.patch('socket.socket') as mock_socket:
            mock_socket.return_value.connect_ex.side_effect = [0, ECONNREFUSED]
            mock_socket.return_value.recv.return_value = b'test\n\r'
            main()
