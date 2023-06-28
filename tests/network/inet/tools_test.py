from unittest import TestCase

from network.inet.inet_tools import read_ip, read_ports, get_hostname


class TestTools(TestCase):
    dummy_address = "127.0.0.1"
    dummy_address2 = "127.0.0.2"
    dummy_range = "127.0.0.0/24"

    def test_single_ip(self):
        read = read_ip(TestTools.dummy_address)
        self.assertEqual([TestTools.dummy_address], read)

    def test_cidr_range(self):
        read = read_ip(TestTools.dummy_range)
        ip_range = []
        for i in range(1, 255):
            ip_range.append("127.0.0." + str(i))
        self.assertEqual(ip_range, read)

    def test_multiple(self):
        read = read_ip("["+TestTools.dummy_address + "," + TestTools.dummy_address2 + "]")
        self.assertEqual([TestTools.dummy_address,TestTools.dummy_address2], read)

    def test_port(self):
        port = read_ports("80")
        self.assertEqual([80], port)

    def test_ports(self):
        port = read_ports("80,443")
        self.assertEqual([80,443], port)

    def test_port_range(self):
        port = read_ports("80-82")
        self.assertEqual([80, 81, 82], port)

    def test_ports_range(self):
        port = read_ports("80-82,443,8080-8081,9090")
        self.assertEqual([80, 81, 82, 443, 8080, 8081, 9090], port)

    def test_hostname(self):
        host = get_hostname("127.0.0.1")
        self.assertEqual("localhost", host)

    def test_hostname_using_hostname(self):
        host = get_hostname("localhost")
        self.assertEqual("localhost", host)

    def test_bad_ports(self):
        self.assertRaises(ValueError, read_ports, "&")

    def test_bad_ip(self):
        self.assertRaises(ValueError, read_ip, "256.256.256.256")
        self.assertRaises(ValueError, read_ip, "1.2.3")
        self.assertRaises(ValueError, read_ip, "bad")

    def test_bad_cidr(self):
        self.assertRaises(ValueError, read_ip, "256.256.256.0/24")

    def test_bad_ips(self):
        self.assertRaises(ValueError, read_ip, "12345")

    def test_bad_ip_group(self):
        value = read_ip("[1.1.1.1,4.5.6]")
        self.assertEqual(["1.1.1.1"], value)

    def test_bad_hostname(self):
        self.assertRaises(OSError, get_hostname, "&")



