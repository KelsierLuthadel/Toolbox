from collections import namedtuple
from dataclasses import dataclass
from typing import Tuple
from unittest import TestCase, mock

from mock.mock import patch
from scapy.packet import Packet
from scapy.plist import PacketList, QueryAnswer

from network.socket.arp import Arp
import scapy.layers.l2 as scapy


@dataclass
class MockResult:
    psrc: str
    hwsrc: str


@dataclass
class MockAnswer:
    answer: MockResult

class TestTools(TestCase):
    mock_answers = [[
        MockAnswer(answer=MockResult(psrc="3", hwsrc="0")),
        MockAnswer(answer=MockResult(psrc="1", hwsrc="0")),
        MockAnswer(answer=MockResult(psrc="2", hwsrc="0")),
    ]]

    @patch.object(scapy, 'arping')
    def test_scan(self, mock_arp):
        mock_arp.return_value = TestTools.mock_answers
        arp = Arp()
        response = arp.arp_scan("1")

        self.assertEqual(3, len(response))

    @patch.object(scapy, 'arping')
    def test_scan_order(self, mock_arp):
        mock_arp.return_value = TestTools.mock_answers
        arp = Arp()
        responses = arp.arp_scan("1")

        last_value = 0
        for response in responses:
            self.assertLess(last_value, int(response.ip))
            last_value = int(response.ip)

