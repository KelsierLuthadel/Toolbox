from dataclasses import dataclass, field
from enum import IntEnum
from typing import List

from network.inet.model.port import Port


class IPFamily(IntEnum):
    IP4 = 0
    IP6 = 1


@dataclass
class NetAddress:
    family: IPFamily
    address: str
    gateway: str = None
    netmask: str = None
    mac_address: str = None
    broadcast: str = None
    hostname: str = None
    ports: List[Port] = field(default_factory=list)
